//! `postmortem system` — audit the machine's **OS-level** package managers.
//!
//! Where `scan`/`tree` read a project's committed lockfiles, `system` inspects
//! what's actually installed on *this* machine by shelling out to the package
//! manager.
//!
//! This module holds what every backend shares — the [`Manager`] detection table,
//! the [`SysSignal`] / [`Repo`] / [`Inventory`] vocabulary they all produce, the
//! [`inventory`] dispatcher, and the [`annotate`] pass that merges their offline
//! signals onto the shared `tree` model. One submodule per package manager:
//!
//! - [`brew`] — Homebrew formulae, casks and taps.
//! - [`pacman`] — Arch `pacman -Qi`, plus AUR provenance for foreign packages.
//! - [`apt`] — Debian/Ubuntu `apt`/`dpkg`, sources and keyring trust.
//! - [`dnf`] — Fedora/RHEL `dnf`/`rpm`, repo and vendor provenance.
//! - [`nix`] — the store closure reachable from the installed profiles.
//! - [`apk`] — Alpine's installed DB as a capability graph.
//! - [`winget`] — Windows' winget sources and the installed table behind them.
//! - [`msix`] — Windows MSIX/AppX packages, their signing and their capabilities.
//!
//! Two cross-cutting concerns are factored out rather than duplicated per
//! backend: [`recipe`] statically analyzes the install code a third-party package
//! runs (a Homebrew Ruby formula, a PKGBUILD, a maintainer script, an rpm
//! scriptlet), and [`privilege`] derives the execution surface from the files a
//! package installs (boot services, scheduled tasks, auth config, setuid bits)
//! and checks them against the package database.
//!
//! Two risk lenses feed the shared `tree` model:
//! - **provenance** (offline): third-party sources, unsigned or unverified
//!   downloads, install-time hooks, diversions, tampered files.
//! - **reputation** (`--online`): the source repo's stars/age/activity/language,
//!   via the same [`crate::resolve`] resolver.

use std::collections::HashMap;
use std::process::Command;

use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use serde::Deserialize;

use crate::model::{Category, DepRef, Dependency, Ecosystem, LicenseSource, Scope, Severity};
use crate::tree::{Node, Tree};

mod apk;
mod apt;
mod brew;
mod dnf;
mod msix;
mod nix;
mod pacman;
mod privilege;
mod recipe;
mod winget;

/// A known OS package manager and whether it's usable on this machine.
pub struct Manager {
    pub name: &'static str,
    /// Its CLI is present on `$PATH`.
    pub available: bool,
    /// postmortem has a backend for it (everything but MacPorts, today).
    pub implemented: bool,
}

/// The managers we recognize. `implemented` marks the ones with a backend; the
/// rest are detected-and-reported so the roadmap is visible.
const KNOWN: &[(&str, &str, bool)] = &[
    ("homebrew", "brew", true),
    ("pacman", "pacman", true),
    ("apt", "apt", true),
    ("dnf", "dnf", true),
    ("nix", "nix-store", true),
    ("apk", "apk", true),
    ("winget", "winget", true),
    // No CLI of its own: the AppX layer is reached through PowerShell, which is
    // what gates whether postmortem can read it at all.
    ("msix", "powershell", true),
    ("macports", "port", false),
];

/// Detect which known package managers are installed on this machine.
pub fn detect() -> Vec<Manager> {
    KNOWN
        .iter()
        .map(|(name, bin, implemented)| Manager {
            name,
            available: in_path(bin),
            implemented: *implemented,
        })
        .collect()
}

/// Is `bin` present as a file on any `$PATH` entry?
///
/// Windows resolves a bare command name through `PATHEXT`, so what sits on disk
/// is `winget.exe`, never `winget`. Probing the bare name alone finds nothing
/// there and every Windows backend would report itself as absent.
fn in_path(bin: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    let exts = path_exts();
    std::env::split_paths(&path).any(|dir| {
        dir.join(bin).is_file() || exts.iter().any(|e| dir.join(format!("{bin}{e}")).is_file())
    })
}

/// The executable suffixes to try alongside the bare name. Empty off Windows,
/// where a bare name is the whole story.
fn path_exts() -> Vec<String> {
    if !cfg!(windows) {
        return Vec::new();
    }
    std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string())
        .split(';')
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| e.starts_with('.'))
        .collect()
}

/// One offline system risk signal attached to a package by name: a label, its
/// severity (drives color + the flagged/unchecked split), and the points it adds
/// to the package's own risk score.
pub struct SysSignal {
    pub label: String,
    /// Which lens this signal belongs to. Carried so an OS-level signal reaches
    /// JSON/SARIF in the same vocabulary the language analyzers already use,
    /// instead of arriving as an uncategorised label.
    pub category: Category,
    pub severity: Severity,
    pub points: u8,
}

impl SysSignal {
    fn new(label: impl Into<String>, category: Category, severity: Severity, points: u8) -> Self {
        SysSignal {
            label: label.into(),
            category,
            severity,
            points,
        }
    }
}

/// One configured source repo, generic across backends (a Homebrew tap, a
/// pacman repo, an apt source, …).
pub struct Repo {
    /// Handle / section name, e.g. `homebrew/core`, `core`, `sn0walice/sshm`.
    pub name: String,
    /// Its URL/remote when known (empty otherwise).
    pub url: String,
    /// A first-party / trusted source (vs. a third-party one).
    pub official: bool,
}

/// The installed inventory for one system manager, in the shared `tree` model.
pub struct Inventory {
    pub manager: &'static str,
    /// Installed packages as `Dependency` nodes.
    pub deps: Vec<Dependency>,
    /// Configured source repos.
    pub repos: Vec<Repo>,
    /// Offline risk signals per package name, merged onto the tree by [`annotate`].
    pub signals: HashMap<String, Vec<SysSignal>>,
    /// A one-line human count, e.g. `117 formula(e) + 2 cask(s)`.
    pub summary: String,
    /// Machine-wide caveats to surface after loading (un-synced DB, weakened
    /// signing trust, tampered files, …) — one per entry, rendered as a list so
    /// a system with many caveats stays readable.
    pub notes: Vec<String>,
}

/// Options for [`inventory`].
#[derive(Default, Clone, Copy)]
pub struct Opts {
    /// Pull networked provenance during inventory (pacman's AUR RPC).
    pub online: bool,
    /// Force foreign/AUR detection past the un-synced-DB guard (pacman).
    pub force_aur: bool,
}

/// Build the installed inventory for a supported backend. Homebrew ignores
/// `opts` (its reputation comes from the shared `--online` path).
pub fn inventory(manager: &str, opts: Opts) -> Result<Inventory> {
    match manager {
        "homebrew" => brew::brew_inventory(),
        "pacman" => pacman::pacman_inventory(opts),
        "apt" => apt::apt_inventory(opts),
        "dnf" => dnf::dnf_inventory(opts),
        "nix" => nix::nix_inventory(opts),
        "apk" => apk::apk_inventory(opts),
        "winget" => winget::winget_inventory(opts),
        "msix" => msix::msix_inventory(opts),
        other => anyhow::bail!("no inventory backend for '{other}'"),
    }
}

/// An installed version behind the current one — running old code means missing
/// upstream (including security) fixes. Mild on its own.
fn outdated_signal(installed: &str, current: &str) -> SysSignal {
    SysSignal::new(
        format!("outdated ({installed} → {current})"),
        Category::Outdated,
        Severity::Low,
        10,
    )
}

fn push_signal(map: &mut HashMap<String, Vec<SysSignal>>, name: &str, sig: SysSignal) {
    map.entry(name.to_string()).or_default().push(sig);
}

// --- risk annotation ----------------------------------------------------------

/// Merge the offline system signals onto the tree, keyed by package name. Each
/// signal raises the node's severity (to at least its own) and adds its risk
/// points, so a package can carry several (e.g. a cask that is both an
/// unverified download and from a third-party tap). Run after
/// [`crate::tree::enrich`] (online) and before [`crate::tree::score`], so
/// `risk:dep` reflects both provenance and repo reputation.
pub fn annotate(tree: &mut Tree, signals: &HashMap<String, Vec<SysSignal>>) {
    fn walk(n: &mut Node, signals: &HashMap<String, Vec<SysSignal>>) {
        if let Some(list) = signals.get(&n.name) {
            for s in list {
                if !n.signals.contains(&s.label) {
                    n.signals.push(s.label.clone());
                }
                n.severity = Some(n.severity.map_or(s.severity, |cur| cur.max(s.severity)));
                n.risk = Some(n.risk.unwrap_or(0).saturating_add(s.points).min(100));
            }
        }
        for c in &mut n.children {
            walk(c, signals);
        }
    }
    for r in &mut tree.roots {
        walk(r, signals);
    }
}

// --- rendering ----------------------------------------------------------------

/// The detection banner: which managers are present, and which postmortem can
/// actually audit. Printed to stderr so it never corrupts `--json` on stdout.
pub fn render_detected(managers: &[Manager]) {
    let names: Vec<String> = managers
        .iter()
        .filter(|m| m.available)
        .map(|m| {
            if m.implemented {
                m.name.green().to_string()
            } else {
                format!("{} {}", m.name, "(detected, not yet supported)".dimmed())
            }
        })
        .collect();
    eprintln!(
        "{} {}",
        "detected package managers:".bold(),
        if names.is_empty() {
            "none".dimmed().to_string()
        } else {
            names.join(", ")
        }
    );
}

/// The `--repos` view: configured source repos, official first.
pub fn render_repos(inv: &Inventory) {
    println!(
        "{} {}",
        "source repos".bold(),
        format!("({})", inv.manager).dimmed()
    );
    if inv.repos.is_empty() {
        println!("  {}", "none configured".dimmed());
        return;
    }
    let (official, third): (Vec<&Repo>, Vec<&Repo>) = inv.repos.iter().partition(|r| r.official);
    for r in official {
        println!("  {}", r.name.green());
    }
    for r in &third {
        let url = if r.url.is_empty() {
            String::new()
        } else {
            format!("[{}]  ", r.url).dimmed().to_string()
        };
        println!(
            "  {}  {}{}",
            r.name.truecolor(255, 165, 0),
            url,
            "third-party".truecolor(255, 165, 0),
        );
    }
    if !third.is_empty() {
        println!(
            "\n{}",
            format!(
                "⚠ {} third-party source(s) outside the official repos",
                third.len()
            )
            .truecolor(255, 165, 0)
        );
    }
}
