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
//! - [`choco`] — Chocolatey's install posture, sources and configuration drift.
//! - [`scoop`] — Scoop's buckets and per-manifest hashes and hooks.
//! - [`orphan`] — Add/Remove Programs: what is installed that no manager claims.
//! - [`asep`] — the auto-start points the machine runs at logon.
//! - [`task`] — scheduled tasks, and the ones hiding from the task listing.
//! - [`service`] — services and drivers, and unquoted image paths.
//! - [`jobs`] — image hijacks, setup scripts, BITS jobs and answer files.
//! - [`posture`] — UAC, LSA, PATH and ACL: Windows' privilege primitives.
//! - [`network`] — hosts, proxies, DNS and root certificates (`--deep`).
//!
//! Three cross-cutting concerns are factored out rather than duplicated per
//! backend: [`recipe`] statically analyzes the install code a third-party package
//! runs (a Homebrew Ruby formula, a PKGBUILD, a maintainer script, an rpm
//! scriptlet), and [`privilege`] derives the execution surface from the files a
//! package installs (boot services, scheduled tasks, auth config, setuid bits)
//! and checks them against the package database. [`authenticode`] establishes
//! per-binary trust on Windows, where a signature covers a file rather than a
//! whole repository.
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
mod asep;
mod authenticode;
mod brew;
mod choco;
mod dnf;
mod jobs;
mod msix;
mod network;
mod nix;
mod orphan;
mod pacman;
mod posture;
mod privilege;
mod recipe;
mod scoop;
mod service;
mod task;
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
    ("choco", "choco", true),
    ("scoop", "scoop", true),
    // No CLI of its own: the registry is reached through PowerShell.
    ("arp", "powershell", true),
    ("asep", "powershell", true),
    ("task", "powershell", true),
    ("service", "powershell", true),
    ("jobs", "powershell", true),
    ("posture", "powershell", true),
    ("network", "powershell", true),
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
    /// Extra identities this layer accounts for, beyond its package names.
    ///
    /// Needed because a layer's package *name* is not always the name another
    /// layer knows it by: winget reports `Ubisoft.Connect` while the registry
    /// records `Ubisoft Connect`. Without the alias, cross-referencing calls a
    /// winget-managed package unclaimed.
    pub claims: Vec<String>,
    /// Machine-wide caveats to surface after loading (un-synced DB, weakened
    /// signing trust, tampered files, …) — one per entry, rendered as a list so
    /// a system with many caveats stays readable.
    pub notes: Vec<String>,
}

pub use orphan::flag_unclaimed;
pub use posture::flag_unsigned_driver_risk;

/// Options for [`inventory`].
#[derive(Default, Clone, Copy)]
pub struct Opts {
    /// Pull networked provenance during inventory (pacman's AUR RPC).
    pub online: bool,
    /// Force foreign/AUR detection past the un-synced-DB guard (pacman).
    pub force_aur: bool,
    /// Read the machine's network posture too (Windows). Incident-response
    /// material, so it is asked for rather than assumed.
    pub deep: bool,
    /// Verify Authenticode signatures on installed binaries (Windows). On by
    /// default from the CLI; `Opts::default()` leaves it off so a caller has to
    /// ask, which keeps the tests explicit about what they exercise.
    pub signatures: bool,
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
        "choco" => choco::choco_inventory(opts),
        "scoop" => scoop::scoop_inventory(opts),
        "arp" => orphan::orphan_inventory(opts),
        "asep" => asep::asep_inventory(opts),
        "task" => task::task_inventory(opts),
        "service" => service::service_inventory(opts),
        "jobs" => jobs::jobs_inventory(opts),
        "posture" => posture::posture_inventory(opts),
        "network" => network::network_inventory(opts),
        other => anyhow::bail!("no inventory backend for '{other}'"),
    }
}

/// Run a PowerShell script and return its stdout.
///
/// Passed as `-EncodedCommand` (base64 UTF-16LE): it sidesteps every layer of
/// quoting between here and PowerShell, and unlike `-File` it is not subject to
/// the script execution policy, so a locked-down machine can still be scanned.
pub(super) fn powershell(script: &str) -> Result<String> {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-EncodedCommand"])
        .arg(base64_utf16le(script))
        .output()
        .context("running powershell")?;
    if !out.status.success() {
        anyhow::bail!(
            "powershell failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Encode `s` as PowerShell's `-EncodedCommand` expects: UTF-16LE, then base64.
/// Hand-rolled rather than pulling a crate in for twenty lines.
pub(super) fn base64_utf16le(s: &str) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - i * 6)) as usize & 0x3F] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
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

/// Can this ACL entry let an **ordinary user** rewrite the object?
///
/// Decided by identifying unprivileged writers positively rather than by
/// listing privileged ones. The blacklist approach reported every Windows task
/// as writable: task files legitimately grant `FullControl` to the service that
/// owns them (`NT SERVICE\CryptSvc`, `LOCAL SERVICE`), and no exclusion list
/// keeps up with those.
///
/// `rights` is checked too: `WriteAttributes` is not the ability to replace a
/// file, and matching the substring `Write` treats it as though it were.
pub(super) fn is_unprivileged_writer(identity: &str, rights: &str) -> bool {
    if !rights_can_replace(rights) {
        return false;
    }

    let id = identity.trim().to_ascii_lowercase();
    // Groups that mean "anyone who can log in".
    const OPEN: &[&str] = &[
        "everyone",
        "builtin\\users",
        "nt authority\\authenticated users",
        "nt authority\\interactive",
        "nt authority\\everyone",
    ];
    if OPEN.contains(&id.as_str()) {
        return true;
    }
    // System and service principals are expected to own what they manage.
    const PRIVILEGED_PREFIXES: &[&str] = &[
        "nt authority\\",
        "nt service\\",
        // Windows creates a virtual account per scheduled task and grants it
        // control of that task's own definition.
        "nt task\\",
        "builtin\\",
        "application package authority\\",
        "window manager\\",
    ];
    if PRIVILEGED_PREFIXES.iter().any(|p| id.starts_with(p)) || id == "creator owner" {
        return false;
    }
    // A raw SID means this machine cannot resolve the principal — typically an
    // ACE inherited from the image the machine was built from. Windows' own
    // task files carry one of these (`S-1-5-21-…-500`, the built-in
    // Administrator of another machine), and reading it as "a person can write
    // here" flagged 48 stock tasks. Well-known privileged RIDs are recognised;
    // anything else unresolvable is *unknown*, and unknown is not a finding.
    if let Some(rest) = id.strip_prefix("s-1-") {
        return is_unprivileged_sid(rest);
    }

    // Anything left is a named account or group - a person, not the platform.
    !id.is_empty()
}

/// Do these rights allow replacing the object?
///
/// Windows renders a rights mask by name only when every bit maps to the
/// `FileSystemRights` enum; otherwise it prints the raw integer — the reference
/// machine's `C:\` carries `-536805376`. Matching names alone silently reads
/// those as "not writable", which is an assumption, not an answer.
fn rights_can_replace(rights: &str) -> bool {
    let r = rights.trim();
    if let Ok(mask) = r.parse::<i64>() {
        return mask_can_replace(mask as u32);
    }
    let r = r.to_ascii_lowercase();
    r.contains("fullcontrol")
        || r.contains("modify")
        || r.contains("writedata")
        || r.contains("createfiles")
        // The composite FILE_GENERIC_WRITE renders as a bare `Write` token.
        || r.split(',').any(|t| t.trim() == "write")
}

/// Decode an access mask.
///
/// The distinction that matters on a directory: `FILE_WRITE_DATA` is the right
/// to create a *file* in it, while `FILE_APPEND_DATA` is only the right to
/// create a *subdirectory*. `C:\` grants Authenticated Users the latter, which
/// is why `C:\Program.exe` cannot be planted there and an unquoted service
/// path under `C:\Program Files` is not exploitable by default.
fn mask_can_replace(mask: u32) -> bool {
    const FILE_WRITE_DATA: u32 = 0x0000_0002;
    const DELETE: u32 = 0x0001_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    mask & (FILE_WRITE_DATA | GENERIC_WRITE | GENERIC_ALL) != 0
        // Delete-then-recreate replaces the object just as effectively.
        || mask & DELETE != 0
}

/// Classify a raw SID (everything after `S-1-`).
///
/// Only the accounts that are *definitely* ordinary users count; a SID whose
/// meaning cannot be established is left alone.
fn is_unprivileged_sid(rest: &str) -> bool {
    // Service and system authorities.
    if rest.starts_with("5-18")
        || rest.starts_with("5-19")
        || rest.starts_with("5-20")
        || rest.starts_with("5-80-")
        || rest.starts_with("5-83-")
        || rest.starts_with("15-")
    {
        return false;
    }
    // Built-in groups: `S-1-5-32-544` is Administrators.
    if rest.starts_with("5-32-") {
        return false;
    }
    // A domain/local account: the trailing RID says which.
    if let Some(rid) = rest.rsplit('-').next().and_then(|r| r.parse::<u32>().ok()) {
        const PRIVILEGED_RIDS: &[u32] = &[
            500, // built-in Administrator
            512, // Domain Admins
            516, // Domain Controllers
            518, // Schema Admins
            519, // Enterprise Admins
            544, // Administrators
        ];
        if PRIVILEGED_RIDS.contains(&rid) {
            return false;
        }
    }
    // Unresolvable and not recognisably privileged: not something to assert.
    false
}

/// The PowerShell helper every Windows layer uses to turn a raw command line
/// into an absolute path.
///
/// Shared on purpose. Three layers resolved targets with three copies of this
/// logic and each learned different lessons: `asep` resolved bare names through
/// `PATH`, `service` expanded `\??\` and `\SystemRoot\`, `task` did neither —
/// which is why two Windows tasks (`sc.exe`, `BthUdTask.exe`) were reported as
/// pointing at missing files.
pub(super) const PS_RESOLVE_IMAGE: &str = r#"
function Resolve-Image([string]$cmd) {
  if (-not $cmd) { return '' }
  $c = $cmd.Trim()

  # A quoted path is authoritative.
  if ($c.StartsWith('"')) {
    $end = $c.IndexOf('"', 1)
    $c = if ($end -gt 0) { $c.Substring(1, $end - 1) } else { $c.Trim('"') }
  } else {
    # Otherwise the executable ends at its extension, not at the first space:
    # `C:\Program Files\A B\x.exe --flag` must not split on the space.
    foreach ($ext in @('.exe','.sys','.dll','.com','.bat','.cmd','.scr','.pif')) {
      $i = $c.ToLower().IndexOf($ext)
      if ($i -ge 0) {
        $end = $i + $ext.Length
        if ($end -eq $c.Length -or $c[$end] -eq ' ') { $c = $c.Substring(0, $end); break }
      }
    }
  }

  $c = $c -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:WINDIR
  $c = [Environment]::ExpandEnvironmentVariables($c).Replace('/', '\')
  if ($c -match '^system32|^SysWOW64') { $c = Join-Path $env:WINDIR $c }

  # A bare name carries no directory: Windows resolves it through PATH at run
  # time, so it is not a dangling reference.
  if ($c -and $c -notmatch '[\\/]') {
    $r = (Get-Command $c -ErrorAction SilentlyContinue).Source
    if ($r) { $c = $r }
  }
  return $c
}
"#;

/// A signal key scoped to one ecosystem.
///
/// The separator is a control character so it cannot occur in a package name —
/// Windows entries in particular carry backslashes, spaces and braces.
pub fn qualify(ecosystem: &str, name: &str) -> String {
    format!("{ecosystem}\u{1f}{name}")
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
        // Qualified first, so a merged multi-layer inventory attributes each
        // finding to the layer that raised it; bare second, because a
        // single-backend run has nothing to disambiguate.
        let qualified = qualify(&n.ecosystem, &n.name);
        if let Some(list) = signals.get(&qualified).or_else(|| signals.get(&n.name)) {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The blacklist this replaced reported **every** Windows scheduled task as
    /// writable: task files legitimately grant `FullControl` to the service
    /// that owns them, and no list of privileged principals keeps up.
    #[test]
    fn service_principals_are_not_unprivileged_writers() {
        for identity in [
            r"NT AUTHORITY\SYSTEM",
            r"NT AUTHORITY\LOCAL SERVICE",
            r"NT AUTHORITY\NETWORK SERVICE",
            r"NT SERVICE\CryptSvc",
            r"NT SERVICE\AppIDSvc",
            r"NT SERVICE\TrustedInstaller",
            r"NT TASK\Microsoft-Windows-AppID-EDP Policy Manager",
            r"BUILTIN\Administrators",
            "CREATOR OWNER",
        ] {
            assert!(
                !is_unprivileged_writer(identity, "FullControl"),
                "{identity} is the platform, not a person"
            );
        }
    }

    #[test]
    fn open_groups_and_named_accounts_are() {
        for identity in [
            "Everyone",
            r"BUILTIN\Users",
            r"NT AUTHORITY\Authenticated Users",
            r"NT AUTHORITY\INTERACTIVE",
            r"DESKTOP-N5AL1VF\alice",
            r"CONTOSO\Domain Users",
        ] {
            assert!(is_unprivileged_writer(identity, "Modify, Synchronize"), "{identity}");
        }
    }

    /// `WriteAttributes` is not the ability to replace a file, and matching the
    /// substring `Write` treated it as though it were.
    #[test]
    fn only_rights_that_can_replace_the_file_count() {
        let user = r"BUILTIN\Users";
        assert!(!is_unprivileged_writer(user, "Read, Synchronize"));
        assert!(!is_unprivileged_writer(user, "ReadAndExecute, Synchronize"));
        assert!(!is_unprivileged_writer(user, "WriteAttributes, ReadData"));
        assert!(!is_unprivileged_writer(user, "WriteExtendedAttributes"));

        assert!(is_unprivileged_writer(user, "FullControl"));
        assert!(is_unprivileged_writer(user, "Modify, Synchronize"));
        assert!(is_unprivileged_writer(user, "Write, Delete, Read, Synchronize"));
        assert!(is_unprivileged_writer(user, "CreateFiles, AppendData"));
    }

    /// Windows' own task files carry an ACE for a SID this machine cannot
    /// resolve — the built-in Administrator of whatever machine built the
    /// image. Reading that as "a person can write here" flagged 48 stock tasks.
    #[test]
    fn an_unresolved_sid_is_not_asserted_to_be_a_person() {
        // The real one, from the reference machine.
        assert!(!is_unprivileged_writer(
            "S-1-5-21-4024195226-107334468-2656468696-500",
            "FullControl"
        ));
        // Well-known privileged principals in raw form.
        for sid in [
            "S-1-5-18",
            "S-1-5-19",
            "S-1-5-32-544",
            "S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003",
            "S-1-5-21-1-2-3-512",
            "S-1-15-2-1",
        ] {
            assert!(!is_unprivileged_writer(sid, "FullControl"), "{sid}");
        }
        // And an ordinary user SID is still not asserted either: unresolvable
        // is unknown, and unknown is not a finding.
        assert!(!is_unprivileged_writer("S-1-5-21-1-2-3-1001", "FullControl"));
    }

    /// Windows prints a raw integer when a mask has bits outside the
    /// `FileSystemRights` enum — `C:\` carries `-536805376`. Matching names
    /// alone read those as "not writable" without ever looking.
    #[test]
    fn numeric_rights_masks_are_decoded_not_ignored() {
        let user = r"BUILTIN\Users";
        // GENERIC_READ | GENERIC_EXECUTE: no write.
        assert!(!is_unprivileged_writer(user, "-1610612736"));
        // FILE_WRITE_DATA on its own is enough to plant a file.
        assert!(is_unprivileged_writer(user, "2"));
        // GENERIC_WRITE and GENERIC_ALL likewise.
        assert!(is_unprivileged_writer(user, "1073741824"));
        assert!(is_unprivileged_writer(user, "268435456"));
        // DELETE alone: replace by removing and recreating.
        assert!(is_unprivileged_writer(user, "65536"));
    }

    /// The distinction the whole unquoted-path verdict rests on: `C:\` grants
    /// Authenticated Users `AppendData` — create a *subdirectory*, not a file.
    /// So `C:\Program.exe` cannot be planted, and the reference machine's one
    /// unquoted service path is correctly reported as not exploitable.
    #[test]
    fn creating_a_subdirectory_is_not_creating_a_file() {
        let au = r"NT AUTHORITY\Authenticated Users";
        assert!(!is_unprivileged_writer(au, "AppendData"));
        assert!(!is_unprivileged_writer(au, "4"), "FILE_APPEND_DATA alone");
        assert!(!is_unprivileged_writer(au, "CreateDirectories"));
        // But the right to create files there is the finding.
        assert!(is_unprivileged_writer(au, "CreateFiles"));
    }

    /// The real ACL of a Windows task file: nothing in it is a finding.
    #[test]
    fn a_real_windows_task_acl_yields_no_writer() {
        const REAL: &[(&str, &str)] = &[
            (r"NT AUTHORITY\SYSTEM", "FullControl"),
            (r"NT AUTHORITY\LOCAL SERVICE", "FullControl"),
            (r"BUILTIN\Administrators", "FullControl"),
            (r"NT SERVICE\CryptSvc", "FullControl"),
            (r"NT SERVICE\AppIDSvc", "FullControl"),
            (r"NT AUTHORITY\Authenticated Users", "Read, Synchronize"),
            (r"NT AUTHORITY\NETWORK SERVICE", "Read, Synchronize"),
        ];
        assert!(
            !REAL.iter().any(|(i, r)| is_unprivileged_writer(i, r)),
            "a stock task file must raise nothing"
        );
    }
}
