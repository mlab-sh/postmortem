//! `postmortem system` — audit the machine's **OS-level** package managers.
//!
//! Where `scan`/`tree` read a project's committed lockfiles, `system` inspects
//! what's actually installed on *this* machine by shelling out to the package
//! manager. Homebrew is the first (and today only) backend:
//!
//! - `brew info --json=v2 --installed` — the full installed forest: **formulae**
//!   (with versions, `installed_on_request` roots, and `declared_directly`
//!   dependency edges) and **casks** (apps installed as prebuilt binaries).
//! - `brew tap-info --json --installed` — the configured **source repos** and
//!   their real git remotes. Anything beyond the official `homebrew/*` taps
//!   bypasses core review → a provenance risk.
//!
//! Two risk lenses feed the shared `tree` model:
//! - **provenance** (offline, [`analyze_signals`]): third-party taps, and for
//!   casks the extra supply-chain surface — an unverified download
//!   (`sha256 :no_check`), an insecure/`http` URL, a download host unrelated to
//!   the homepage, a `pkg`/`installer` artifact (elevated install), self-updates,
//!   deprecation.
//! - **reputation** (`--online`): the source repo's stars/age/activity/language,
//!   via the same [`crate::resolve`] resolver (formula `homepage` / cask download
//!   URL → GitHub).

use std::collections::HashMap;
use std::process::Command;

use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use serde::Deserialize;

use crate::model::{DepRef, Dependency, Ecosystem, Severity};
use crate::tree::{Node, Tree};

/// Download hosts that are legitimate release mirrors, so a cask downloading
/// from them while its homepage is elsewhere is normal (not a redirect tell).
const TRUSTED_DL_HOSTS: &[&str] =
    &["github.com", "gitlab.com", "codeberg.org", "sourceforge.net", "bitbucket.org"];

/// A known OS package manager and whether it's usable on this machine.
pub struct Manager {
    pub name: &'static str,
    /// Its CLI is present on `$PATH`.
    pub available: bool,
    /// postmortem has a backend for it (only Homebrew, today).
    pub implemented: bool,
}

/// The managers we recognize. `implemented` marks the ones with a backend; the
/// rest are detected-and-reported so the roadmap is visible.
const KNOWN: &[(&str, &str, bool)] = &[
    ("homebrew", "brew", true),
    ("apt", "apt", false),
    ("dpkg", "dpkg", false),
    ("pacman", "pacman", false),
    ("dnf", "dnf", false),
    ("apk", "apk", false),
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
fn in_path(bin: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(bin).is_file())
}

/// One configured Homebrew tap (a source repo backing installable packages).
pub struct Tap {
    /// Tap handle, e.g. `sn0walice/sshm` or `homebrew/core`.
    pub name: String,
    /// The tap's actual git remote (from `brew tap-info`), e.g.
    /// `https://github.com/Sn0wAlice/sshm`. Empty for official taps (no remote).
    pub remote: String,
    /// An official `homebrew/*` tap (core-reviewed).
    pub official: bool,
}

/// One offline system risk signal attached to a package by name: a label, its
/// severity (drives color + the flagged/unchecked split), and the points it adds
/// to the package's own risk score.
pub struct SysSignal {
    pub label: String,
    pub severity: Severity,
    pub points: u8,
}

impl SysSignal {
    fn new(label: impl Into<String>, severity: Severity, points: u8) -> Self {
        SysSignal { label: label.into(), severity, points }
    }
}

/// The installed inventory for one system manager, in the shared `tree` model.
pub struct Inventory {
    pub manager: &'static str,
    /// Installed packages as `Dependency` nodes (ecosystem `brew`): formulae
    /// (with dependency edges) followed by casks (flat roots).
    pub deps: Vec<Dependency>,
    /// Configured source repos (taps).
    pub taps: Vec<Tap>,
    /// Number of installed casks (for the summary line).
    pub casks: usize,
    /// Offline risk signals per package name (third-party taps + cask analysis),
    /// merged onto the tree by [`annotate`].
    pub signals: HashMap<String, Vec<SysSignal>>,
}

// --- Homebrew JSON (`brew info --json=v2 --installed`) --------------------------

#[derive(Deserialize, Default)]
struct BrewOut {
    #[serde(default)]
    formulae: Vec<Formula>,
    #[serde(default)]
    casks: Vec<Cask>,
}

#[derive(Deserialize)]
struct Formula {
    name: String,
    tap: Option<String>,
    #[serde(default)]
    installed: Vec<Installed>,
}

#[derive(Deserialize)]
struct Installed {
    version: String,
    #[serde(default)]
    installed_on_request: bool,
    #[serde(default)]
    runtime_dependencies: Vec<RuntimeDep>,
}

#[derive(Deserialize)]
struct RuntimeDep {
    full_name: String,
    /// True when the parent formula declares this dep directly (vs. pulled
    /// transitively) — the signal we use to draw a single graph edge.
    #[serde(default)]
    declared_directly: bool,
}

#[derive(Deserialize)]
struct Cask {
    token: String,
    tap: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    installed: Option<String>,
    url: Option<String>,
    /// A hex digest, or the literal `"no_check"` when the cask declares
    /// `sha256 :no_check` (an unverified download).
    sha256: Option<String>,
    homepage: Option<String>,
    #[serde(default)]
    auto_updates: Option<bool>,
    #[serde(default)]
    deprecated: bool,
    #[serde(default)]
    disabled: bool,
    /// Each entry is a one-key object naming the artifact kind (`app`, `pkg`,
    /// `installer`, `binary`, `zap`, …).
    #[serde(default)]
    artifacts: Vec<serde_json::Value>,
}

/// Read the installed Homebrew forest, casks, and taps into an [`Inventory`].
pub fn brew_inventory() -> Result<Inventory> {
    let out = Command::new("brew")
        .args(["info", "--json=v2", "--installed"])
        .output()
        .context("running `brew info --json=v2 --installed`")?;
    if !out.status.success() {
        anyhow::bail!("`brew info` failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let (taps, tap_remote) = read_tap_info();
    let (deps, casks, signals) =
        analyze(&out.stdout, &tap_remote).context("parsing brew JSON")?;
    Ok(Inventory { manager: "homebrew", deps, taps, casks, signals })
}

/// The output of [`analyze`]: the packages (formulae forest + cask roots), the
/// cask count, and the offline risk signals keyed by package name.
type Analyzed = (Vec<Dependency>, usize, HashMap<String, Vec<SysSignal>>);

/// Turn `brew info --json=v2` output into the dependency forest, the cask count,
/// and the offline risk signals. `tap_remote` maps a tap handle to its real git
/// remote (used to point a third-party package at its tap's repo). Split from the
/// shell-out so it's unit-testable against a fixture.
fn analyze(json: &[u8], tap_remote: &HashMap<String, String>) -> Result<Analyzed> {
    let parsed: BrewOut = serde_json::from_slice(json)?;
    let mut signals: HashMap<String, Vec<SysSignal>> = HashMap::new();

    // --- formulae: the dependency forest ---
    let version: HashMap<&str, &str> = parsed
        .formulae
        .iter()
        .filter_map(|f| f.installed.first().map(|i| (f.name.as_str(), i.version.as_str())))
        .collect();

    // Invert declared-direct edges into a parent map: dep → its declaring
    // formulae. tree::build re-inverts this into the child forest.
    let mut parents: HashMap<String, Vec<DepRef>> = HashMap::new();
    for f in &parsed.formulae {
        let Some(inst) = f.installed.first() else { continue };
        for rd in &inst.runtime_dependencies {
            if rd.declared_directly && version.contains_key(rd.full_name.as_str()) {
                parents
                    .entry(rd.full_name.clone())
                    .or_default()
                    .push((f.name.clone(), inst.version.clone()));
            }
        }
    }

    let mut deps = Vec::with_capacity(parsed.formulae.len() + parsed.casks.len());
    for f in &parsed.formulae {
        let Some(inst) = f.installed.first() else { continue };
        // Third-party tap → provenance signal + carry the tap's remote so the
        // resolver assesses the tap repo instead of reporting "no repository".
        let third_party = f.tap.as_deref().filter(|t| !is_official_tap(t));
        if let Some(tap) = third_party {
            push_signal(&mut signals, &f.name, third_party_tap(tap));
        }
        deps.push(Dependency {
            name: f.name.clone(),
            version: inst.version.clone(),
            ecosystem: Ecosystem::Brew,
            direct: inst.installed_on_request,
            resolved_url: third_party.and_then(|t| tap_remote.get(t).cloned()),
            integrity: None,
            parents: parents.remove(&f.name).unwrap_or_default(),
        });
    }

    // --- casks: flat roots + the extra download/artifact risk surface ---
    let casks = parsed.casks.len();
    for c in &parsed.casks {
        let mut sigs = cask_signals(c);
        if let Some(tap) = c.tap.as_deref().filter(|t| !is_official_tap(t)) {
            sigs.push(third_party_tap(tap));
        }
        if !sigs.is_empty() {
            signals.entry(c.token.clone()).or_default().extend(sigs);
        }
        deps.push(Dependency {
            name: c.token.clone(),
            version: c.installed.clone().or_else(|| c.version.clone()).unwrap_or_default(),
            ecosystem: Ecosystem::Brew,
            direct: true, // casks are always user-installed
            // The download URL is often a GitHub release → resolves to the repo.
            resolved_url: c.url.clone(),
            integrity: c.sha256.clone(),
            parents: Vec::new(),
        });
    }

    Ok((deps, casks, signals))
}

/// The provenance signal for a package installed from a non-official tap.
fn third_party_tap(tap: &str) -> SysSignal {
    SysSignal::new(format!("third-party-tap ({tap})"), Severity::Medium, 30)
}

fn push_signal(map: &mut HashMap<String, Vec<SysSignal>>, name: &str, sig: SysSignal) {
    map.entry(name.to_string()).or_default().push(sig);
}

/// Cask-specific risk signals derived from its metadata: the download-and-run
/// surface a cask carries that a source-built formula doesn't.
fn cask_signals(c: &Cask) -> Vec<SysSignal> {
    let mut out = Vec::new();

    // An unverified download — brew runs whatever bytes arrive, no integrity pin.
    if c.sha256.as_deref() == Some("no_check") {
        out.push(SysSignal::new("unverified-download (sha256 :no_check)", Severity::High, 40));
    }
    if let Some(url) = &c.url {
        if url.starts_with("http://") {
            out.push(SysSignal::new("insecure-url (http)", Severity::High, 40));
        }
        // Download host unrelated to the homepage and not a known release mirror.
        if let (Some(home), Some(dl)) =
            (c.homepage.as_deref().and_then(host_domain), host_domain(url))
            && dl != home
            && !TRUSTED_DL_HOSTS.contains(&dl.as_str())
        {
            out.push(SysSignal::new(format!("download-host-mismatch ({dl})"), Severity::Low, 10));
        }
    }
    // A pkg/installer artifact runs an installer (elevated) rather than a plain
    // app drop — worth surfacing (informational).
    if c.artifacts.iter().any(is_installer_artifact) {
        out.push(SysSignal::new("runs-installer", Severity::Info, 0));
    }
    // Self-updating outside brew — later versions bypass this audit.
    if c.auto_updates == Some(true) {
        out.push(SysSignal::new("auto-updates", Severity::Info, 0));
    }
    if c.deprecated || c.disabled {
        out.push(SysSignal::new("deprecated", Severity::Medium, 20));
    }
    out
}

/// A cask artifact that runs an installer (`pkg`/`installer`) rather than just
/// dropping an `.app`.
fn is_installer_artifact(a: &serde_json::Value) -> bool {
    a.as_object().is_some_and(|o| o.contains_key("pkg") || o.contains_key("installer"))
}

/// The registrable-ish domain of a URL's host — the last two dot-labels
/// (`dl.google.com` → `google.com`, `github.com` → `github.com`). Naive for
/// multi-part TLDs (`co.uk`), which is acceptable for a coarse host comparison.
fn host_domain(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit('@').next()?; // strip any userinfo
    let host = host.split(':').next()?; // strip port
    let labels: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }
    Some(labels[labels.len() - 2..].join("."))
}

/// `brew tap-info --json --installed` → the configured taps with their **real**
/// git remotes (taps don't follow a fixed `homebrew-<name>` naming; the remote
/// is authoritative, e.g. `sn0walice/sshm` → `github.com/Sn0wAlice/sshm`).
/// Returns the taps plus a `handle → remote` map for the non-official ones (used
/// to resolve their packages). Best-effort: a failure yields none.
fn read_tap_info() -> (Vec<Tap>, HashMap<String, String>) {
    #[derive(Deserialize)]
    struct TapInfo {
        name: String,
        remote: Option<String>,
        #[serde(default)]
        official: bool,
    }
    let Ok(out) = Command::new("brew").args(["tap-info", "--json", "--installed"]).output() else {
        return (Vec::new(), HashMap::new());
    };
    if !out.status.success() {
        return (Vec::new(), HashMap::new());
    }
    let infos: Vec<TapInfo> = serde_json::from_slice(&out.stdout).unwrap_or_default();

    let mut taps = Vec::with_capacity(infos.len());
    let mut remotes = HashMap::new();
    for t in infos {
        if let Some(r) = &t.remote
            && !t.official
        {
            remotes.insert(t.name.clone(), r.clone());
        }
        taps.push(Tap { name: t.name, remote: t.remote.unwrap_or_default(), official: t.official });
    }
    (taps, remotes)
}

/// An official `homebrew/*` tap (core-reviewed, trusted).
fn is_official_tap(tap: &str) -> bool {
    tap.starts_with("homebrew/")
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
        if names.is_empty() { "none".dimmed().to_string() } else { names.join(", ") }
    );
}

/// The `--repos` view: configured taps, official first, with their source repo.
pub fn render_repos(inv: &Inventory) {
    println!("{} {}", "source repos".bold(), format!("({})", inv.manager).dimmed());
    if inv.taps.is_empty() {
        println!("  {}", "none configured".dimmed());
        return;
    }
    let (official, third): (Vec<&Tap>, Vec<&Tap>) = inv.taps.iter().partition(|t| t.official);
    for t in official {
        println!("  {}", t.name.green());
    }
    for t in &third {
        println!(
            "  {}  {}  {}",
            t.name.truecolor(255, 165, 0),
            format!("[{}]", t.remote).dimmed(),
            "third-party".truecolor(255, 165, 0),
        );
    }
    if !third.is_empty() {
        println!(
            "\n{}",
            format!("⚠ {} third-party tap(s) bypass Homebrew-core review", third.len())
                .truecolor(255, 165, 0)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tap_classification() {
        assert!(is_official_tap("homebrew/core"));
        assert!(is_official_tap("homebrew/cask"));
        assert!(!is_official_tap("sn0walice/sshm"));
    }

    #[test]
    fn host_domain_extracts_registrable() {
        assert_eq!(host_domain("https://dl.google.com/chrome/x.dmg").as_deref(), Some("google.com"));
        assert_eq!(host_domain("https://github.com/o/r/releases/x").as_deref(), Some("github.com"));
        assert_eq!(host_domain("https://cryptomator.org/").as_deref(), Some("cryptomator.org"));
    }

    #[test]
    fn brew_graph_builds_edges_versions_and_directs() {
        // app (requested) → lib (declared_directly); lib is a transitive-only
        // install. A non-declared edge (app→sysdep) must NOT create an edge.
        let json = br#"{
          "formulae": [
            { "name": "app", "tap": "sn0walice/sshm", "installed": [
                { "version": "1.2.0", "installed_on_request": true,
                  "runtime_dependencies": [
                    { "full_name": "lib", "declared_directly": true },
                    { "full_name": "lib", "declared_directly": false }
                  ] } ] },
            { "name": "lib", "tap": "homebrew/core", "installed": [
                { "version": "0.9.0", "installed_on_request": false,
                  "runtime_dependencies": [] } ] }
          ]
        }"#;
        let tap_remote = HashMap::from([(
            "sn0walice/sshm".to_string(),
            "https://github.com/Sn0wAlice/sshm".to_string(),
        )]);
        let (deps, casks, signals) = analyze(json, &tap_remote).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(casks, 0);
        let app = deps.iter().find(|d| d.name == "app").unwrap();
        let lib = deps.iter().find(|d| d.name == "lib").unwrap();
        assert!(app.direct, "installed_on_request ⇒ direct/root");
        assert!(!lib.direct, "pulled as a dependency");
        assert_eq!(app.version, "1.2.0");
        assert_eq!(lib.parents, vec![("app".to_string(), "1.2.0".to_string())]);
        assert!(app.parents.is_empty());
        // Third-party tap → provenance signal + its real remote for the resolver.
        assert_eq!(app.resolved_url.as_deref(), Some("https://github.com/Sn0wAlice/sshm"));
        assert_eq!(lib.resolved_url, None);
        assert!(signals["app"].iter().any(|s| s.label.contains("third-party-tap")));
        assert!(!signals.contains_key("lib"));
    }

    #[test]
    fn cask_flags_unverified_and_autoupdate() {
        // A cask with an unverified download, auto-updates, and a pkg installer,
        // from an official tap → the download surface, no tap flag.
        let json = br#"{
          "casks": [
            { "token": "risky", "tap": "homebrew/cask", "installed": "1.0",
              "url": "https://cdn.evil.test/app.dmg", "sha256": "no_check",
              "homepage": "https://vendor.test/", "auto_updates": true,
              "artifacts": [ { "pkg": ["x.pkg"] }, { "uninstall": [] } ] }
          ]
        }"#;
        let (deps, casks, signals) = analyze(json, &HashMap::new()).unwrap();
        assert_eq!(casks, 1);
        let risky = deps.iter().find(|d| d.name == "risky").unwrap();
        assert!(risky.direct, "casks are user-installed roots");
        assert_eq!(risky.resolved_url.as_deref(), Some("https://cdn.evil.test/app.dmg"));
        let labels: Vec<&str> = signals["risky"].iter().map(|s| s.label.as_str()).collect();
        assert!(labels.iter().any(|l| l.contains("unverified-download")));
        assert!(labels.iter().any(|l| l.contains("download-host-mismatch")));
        assert!(labels.iter().any(|l| l.contains("runs-installer")));
        assert!(labels.iter().any(|l| l.contains("auto-updates")));
        // Worst severity is High (the unverified download).
        assert_eq!(
            signals["risky"].iter().map(|s| s.severity).max(),
            Some(Severity::High)
        );
    }

    #[test]
    fn github_cask_download_is_not_a_host_mismatch() {
        // GitHub releases are a trusted mirror → no host-mismatch flag even
        // though the homepage domain differs.
        let json = br#"{
          "casks": [
            { "token": "ok", "tap": "homebrew/cask", "installed": "1.0",
              "url": "https://github.com/o/r/releases/download/1.0/app.dmg",
              "sha256": "abc123", "homepage": "https://project.test/",
              "artifacts": [ { "app": ["A.app"] } ] }
          ]
        }"#;
        let (_deps, _casks, signals) = analyze(json, &HashMap::new()).unwrap();
        assert!(!signals.contains_key("ok"), "verified github cask has no offline signals");
    }

    #[test]
    fn annotate_merges_signals_onto_tree() {
        use crate::tree;
        let json = br#"{
          "formulae": [
            { "name": "app", "tap": "sn0walice/x", "installed": [
                { "version": "1.0.0", "installed_on_request": true, "runtime_dependencies": [] } ] }
          ]
        }"#;
        let remote = HashMap::from([("sn0walice/x".to_string(), "https://github.com/o/x".to_string())]);
        let (deps, _casks, signals) = analyze(json, &remote).unwrap();
        let mut forest = tree::build("brew", &["brew".to_string()], &deps, None);
        annotate(&mut forest, &signals);
        let app = &forest.roots[0];
        assert_eq!(app.severity, Some(Severity::Medium));
        assert_eq!(app.risk, Some(30));
        assert!(app.signals.iter().any(|s| s.contains("third-party-tap")));
    }
}
