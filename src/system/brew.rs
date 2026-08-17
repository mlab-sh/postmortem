//! Homebrew backend (`brew info --json=v2 --installed`).
//!
//! The installed forest — **formulae** (versions, `installed_on_request` roots,
//! `declared_directly` dependency edges) and **casks** (prebuilt app downloads) —
//! plus the configured taps from `brew tap-info --json --installed`. Anything
//! beyond the official `homebrew/*` taps bypasses core review, so it is both a
//! provenance signal and the trigger for static-analyzing the install recipe.

use super::*;
use super::recipe::{analyze_recipe, host_domain};

/// Download hosts that are legitimate release mirrors, so a cask downloading
/// from them while its homepage is elsewhere is normal (not a redirect tell).
const TRUSTED_DL_HOSTS: &[&str] =
    &["github.com", "gitlab.com", "codeberg.org", "sourceforge.net", "bitbucket.org"];

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
    Ok(Inventory { manager: "homebrew", deps, repos, signals, summary, notes: Vec::new() })
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

/// A cask artifact that runs an installer (`pkg`/`installer`) rather than just
/// dropping an `.app`.
fn is_installer_artifact(a: &serde_json::Value) -> bool {
    a.as_object().is_some_and(|o| o.contains_key("pkg") || o.contains_key("installer"))
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
