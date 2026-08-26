//! Arch `pacman` backend (`pacman -Qi`), plus AUR provenance.
//!
//! Foreign (non-repo) packages are the interesting surface: they were built from
//! an AUR PKGBUILD rather than a signed repo, so they are resolved against the
//! `aur.archlinux.org` RPC and their PKGBUILD is statically analyzed.

use super::privilege::{find_setuid_files, persistence_signals};
use super::recipe::analyze_recipe;
use super::*;

// --- pacman backend (`pacman -Qi`) -------------------------------------------

/// Read the installed pacman forest into an [`Inventory`]. `pacman -Qi` dumps
/// every installed package's info in one call: name, version, deps, URL,
/// signature status, install-reason (explicit vs pulled-in), and whether it
/// ships an install hook. `online` additionally enriches foreign/AUR packages
/// via the AUR RPC.
pub fn pacman_inventory(opts: Opts) -> Result<Inventory> {
    let out = Command::new("pacman")
        .arg("-Qi")
        .output()
        .context("running `pacman -Qi`")?;
    if !out.status.success() {
        anyhow::bail!(
            "`pacman -Qi` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let (deps, mut signals) = pacman_graph(&String::from_utf8_lossy(&out.stdout));

    // Foreign packages (not from an official repo) = AUR builds / manual installs
    // — the untrusted surface. An un-synced sync-DB reports ~everything foreign,
    // which is useless, so it's skipped unless forced.
    let raw = read_foreign();
    let unsynced = !raw.is_empty() && raw.len() * 10 >= deps.len() * 9;
    let mut warnings: Vec<String> = Vec::new();
    let foreign = if unsynced && !opts.force_aur {
        warnings.push(
            "package DB not synced, so AUR/foreign detection is unavailable. \
             Run `sudo pacman -Sy` first, or pass --force-aur to scan anyway."
                .to_string(),
        );
        Vec::new()
    } else {
        raw
    };

    if !foreign.is_empty() {
        let aur = if opts.online {
            aur_info(&foreign)
        } else {
            HashMap::new()
        };
        let version_of: HashMap<&str, &str> = deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str()))
            .collect();
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

    // Execution & privilege: the boot/scheduled/auth/setuid surface a package sets
    // up through its files (shared with the apt/dnf backends).
    let file_index = pacman_file_index();
    let setuid = find_setuid_files();
    for d in &deps {
        if let Some(files) = file_index.get(&d.name) {
            for sig in persistence_signals(files, &setuid) {
                push_signal(&mut signals, &d.name, sig);
            }
        }
    }

    // Version drift (needs a synced DB; best-effort).
    for (name, (old, new)) in read_pacman_outdated() {
        signals
            .entry(name)
            .or_default()
            .push(outdated_signal(&old, &new));
    }

    // Integrity & trust caveats.
    let modified = pacman_modified_files();
    if modified > 0 {
        warnings.push(format!(
            "{modified} installed file(s) modified since install (pacman -Qkk)"
        ));
    }
    if pacman_sig_disabled() {
        warnings.push("pacman signature verification disabled (SigLevel = Never)".to_string());
    }

    let explicit = deps.iter().filter(|d| d.direct).count();
    let extra = if foreign.is_empty() {
        String::new()
    } else {
        format!(", {} foreign", foreign.len())
    };
    let summary = format!("{} package(s) ({explicit} explicit{extra})", deps.len());
    Ok(Inventory {
        manager: "pacman",
        deps,
        repos: pacman_repos(),
        signals,
        claims: Vec::new(),
        summary,
        notes: warnings,
    })
}

/// `name → installed files`, from one `pacman -Ql` (`<pkg> <path>` per line).
fn pacman_file_index() -> HashMap<String, Vec<String>> {
    let Ok(out) = Command::new("pacman").arg("-Ql").output() else {
        return HashMap::new();
    };
    if !out.status.success() {
        return HashMap::new();
    }
    let mut idx: HashMap<String, Vec<String>> = HashMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some((name, path)) = line.split_once(' ') {
            idx.entry(name.to_string())
                .or_default()
                .push(path.trim().to_string());
        }
    }
    idx
}

/// Count installed files whose content no longer matches the package database
/// (`pacman -Qkk` SHA256 mismatch). Size/mtime-only differences are ignored.
fn pacman_modified_files() -> usize {
    let Ok(out) = Command::new("pacman").arg("-Qkk").output() else {
        return 0;
    };
    // `pacman -Qkk` prints its findings to stderr and exits non-zero when any file
    // is altered; the SHA256 line is the definitive content-tamper signal.
    let text = String::from_utf8_lossy(&out.stderr);
    text.lines()
        .filter(|l| l.contains("SHA256 checksum mismatch"))
        .count()
}

/// Is package signature verification switched off in `/etc/pacman.conf`
/// (`SigLevel = Never`)? The weaker `Optional`/`DatabaseOptional` defaults are not
/// flagged.
fn pacman_sig_disabled() -> bool {
    let Ok(text) = std::fs::read_to_string("/etc/pacman.conf") else {
        return false;
    };
    text.lines().any(|l| {
        let l = l.trim();
        l.starts_with("SigLevel") && l.contains('=') && l.contains("Never")
    })
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
    let net = crate::settings::Settings::load_or_warn().network;
    let agent = net
        .apply(ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(15)))
        .build();
    let aur = net.endpoints.aur();
    let mut out = HashMap::new();
    for chunk in names.chunks(120) {
        let query: String = chunk.iter().map(|n| format!("&arg[]={n}")).collect();
        let url = format!("{aur}/rpc/v5/info?{}", query.trim_start_matches('&'));
        let Ok(resp) = agent.get(&url).set("User-Agent", UA).call() else {
            continue;
        };
        let Ok(text) = resp.into_string() else {
            continue;
        };
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
    let net = crate::settings::Settings::load_or_warn().network;
    let agent = net
        .apply(ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(15)))
        .build();
    let url = format!(
        "{}/cgit/aur.git/plain/PKGBUILD?h={name}",
        net.endpoints.aur()
    );
    agent
        .get(&url)
        .set("User-Agent", UA)
        .call()
        .ok()?
        .into_string()
        .ok()
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
        Category::ThirdPartySource,
        Severity::Medium,
        30,
    )];
    if let Some(p) = aur {
        if p.maintainer.is_none() {
            v.push(SysSignal::new(
                "aur-orphaned (no maintainer)",
                Category::ThirdPartySource,
                Severity::Medium,
                30,
            ));
        }
        if p.out_of_date.is_some() {
            v.push(SysSignal::new("aur-out-of-date", Category::Outdated, Severity::Medium, 20));
        }
        let votes = p.num_votes.unwrap_or(0);
        if votes < 10 {
            v.push(SysSignal::new(
                format!("aur-unpopular ({votes} votes)"),
                Category::ThirdPartySource,
                Severity::Low,
                10,
            ));
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
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
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
            pkgs.push(P {
                name,
                version,
                url,
                depends,
                explicit,
                unsigned,
                has_install,
            });
        }
    }

    let installed: HashMap<&str, &str> = pkgs
        .iter()
        .map(|p| (p.name.as_str(), p.version.as_str()))
        .collect();
    let mut parents: HashMap<String, Vec<DepRef>> = HashMap::new();
    for p in &pkgs {
        for d in &p.depends {
            if installed.contains_key(d.as_str()) {
                parents
                    .entry(d.clone())
                    .or_default()
                    .push((p.name.clone(), p.version.clone()));
            }
        }
    }

    let mut signals: HashMap<String, Vec<SysSignal>> = HashMap::new();
    let mut deps = Vec::with_capacity(pkgs.len());
    for p in &pkgs {
        if p.unsigned {
            push_signal(
                &mut signals,
                &p.name,
                SysSignal::new("unsigned", Category::Unsigned, Severity::High, 40),
            );
        }
        if p.has_install {
            push_signal(
                &mut signals,
                &p.name,
                SysSignal::new("install-script (runs code at install)", Category::InstallHook, Severity::Info, 0),
            );
        }
        deps.push(Dependency {
            name: p.name.clone(),
            version: p.version.clone(),
            ecosystem: Ecosystem::Pacman,
            direct: p.explicit,
            scope: Scope::Prod,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
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
        "core",
        "extra",
        "multilib",
        "testing",
        "core-testing",
        "extra-testing",
        "multilib-testing",
        "community",
        "community-testing",
        "alarm",
        "aur-disabled",
    ];
    let Ok(text) = std::fs::read_to_string("/etc/pacman.conf") else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| {
            l.trim()
                .strip_prefix('[')?
                .strip_suffix(']')
                .map(str::to_string)
        })
        .filter(|s| s != "options")
        .map(|s| {
            let official = OFFICIAL.contains(&s.as_str());
            Repo {
                name: s,
                url: String::new(),
                official,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            app.resolved_url.as_deref(),
            Some("https://github.com/o/app")
        );
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
        let bad = AurPkg {
            name: "x".into(),
            maintainer: None,
            out_of_date: Some(1),
            num_votes: Some(3),
        };
        let sigs = foreign_signals(Some(&bad));
        let labels: Vec<&str> = sigs.iter().map(|s| s.label.as_str()).collect();
        assert!(labels.iter().any(|l| l.contains("aur-orphaned")));
        assert!(labels.iter().any(|l| l.contains("aur-out-of-date")));
        assert!(labels.iter().any(|l| l.contains("aur-unpopular")));

        // Healthy AUR package → foreign-package only (maintained, popular, current).
        let good = AurPkg {
            name: "y".into(),
            maintainer: Some("dev".into()),
            out_of_date: None,
            num_votes: Some(500),
        };
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
}
