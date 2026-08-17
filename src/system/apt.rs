//! Debian/Ubuntu `apt` / `dpkg` backend.
//!
//! The installed set from `dpkg-query`, the manually-installed roots from
//! `apt-mark showmanual`, and provenance from `apt-cache policy` — plus the
//! trust surface around it: untrusted sources, custom/expired keys, a legacy
//! keyring, pins, holds, foreign architectures, diversions and maintainer
//! scripts.

use super::*;
use super::privilege::{find_setuid_files, persistence_signals, verify_line_is_tamper};
use super::recipe::{analyze_recipe, host_domain};

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
    let setuid = find_setuid_files();
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

    Ok(Inventory { manager: "apt", deps, repos, signals, summary, notes: warnings })
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
    String::from_utf8_lossy(&out.stdout).lines().filter(|l| verify_line_is_tamper(l)).count()
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
            scope: Scope::Prod,
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



#[cfg(test)]
mod tests {
    use super::*;

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
}
