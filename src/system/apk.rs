//! Alpine `apk` backend — the installed DB as a capability graph, the explicit
//! `world` set as roots, and the repo-level provenance behind them.

use super::*;
use super::recipe::analyze_recipe;

// --- apk backend (Alpine) ----------------------------------------------------

/// Read the installed apk database into an [`Inventory`]. `/lib/apk/db/installed`
/// holds every package (blank-line-separated `K:value` records: name, version,
/// url, depends, provides); `/etc/apk/world` is the explicitly-requested (direct)
/// set; edges come from the capability graph (`D:` requires ↔ `P:`/`p:` provides).
///
/// Alpine's DB does not record a per-package origin repo, so provenance is
/// repo-level (third-party repos in `/etc/apk/repositories`); install scripts are
/// few and curated, so postmortem analyzes every one it finds rather than gating.
pub fn apk_inventory(opts: Opts) -> Result<Inventory> {
    let _ = opts; // apk reputation comes from the shared `--online` path
    let db = std::fs::read_to_string("/lib/apk/db/installed")
        .context("reading /lib/apk/db/installed")?;
    let world = apk_world();
    let deps = apk_graph(&db, &world);

    // Install scripts (`.pre-install`/`.post-install`/`.trigger`, in
    // scripts.tar.gz): flag their presence and static-analyze the shell.
    let scripts = apk_scripts();
    let mut signals: HashMap<String, Vec<SysSignal>> = HashMap::new();
    for d in &deps {
        // Members are named `<name>-<version>.<checksum>.<type>`, so a package owns
        // every member under the `<name>-<version>.` prefix.
        let prefix = format!("{}-{}.", d.name, d.version);
        let code: String = scripts
            .iter()
            .filter(|(m, _)| m.starts_with(&prefix))
            .map(|(_, b)| b.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        if code.is_empty() {
            continue;
        }
        push_signal(
            &mut signals,
            &d.name,
            SysSignal::new("install-script (runs code at install)", Severity::Info, 0),
        );
        for sig in analyze_recipe(&d.name, &code, "sh") {
            push_signal(&mut signals, &d.name, sig);
        }
    }

    let repos = apk_repos();
    let third = repos.iter().filter(|r| !r.official).count();
    let notes = if third > 0 {
        vec![format!("{third} third-party apk repo(s) configured (outside the official Alpine archives)")]
    } else {
        Vec::new()
    };
    let direct = deps.iter().filter(|d| d.direct).count();
    let summary = format!("{} package(s) ({direct} in world)", deps.len());
    Ok(Inventory { manager: "apk", deps, repos, signals, summary, notes })
}

/// The explicitly-requested (direct) set from `/etc/apk/world` (version
/// constraints and `@tag` suffixes stripped).
fn apk_world() -> std::collections::HashSet<String> {
    std::fs::read_to_string("/etc/apk/world")
        .ok()
        .map(|t| t.lines().filter_map(|l| apk_dep_token(l.trim())).collect())
        .unwrap_or_default()
}

/// Parse `/lib/apk/db/installed` into the dependency forest. Edges resolve each
/// package's `D:` requires (package names, `so:`/`cmd:`/`pc:` capabilities)
/// through a `capability → package` map built from every `P:` name and `p:`
/// provides.
fn apk_graph(db: &str, world: &std::collections::HashSet<String>) -> Vec<Dependency> {
    struct P {
        name: String,
        version: String,
        url: String,
        depends: Vec<String>,
        provides: Vec<String>,
    }
    let mut pkgs: Vec<P> = Vec::new();
    for block in db.split("\n\n") {
        let (mut name, mut version, mut url) = (String::new(), String::new(), String::new());
        let (mut depends, mut provides) = (Vec::new(), Vec::new());
        for line in block.lines() {
            let Some((k, v)) = line.split_once(':') else { continue };
            match k {
                "P" => name = v.to_string(),
                "V" => version = v.to_string(),
                "U" => url = v.to_string(),
                "D" => depends.extend(v.split_whitespace().filter_map(apk_dep_token)),
                "p" => provides.extend(v.split_whitespace().filter_map(apk_dep_token)),
                _ => {}
            }
        }
        if !name.is_empty() {
            pkgs.push(P { name, version, url, depends, provides });
        }
    }

    // capability → a providing package (its own name + everything in `p:`).
    let mut provider: HashMap<String, String> = HashMap::new();
    for p in &pkgs {
        provider.entry(p.name.clone()).or_insert_with(|| p.name.clone());
        for cap in &p.provides {
            provider.entry(cap.clone()).or_insert_with(|| p.name.clone());
        }
    }
    let mut parents: HashMap<String, Vec<DepRef>> = HashMap::new();
    for p in &pkgs {
        let mut seen = std::collections::HashSet::new();
        for d in &p.depends {
            let Some(child) = provider.get(d) else { continue };
            if child != &p.name && seen.insert(child.clone()) {
                parents.entry(child.clone()).or_default().push((p.name.clone(), p.version.clone()));
            }
        }
    }
    pkgs.into_iter()
        .map(|p| Dependency {
            direct: world.contains(&p.name),
            scope: Scope::Prod,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url: (!p.url.is_empty()).then(|| p.url.clone()),
            parents: parents.remove(&p.name).unwrap_or_default(),
            name: p.name,
            version: p.version,
            ecosystem: Ecosystem::Apk,
            integrity: None,
        })
        .collect()
}

/// An apk `D:`/`p:`/world token → its capability name: drop a conflict marker
/// (`!foo`) and strip a version constraint (`musl>=1.2`) or `@tag` (`foo@edge`).
/// `so:`/`cmd:`/`pc:` capability prefixes are kept.
fn apk_dep_token(tok: &str) -> Option<String> {
    if tok.is_empty() || tok.starts_with('!') {
        return None;
    }
    let name = tok.split(['>', '<', '=', '~', '@']).next()?.trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// Configured apk repos from `/etc/apk/repositories`. `*.alpinelinux.org` archives
/// are official; a custom host or a local path is third-party.
fn apk_repos() -> Vec<Repo> {
    std::fs::read_to_string("/etc/apk/repositories")
        .ok()
        .map(|t| {
            t.lines()
                .filter_map(|l| {
                    let l = l.trim();
                    if l.is_empty() || l.starts_with('#') {
                        return None;
                    }
                    // A line may carry a leading `@tag`; the URL is the last token.
                    let url = l.split_whitespace().next_back()?;
                    let official = url.contains("alpinelinux.org");
                    Some(Repo { name: url.to_string(), url: String::new(), official })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Install scripts from `/lib/apk/db/scripts.tar.gz` as `(member, body)` pairs.
/// Members are named `<name>-<version>.<checksum>.<type>`; the caller matches them
/// to a package by the `<name>-<version>.` prefix. Empty when no scripts archive
/// is present.
fn apk_scripts() -> Vec<(String, String)> {
    let archive = "/lib/apk/db/scripts.tar.gz";
    let Ok(list) = Command::new("tar").args(["tzf", archive]).output() else {
        return Vec::new();
    };
    if !list.status.success() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for member in String::from_utf8_lossy(&list.stdout).lines() {
        let member = member.trim();
        if member.is_empty() {
            continue;
        }
        let Ok(body) = Command::new("tar").args(["xzOf", archive, member]).output() else {
            continue;
        };
        if body.status.success() {
            out.push((member.to_string(), String::from_utf8_lossy(&body.stdout).into_owned()));
        }
    }
    out
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apk_dep_token_strips() {
        assert_eq!(apk_dep_token("musl>=1.2.3_git20230424").as_deref(), Some("musl"));
        assert_eq!(apk_dep_token("libapk=3.0.6-r0").as_deref(), Some("libapk"));
        assert_eq!(apk_dep_token("ca-certificates-bundle").as_deref(), Some("ca-certificates-bundle"));
        assert_eq!(apk_dep_token("so:libc.musl-aarch64.so.1").as_deref(), Some("so:libc.musl-aarch64.so.1"));
        assert_eq!(apk_dep_token("cmd:apk=3.0.6-r0").as_deref(), Some("cmd:apk"));
        assert_eq!(apk_dep_token("foo@edge").as_deref(), Some("foo"));
        assert_eq!(apk_dep_token("!conflict"), None); // conflict marker dropped
    }

    #[test]
    fn apk_graph_resolves_capabilities() {
        // `app` requires a soname provided by `lib`, plus a bare-name dep; `world`
        // marks `app` direct. The soname edge must resolve through `p:`.
        let db = "\
P:app
V:1.0
U:https://example.org/app
D:libz>=1 so:libfoo.so.1
p:cmd:app=1.0

P:libz
V:1.3

P:lib
V:2.0
p:so:libfoo.so.1
";
        let world: std::collections::HashSet<String> = ["app".to_string()].into_iter().collect();
        let deps = apk_graph(db, &world);
        assert_eq!(deps.len(), 3);
        let app = deps.iter().find(|d| d.name == "app").unwrap();
        assert!(app.direct, "in world ⇒ direct");
        assert_eq!(app.resolved_url.as_deref(), Some("https://example.org/app"));
        // Both the bare-name dep (libz) and the soname dep (→ lib) are edges of app.
        let lib = deps.iter().find(|d| d.name == "lib").unwrap();
        let libz = deps.iter().find(|d| d.name == "libz").unwrap();
        assert_eq!(lib.parents, vec![("app".to_string(), "1.0".to_string())]);
        assert_eq!(libz.parents, vec![("app".to_string(), "1.0".to_string())]);
        assert!(!lib.direct);
    }
}
