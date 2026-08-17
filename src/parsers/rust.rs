//! Cargo.lock parser. Reads the v3/v4 format produced by modern cargo.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

use crate::model::{Dependency, Ecosystem, Scope};

#[derive(Debug, Deserialize)]
struct CargoLock {
    #[serde(default)]
    package: Vec<CargoPkg>,
}

#[derive(Debug, Deserialize, Clone)]
struct CargoPkg {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    checksum: Option<String>,
    #[serde(default)]
    dependencies: Vec<String>,
}

pub fn parse_lockfile(path: &Path, manifest: Option<&Path>) -> Result<Vec<Dependency>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let lock: CargoLock = toml::from_str(&text)
        .with_context(|| format!("parsing {} as Cargo.lock", path.display()))?;

    // Cargo.lock is a flat resolved set with no dev/prod split — only Cargo.toml
    // knows which table a dependency was declared in, and only for the direct
    // ones. The rest is inferred from the lock's edges by `crate::scope`.
    let direct: BTreeMap<String, Scope> = match manifest {
        Some(m) => read_manifest_direct(m).unwrap_or_default(),
        None => BTreeMap::new(),
    };

    // Workspace member packages have no `source` field — they're local.
    // Skip them (the scan target itself is not its own dependency).
    let externals: Vec<&CargoPkg> = lock
        .package
        .iter()
        .filter(|p| p.source.is_some())
        .collect();

    let mut out = Vec::with_capacity(externals.len());
    for pkg in &externals {
        let mut parents = Vec::new();
        for other in &lock.package {
            if other.dependencies.iter().any(|dep_str| {
                // entries are either "name" or "name VERSION" or "name VERSION (registry+...)"
                let mut parts = dep_str.split_whitespace();
                let dname = parts.next().unwrap_or("");
                let dver = parts.next();
                dname == pkg.name && dver.map(|v| v == pkg.version).unwrap_or(true)
            }) {
                if other.source.is_some() {
                    parents.push((other.name.clone(), other.version.clone()));
                }
            }
        }
        out.push(Dependency {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            ecosystem: Ecosystem::Rust,
            direct: direct.contains_key(&pkg.name),
            scope: direct.get(&pkg.name).copied().unwrap_or(Scope::Prod),
            resolved_url: pkg.source.clone(),
            integrity: pkg.checksum.clone(),
            parents,
        });
    }
    Ok(out)
}

/// Direct dependency names from Cargo.toml, each mapped to the scope its table
/// implies.
///
/// `[build-dependencies]` is deliberately **production**, not dev: a build
/// script's dependencies execute on the build machine with full privileges, so
/// they are squarely part of the supply chain even though they never ship in the
/// binary. Omitting them would hide the most dangerous class of Rust dependency.
/// A crate listed in several tables keeps the strongest scope.
fn read_manifest_direct(path: &Path) -> Result<BTreeMap<String, Scope>> {
    let text = std::fs::read_to_string(path)?;
    let val: toml::Value = toml::from_str(&text)?;
    let mut out: BTreeMap<String, Scope> = BTreeMap::new();
    let mut add = |name: &String, scope: Scope| {
        let e = out.entry(name.clone()).or_insert(scope);
        *e = (*e).max(scope);
    };
    for (key, scope) in [
        ("dependencies", Scope::Prod),
        ("build-dependencies", Scope::Prod),
        ("dev-dependencies", Scope::Dev),
    ] {
        if let Some(tbl) = val.get(key).and_then(|v| v.as_table()) {
            for k in tbl.keys() {
                add(k, scope);
            }
        }
        // Target-specific tables: `[target.'cfg(unix)'.dev-dependencies]`.
        if let Some(targets) = val.get("target").and_then(|v| v.as_table()) {
            for t in targets.values() {
                if let Some(tbl) = t.get(key).and_then(|v| v.as_table()) {
                    for k in tbl.keys() {
                        add(k, scope);
                    }
                }
            }
        }
    }
    // Workspace deps — the table itself carries no dev/prod distinction.
    if let Some(ws) = val.get("workspace").and_then(|v| v.as_table()) {
        if let Some(deps) = ws.get("dependencies").and_then(|v| v.as_table()) {
            for k in deps.keys() {
                add(k, Scope::Prod);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str, body: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "postmortem-rust-scope-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    const MANIFEST: &str = r#"
[package]
name = "victim"

[dependencies]
serde = "1"

[build-dependencies]
cc = "1"

[dev-dependencies]
criterion = "0.5"

[target.'cfg(unix)'.dev-dependencies]
nix-test = "0.1"
"#;

    #[test]
    fn manifest_tables_map_to_scopes() {
        let m = read_manifest_direct(&tmp("Cargo.toml", MANIFEST)).unwrap();
        assert_eq!(m.get("serde"), Some(&Scope::Prod));
        assert_eq!(m.get("criterion"), Some(&Scope::Dev));
        assert_eq!(
            m.get("cc"),
            Some(&Scope::Prod),
            "build scripts execute at build time — omitting them would hide the \
             most dangerous class of Rust dependency"
        );
        assert_eq!(
            m.get("nix-test"),
            Some(&Scope::Dev),
            "target-specific dev-dependencies count too"
        );
    }

    #[test]
    fn a_crate_in_two_tables_keeps_the_strongest_scope() {
        let m = read_manifest_direct(&tmp(
            "Cargo.toml",
            "[dependencies]\nboth = \"1\"\n\n[dev-dependencies]\nboth = \"1\"\n",
        ))
        .unwrap();
        assert_eq!(m.get("both"), Some(&Scope::Prod));
    }

    #[test]
    fn lockfile_scopes_come_from_the_manifest() {
        let lock = tmp(
            "Cargo.lock",
            r#"
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "criterion"
version = "0.5.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        );
        let manifest = tmp("Cargo.toml", MANIFEST);
        let deps = parse_lockfile(&lock, Some(&manifest)).unwrap();
        let scope = |n: &str| deps.iter().find(|d| d.name == n).unwrap().scope;
        assert_eq!(scope("serde"), Scope::Prod);
        assert_eq!(scope("criterion"), Scope::Dev);
    }

    #[test]
    fn without_a_manifest_everything_stays_production() {
        // Cargo.lock alone carries no dev/prod split, so nothing may be omitted.
        let lock = tmp(
            "Cargo.lock",
            "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+x\"\n",
        );
        let deps = parse_lockfile(&lock, None).unwrap();
        assert!(deps.iter().all(|d| d.scope == Scope::Prod));
    }
}
