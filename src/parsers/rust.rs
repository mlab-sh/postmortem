//! Cargo.lock parser. Reads the v3/v4 format produced by modern cargo.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;

use crate::model::{Dependency, Ecosystem};

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

    let direct: BTreeSet<String> = match manifest {
        Some(m) => read_manifest_direct(m).unwrap_or_default(),
        None => BTreeSet::new(),
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
            direct: direct.contains(&pkg.name),
            resolved_url: pkg.source.clone(),
            integrity: pkg.checksum.clone(),
            parents,
        });
    }
    Ok(out)
}

fn read_manifest_direct(path: &Path) -> Result<BTreeSet<String>> {
    let text = std::fs::read_to_string(path)?;
    let val: toml::Value = toml::from_str(&text)?;
    let mut out = BTreeSet::new();
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(tbl) = val.get(key).and_then(|v| v.as_table()) {
            for k in tbl.keys() {
                out.insert(k.clone());
            }
        }
    }
    // Workspace deps
    if let Some(ws) = val.get("workspace").and_then(|v| v.as_table()) {
        if let Some(deps) = ws.get("dependencies").and_then(|v| v.as_table()) {
            for k in deps.keys() {
                out.insert(k.clone());
            }
        }
    }
    Ok(out)
}
