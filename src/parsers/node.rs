//! npm package-lock.json parser (v2 / v3).
//!
//! v3 stores a flat `packages` map keyed by install path (`""` for root,
//! `"node_modules/foo"`, `"node_modules/a/node_modules/b"`, etc.). Each entry
//! lists its own declared `dependencies`. We resolve parent edges by walking
//! each package's declared deps against the installed tree (npm's hoisting
//! rules) — same-dir first, then parent walk up to root.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use crate::model::{DepRef, Dependency, Ecosystem};

#[derive(Debug, Deserialize)]
struct Lockfile {
    #[serde(default, rename = "lockfileVersion")]
    lockfile_version: u32,
    #[serde(default)]
    packages: BTreeMap<String, PkgEntry>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct PkgEntry {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    resolved: Option<String>,
    #[serde(default)]
    integrity: Option<String>,
    #[serde(default)]
    dependencies: HashMap<String, String>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: HashMap<String, String>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: HashMap<String, String>,
    #[serde(default, rename = "peerDependencies")]
    #[allow(dead_code)]
    peer_dependencies: HashMap<String, String>,
}

pub fn parse_lockfile(path: &Path) -> Result<Vec<Dependency>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let lock: Lockfile = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {} as package-lock", path.display()))?;

    if lock.lockfile_version < 2 {
        anyhow::bail!(
            "package-lock v{} not supported (need v2 or v3)",
            lock.lockfile_version
        );
    }

    let root = lock.packages.get("").cloned().unwrap_or_default();
    let root_direct: HashSet<String> = root
        .dependencies
        .keys()
        .chain(root.dev_dependencies.keys())
        .chain(root.optional_dependencies.keys())
        .cloned()
        .collect();

    // Index every installed package by path → (name, version, entry)
    let mut by_path: BTreeMap<String, (String, String)> = BTreeMap::new();
    for (key, entry) in &lock.packages {
        if key.is_empty() {
            continue;
        }
        let Some(name) = pkg_name_from_key(key) else {
            continue;
        };
        let version = entry.version.clone().unwrap_or_else(|| "unknown".into());
        by_path.insert(key.clone(), (name.to_string(), version));
    }

    // Resolve each declared dep to its installed path using npm hoisting rules:
    // look in <pkg_dir>/node_modules/<dep>, then walk up.
    let resolve = |from_key: &str, dep_name: &str| -> Option<String> {
        let mut current: String = from_key.to_string();
        loop {
            let candidate = if current.is_empty() {
                format!("node_modules/{dep_name}")
            } else {
                format!("{current}/node_modules/{dep_name}")
            };
            if by_path.contains_key(&candidate) {
                return Some(candidate);
            }
            if current.is_empty() {
                return None;
            }
            // Walk up by stripping the trailing `/node_modules/<seg>` segment.
            match current.rfind("/node_modules/") {
                Some(i) => current.truncate(i),
                None => {
                    if current.starts_with("node_modules/") {
                        current.clear();
                    } else {
                        return None;
                    }
                }
            }
        }
    };

    // Build (DepRef -> Dependency), merging multiple install paths for the same
    // (name, version) and collecting all parents.
    let mut acc: BTreeMap<DepRef, Dependency> = BTreeMap::new();
    // Reverse-index parents: for each (parent_name, parent_version, dep_path), add to dep entry
    for (parent_key, parent_entry) in &lock.packages {
        let parent_ref: Option<DepRef> = if parent_key.is_empty() {
            None
        } else {
            by_path.get(parent_key).cloned()
        };
        let declared = parent_entry
            .dependencies
            .keys()
            .chain(parent_entry.dev_dependencies.keys())
            .chain(parent_entry.optional_dependencies.keys());
        for dep_name in declared {
            let Some(resolved_key) = resolve(parent_key, dep_name) else {
                continue;
            };
            let Some((rn, rv)) = by_path.get(&resolved_key).cloned() else {
                continue;
            };
            let entry = lock.packages.get(&resolved_key).cloned().unwrap_or_default();
            let dep_key = (rn.clone(), rv.clone());
            let dep = acc.entry(dep_key.clone()).or_insert_with(|| Dependency {
                name: rn.clone(),
                version: rv.clone(),
                ecosystem: Ecosystem::Node,
                direct: false,
                resolved_url: entry.resolved.clone(),
                integrity: entry.integrity.clone(),
                parents: Vec::new(),
            });
            // Mark direct if root is the parent and root listed this dep.
            if parent_key.is_empty() && root_direct.contains(&rn) {
                dep.direct = true;
            }
            if let Some(pr) = parent_ref.clone() {
                if !dep.parents.contains(&pr) {
                    dep.parents.push(pr);
                }
            }
            if dep.resolved_url.is_none() {
                dep.resolved_url = entry.resolved.clone();
            }
            if dep.integrity.is_none() {
                dep.integrity = entry.integrity.clone();
            }
        }
    }

    // Catch any installed packages not referenced by anyone (defensive: bare lock
    // entries for stuff like bundled deps or root's own peer slot). Add them
    // with no parents; mark direct if applicable.
    for (key, (name, version)) in &by_path {
        let dep_key = (name.clone(), version.clone());
        if !acc.contains_key(&dep_key) {
            let entry = lock.packages.get(key).cloned().unwrap_or_default();
            let direct = parent_is_root(key) && root_direct.contains(name);
            acc.insert(
                dep_key,
                Dependency {
                    name: name.clone(),
                    version: version.clone(),
                    ecosystem: Ecosystem::Node,
                    direct,
                    resolved_url: entry.resolved.clone(),
                    integrity: entry.integrity.clone(),
                    parents: Vec::new(),
                },
            );
        }
    }

    Ok(acc.into_values().collect())
}

fn parent_is_root(key: &str) -> bool {
    !key.contains("/node_modules/") && key.starts_with("node_modules/")
}

/// Extract the package name from a key like `node_modules/foo` or
/// `node_modules/@scope/bar/node_modules/baz`.
fn pkg_name_from_key(key: &str) -> Option<&str> {
    let idx = key.rfind("node_modules/")?;
    let rest = &key[idx + "node_modules/".len()..];
    if rest.is_empty() {
        return None;
    }
    if let Some(stripped) = rest.strip_prefix('@') {
        let mut it = stripped.splitn(3, '/');
        let scope = it.next()?;
        let name = it.next()?;
        let start = idx + "node_modules/".len();
        let end = start + 1 + scope.len() + 1 + name.len();
        Some(&key[start..end])
    } else {
        let end_rel = rest.find('/').unwrap_or(rest.len());
        let start = idx + "node_modules/".len();
        Some(&key[start..start + end_rel])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_unscoped() {
        assert_eq!(pkg_name_from_key("node_modules/foo"), Some("foo"));
    }

    #[test]
    fn name_nested() {
        assert_eq!(
            pkg_name_from_key("node_modules/a/node_modules/b"),
            Some("b")
        );
    }

    #[test]
    fn name_scoped() {
        assert_eq!(
            pkg_name_from_key("node_modules/@scope/pkg"),
            Some("@scope/pkg")
        );
    }
}
