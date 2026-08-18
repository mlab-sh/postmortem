//! npm package-lock.json parser (v2 / v3).
//!
//! v3 stores a flat `packages` map keyed by install path (`""` for root,
//! `"node_modules/foo"`, `"node_modules/a/node_modules/b"`, etc.). Each entry
//! lists its own declared `dependencies`. We resolve parent edges by walking
//! each package's declared deps against the installed tree (npm's hoisting
//! rules) — same-dir first, then parent walk up to root.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use crate::model::{DepRef, Dependency, Ecosystem, License, LicenseSource, Scope};

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
    /// npm records the license on almost every entry of a v2/v3 lockfile — a
    /// fully offline source for the biggest ecosystem. Usually a plain SPDX
    /// string; very old packages instead used a `licenses` array, kept below.
    #[serde(default)]
    license: Option<serde_json::Value>,
    #[serde(default)]
    licenses: Option<serde_json::Value>,
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
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: Lockfile = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {} as package-lock", path.display()))?;

    if lock.lockfile_version < 2 {
        anyhow::bail!(
            "package-lock v{} not supported (need v2 or v3)",
            lock.lockfile_version
        );
    }

    let root = lock.packages.get("").cloned().unwrap_or_default();
    // The root entry is the only place package-lock states *intent*: which of
    // its three fields lists a dependency is what makes it prod / dev / optional.
    // Everything below is inferred from the graph by `crate::scope::propagate`.
    // A name listed in several fields keeps the strongest scope (prod wins).
    let mut root_direct: HashMap<String, Scope> = HashMap::new();
    let declared_roots = [
        (&root.dependencies, Scope::Prod),
        (&root.optional_dependencies, Scope::Optional),
        (&root.dev_dependencies, Scope::Dev),
    ];
    for (map, scope) in declared_roots {
        for name in map.keys() {
            let e = root_direct.entry(name.clone()).or_insert(scope);
            *e = (*e).max(scope);
        }
    }

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
            let entry = lock
                .packages
                .get(&resolved_key)
                .cloned()
                .unwrap_or_default();
            let (lics, lsrc) = entry_licenses_sourced(&entry);
            let dep_key = (rn.clone(), rv.clone());
            let dep = acc.entry(dep_key.clone()).or_insert_with(|| Dependency {
                name: rn.clone(),
                version: rv.clone(),
                ecosystem: Ecosystem::Node,
                direct: false,
                scope: Scope::Prod,
                licenses: lics,
                license_source: lsrc,
                resolved_url: entry.resolved.clone(),
                integrity: entry.integrity.clone(),
                parents: Vec::new(),
            });
            // Mark direct if root is the parent and root listed this dep, and
            // seed the scope the root declared it under.
            if parent_key.is_empty()
                && let Some(scope) = root_direct.get(&rn)
            {
                dep.direct = true;
                dep.scope = *scope;
            }
            if let Some(pr) = parent_ref.clone()
                && !dep.parents.contains(&pr)
            {
                dep.parents.push(pr);
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
        if let std::collections::btree_map::Entry::Vacant(slot) = acc.entry(dep_key) {
            let entry = lock.packages.get(key).cloned().unwrap_or_default();
            let (lics, lsrc) = entry_licenses_sourced(&entry);
            let declared = parent_is_root(key).then(|| root_direct.get(name)).flatten();
            slot.insert(Dependency {
                name: name.clone(),
                version: version.clone(),
                ecosystem: Ecosystem::Node,
                direct: declared.is_some(),
                scope: declared.copied().unwrap_or(Scope::Prod),
                licenses: lics,
                license_source: lsrc,
                resolved_url: entry.resolved.clone(),
                integrity: entry.integrity.clone(),
                parents: Vec::new(),
            });
        }
    }

    Ok(acc.into_values().collect())
}

/// The licenses plus the source to record for them. An empty list must stay
/// [`LicenseSource::Unknown`]: claiming a lockfile *told* us nothing is different
/// from it not telling us anything.
fn entry_licenses_sourced(entry: &PkgEntry) -> (Vec<License>, LicenseSource) {
    let l = entry_licenses(entry);
    let src = if l.is_empty() {
        LicenseSource::Unknown
    } else {
        LicenseSource::Lockfile
    };
    (l, src)
}

/// Licenses declared by a package-lock entry.
///
/// npm has used three shapes over the years, all still present in lockfiles in
/// the wild:
///
/// * `"license": "MIT"` — the modern form, an SPDX string or expression.
/// * `"license": {"type": "MIT", "url": "..."}` — an older object form.
/// * `"licenses": [{"type": "MIT"}, ...]` — the oldest, an array meaning
///   "any of these".
fn entry_licenses(entry: &PkgEntry) -> Vec<License> {
    /// A value that may be a bare string or a `{type: ...}` object.
    fn as_text(v: &serde_json::Value) -> Option<String> {
        v.as_str()
            .map(String::from)
            .or_else(|| v.get("type").and_then(|t| t.as_str()).map(String::from))
    }

    if let Some(v) = &entry.license {
        // The modern string form may itself be an expression; `normalize`
        // handles that. An array here is unusual but harmless to accept.
        if let Some(arr) = v.as_array() {
            let raws: Vec<String> = arr.iter().filter_map(as_text).collect();
            return crate::license::normalize_list(&raws);
        }
        if let Some(t) = as_text(v) {
            return crate::license::normalize(&t).into_iter().collect();
        }
    }
    if let Some(v) = &entry.licenses
        && let Some(arr) = v.as_array()
    {
        let raws: Vec<String> = arr.iter().filter_map(as_text).collect();
        return crate::license::normalize_list(&raws);
    }
    Vec::new()
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

    fn tmp_lock(body: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "postmortem-node-scope-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("package-lock.json");
        std::fs::write(&p, body).unwrap();
        p
    }

    const SCOPED_LOCK: &str = r#"{
      "lockfileVersion": 3,
      "packages": {
        "": {
          "dependencies": { "prod-lib": "1.0.0" },
          "devDependencies": { "dev-tool": "1.0.0" },
          "optionalDependencies": { "opt-lib": "1.0.0" }
        },
        "node_modules/prod-lib": { "version": "1.0.0" },
        "node_modules/dev-tool": { "version": "1.0.0" },
        "node_modules/opt-lib": { "version": "1.0.0" }
      }
    }"#;

    #[test]
    fn root_fields_seed_the_scope_of_direct_deps() {
        let deps = parse_lockfile(&tmp_lock(SCOPED_LOCK)).unwrap();
        let scope = |n: &str| deps.iter().find(|d| d.name == n).unwrap().scope;
        assert_eq!(scope("prod-lib"), Scope::Prod);
        assert_eq!(scope("dev-tool"), Scope::Dev);
        assert_eq!(scope("opt-lib"), Scope::Optional);
        assert!(deps.iter().all(|d| d.direct), "all three are root-declared");
    }

    #[test]
    fn a_package_in_two_root_fields_keeps_the_strongest_scope() {
        // npm allows the same name under `dependencies` and `devDependencies`;
        // it ships, so it must not be omittable.
        let lock = tmp_lock(
            r#"{
              "lockfileVersion": 3,
              "packages": {
                "": {
                  "dependencies": { "both": "1.0.0" },
                  "devDependencies": { "both": "1.0.0" }
                },
                "node_modules/both": { "version": "1.0.0" }
              }
            }"#,
        );
        let deps = parse_lockfile(&lock).unwrap();
        assert_eq!(
            deps.iter().find(|d| d.name == "both").unwrap().scope,
            Scope::Prod
        );
    }

    #[test]
    fn transitive_packages_are_left_for_propagation() {
        // The parser must not guess at depth — it seeds roots and leaves the
        // rest at the safe default for `crate::scope::propagate` to resolve.
        let lock = tmp_lock(
            r#"{
              "lockfileVersion": 3,
              "packages": {
                "": { "devDependencies": { "dev-tool": "1.0.0" } },
                "node_modules/dev-tool": {
                  "version": "1.0.0",
                  "dependencies": { "deep": "1.0.0" }
                },
                "node_modules/deep": { "version": "1.0.0" }
              }
            }"#,
        );
        let deps = parse_lockfile(&lock).unwrap();
        let deep = deps.iter().find(|d| d.name == "deep").unwrap();
        assert!(!deep.direct);
        assert_eq!(
            deep.scope,
            Scope::Prod,
            "unclassified until propagation runs"
        );
        assert!(
            deep.parents.iter().any(|(n, _)| n == "dev-tool"),
            "edge is present"
        );
    }

    #[test]
    fn lockfile_licenses_are_read_offline() {
        // npm records the license on ~99% of v2/v3 lock entries, so the biggest
        // ecosystem needs no network at all.
        let lock = tmp_lock(
            r#"{
              "lockfileVersion": 3,
              "packages": {
                "": { "dependencies": { "a": "1.0.0", "b": "1.0.0", "c": "1.0.0" } },
                "node_modules/a": { "version": "1.0.0", "license": "MIT" },
                "node_modules/b": { "version": "1.0.0", "license": "MIT OR Apache-2.0" },
                "node_modules/c": { "version": "1.0.0" }
              }
            }"#,
        );
        let deps = parse_lockfile(&lock).unwrap();
        let get = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(
            get("a").licenses,
            vec![License::Id {
                value: "MIT".into()
            }]
        );
        assert_eq!(get("a").license_source, LicenseSource::Lockfile);
        assert_eq!(
            get("b").licenses,
            vec![License::Expression {
                value: "MIT OR Apache-2.0".into()
            }]
        );
        // No license declared: stays empty AND unsourced — claiming the lockfile
        // told us nothing differs from it not telling us anything.
        assert!(get("c").licenses.is_empty());
        assert_eq!(get("c").license_source, LicenseSource::Unknown);
    }

    #[test]
    fn legacy_npm_license_shapes_are_understood() {
        // `{"type": ...}` and the `licenses` array are both still in the wild.
        let lock = tmp_lock(
            r#"{
              "lockfileVersion": 3,
              "packages": {
                "": { "dependencies": { "old": "1.0.0", "older": "1.0.0" } },
                "node_modules/old": { "version": "1.0.0", "license": {"type": "ISC", "url": "x"} },
                "node_modules/older": {
                  "version": "1.0.0",
                  "licenses": [{"type": "MIT"}, {"type": "Apache-2.0"}]
                }
              }
            }"#,
        );
        let deps = parse_lockfile(&lock).unwrap();
        let get = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(
            get("old").licenses,
            vec![License::Id {
                value: "ISC".into()
            }]
        );
        assert_eq!(
            get("older").licenses,
            vec![License::Expression {
                value: "MIT OR Apache-2.0".into()
            }],
            "an array of alternatives collapses into one OR expression"
        );
    }
}
