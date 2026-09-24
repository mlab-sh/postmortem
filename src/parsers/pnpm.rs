//! `pnpm-lock.yaml` parser — lockfileVersion 5.x / 6.x / 9.x.
//!
//! The layout moved around across pnpm majors, so every field of the typed
//! [`Lock`] is optional:
//! - **nodes + integrity** come from the `packages:` map (all versions);
//! - **edges** come from `snapshots:` (v9) or from each package's own
//!   `dependencies:` (v5/v6);
//! - **direct deps** come from `importers:` (v9) or the top-level
//!   `dependencies:`/`devDependencies:` (v5/v6).
//!
//! Package keys vary: `name@version` (v9), `/name@version` (v6),
//! `/name/version` (v5), all optionally scoped and with a `(peer@x)` suffix.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_yaml::Value;

use super::YamlMap;

use crate::model::{DepRef, Dependency, Ecosystem, LicenseSource, Scope};

/// The subset of a pnpm lockfile the parser reads. Everything is optional: the
/// layout moved across majors, and a field one version lacks must read as
/// absent, not fail the parse. Leaves stay `serde_yaml::Value` so a non-string
/// scalar is skipped exactly as `Value::as_str` skipped it before.
#[derive(Deserialize)]
struct Lock {
    #[serde(default)]
    packages: Option<YamlMap<Option<PkgEntry>>>,
    #[serde(default)]
    snapshots: Option<YamlMap<Option<PkgEntry>>>,
    #[serde(default)]
    importers: Option<YamlMap<Option<Directs>>>,
    /// v5/v6 keep the root's direct deps at the top level.
    #[serde(flatten)]
    root: Directs,
}

#[derive(Deserialize)]
struct PkgEntry {
    #[serde(default)]
    resolution: Option<Resolution>,
    #[serde(default)]
    dependencies: Option<YamlMap<Value>>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: Option<YamlMap<Value>>,
}

#[derive(Deserialize)]
struct Resolution {
    #[serde(default)]
    integrity: Option<Value>,
}

/// A `dependencies`/`devDependencies`/`optionalDependencies` block, whose
/// values are either a bare version string (v5) or a `{specifier, version}`
/// map (v6/v9).
#[derive(Deserialize, Default)]
struct Directs {
    #[serde(default)]
    dependencies: Option<YamlMap<Value>>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: Option<YamlMap<Value>>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: Option<YamlMap<Value>>,
}

pub fn parse(path: &Path) -> Result<Vec<Dependency>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let doc: Lock = serde_yaml::from_str(&text)
        .with_context(|| format!("parsing {} as pnpm-lock.yaml", path.display()))?;

    let mut acc: BTreeMap<DepRef, Dependency> = BTreeMap::new();

    // 1. Nodes + integrity from `packages:`.
    if let Some(pkgs) = &doc.packages {
        for (k, v) in &pkgs.0 {
            let Some((name, version)) = k.as_str().and_then(key_to_ref) else {
                continue;
            };
            let integrity = v
                .as_ref()
                .and_then(|v| v.resolution.as_ref())
                .and_then(|r| r.integrity.as_ref())
                .and_then(Value::as_str);
            acc.entry((name, version))
                .or_insert_with_key(|(n, v)| node(n.clone(), v.clone()))
                .integrity
                .get_or_insert_with(|| integrity.unwrap_or_default().to_string());
        }
    }

    // 2. Edges: prefer `snapshots:` (v9), else the per-package `dependencies:`.
    // A child reached from p parents used to pay an O(p) `contains` per edge.
    // Each distinct parent gets a small id and each child a set of the ids it
    // already records: O(1) dedup, same first-seen order. Dedup is by parent
    // *ref*, not by key — `a@1(peer@x)` and `a@1(peer@y)` are one parent.
    let mut parent_ids: HashMap<DepRef, u32> = HashMap::new();
    let mut seen: BTreeMap<DepRef, (Dependency, HashSet<u32>)> = std::mem::take(&mut acc)
        .into_iter()
        .map(|(k, d)| (k, (d, HashSet::new())))
        .collect();
    if let Some(map) = doc.snapshots.as_ref().or(doc.packages.as_ref()) {
        for (k, v) in &map.0 {
            let Some(parent) = k.as_str().and_then(key_to_ref) else {
                continue;
            };
            let Some(v) = v else { continue };
            let next = parent_ids.len() as u32;
            let pid = *parent_ids.entry(parent.clone()).or_insert(next);
            for deps in [&v.dependencies, &v.optional_dependencies] {
                let Some(deps) = deps else { continue };
                for (dn, dv) in &deps.0 {
                    let (Some(dn), Some(dv)) = (dn.as_str(), dv.as_str()) else {
                        continue;
                    };
                    let child = (dn.to_string(), strip_peer(dv).to_string());
                    let (dep, ids) = seen
                        .entry(child)
                        .or_insert_with_key(|(n, v)| (node(n.clone(), v.clone()), HashSet::new()));
                    if ids.insert(pid) {
                        dep.parents.push(parent.clone());
                    }
                }
            }
        }
    }
    drop(parent_ids);
    let mut acc: BTreeMap<DepRef, Dependency> =
        seen.into_iter().map(|(k, (d, _))| (k, d)).collect();

    // 3. Direct deps: from `importers:` (v9) or the top-level maps (v5/v6). The
    // block each came from seeds its scope; the rest of the graph is inferred by
    // `crate::scope::propagate`.
    let mut directs: Vec<(String, Option<String>, Scope)> = Vec::new();
    if let Some(importers) = &doc.importers {
        for (_, imp) in &importers.0 {
            if let Some(m) = imp {
                collect_directs(m, &mut directs);
            }
        }
    } else {
        collect_directs(&doc.root, &mut directs);
    }
    // Resolve precedence across declarations before assigning: nodes start as
    // `Prod`, so folding a `Dev` seed in with `max` would never take effect. In a
    // workspace the same package can be a dev dep of one importer and a prod dep
    // of another — prod wins, which is the safe direction.
    //
    // Every direct dep scanned every node key before — O(D·V), ~2 M string
    // compares for 1 000 directs over 2 000 packages. A name index built once
    // makes each lookup touch only that name's versions, in the same key order.
    let mut by_name: HashMap<&str, Vec<&DepRef>> = HashMap::new();
    for key in acc.keys() {
        by_name.entry(key.0.as_str()).or_default().push(key);
    }
    let mut seeds: BTreeMap<DepRef, Scope> = BTreeMap::new();
    for (name, version, scope) in directs {
        for key in by_name.get(name.as_str()).into_iter().flatten() {
            if version.as_ref().is_none_or(|v| &key.1 == v) {
                let e = seeds.entry((*key).clone()).or_insert(scope);
                *e = (*e).max(scope);
            }
        }
    }
    drop(by_name);
    for (key, scope) in seeds {
        if let Some(dep) = acc.get_mut(&key) {
            dep.direct = true;
            dep.scope = scope;
        }
    }

    // Integrity was seeded with "" for pnpm entries lacking a hash — normalize.
    for dep in acc.values_mut() {
        if dep.integrity.as_deref() == Some("") {
            dep.integrity = None;
        }
    }

    Ok(acc.into_values().collect())
}

fn node(name: String, version: String) -> Dependency {
    Dependency {
        name,
        version,
        ecosystem: Ecosystem::Node,
        direct: false,
        scope: Scope::Prod,
        licenses: Vec::new(),
        license_source: LicenseSource::Unknown,
        resolved_url: None,
        integrity: None,
        parents: Vec::new(),
    }
}

/// Pull direct deps out of a `dependencies`/`devDependencies`/`optionalDependencies`
/// block, whose values are either a bare version string (v5) or a
/// `{specifier, version}` map (v6/v9).
fn collect_directs(block: &Directs, out: &mut Vec<(String, Option<String>, Scope)>) {
    for (m, scope) in [
        (&block.dependencies, Scope::Prod),
        (&block.optional_dependencies, Scope::Optional),
        (&block.dev_dependencies, Scope::Dev),
    ] {
        let Some(m) = m else {
            continue;
        };
        for (n, v) in &m.0 {
            let Some(name) = n.as_str() else { continue };
            let version = match v {
                Value::String(s) => Some(strip_peer(s).to_string()),
                Value::Mapping(_) => v
                    .get("version")
                    .and_then(Value::as_str)
                    .map(|s| strip_peer(s).to_string()),
                _ => None,
            };
            out.push((name.to_string(), version, scope));
        }
    }
}

/// A pnpm package key → `(name, version)`, across all three key shapes.
fn key_to_ref(key: &str) -> Option<(String, String)> {
    let k = key.strip_prefix('/').unwrap_or(key);
    let k = strip_peer(k);

    // v6/v9: `name@version` (name may be scoped, so ignore a leading `@`).
    if let Some(at) = k.rfind('@')
        && at > 0
    {
        let (name, ver) = k.split_at(at);
        let ver = &ver[1..];
        if !name.is_empty() && !ver.is_empty() && !ver.contains('/') {
            return Some((name.to_string(), ver.to_string()));
        }
    }
    // v5: `name/version` — version is the final segment.
    if let Some(slash) = k.rfind('/') {
        let (name, ver) = (&k[..slash], &k[slash + 1..]);
        if !name.is_empty() && !ver.is_empty() {
            return Some((name.to_string(), ver.to_string()));
        }
    }
    None
}

/// Drop pnpm's `(peer@x)` disambiguation suffix.
fn strip_peer(s: &str) -> &str {
    s.split('(').next().unwrap_or(s).trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_shapes() {
        assert_eq!(
            key_to_ref("lodash@4.17.21"),
            Some(("lodash".into(), "4.17.21".into()))
        );
        assert_eq!(
            key_to_ref("/lodash@4.17.21"),
            Some(("lodash".into(), "4.17.21".into()))
        );
        assert_eq!(
            key_to_ref("/lodash/4.17.21"),
            Some(("lodash".into(), "4.17.21".into()))
        );
        assert_eq!(
            key_to_ref("/@babel/core@7.0.0"),
            Some(("@babel/core".into(), "7.0.0".into()))
        );
        assert_eq!(
            key_to_ref("/@babel/core/7.0.0"),
            Some(("@babel/core".into(), "7.0.0".into()))
        );
        assert_eq!(
            key_to_ref("react-dom@18.2.0(react@18.2.0)"),
            Some(("react-dom".into(), "18.2.0".into()))
        );
    }

    #[test]
    fn parses_v9_importers_and_snapshots() {
        let lock = r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      express:
        specifier: ^4.18.2
        version: 4.18.2
packages:
  express@4.18.2:
    resolution: {integrity: sha512-aaa}
  cookie@0.5.0:
    resolution: {integrity: sha512-bbb}
snapshots:
  express@4.18.2:
    dependencies:
      cookie: 0.5.0
  cookie@0.5.0: {}
"#;
        let dir = std::env::temp_dir().join(format!("pm-pnpm9-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("pnpm-lock.yaml");
        std::fs::write(&p, lock).unwrap();
        let deps = parse(&p).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        let express = deps.iter().find(|d| d.name == "express").unwrap();
        assert_eq!(express.version, "4.18.2");
        assert!(express.direct);
        assert_eq!(express.integrity.as_deref(), Some("sha512-aaa"));

        let cookie = deps.iter().find(|d| d.name == "cookie").unwrap();
        assert!(!cookie.direct);
        assert!(
            cookie
                .parents
                .contains(&("express".into(), "4.18.2".into()))
        );
    }

    #[test]
    fn parses_v6_flat_packages() {
        let lock = r#"
lockfileVersion: '6.0'
dependencies:
  express:
    specifier: ^4
    version: 4.18.2
packages:
  /express@4.18.2:
    resolution: {integrity: sha512-aaa}
    dependencies:
      cookie: 0.5.0
  /cookie@0.5.0:
    resolution: {integrity: sha512-bbb}
"#;
        let dir = std::env::temp_dir().join(format!("pm-pnpm6-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("pnpm-lock.yaml");
        std::fs::write(&p, lock).unwrap();
        let deps = parse(&p).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        assert!(deps.iter().find(|d| d.name == "express").unwrap().direct);
        let cookie = deps.iter().find(|d| d.name == "cookie").unwrap();
        assert!(
            cookie
                .parents
                .contains(&("express".into(), "4.18.2".into()))
        );
    }

    #[test]
    fn dev_and_optional_blocks_seed_direct_scopes() {
        let lock = r#"
lockfileVersion: '6.0'
dependencies:
  express:
    specifier: ^4
    version: 4.18.2
devDependencies:
  jest:
    specifier: ^29
    version: 29.0.0
optionalDependencies:
  fsevents:
    specifier: ^2
    version: 2.3.2
packages:
  /express@4.18.2:
    resolution: {integrity: sha512-aaa}
  /jest@29.0.0:
    resolution: {integrity: sha512-bbb}
  /fsevents@2.3.2:
    resolution: {integrity: sha512-ccc}
"#;
        let dir = std::env::temp_dir().join(format!("pm-pnpm-scope-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("pnpm-lock.yaml");
        std::fs::write(&p, lock).unwrap();
        let deps = parse(&p).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        let scope = |n: &str| deps.iter().find(|d| d.name == n).unwrap().scope;
        assert_eq!(scope("express"), Scope::Prod);
        assert_eq!(scope("jest"), Scope::Dev);
        assert_eq!(scope("fsevents"), Scope::Optional);
    }

    #[test]
    fn a_workspace_dev_dep_that_is_prod_elsewhere_stays_prod() {
        // Two importers disagree: one uses `shared` as a dev tool, the other
        // ships it. Production must win, or `--omit dev` would hide it.
        let lock = r#"
lockfileVersion: '6.0'
importers:
  packages/tools:
    devDependencies:
      shared:
        specifier: ^1
        version: 1.0.0
  packages/app:
    dependencies:
      shared:
        specifier: ^1
        version: 1.0.0
packages:
  /shared@1.0.0:
    resolution: {integrity: sha512-aaa}
"#;
        let dir = std::env::temp_dir().join(format!("pm-pnpm-ws-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("pnpm-lock.yaml");
        std::fs::write(&p, lock).unwrap();
        let deps = parse(&p).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            deps.iter().find(|d| d.name == "shared").unwrap().scope,
            Scope::Prod
        );
    }
}
