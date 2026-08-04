//! `pnpm-lock.yaml` parser — lockfileVersion 5.x / 6.x / 9.x.
//!
//! The layout moved around across pnpm majors, so we work off `serde_yaml`
//! values rather than a fixed struct:
//! - **nodes + integrity** come from the `packages:` map (all versions);
//! - **edges** come from `snapshots:` (v9) or from each package's own
//!   `dependencies:` (v5/v6);
//! - **direct deps** come from `importers:` (v9) or the top-level
//!   `dependencies:`/`devDependencies:` (v5/v6).
//!
//! Package keys vary: `name@version` (v9), `/name@version` (v6),
//! `/name/version` (v5), all optionally scoped and with a `(peer@x)` suffix.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde_yaml::{Mapping, Value};

use crate::model::{DepRef, Dependency, Ecosystem};

pub fn parse(path: &Path) -> Result<Vec<Dependency>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let doc: Value = serde_yaml::from_str(&text)
        .with_context(|| format!("parsing {} as pnpm-lock.yaml", path.display()))?;

    let mut acc: BTreeMap<DepRef, Dependency> = BTreeMap::new();

    // 1. Nodes + integrity from `packages:`.
    if let Some(pkgs) = doc.get("packages").and_then(Value::as_mapping) {
        for (k, v) in pkgs {
            let Some((name, version)) = k.as_str().and_then(key_to_ref) else {
                continue;
            };
            let integrity = v
                .get("resolution")
                .and_then(|r| r.get("integrity"))
                .and_then(Value::as_str)
                .map(String::from);
            acc.entry((name.clone(), version.clone()))
                .or_insert_with(|| node(name, version))
                .integrity
                .get_or_insert_with(|| integrity.clone().unwrap_or_default());
        }
    }

    // 2. Edges: prefer `snapshots:` (v9), else the per-package `dependencies:`.
    let edge_src = doc
        .get("snapshots")
        .and_then(Value::as_mapping)
        .or_else(|| doc.get("packages").and_then(Value::as_mapping));
    if let Some(map) = edge_src {
        for (k, v) in map {
            let Some(parent) = k.as_str().and_then(key_to_ref) else {
                continue;
            };
            for field in ["dependencies", "optionalDependencies"] {
                let Some(deps) = v.get(field).and_then(Value::as_mapping) else {
                    continue;
                };
                for (dn, dv) in deps {
                    let (Some(dn), Some(dv)) = (dn.as_str(), dv.as_str()) else {
                        continue;
                    };
                    let child = (dn.to_string(), strip_peer(dv).to_string());
                    let dep = acc
                        .entry(child.clone())
                        .or_insert_with(|| node(child.0.clone(), child.1.clone()));
                    if !dep.parents.contains(&parent) {
                        dep.parents.push(parent.clone());
                    }
                }
            }
        }
    }

    // 3. Direct deps: from `importers:` (v9) or the top-level maps (v5/v6).
    let mut directs: Vec<(String, Option<String>)> = Vec::new();
    if let Some(importers) = doc.get("importers").and_then(Value::as_mapping) {
        for (_, imp) in importers {
            if let Some(m) = imp.as_mapping() {
                collect_directs(m, &mut directs);
            }
        }
    } else if let Some(root) = doc.as_mapping() {
        collect_directs(root, &mut directs);
    }
    for (name, version) in directs {
        for (key, dep) in acc.iter_mut() {
            if key.0 == name && version.as_ref().is_none_or(|v| &key.1 == v) {
                dep.direct = true;
            }
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
        resolved_url: None,
        integrity: None,
        parents: Vec::new(),
    }
}

/// Pull direct deps out of a `dependencies`/`devDependencies`/`optionalDependencies`
/// block, whose values are either a bare version string (v5) or a
/// `{specifier, version}` map (v6/v9).
fn collect_directs(map: &Mapping, out: &mut Vec<(String, Option<String>)>) {
    for field in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(m) = map.get(field).and_then(Value::as_mapping) else {
            continue;
        };
        for (n, v) in m {
            let Some(name) = n.as_str() else { continue };
            let version = match v {
                Value::String(s) => Some(strip_peer(s).to_string()),
                Value::Mapping(_) => v
                    .get("version")
                    .and_then(Value::as_str)
                    .map(|s| strip_peer(s).to_string()),
                _ => None,
            };
            out.push((name.to_string(), version));
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
        assert_eq!(key_to_ref("lodash@4.17.21"), Some(("lodash".into(), "4.17.21".into())));
        assert_eq!(key_to_ref("/lodash@4.17.21"), Some(("lodash".into(), "4.17.21".into())));
        assert_eq!(key_to_ref("/lodash/4.17.21"), Some(("lodash".into(), "4.17.21".into())));
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
        assert!(cookie.parents.contains(&("express".into(), "4.18.2".into())));
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
        assert!(cookie.parents.contains(&("express".into(), "4.18.2".into())));
    }
}
