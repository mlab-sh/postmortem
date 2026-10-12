//! Deno's `deno.lock` (v3, v4, v5).
//!
//! * `specifiers` maps what code imports (`jsr:@std/fs@1`, `npm:vite@^7`) to
//!   the version it resolved to.
//! * `jsr` — JSR packages (`@std/fs@1.0.19`), reported as `jsr`, each with
//!   its `dependencies` as specifiers.
//! * `npm` — npm packages, reported as `node`: they are npm's. A key may carry
//!   a peer suffix (`a@1.0.0_b@2.0.0`), which is the same package. Its
//!   `dependencies` are names (`ms`), or `name@version` where two coexist;
//!   v3 maps name -> `name@version`.
//! * `workspace` (and its `members`) lists the direct specifiers.
//! * `remote` — URL imports (`https://deno.land/x/...`): not packages of any
//!   registry, counted rather than reported (see [`remote_count`]).
//!
//! v3 nests `specifiers` / `jsr` / `npm` under `packages`.

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

use crate::model::{Dependency, Ecosystem, LicenseSource, Scope};

/// `@std/fs@1.0.19` / `vite@7.3.1_rollup@4.55.1` -> (`@std/fs`, `1.0.19`).
fn split(id: &str) -> Option<(&str, &str)> {
    let at = id.get(1..)?.find('@')? + 1;
    let version = &id[at + 1..];
    Some((&id[..at], version.split('_').next().unwrap_or(version)))
}

fn sections(lock: &Value) -> &Value {
    // v3 nests the package sections under `packages`.
    match lock.get("packages") {
        Some(p) if p.get("specifiers").is_some() || p.get("npm").is_some() => p,
        _ => lock,
    }
}

/// URL imports recorded in `remote` — Deno's pre-JSR way of depending on code.
pub fn remote_count(path: &Path) -> usize {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v.get("remote").and_then(|r| r.as_object()).map(|r| r.len()))
        .unwrap_or(0)
}

pub fn parse(path: &Path) -> Result<Vec<Dependency>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {} as deno.lock", path.display()))?;
    let s = sections(&lock);
    let obj = |k: &str| s.get(k).and_then(|v| v.as_object());
    let specifiers: HashMap<&str, &str> = obj("specifiers")
        .into_iter()
        .flatten()
        .filter_map(|(k, v)| Some((k.as_str(), v.as_str()?)))
        .collect();

    let mut out: Vec<Dependency> = Vec::new();
    let mut index: HashMap<(Ecosystem, String, String), usize> = HashMap::new();
    // name -> versions, per registry, for a bare-name dependency.
    let mut versions: HashMap<(Ecosystem, String), Vec<String>> = HashMap::new();
    let mut entries: Vec<(usize, &Value)> = Vec::new();
    for (eco, section) in [(Ecosystem::Jsr, "jsr"), (Ecosystem::Node, "npm")] {
        for (key, entry) in obj(section).into_iter().flatten() {
            let Some((name, version)) = split(key) else {
                continue;
            };
            let id = (eco, name.to_string(), version.to_string());
            let i = match index.get(&id) {
                Some(&i) => i,
                None => {
                    out.push(Dependency {
                        name: name.to_string(),
                        version: version.to_string(),
                        ecosystem: eco,
                        direct: false,
                        scope: Scope::Prod,
                        licenses: Vec::new(),
                        license_source: LicenseSource::Unknown,
                        resolved_url: None,
                        integrity: entry.get("integrity").and_then(|v| v.as_str()).map(|h| {
                            if eco == Ecosystem::Jsr {
                                format!("sha256-{h}")
                            } else {
                                h.to_string()
                            }
                        }),
                        parents: Vec::new(),
                    });
                    index.insert(id, out.len() - 1);
                    versions
                        .entry((eco, name.to_string()))
                        .or_default()
                        .push(version.to_string());
                    out.len() - 1
                }
            };
            entries.push((i, entry));
        }
    }

    // A dependency reference to a node: `jsr:@std/fs@1` (a specifier),
    // `jsr:@std/fs@1.0.19` (exact), `npm:ms` / `ms` (a name), `ms@2.1.2`.
    let lookup = |reference: &str, default: Ecosystem| -> Option<usize> {
        let (eco, bare) = match reference.split_once(':') {
            Some(("jsr", r)) => (Ecosystem::Jsr, r),
            Some(("npm", r)) => (Ecosystem::Node, r),
            _ => (default, reference),
        };
        let prefix = if eco == Ecosystem::Jsr {
            "jsr:"
        } else {
            "npm:"
        };
        if let Some(v) = specifiers.get(format!("{prefix}{bare}").as_str()) {
            let name = split(bare).map_or(bare, |(n, _)| n);
            let v = v.split('_').next().unwrap_or(v);
            if let Some(&i) = index.get(&(eco, name.to_string(), v.to_string())) {
                return Some(i);
            }
        }
        if let Some((name, v)) = split(bare)
            && let Some(&i) = index.get(&(eco, name.to_string(), v.to_string()))
        {
            return Some(i);
        }
        let name = split(bare).map_or(bare, |(n, _)| n);
        match versions.get(&(eco, name.to_string())).map(Vec::as_slice) {
            Some([only]) => index.get(&(eco, name.to_string(), only.clone())).copied(),
            _ => None,
        }
    };

    for (pi, entry) in entries {
        let default = out[pi].ecosystem;
        let refs: Vec<String> = match entry.get("dependencies") {
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|v| v.as_str())
                .map(String::from)
                .collect(),
            // v3 npm: name -> `name@version`.
            Some(Value::Object(m)) => m
                .values()
                .filter_map(|v| v.as_str())
                .map(String::from)
                .collect(),
            _ => Vec::new(),
        };
        let parent = (out[pi].name.clone(), out[pi].version.clone());
        for r in refs {
            if let Some(ci) = lookup(&r, default)
                && ci != pi
                && !out[ci].parents.contains(&parent)
            {
                out[ci].parents.push(parent.clone());
            }
        }
    }

    // Direct: the workspace's specifiers, its members', and (v4+) the
    // `packageJson` dependencies it records.
    let mut direct: Vec<String> = Vec::new();
    if let Some(ws) = lock.get("workspace") {
        let mut collect = |v: &Value| {
            for key in ["dependencies"] {
                direct.extend(
                    v.get(key)
                        .and_then(|d| d.as_array())
                        .into_iter()
                        .flatten()
                        .filter_map(|x| x.as_str())
                        .map(String::from),
                );
            }
            if let Some(pj) = v.get("packageJson") {
                direct.extend(
                    pj.get("dependencies")
                        .and_then(|d| d.as_array())
                        .into_iter()
                        .flatten()
                        .filter_map(|x| x.as_str())
                        .map(String::from),
                );
            }
        };
        collect(ws);
        for m in ws
            .get("members")
            .and_then(|m| m.as_object())
            .into_iter()
            .flatten()
        {
            collect(m.1);
        }
    }
    for spec in direct {
        if let Some(i) = lookup(&spec, Ecosystem::Node) {
            out[i].direct = true;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v5_jsr_npm_peers_and_workspace() {
        let dir = std::env::temp_dir().join(format!("postmortem-deno-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("deno.lock");
        std::fs::write(
            &p,
            r#"{
  "version": "5",
  "specifiers": {
    "jsr:@std/fs@1": "1.0.19",
    "jsr:@std/path@^1.1.2": "1.1.2",
    "npm:preact@^10.28.2": "10.28.2",
    "npm:@preact/signals@^2.5.1": "2.5.1_preact@10.28.2"
  },
  "jsr": {
    "@std/fs@1.0.19": { "integrity": "abc", "dependencies": ["jsr:@std/path"] },
    "@std/path@1.1.2": { "integrity": "def" }
  },
  "npm": {
    "@preact/signals@2.5.1_preact@10.28.2": { "integrity": "sha512-sig==", "dependencies": ["@preact/signals-core", "preact"] },
    "@preact/signals-core@1.8.0": { "integrity": "sha512-core==" },
    "preact@10.28.2": { "integrity": "sha512-preact==" }
  },
  "remote": { "https://deno.land/x/oak@v12.6.1/mod.ts": "abc" },
  "workspace": {
    "dependencies": ["jsr:@std/fs@1", "npm:@preact/signals@^2.5.1"],
    "members": { "www": { "dependencies": ["npm:preact@^10.28.2"] } }
  }
}"#,
        )
        .unwrap();
        let deps = parse(&p).unwrap();
        let get = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(deps.len(), 5);
        assert_eq!(get("@std/fs").ecosystem, Ecosystem::Jsr);
        assert_eq!(get("preact").ecosystem, Ecosystem::Node);
        assert_eq!(
            get("@preact/signals").version,
            "2.5.1",
            "peer suffix dropped"
        );
        assert!(get("@std/fs").direct && get("@preact/signals").direct && get("preact").direct);
        assert!(!get("@std/path").direct && !get("@preact/signals-core").direct);
        assert_eq!(
            get("@std/path").parents,
            vec![("@std/fs".to_string(), "1.0.19".to_string())]
        );
        assert_eq!(
            get("preact").parents,
            vec![("@preact/signals".to_string(), "2.5.1".to_string())]
        );
        assert_eq!(get("@std/path").integrity.as_deref(), Some("sha256-def"));
        assert_eq!(remote_count(&p), 1);
    }
}
