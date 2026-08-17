//! `yarn.lock` parser — classic v1 (custom text) and Berry v2+ (YAML).
//!
//! yarn.lock keys are *descriptors* (`name@range`), and one entry can satisfy
//! several descriptors. We build a descriptor → `(name, version)` map, then:
//! - **direct** deps come from the project's `package.json` (yarn.lock doesn't
//!   record which deps are the root's), resolved through the descriptor map;
//! - **edges** come from each entry's own `dependencies` descriptors.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::{Context, Result};
use serde_yaml::Value;

use crate::model::{DepRef, Dependency, Ecosystem, Scope};

pub fn parse(manifest: &Path, lockfile: &Path) -> Result<Vec<Dependency>> {
    let text = std::fs::read_to_string(lockfile)
        .with_context(|| format!("reading {}", lockfile.display()))?;

    // Berry lockfiles are YAML and carry a `__metadata` block; classic v1 is a
    // bespoke text format.
    let entries = if text.contains("__metadata") {
        parse_berry(&text).with_context(|| format!("parsing {} as a Berry yarn.lock", lockfile.display()))?
    } else {
        parse_v1(&text)
    };

    Ok(assemble(entries, manifest))
}

/// One resolved lockfile entry.
struct Entry {
    /// Descriptors this entry satisfies (`name@range`), name pre-split off.
    descriptors: Vec<(String, String)>, // (name, range)
    name: String,
    version: String,
    resolved: Option<String>,
    integrity: Option<String>,
    /// Declared deps as `(name, range)`.
    deps: Vec<(String, String)>,
}

fn assemble(entries: Vec<Entry>, manifest: &Path) -> Vec<Dependency> {
    // descriptor "name@range" -> (name, version)
    let mut by_descriptor: HashMap<String, DepRef> = HashMap::new();
    for e in &entries {
        for (n, r) in &e.descriptors {
            by_descriptor.insert(format!("{n}@{r}"), (e.name.clone(), e.version.clone()));
        }
    }

    // Pass 1: create every node with its metadata (before any edge can).
    let mut acc: BTreeMap<DepRef, Dependency> = BTreeMap::new();
    for e in &entries {
        acc.entry((e.name.clone(), e.version.clone())).or_insert_with(|| Dependency {
            name: e.name.clone(),
            version: e.version.clone(),
            ecosystem: Ecosystem::Node,
            direct: false,
            scope: Scope::Prod,
            resolved_url: e.resolved.clone(),
            integrity: e.integrity.clone(),
            parents: Vec::new(),
        });
    }
    // Pass 2: add parent edges (nodes already exist, so metadata is preserved).
    for e in &entries {
        let parent = (e.name.clone(), e.version.clone());
        for (dn, dr) in &e.deps {
            if let Some(child) = by_descriptor.get(&format!("{dn}@{dr}"))
                && let Some(dep) = acc.get_mut(child)
            {
                dep.parents.push(parent.clone());
            }
        }
    }
    for dep in acc.values_mut() {
        dep.parents.sort();
        dep.parents.dedup();
    }

    // Direct deps: resolve each root descriptor from package.json. The field it
    // came from is what seeds the scope; everything deeper is inferred later by
    // `crate::scope::propagate`.
    //
    // Precedence is resolved across the root declarations *first*, then assigned:
    // nodes were created as `Prod`, so folding a `Dev` seed into the node with
    // `max` would always lose and no dev root would ever be marked.
    let mut seeds: HashMap<DepRef, Scope> = HashMap::new();
    for (name, range, scope) in root_deps(manifest) {
        let resolved = by_descriptor
            .get(&format!("{name}@{range}"))
            .cloned()
            // Fall back to marking every version of a root dep name direct.
            .or_else(|| acc.keys().find(|(n, _)| n == &name).cloned());
        if let Some(k) = resolved {
            let e = seeds.entry(k).or_insert(scope);
            *e = (*e).max(scope);
        }
    }
    for (k, scope) in seeds {
        if let Some(d) = acc.get_mut(&k) {
            d.direct = true;
            d.scope = scope;
        }
    }

    acc.into_values().collect()
}

/// Root direct deps `(name, range, scope)` from `package.json`, the scope being
/// the field each was declared under.
fn root_deps(manifest: &Path) -> Vec<(String, String, Scope)> {
    let Ok(text) = std::fs::read_to_string(manifest) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (field, scope) in [
        ("dependencies", Scope::Prod),
        ("optionalDependencies", Scope::Optional),
        ("devDependencies", Scope::Dev),
    ] {
        if let Some(m) = json.get(field).and_then(|v| v.as_object()) {
            for (n, r) in m {
                if let Some(r) = r.as_str() {
                    out.push((n.clone(), r.to_string(), scope));
                }
            }
        }
    }
    out
}

// --- classic v1 -------------------------------------------------------------

fn parse_v1(text: &str) -> Vec<Entry> {
    // Group into (header line, body lines) by column-0 headers.
    let mut blocks: Vec<(String, Vec<String>)> = Vec::new();
    let mut header: Option<String> = None;
    let mut body: Vec<String> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            body.push(line.to_string());
        } else {
            if let Some(h) = header.take() {
                blocks.push((h, std::mem::take(&mut body)));
            }
            header = Some(line.to_string());
        }
    }
    if let Some(h) = header.take() {
        blocks.push((h, body));
    }

    blocks
        .into_iter()
        .filter_map(|(h, body)| entry_from_v1(&h, &body))
        .collect()
}

fn entry_from_v1(header: &str, body: &[String]) -> Option<Entry> {
    let descriptors: Vec<(String, String)> = header
        .trim_end_matches(':')
        .split(',')
        .map(|d| split_descriptor(unquote(d.trim())))
        .collect();

    let mut version = None;
    let mut resolved = None;
    let mut integrity = None;
    let mut deps = Vec::new();
    let mut in_deps = false;
    for line in body {
        let t = line.trim();
        if let Some(v) = t.strip_prefix("version ") {
            version = Some(unquote(v.trim()).to_string());
            in_deps = false;
        } else if let Some(r) = t.strip_prefix("resolved ") {
            resolved = Some(unquote(r.trim()).to_string());
            in_deps = false;
        } else if let Some(i) = t.strip_prefix("integrity ") {
            integrity = Some(unquote(i.trim()).to_string());
            in_deps = false;
        } else if t == "dependencies:" || t == "optionalDependencies:" {
            in_deps = true;
        } else if in_deps {
            // `foo "^1.0.0"` / `"@scope/foo" "^1.0.0"`
            match t.split_once(' ') {
                Some((n, r)) => deps.push((unquote(n.trim()).to_string(), unquote(r.trim()).to_string())),
                None => in_deps = false,
            }
        }
    }

    let name = descriptors.first()?.0.clone();
    Some(Entry {
        descriptors,
        name,
        version: version?,
        resolved,
        integrity,
        deps,
    })
}

// --- Berry v2+ (YAML) -------------------------------------------------------

fn parse_berry(text: &str) -> Result<Vec<Entry>> {
    let doc: Value = serde_yaml::from_str(text)?;
    let Some(map) = doc.as_mapping() else {
        return Ok(Vec::new());
    };
    let mut entries = Vec::new();
    for (k, v) in map {
        let Some(key) = k.as_str() else { continue };
        if key == "__metadata" {
            continue;
        }
        let descriptors: Vec<(String, String)> =
            key.split(',').map(|d| split_descriptor(d.trim())).collect();
        let Some(version) = v.get("version").and_then(Value::as_str) else {
            continue;
        };
        let deps = v
            .get("dependencies")
            .and_then(Value::as_mapping)
            .map(|m| {
                m.iter()
                    .filter_map(|(dn, dr)| Some((dn.as_str()?.to_string(), dr.as_str()?.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        let name = match descriptors.first() {
            Some((n, _)) => n.clone(),
            None => continue,
        };
        entries.push(Entry {
            descriptors,
            name,
            version: version.to_string(),
            resolved: v.get("resolution").and_then(Value::as_str).map(String::from),
            integrity: v.get("checksum").and_then(Value::as_str).map(String::from),
            deps,
        });
    }
    Ok(entries)
}

// --- shared helpers ---------------------------------------------------------

fn unquote(s: &str) -> &str {
    s.trim().trim_matches('"')
}

/// Split a descriptor `name@range` into `(name, range)`, respecting a leading
/// `@scope/` and Berry's `npm:` protocol (kept in the range).
fn split_descriptor(d: &str) -> (String, String) {
    let at = if let Some(rest) = d.strip_prefix('@') {
        rest.find('@').map(|i| i + 1)
    } else {
        d.find('@')
    };
    match at {
        Some(i) => (d[..i].to_string(), d[i + 1..].to_string()),
        None => (d.to_string(), String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("pm-yarn-{}-{}", dir, std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        for (name, body) in files {
            std::fs::write(d.join(name), body).unwrap();
        }
        d
    }

    #[test]
    fn split_descriptor_scoped_and_protocol() {
        assert_eq!(split_descriptor("lodash@^4.17.21"), ("lodash".into(), "^4.17.21".into()));
        assert_eq!(split_descriptor("@babel/core@^7.0.0"), ("@babel/core".into(), "^7.0.0".into()));
        assert_eq!(split_descriptor("lodash@npm:^4"), ("lodash".into(), "npm:^4".into()));
    }

    #[test]
    fn parses_v1_graph_and_direct() {
        let lock = r#"# yarn lockfile v1

express@^4.18.2:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz#abc"
  integrity sha512-aaa
  dependencies:
    cookie "0.5.0"

cookie@0.5.0:
  version "0.5.0"
  resolved "https://registry.yarnpkg.com/cookie/-/cookie-0.5.0.tgz#def"
  integrity sha512-bbb
"#;
        let d = write("v1", &[
            ("yarn.lock", lock),
            ("package.json", r#"{"dependencies":{"express":"^4.18.2"}}"#),
        ]);
        let deps = parse(&d.join("package.json"), &d.join("yarn.lock")).unwrap();
        let _ = std::fs::remove_dir_all(&d);

        let express = deps.iter().find(|d| d.name == "express").unwrap();
        assert_eq!(express.version, "4.18.2");
        assert!(express.direct);
        assert_eq!(express.integrity.as_deref(), Some("sha512-aaa"));

        let cookie = deps.iter().find(|d| d.name == "cookie").unwrap();
        assert!(!cookie.direct);
        assert!(cookie.parents.contains(&("express".into(), "4.18.2".into())));
    }

    #[test]
    fn parses_berry_graph() {
        let lock = r#"__metadata:
  version: 8
"express@npm:^4.18.2":
  version: 4.18.2
  resolution: "express@npm:4.18.2"
  checksum: aaa
  dependencies:
    cookie: "npm:0.5.0"
"cookie@npm:0.5.0":
  version: 0.5.0
  resolution: "cookie@npm:0.5.0"
  checksum: bbb
"#;
        let d = write("berry", &[
            ("yarn.lock", lock),
            ("package.json", r#"{"dependencies":{"express":"^4.18.2"}}"#),
        ]);
        let deps = parse(&d.join("package.json"), &d.join("yarn.lock")).unwrap();
        let _ = std::fs::remove_dir_all(&d);

        let express = deps.iter().find(|d| d.name == "express").unwrap();
        assert!(express.direct, "express should be direct");
        let cookie = deps.iter().find(|d| d.name == "cookie").unwrap();
        assert!(cookie.parents.contains(&("express".into(), "4.18.2".into())));
    }

    #[test]
    fn package_json_fields_seed_direct_scopes() {
        let lock = r#"# yarn lockfile v1

express@^4.18.2:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"

jest@^29.0.0:
  version "29.0.0"
  resolved "https://registry.yarnpkg.com/jest/-/jest-29.0.0.tgz"

fsevents@^2.3.2:
  version "2.3.2"
  resolved "https://registry.yarnpkg.com/fsevents/-/fsevents-2.3.2.tgz"
"#;
        let d = write(
            "scope",
            &[
                ("yarn.lock", lock),
                (
                    "package.json",
                    r#"{"dependencies":{"express":"^4.18.2"},
                        "devDependencies":{"jest":"^29.0.0"},
                        "optionalDependencies":{"fsevents":"^2.3.2"}}"#,
                ),
            ],
        );
        let deps = parse(&d.join("package.json"), &d.join("yarn.lock")).unwrap();
        let _ = std::fs::remove_dir_all(&d);

        let scope = |n: &str| deps.iter().find(|x| x.name == n).unwrap().scope;
        assert_eq!(scope("express"), Scope::Prod);
        assert_eq!(scope("jest"), Scope::Dev);
        assert_eq!(scope("fsevents"), Scope::Optional);
    }

    #[test]
    fn a_package_in_two_manifest_fields_keeps_the_strongest_scope() {
        let lock = r#"# yarn lockfile v1

both@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/both/-/both-1.0.0.tgz"
"#;
        let d = write(
            "scope-dup",
            &[
                ("yarn.lock", lock),
                (
                    "package.json",
                    r#"{"dependencies":{"both":"^1.0.0"},"devDependencies":{"both":"^1.0.0"}}"#,
                ),
            ],
        );
        let deps = parse(&d.join("package.json"), &d.join("yarn.lock")).unwrap();
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(deps.iter().find(|x| x.name == "both").unwrap().scope, Scope::Prod);
    }
}
