//! Bun's text lockfile, `bun.lock` (the default since Bun 1.2).
//!
//! JSONC — JSON with trailing commas. `workspaces` holds each workspace's
//! declared `dependencies` / `devDependencies` / `optionalDependencies` (the
//! direct set and its scopes); `packages` maps an install path to
//! `[ "name@version", registry, { dependencies, ... }, integrity ]`.
//!
//! The install path mirrors `node_modules` nesting: `"@babel/core/semver"` is
//! the `semver` installed under `@babel/core`. A dependency is resolved the way
//! Node resolves it — the nearest enclosing path first, the hoisted top level
//! last.
//!
//! The binary `bun.lockb` (Bun < 1.2) cannot be read without Bun itself.

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

use crate::model::{Dependency, Ecosystem, LicenseSource, Scope};

/// Drop JSONC trailing commas (`,` before `}` / `]`), outside strings.
fn strip_trailing_commas(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let (mut i, mut in_str) = (0, false);
    while i < b.len() {
        let c = b[i];
        if in_str {
            if c == b'\\' {
                out.push_str(&src[i..(i + 2).min(b.len())]);
                i += 2;
                continue;
            }
            if c == b'"' {
                in_str = false;
            }
        } else if c == b'"' {
            in_str = true;
        } else if c == b',' {
            let next = b[i + 1..].iter().find(|x| !x.is_ascii_whitespace());
            if matches!(next, Some(b'}') | Some(b']')) {
                i += 1;
                continue;
            }
        }
        // Copy the whole UTF-8 sequence.
        let len = match c {
            0x00..=0x7f => 1,
            0xc0..=0xdf => 2,
            0xe0..=0xef => 3,
            _ => 4,
        }
        .min(b.len() - i);
        out.push_str(&src[i..i + len]);
        i += len;
    }
    out
}

/// `@babel/core@7.24.0` -> (`@babel/core`, `7.24.0`).
fn split_ident(id: &str) -> Option<(&str, &str)> {
    let at = id[1..].find('@')? + 1;
    Some((&id[..at], &id[at + 1..]))
}

/// `"@babel/core/semver"` -> [`@babel/core`, `semver`].
fn path_segments(key: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut parts = key.split('/');
    while let Some(p) = parts.next() {
        if p.starts_with('@') {
            out.push(format!("{p}/{}", parts.next().unwrap_or_default()));
        } else {
            out.push(p.to_string());
        }
    }
    out
}

pub fn parse(path: &Path) -> Result<Vec<Dependency>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: Value = serde_json::from_str(&strip_trailing_commas(&text))
        .with_context(|| format!("parsing {} as bun.lock", path.display()))?;
    let empty = serde_json::Map::new();
    let packages = lock
        .get("packages")
        .and_then(|p| p.as_object())
        .unwrap_or(&empty);

    // install path -> index in `out`; workspace packages are the project.
    let mut out: Vec<Dependency> = Vec::new();
    let mut at_path: HashMap<&str, usize> = HashMap::new();
    let mut by_ident: HashMap<(String, String), usize> = HashMap::new();
    for (key, entry) in packages {
        let Some(ident) = entry.get(0).and_then(|v| v.as_str()) else {
            continue;
        };
        let Some((name, version)) = split_ident(ident) else {
            continue;
        };
        if version.starts_with("workspace:") {
            continue;
        }
        let integrity = entry
            .as_array()
            .and_then(|a| a.iter().skip(2).find_map(|v| v.as_str()))
            .filter(|s| s.starts_with("sha"))
            .map(String::from);
        let id = (name.to_string(), version.to_string());
        let i = *by_ident.entry(id).or_insert_with(|| {
            out.push(Dependency {
                name: name.to_string(),
                version: version.to_string(),
                ecosystem: Ecosystem::Node,
                direct: false,
                scope: Scope::Prod,
                licenses: Vec::new(),
                license_source: LicenseSource::Unknown,
                // A registry tarball has no URL here; a git / tarball source
                // is its own version string.
                resolved_url: None,
                integrity,
                parents: Vec::new(),
            });
            out.len() - 1
        });
        at_path.insert(key.as_str(), i);
    }

    // Node resolution from an install path: `a/b` + `c` tries `a/b/c`, `a/c`, `c`.
    let resolve = |from: &[String], dep: &str| -> Option<usize> {
        (0..=from.len()).rev().find_map(|n| {
            let key = from[..n]
                .iter()
                .map(String::as_str)
                .chain([dep])
                .collect::<Vec<_>>()
                .join("/");
            at_path.get(key.as_str()).copied()
        })
    };

    for (key, entry) in packages {
        let Some(&pi) = at_path.get(key.as_str()) else {
            continue;
        };
        let parent = (out[pi].name.clone(), out[pi].version.clone());
        let segs = path_segments(key);
        let meta = entry
            .as_array()
            .and_then(|a| a.iter().find(|v| v.is_object()));
        for field in ["dependencies", "optionalDependencies"] {
            for dep in meta
                .and_then(|m| m.get(field))
                .and_then(|d| d.as_object())
                .into_iter()
                .flatten()
                .map(|(k, _)| k)
            {
                if let Some(ci) = resolve(&segs, dep)
                    && ci != pi
                    && !out[ci].parents.contains(&parent)
                {
                    out[ci].parents.push(parent.clone());
                }
            }
        }
    }

    // Direct set: every workspace's declared dependencies, resolved from that
    // workspace's own install path (its name), then the top level.
    for (_, ws) in lock
        .get("workspaces")
        .and_then(|w| w.as_object())
        .into_iter()
        .flatten()
    {
        let from: Vec<String> = ws
            .get("name")
            .and_then(|n| n.as_str())
            .map(|n| vec![n.to_string()])
            .unwrap_or_default();
        for (field, scope) in [
            ("dependencies", Scope::Prod),
            ("optionalDependencies", Scope::Optional),
            ("devDependencies", Scope::Dev),
        ] {
            for dep in ws
                .get(field)
                .and_then(|d| d.as_object())
                .into_iter()
                .flatten()
                .map(|(k, _)| k)
            {
                if let Some(i) = resolve(&from, dep) {
                    let d = &mut out[i];
                    // Declared prod by one workspace, dev by another: it ships.
                    d.scope = if d.direct { d.scope.max(scope) } else { scope };
                    d.direct = true;
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_paths_workspaces_and_scopes() {
        let dir = std::env::temp_dir().join(format!("postmortem-bun-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("bun.lock");
        std::fs::write(
            &p,
            r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "app",
      "dependencies": { "@babel/core": "^7.24.0", "lib": "workspace:*", },
      "devDependencies": { "typescript": "^5.8.3", },
    },
    "packages/lib": {
      "name": "lib",
      "dependencies": { "semver": "^7.6.0", },
    },
  },
  "packages": {
    "@babel/core": ["@babel/core@7.24.0", "", { "dependencies": { "semver": "^6.3.1", "debug": "^4.3.1" } }, "sha512-core=="],
    "@babel/core/semver": ["semver@6.3.1", "", {}, "sha512-six=="],
    "debug": ["debug@4.3.4", "", { "dependencies": { "ms": "2.1.2" } }, "sha512-debug=="],
    "ms": ["ms@2.1.2", "", {}, "sha512-ms=="],
    "semver": ["semver@7.6.0", "", {}, "sha512-seven=="],
    "lib": ["lib@workspace:packages/lib"],
    "typescript": ["typescript@5.8.3", "", { "bin": { "tsc": "bin/tsc" } }, "sha512-ts=="],
  },
}"#,
        )
        .unwrap();
        let deps = parse(&p).unwrap();
        let get = |n: &str, v: &str| deps.iter().find(|d| d.name == n && d.version == v).unwrap();
        assert_eq!(deps.len(), 6, "the workspace package is the project");
        assert_eq!(
            get("semver", "6.3.1").parents,
            vec![("@babel/core".to_string(), "7.24.0".to_string())],
            "the nested install wins over the hoisted one"
        );
        assert!(
            get("semver", "7.6.0").direct,
            "a workspace's own dependency"
        );
        assert!(get("semver", "7.6.0").parents.is_empty());
        assert_eq!(
            get("ms", "2.1.2").parents,
            vec![("debug".to_string(), "4.3.4".to_string())]
        );
        assert_eq!(get("typescript", "5.8.3").scope, Scope::Dev);
        assert!(get("@babel/core", "7.24.0").direct && !get("debug", "4.3.4").direct);
        assert_eq!(get("ms", "2.1.2").integrity.as_deref(), Some("sha512-ms=="));
    }
}
