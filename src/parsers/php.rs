//! composer.lock parser (Composer / PHP).
//!
//! composer.lock is JSON: production packages live under `packages`, dev
//! packages under `packages-dev`. Each package lists its own runtime
//! dependencies as a `require` map (name -> constraint), where names may be
//! real packages (`psr/log`) or platform pseudo-packages (`php`, `ext-json`).
//! The direct set comes from the root composer.json `require` / `require-dev`.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;

use crate::model::{Dependency, Ecosystem};

#[derive(Debug, Deserialize)]
struct ComposerLock {
    #[serde(default)]
    packages: Vec<ComposerPkg>,
    #[serde(default, rename = "packages-dev")]
    packages_dev: Vec<ComposerPkg>,
}

#[derive(Debug, Deserialize)]
struct ComposerPkg {
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    require: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    dist: Option<Artifact>,
    #[serde(default)]
    source: Option<Artifact>,
}

#[derive(Debug, Deserialize)]
struct Artifact {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    reference: Option<String>,
    #[serde(default)]
    shasum: Option<String>,
}

pub fn parse_lockfile(path: &Path, manifest: Option<&Path>) -> Result<Vec<Dependency>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: ComposerLock = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {} as composer.lock", path.display()))?;

    let direct: HashSet<String> = manifest
        .and_then(|m| read_manifest_direct(m).ok())
        .unwrap_or_default();

    let all: Vec<&ComposerPkg> = lock.packages.iter().chain(lock.packages_dev.iter()).collect();

    let mut out = Vec::with_capacity(all.len());
    for pkg in &all {
        let parents: Vec<_> = all
            .iter()
            .filter(|o| o.name != pkg.name && o.require.contains_key(&pkg.name))
            .map(|o| (o.name.clone(), o.version.clone().unwrap_or_default()))
            .collect();
        // If composer.json listed no direct deps (or is absent), fall back to
        // "nobody in the lock requires it" — the roots of the graph.
        let is_direct = if direct.is_empty() {
            parents.is_empty()
        } else {
            direct.contains(&pkg.name)
        };
        let resolved_url = pkg
            .dist
            .as_ref()
            .and_then(|d| d.url.clone())
            .or_else(|| pkg.source.as_ref().and_then(|s| s.url.clone()));
        let integrity = pkg.dist.as_ref().and_then(|d| {
            d.shasum
                .clone()
                .filter(|s| !s.is_empty())
                .or_else(|| d.reference.clone())
        });
        out.push(Dependency {
            name: pkg.name.clone(),
            version: pkg.version.clone().unwrap_or_else(|| "unknown".into()),
            ecosystem: Ecosystem::Php,
            direct: is_direct,
            resolved_url,
            integrity,
            parents,
        });
    }
    Ok(out)
}

/// Read `require` + `require-dev` package names from composer.json, dropping the
/// platform pseudo-packages (`php`, `ext-*`, `lib-*`, `composer-*`).
fn read_manifest_direct(path: &Path) -> Result<HashSet<String>> {
    let bytes = std::fs::read(path)?;
    let json: serde_json::Value = serde_json::from_slice(&bytes)?;
    let mut out = HashSet::new();
    for key in ["require", "require-dev"] {
        if let Some(map) = json.get(key).and_then(|v| v.as_object()) {
            for name in map.keys() {
                if is_platform_package(name) {
                    continue;
                }
                out.insert(name.clone());
            }
        }
    }
    Ok(out)
}

fn is_platform_package(name: &str) -> bool {
    name == "php"
        || name.starts_with("php-")
        || name.starts_with("ext-")
        || name.starts_with("lib-")
        || name.starts_with("composer-")
        || name.starts_with("composer/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const LOCK: &str = r#"{
      "packages": [
        {
          "name": "monolog/monolog",
          "version": "2.8.0",
          "require": { "php": ">=7.2", "psr/log": "^1.0 || ^2.0" },
          "dist": { "url": "https://api.github.com/x.zip", "reference": "abc123", "shasum": "" }
        },
        {
          "name": "psr/log",
          "version": "1.1.4",
          "require": { "php": ">=5.3.0" }
        }
      ],
      "packages-dev": [
        { "name": "phpunit/phpunit", "version": "9.5.0" }
      ]
    }"#;

    fn tmp(name: &str, body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("postmortem-php-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        p
    }

    #[test]
    fn parses_packages_and_parents() {
        let lock = tmp("composer.lock", LOCK);
        let deps = parse_lockfile(&lock, None).unwrap();
        assert_eq!(deps.len(), 3);
        let psr = deps.iter().find(|d| d.name == "psr/log").unwrap();
        assert_eq!(psr.version, "1.1.4");
        assert_eq!(psr.ecosystem, Ecosystem::Php);
        assert!(psr.parents.iter().any(|(n, _)| n == "monolog/monolog"));
        // No manifest → roots (nobody requires them) are direct.
        assert!(!psr.direct, "psr/log is required by monolog");
        assert!(deps.iter().find(|d| d.name == "monolog/monolog").unwrap().direct);
    }

    #[test]
    fn manifest_marks_direct() {
        let lock = tmp("composer.lock", LOCK);
        let manifest = tmp(
            "composer.json",
            r#"{ "require": { "php": ">=8.0", "monolog/monolog": "^2.8" }, "require-dev": { "phpunit/phpunit": "^9.5" } }"#,
        );
        let deps = parse_lockfile(&lock, Some(&manifest)).unwrap();
        assert!(deps.iter().find(|d| d.name == "monolog/monolog").unwrap().direct);
        assert!(deps.iter().find(|d| d.name == "phpunit/phpunit").unwrap().direct);
        assert!(!deps.iter().find(|d| d.name == "psr/log").unwrap().direct);
    }
}
