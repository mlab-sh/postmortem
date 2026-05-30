//! Python lockfile parsers: poetry.lock (TOML), Pipfile.lock (JSON), requirements*.txt.
//!
//! Python has no single source of truth for transitive resolution — we extract what each
//! format reveals. poetry.lock is the richest (full graph + hashes), Pipfile.lock is decent,
//! requirements.txt only gives a flat pin list.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use crate::model::{Dependency, Ecosystem};

pub fn parse_any(manifest: &Path, lockfile: Option<&Path>) -> Result<Vec<Dependency>> {
    if let Some(lf) = lockfile {
        let name = lf.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if name == "poetry.lock" {
            return parse_poetry(lf);
        }
        if name == "Pipfile.lock" {
            return parse_pipfile_lock(lf);
        }
        if name.starts_with("requirements") && name.ends_with(".txt") {
            return parse_requirements(lf);
        }
    }
    // Fall back to manifest as a flat requirements file.
    let mname = manifest.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if mname.starts_with("requirements") && mname.ends_with(".txt") {
        return parse_requirements(manifest);
    }
    Ok(Vec::new())
}

#[derive(Debug, Deserialize)]
struct PoetryLock {
    #[serde(default)]
    package: Vec<PoetryPkg>,
}

#[derive(Debug, Deserialize)]
struct PoetryPkg {
    name: String,
    version: String,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, toml::Value>,
}

fn parse_poetry(path: &Path) -> Result<Vec<Dependency>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let lock: PoetryLock = toml::from_str(&text)
        .with_context(|| format!("parsing {} as poetry.lock", path.display()))?;

    let by_name: BTreeMap<String, &PoetryPkg> =
        lock.package.iter().map(|p| (norm(&p.name), p)).collect();

    let mut out = Vec::with_capacity(lock.package.len());
    for pkg in &lock.package {
        let mut parents = Vec::new();
        for other in &lock.package {
            if other.name == pkg.name {
                continue;
            }
            if other.dependencies.keys().any(|k| norm(k) == norm(&pkg.name)) {
                parents.push((other.name.clone(), other.version.clone()));
            }
        }
        // direct = nobody depends on it AND it's listed under main category (best-effort)
        let referenced = by_name
            .values()
            .any(|p| p.dependencies.keys().any(|k| norm(k) == norm(&pkg.name)));
        let direct = !referenced
            && pkg
                .category
                .as_deref()
                .map(|c| c == "main" || c == "dev")
                .unwrap_or(true);
        out.push(Dependency {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            ecosystem: Ecosystem::Python,
            direct,
            resolved_url: None,
            integrity: None,
            parents,
        });
    }
    Ok(out)
}

#[derive(Debug, Deserialize)]
struct PipfileLock {
    #[serde(default)]
    default: BTreeMap<String, PipfileEntry>,
    #[serde(default)]
    develop: BTreeMap<String, PipfileEntry>,
}

#[derive(Debug, Deserialize)]
struct PipfileEntry {
    #[serde(default)]
    version: Option<String>,
}

fn parse_pipfile_lock(path: &Path) -> Result<Vec<Dependency>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let lock: PipfileLock = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {} as Pipfile.lock", path.display()))?;
    let mut out = Vec::new();
    for (name, entry) in lock.default.iter().chain(lock.develop.iter()) {
        let version = entry
            .version
            .as_deref()
            .map(|v| v.trim_start_matches("==").to_string())
            .unwrap_or_else(|| "unknown".into());
        out.push(Dependency {
            name: name.clone(),
            version,
            ecosystem: Ecosystem::Python,
            direct: true, // Pipfile.lock doesn't distinguish — best we can do.
            resolved_url: None,
            integrity: None,
            parents: Vec::new(),
        });
    }
    Ok(out)
}

fn parse_requirements(path: &Path) -> Result<Vec<Dependency>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        let (name, version) = if let Some((n, v)) = line.split_once("==") {
            (n.trim().to_string(), v.split([';', ' ']).next().unwrap_or(v).trim().to_string())
        } else if let Some((n, v)) = line.split_once(">=") {
            (n.trim().to_string(), format!(">={}", v.trim()))
        } else {
            (line.split([';', '[']).next().unwrap_or(line).trim().to_string(), "unspecified".to_string())
        };
        if name.is_empty() || !seen.insert(norm(&name)) {
            continue;
        }
        out.push(Dependency {
            name,
            version,
            ecosystem: Ecosystem::Python,
            direct: true,
            resolved_url: None,
            integrity: None,
            parents: Vec::new(),
        });
    }
    Ok(out)
}

fn norm(name: &str) -> String {
    name.to_ascii_lowercase().replace(['_', '.'], "-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirements_parses_simple() {
        let dir = std::env::temp_dir().join("postmortem-py-req-test");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("requirements.txt");
        std::fs::write(&p, "requests==2.31.0\nflask>=2.0\n# comment\nctx==0.2.6\n").unwrap();
        let deps = parse_requirements(&p).unwrap();
        assert_eq!(deps.len(), 3);
        assert!(deps.iter().any(|d| d.name == "ctx" && d.version == "0.2.6"));
    }
}
