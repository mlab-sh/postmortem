//! Python lockfile parsers: poetry.lock / uv.lock (TOML), Pipfile.lock (JSON), requirements*.txt.
//!
//! Python has no single source of truth for transitive resolution — we extract what each
//! format reveals. poetry.lock is the richest (full graph + hashes), Pipfile.lock is decent,
//! requirements.txt only gives a flat pin list.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use crate::model::{Dependency, Ecosystem, LicenseSource, Scope};

pub fn parse_any(manifest: &Path, lockfile: Option<&Path>) -> Result<Vec<Dependency>> {
    if let Some(lf) = lockfile {
        let name = lf.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if name == "poetry.lock" {
            return parse_poetry(lf);
        }
        if name == "uv.lock" {
            return parse_uv(lf);
        }
        if name == "Pipfile.lock" {
            return parse_pipfile_lock(lf);
        }
        // Any `.txt` that got this far is a requirements file: detection only
        // takes `requirements.txt` itself, or a `.txt` the user named.
        if name.ends_with(".txt") {
            return parse_requirements(lf);
        }
    }
    // Fall back to manifest as a flat requirements file.
    let mname = manifest.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if mname.ends_with(".txt") {
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
    /// Poetry < 1.5 wrote a single `category = "main" | "dev"`.
    #[serde(default)]
    category: Option<String>,
    /// Poetry >= 1.5 replaced `category` with the dependency groups a package
    /// belongs to, e.g. `groups = ["main", "dev"]`.
    #[serde(default)]
    groups: Option<Vec<String>>,
    #[serde(default)]
    dependencies: BTreeMap<String, toml::Value>,
}

impl PoetryPkg {
    /// The scope poetry recorded, across both lockfile generations. `main` is the
    /// production group; a package in *any* non-dev group stays production.
    /// Absent metadata means production — never hide what we could not classify.
    fn scope(&self) -> Scope {
        if let Some(groups) = &self.groups {
            if groups.is_empty() {
                return Scope::Prod;
            }
            return if groups.iter().all(|g| is_dev_group(g)) {
                Scope::Dev
            } else {
                Scope::Prod
            };
        }
        match self.category.as_deref() {
            Some(c) if is_dev_group(c) => Scope::Dev,
            _ => Scope::Prod,
        }
    }
}

/// Group names that mean "not shipped". `main` (poetry's production group) and
/// anything unrecognised are treated as production.
fn is_dev_group(group: &str) -> bool {
    matches!(
        group.to_ascii_lowercase().as_str(),
        "dev" | "development" | "test" | "tests" | "lint" | "docs"
    )
}

fn parse_poetry(path: &Path) -> Result<Vec<Dependency>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: PoetryLock = toml::from_str(&text)
        .with_context(|| format!("parsing {} as poetry.lock", path.display()))?;

    // Reverse index: normalised dependency name → indices of the packages that
    // declare it, ascending and deduplicated. Every package used to scan every
    // other package's dependency keys with two `norm` allocations per compare —
    // O(P²·d), ~40 M allocations for a 1 000-package lock.
    let names: Vec<String> = lock.package.iter().map(|p| norm(&p.name)).collect();
    let mut dependents: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, p) in lock.package.iter().enumerate() {
        for k in p.dependencies.keys() {
            let v = dependents.entry(norm(k)).or_default();
            if v.last() != Some(&i) {
                v.push(i);
            }
        }
    }
    // `referenced` only ever looked at the *last* package of each normalised
    // name (a name-keyed map kept the last one); `is_last` keeps that exactly.
    let mut last_of: HashMap<&str, usize> = HashMap::new();
    for (i, n) in names.iter().enumerate() {
        last_of.insert(n, i);
    }
    let is_last: Vec<bool> = names
        .iter()
        .enumerate()
        .map(|(i, n)| last_of[n.as_str()] == i)
        .collect();

    let mut out = Vec::with_capacity(lock.package.len());
    for (pkg, n) in lock.package.iter().zip(&names) {
        let declarers = dependents.get(n).map(Vec::as_slice).unwrap_or_default();
        let parents = declarers
            .iter()
            .map(|&i| &lock.package[i])
            .filter(|other| other.name != pkg.name)
            .map(|other| (other.name.clone(), other.version.clone()))
            .collect();
        // direct = nobody depends on it AND it's listed under main category (best-effort)
        let referenced = declarers.iter().any(|&i| is_last[i]);
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
            scope: pkg.scope(),
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url: None,
            integrity: None,
            parents,
        });
    }
    Ok(out)
}

#[derive(Debug, Deserialize)]
struct UvLock {
    #[serde(default)]
    package: Vec<UvPkg>,
}

#[derive(Debug, Deserialize)]
struct UvPkg {
    name: String,
    /// Absent on a virtual workspace root.
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    source: BTreeMap<String, toml::Value>,
    #[serde(default)]
    dependencies: Vec<UvDep>,
    #[serde(default, rename = "optional-dependencies")]
    optional_dependencies: BTreeMap<String, Vec<UvDep>>,
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: BTreeMap<String, Vec<UvDep>>,
}

#[derive(Debug, Deserialize)]
struct UvDep {
    name: String,
    /// Only written when several versions of `name` are locked.
    #[serde(default)]
    version: Option<String>,
}

impl UvPkg {
    /// A workspace member or local path: the project itself, not a dependency.
    fn is_local(&self) -> bool {
        ["editable", "virtual", "directory", "path"]
            .iter()
            .any(|k| self.source.contains_key(*k))
    }
}

/// `uv.lock`: every package with its edges. Workspace members (editable /
/// virtual sources) are the project — their dependencies are the direct set,
/// `dev-dependencies` seeding `Dev`, the rest left to `scope::propagate`.
fn parse_uv(path: &Path) -> Result<Vec<Dependency>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: UvLock =
        toml::from_str(&text).with_context(|| format!("parsing {} as uv.lock", path.display()))?;

    let locked = |p: &UvPkg| (!p.is_local()).then(|| p.version.clone()).flatten();
    // name → locked versions, to resolve an edge that names no version.
    let mut versions: HashMap<String, Vec<String>> = HashMap::new();
    for p in &lock.package {
        if let Some(v) = locked(p) {
            versions.entry(norm(&p.name)).or_default().push(v);
        }
    }
    let resolve = |d: &UvDep| -> Vec<(String, String)> {
        let vs = versions.get(&norm(&d.name)).map(Vec::as_slice).unwrap_or_default();
        vs.iter()
            .filter(|v| d.version.as_ref().is_none_or(|w| w == *v))
            .map(|v| (norm(&d.name), v.clone()))
            .collect()
    };

    let mut acc: BTreeMap<(String, String), Dependency> = BTreeMap::new();
    for p in &lock.package {
        if let Some(v) = locked(p) {
            acc.insert((norm(&p.name), v.clone()), Dependency {
                name: p.name.clone(),
                version: v,
                ecosystem: Ecosystem::Python,
                direct: false,
                scope: Scope::Prod,
                licenses: Vec::new(),
                license_source: LicenseSource::Unknown,
                resolved_url: None,
                integrity: None,
                parents: Vec::new(),
            });
        }
    }
    let mut seeds: HashMap<(String, String), Scope> = HashMap::new();
    for p in &lock.package {
        let prod = p.dependencies.iter().chain(p.optional_dependencies.values().flatten());
        let dev = p.dev_dependencies.values().flatten();
        let edges = prod.map(|d| (d, Scope::Prod)).chain(dev.map(|d| (d, Scope::Dev)));
        match locked(p) {
            None => {
                for (d, scope) in edges {
                    for k in resolve(d) {
                        let e = seeds.entry(k).or_insert(scope);
                        *e = (*e).max(scope);
                    }
                }
            }
            Some(v) => {
                let parent = (p.name.clone(), v);
                for (d, _) in edges {
                    for k in resolve(d) {
                        if let Some(dep) = acc.get_mut(&k)
                            && !dep.parents.contains(&parent)
                        {
                            dep.parents.push(parent.clone());
                        }
                    }
                }
            }
        }
    }
    for (k, scope) in seeds {
        if let Some(d) = acc.get_mut(&k) {
            d.direct = true;
            d.scope = scope;
        }
    }
    Ok(acc.into_values().collect())
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
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: PipfileLock = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {} as Pipfile.lock", path.display()))?;
    // `default` / `develop` are pipenv's own fully-resolved split, so the scope
    // is authoritative here (unlike direct/transitive, which the format loses).
    let mut out = Vec::new();
    let sections = [(&lock.default, Scope::Prod), (&lock.develop, Scope::Dev)];
    for (section, scope) in sections {
        for (name, entry) in section.iter() {
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
                scope,
                licenses: Vec::new(),
                license_source: LicenseSource::Unknown,
                resolved_url: None,
                integrity: None,
                parents: Vec::new(),
            });
        }
    }
    Ok(out)
}

fn parse_requirements(path: &Path) -> Result<Vec<Dependency>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    // A bare requirements file carries no scope metadata at all; the filename is
    // the only signal Python's conventions give us.
    let scope = requirements_scope(path);
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        let (name, version) = if let Some((n, v)) = line.split_once("==") {
            (
                n.trim().to_string(),
                v.split([';', ' ']).next().unwrap_or(v).trim().to_string(),
            )
        } else if let Some((n, v)) = line.split_once(">=") {
            (n.trim().to_string(), format!(">={}", v.trim()))
        } else {
            (
                line.split([';', '['])
                    .next()
                    .unwrap_or(line)
                    .trim()
                    .to_string(),
                "unspecified".to_string(),
            )
        };
        if name.is_empty() || !seen.insert(norm(&name)) {
            continue;
        }
        out.push(Dependency {
            name,
            version,
            ecosystem: Ecosystem::Python,
            direct: true,
            scope,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
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

/// Classify a requirements file from its path, following the conventions the
/// Python ecosystem settled on: `requirements-dev.txt`, `dev-requirements.txt`,
/// `requirements/dev.txt`, and the `test` / `lint` / `docs` variants of each.
///
/// This is a naming convention, not metadata — so it only ever *demotes* a file
/// that clearly announces itself as non-shipping. A plain `requirements.txt`, or
/// anything unrecognised, stays production.
fn requirements_scope(path: &Path) -> Scope {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    // `requirements/dev.txt` — the marker is the file name, `requirements` the dir.
    let in_requirements_dir = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .is_some_and(|d| d.eq_ignore_ascii_case("requirements"));

    let markers = ["dev", "development", "test", "tests", "lint", "docs"];
    let is_dev = markers.iter().any(|m| {
        stem == *m && in_requirements_dir
            || stem == format!("requirements-{m}")
            || stem == format!("requirements_{m}")
            || stem == format!("{m}-requirements")
            || stem == format!("{m}_requirements")
    });
    if is_dev { Scope::Dev } else { Scope::Prod }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uv_lock_graph_and_workspace_directs() {
        let dir = std::env::temp_dir().join(format!("pm-uv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("uv.lock");
        std::fs::write(&p, r#"version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "requests" }]
[package.dev-dependencies]
dev = [{ name = "pytest" }]

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "urllib3" }]

[[package]]
name = "urllib3"
version = "2.2.3"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.3.3"
source = { registry = "https://pypi.org/simple" }
"#).unwrap();
        let deps = parse_any(&dir.join("pyproject.toml"), Some(&p)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let get = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(deps.len(), 3, "the workspace member is the project, not a dep");
        assert!(get("requests").direct && get("requests").scope == Scope::Prod);
        assert!(get("pytest").direct && get("pytest").scope == Scope::Dev);
        assert!(!get("urllib3").direct);
        assert_eq!(get("urllib3").parents, [("requests".into(), "2.32.3".into())]);
    }

    #[test]
    fn requirements_parses_simple() {
        let dir = std::env::temp_dir().join("postmortem-py-req-test");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("requirements.txt");
        std::fs::write(&p, "requests==2.31.0\nflask>=2.0\n# comment\nctx==0.2.6\n").unwrap();
        let deps = parse_requirements(&p).unwrap();
        assert_eq!(deps.len(), 3);
        assert!(deps.iter().any(|d| d.name == "ctx" && d.version == "0.2.6"));
        assert!(
            deps.iter().all(|d| d.scope == Scope::Prod),
            "plain requirements.txt ships"
        );
    }

    #[test]
    fn requirements_filename_conventions_classify() {
        let dev = |p: &str| requirements_scope(Path::new(p));
        assert_eq!(dev("requirements.txt"), Scope::Prod);
        assert_eq!(dev("requirements-dev.txt"), Scope::Dev);
        assert_eq!(dev("requirements_dev.txt"), Scope::Dev);
        assert_eq!(dev("dev-requirements.txt"), Scope::Dev);
        assert_eq!(dev("test-requirements.txt"), Scope::Dev);
        assert_eq!(dev("requirements-test.txt"), Scope::Dev);
        assert_eq!(dev("requirements/dev.txt"), Scope::Dev);
        assert_eq!(dev("requirements/base.txt"), Scope::Prod);
        // A `dev.txt` outside a `requirements/` directory is not the convention.
        assert_eq!(dev("config/dev.txt"), Scope::Prod);
        // Near-misses must not be swept up.
        assert_eq!(dev("requirements-prod.txt"), Scope::Prod);
        assert_eq!(dev("my-requirements.txt"), Scope::Prod);
    }

    #[test]
    fn poetry_category_classifies_legacy_lockfiles() {
        let pkg = |cat: Option<&str>| PoetryPkg {
            name: "x".into(),
            version: "1.0".into(),
            category: cat.map(String::from),
            groups: None,
            dependencies: BTreeMap::new(),
        };
        assert_eq!(pkg(Some("main")).scope(), Scope::Prod);
        assert_eq!(pkg(Some("dev")).scope(), Scope::Dev);
        assert_eq!(pkg(None).scope(), Scope::Prod, "no metadata means it ships");
    }

    #[test]
    fn poetry_groups_classify_modern_lockfiles() {
        let pkg = |groups: &[&str]| PoetryPkg {
            name: "x".into(),
            version: "1.0".into(),
            category: None,
            groups: Some(groups.iter().map(|s| s.to_string()).collect()),
            dependencies: BTreeMap::new(),
        };
        assert_eq!(pkg(&["main"]).scope(), Scope::Prod);
        assert_eq!(pkg(&["dev"]).scope(), Scope::Dev);
        assert_eq!(pkg(&["dev", "test"]).scope(), Scope::Dev);
        // Belonging to a production group anywhere means it ships.
        assert_eq!(pkg(&["main", "dev"]).scope(), Scope::Prod);
        assert_eq!(
            pkg(&["custom"]).scope(),
            Scope::Prod,
            "unknown groups are not dev"
        );
    }

    #[test]
    fn poetry_groups_win_over_a_stale_category() {
        // Poetry 1.5 kept writing `category` for a while; `groups` is newer.
        let pkg = PoetryPkg {
            name: "x".into(),
            version: "1.0".into(),
            category: Some("dev".into()),
            groups: Some(vec!["main".into()]),
            dependencies: BTreeMap::new(),
        };
        assert_eq!(pkg.scope(), Scope::Prod);
    }

    #[test]
    fn pipfile_lock_default_and_develop_split() {
        let dir = std::env::temp_dir().join("postmortem-py-pipfile-test");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("Pipfile.lock");
        std::fs::write(
            &p,
            r#"{"default": {"requests": {"version": "==2.31.0"}},
                "develop": {"pytest": {"version": "==7.4.0"}}}"#,
        )
        .unwrap();
        let deps = parse_pipfile_lock(&p).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(
            deps.iter().find(|d| d.name == "requests").unwrap().scope,
            Scope::Prod
        );
        assert_eq!(
            deps.iter().find(|d| d.name == "pytest").unwrap().scope,
            Scope::Dev
        );
    }
}
