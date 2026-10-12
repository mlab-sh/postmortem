//! Conda: `environment.yml`, and conda-lock's `conda-lock.yml`.
//!
//! * `conda-lock.yml` — every package, once per platform, with its version,
//!   `manager` (`conda` or `pip`), `dependencies` by name, `url`, `hash` and
//!   `category`. The full graph: edges resolve within the same platform and
//!   manager; the same `name@version` on several platforms is one package.
//!   Virtual packages (`__glibc`, `__osx`) are the machine, not dependencies.
//! * `environment.yml` — what is declared: the direct set. Alone, it is the
//!   whole (flat) picture: `numpy==1.26.4` / `numpy=1.26.4=py311h...` pin a
//!   version, any other spec is `managed`.
//!
//! Conda packages are reported as `conda`; a `pip:` entry (or a `pip`-managed
//! lock entry) is a PyPI package, reported as `python`.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use crate::model::{Dependency, Ecosystem, LicenseSource, Scope};

#[derive(Deserialize)]
struct CondaLock {
    #[serde(default)]
    package: Vec<LockedPackage>,
}

#[derive(Deserialize)]
struct LockedPackage {
    name: String,
    version: String,
    #[serde(default)]
    manager: String,
    #[serde(default)]
    platform: String,
    #[serde(default)]
    dependencies: BTreeMap<String, serde_yaml::Value>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    hash: BTreeMap<String, String>,
    #[serde(default)]
    category: Option<String>,
}

fn eco(manager: &str) -> Ecosystem {
    if manager == "pip" {
        Ecosystem::Python
    } else {
        Ecosystem::Conda
    }
}

/// One `environment.yml` entry: (ecosystem, name, exact version?).
fn spec(entry: &str, pip: bool) -> Option<(Ecosystem, String, Option<String>)> {
    let entry = entry.split('#').next()?.trim();
    if entry.is_empty() || entry.starts_with('-') || entry.contains("://") {
        return None; // `-r requirements.txt`, `-e .`, a URL / VCS requirement
    }
    if pip {
        let name_end = entry
            .find(|c: char| "=<>!~;[ ".contains(c))
            .unwrap_or(entry.len());
        let version = entry[name_end..].trim_start().strip_prefix("==").map(|v| {
            v.split([';', ',', ' '])
                .next()
                .unwrap_or(v)
                .trim()
                .to_string()
        });
        return Some((Ecosystem::Python, entry[..name_end].to_lowercase(), version));
    }
    // `conda-forge::numpy==1.26.4`, `numpy=1.26.4=py311h...`, `python>=3.11`.
    let entry = entry.rsplit("::").next()?;
    let name_end = entry
        .find(|c: char| "=<>!~ ".contains(c))
        .unwrap_or(entry.len());
    let rest = entry[name_end..].trim();
    let version = if let Some(v) = rest.strip_prefix("==") {
        Some(v.trim().to_string())
    } else if let Some(v) = rest.strip_prefix('=') {
        // `=1.26.4=build` is exact; `=1.26` alone means `1.26.*`.
        let mut parts = v.split('=');
        let ver = parts.next().unwrap_or("").trim();
        (parts.next().is_some() && !ver.contains('*')).then(|| ver.to_string())
    } else {
        None
    };
    Some((Ecosystem::Conda, entry[..name_end].to_string(), version))
}

/// The declared packages of an `environment.yml`.
fn declared(path: &Path) -> Result<Vec<(Ecosystem, String, Option<String>)>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let v: serde_yaml::Value = serde_yaml::from_str(&text)
        .with_context(|| format!("parsing {} as environment.yml", path.display()))?;
    let mut out = Vec::new();
    for d in v
        .get("dependencies")
        .and_then(|d| d.as_sequence())
        .into_iter()
        .flatten()
    {
        match d {
            serde_yaml::Value::String(s) => out.extend(spec(s, false)),
            serde_yaml::Value::Mapping(m) => {
                for pip in m
                    .get("pip")
                    .and_then(|p| p.as_sequence())
                    .into_iter()
                    .flatten()
                {
                    out.extend(pip.as_str().and_then(|s| spec(s, true)));
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

fn dependency(eco: Ecosystem, name: &str, version: &str, direct: bool, scope: Scope) -> Dependency {
    Dependency {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem: eco,
        direct,
        scope,
        licenses: Vec::new(),
        license_source: LicenseSource::Unknown,
        resolved_url: None,
        integrity: None,
        parents: Vec::new(),
    }
}

pub fn parse(manifest: Option<&Path>, lockfile: Option<&Path>) -> Result<Vec<Dependency>> {
    let declared = match manifest {
        Some(m) => declared(m)?,
        None => Vec::new(),
    };
    let Some(lock) = lockfile else {
        return Ok(declared
            .into_iter()
            .map(|(e, n, v)| {
                dependency(e, &n, v.as_deref().unwrap_or("managed"), true, Scope::Prod)
            })
            .collect());
    };

    let text =
        std::fs::read_to_string(lock).with_context(|| format!("reading {}", lock.display()))?;
    let lock: CondaLock = serde_yaml::from_str(&text)
        .with_context(|| format!("parsing {} as conda-lock.yml", lock.display()))?;
    let direct: HashSet<(Ecosystem, String)> = declared
        .iter()
        .map(|(e, n, _)| {
            (
                *e,
                if *e == Ecosystem::Python {
                    n.to_lowercase()
                } else {
                    n.clone()
                },
            )
        })
        .collect();

    let mut out: Vec<Dependency> = Vec::new();
    let mut index: HashMap<(Ecosystem, String, String), usize> = HashMap::new();
    // (platform, ecosystem, name) -> node, for edge resolution.
    let mut on_platform: HashMap<(&str, Ecosystem, &str), usize> = HashMap::new();
    for p in &lock.package {
        let e = eco(&p.manager);
        let id = (e, p.name.clone(), p.version.clone());
        let i = *index.entry(id).or_insert_with(|| {
            let key = if e == Ecosystem::Python {
                p.name.to_lowercase()
            } else {
                p.name.clone()
            };
            let scope = match p.category.as_deref() {
                None | Some("main") => Scope::Prod,
                _ => Scope::Dev,
            };
            let mut d = dependency(e, &p.name, &p.version, direct.contains(&(e, key)), scope);
            d.resolved_url = p.url.clone();
            d.integrity = p.hash.get("sha256").map(|h| format!("sha256-{h}"));
            out.push(d);
            out.len() - 1
        });
        on_platform.insert((p.platform.as_str(), e, p.name.as_str()), i);
    }
    for p in &lock.package {
        let e = eco(&p.manager);
        let pi = on_platform[&(p.platform.as_str(), e, p.name.as_str())];
        let parent = (out[pi].name.clone(), out[pi].version.clone());
        for child in p.dependencies.keys().filter(|c| !c.starts_with("__")) {
            // A pip package may depend on a conda one (and the reverse is
            // never recorded): same manager first, then conda.
            let ci = on_platform
                .get(&(p.platform.as_str(), e, child.as_str()))
                .or_else(|| {
                    on_platform.get(&(p.platform.as_str(), Ecosystem::Conda, child.as_str()))
                });
            if let Some(&ci) = ci
                && ci != pi
                && !out[ci].parents.contains(&parent)
            {
                out[ci].parents.push(parent.clone());
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "postmortem-conda-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const ENV: &str = "name: app\nchannels:\n - conda-forge\ndependencies:\n - python=3.11\n - numpy==1.26.4\n - conda-forge::xarray=2024.1.0=pyhd8ed1ab_0\n - gcsfs>=2025  # comment\n - pip\n - pip:\n   - requests==2.31.0\n   - -r requirements.txt\n   - Flask>=3\n";

    #[test]
    fn environment_alone_is_declared_and_flat() {
        let dir = tmp_dir();
        let env = dir.join("environment.yml");
        std::fs::write(&env, ENV).unwrap();
        let deps = parse(Some(&env), None).unwrap();
        let got: Vec<(Ecosystem, &str, &str)> = deps
            .iter()
            .map(|d| (d.ecosystem, d.name.as_str(), d.version.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                (Ecosystem::Conda, "python", "managed"),
                (Ecosystem::Conda, "numpy", "1.26.4"),
                (Ecosystem::Conda, "xarray", "2024.1.0"),
                (Ecosystem::Conda, "gcsfs", "managed"),
                (Ecosystem::Conda, "pip", "managed"),
                (Ecosystem::Python, "requests", "2.31.0"),
                (Ecosystem::Python, "flask", "managed"),
            ]
        );
    }

    #[test]
    fn lock_merges_platforms_and_resolves_edges() {
        let dir = tmp_dir();
        let (env, lock) = (dir.join("environment.yml"), dir.join("conda-lock.yml"));
        std::fs::write(&env, ENV).unwrap();
        std::fs::write(
            &lock,
            "version: 1\nmetadata:\n  platforms: [linux-64, osx-arm64]\npackage:\n\
- name: numpy\n  version: 1.26.4\n  manager: conda\n  platform: linux-64\n  dependencies:\n    __glibc: '>=2.17'\n    libblas: '>=3.9'\n    python: '>=3.11'\n  url: https://conda.anaconda.org/conda-forge/linux-64/numpy-1.26.4.conda\n  hash:\n    md5: aa\n    sha256: bb\n  category: main\n  optional: false\n\
- name: numpy\n  version: 1.26.4\n  manager: conda\n  platform: osx-arm64\n  dependencies:\n    libblas: '>=3.9'\n  url: https://conda.anaconda.org/conda-forge/osx-arm64/numpy-1.26.4.conda\n  hash:\n    sha256: cc\n  category: main\n  optional: false\n\
- name: libblas\n  version: 3.9.0\n  manager: conda\n  platform: linux-64\n  dependencies: {}\n  category: main\n  optional: false\n\
- name: libblas\n  version: 3.9.0\n  manager: conda\n  platform: osx-arm64\n  dependencies: {}\n  category: main\n  optional: false\n\
- name: python\n  version: 3.11.8\n  manager: conda\n  platform: linux-64\n  dependencies: {}\n  category: main\n  optional: false\n\
- name: requests\n  version: 2.31.0\n  manager: pip\n  platform: linux-64\n  dependencies:\n    urllib3: '>=1.21.1'\n    python: '>=3.7'\n  category: main\n  optional: false\n\
- name: urllib3\n  version: 2.2.1\n  manager: pip\n  platform: linux-64\n  dependencies: {}\n  category: main\n  optional: false\n\
- name: pytest\n  version: 8.0.0\n  manager: conda\n  platform: linux-64\n  dependencies: {}\n  category: dev\n  optional: true\n",
        )
        .unwrap();
        let deps = parse(Some(&env), Some(&lock)).unwrap();
        let get = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(deps.len(), 6, "one numpy across platforms");
        assert_eq!(
            get("libblas").parents,
            vec![("numpy".to_string(), "1.26.4".to_string())]
        );
        assert_eq!(
            get("python").parents,
            vec![
                ("numpy".to_string(), "1.26.4".to_string()),
                ("requests".to_string(), "2.31.0".to_string())
            ],
            "a pip package's conda dependency"
        );
        assert_eq!(get("requests").ecosystem, Ecosystem::Python);
        assert!(get("requests").direct && get("numpy").direct && !get("libblas").direct);
        assert_eq!(
            get("urllib3").parents,
            vec![("requests".to_string(), "2.31.0".to_string())]
        );
        assert_eq!(get("pytest").scope, Scope::Dev);
        assert_eq!(get("numpy").integrity.as_deref(), Some("sha256-bb"));
    }
}
