//! R: renv `renv.lock`.
//!
//! JSON: `Packages` maps each package to its `Version`, `Source` (`Repository`
//! / `CRAN` / `Bioconductor` / `GitHub` / ...) and, in renv >= 1.0 lockfiles,
//! its `Requirements` — the edges. Older lockfiles carry none: the graph is
//! then flat. The direct set comes from the project's `DESCRIPTION`
//! (`Depends` / `Imports` / `LinkingTo`; `Suggests` is development).

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use crate::model::{Dependency, Ecosystem, LicenseSource, Scope};

#[derive(Deserialize)]
struct Lock {
    #[serde(default, rename = "Packages")]
    packages: BTreeMap<String, Package>,
}

#[derive(Deserialize)]
struct Package {
    #[serde(rename = "Version")]
    version: String,
    #[serde(default, rename = "Source")]
    source: String,
    #[serde(default, rename = "Requirements")]
    requirements: Vec<String>,
    #[serde(default, rename = "RemoteHost")]
    remote_host: Option<String>,
    #[serde(default, rename = "RemoteUsername")]
    remote_username: Option<String>,
    #[serde(default, rename = "RemoteRepo")]
    remote_repo: Option<String>,
    #[serde(default, rename = "RemoteUrl")]
    remote_url: Option<String>,
}

/// `DESCRIPTION` dependency fields: package -> Suggests only.
fn description_deps(path: &Path) -> HashMap<String, bool> {
    let Ok(src) = std::fs::read_to_string(path) else {
        return HashMap::new();
    };
    // DCF: `Field: value`, continued on indented lines.
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in src.lines() {
        if line.starts_with([' ', '\t']) {
            if let Some((_, v)) = fields.last_mut() {
                v.push(' ');
                v.push_str(line.trim());
            }
        } else if let Some((k, v)) = line.split_once(':') {
            fields.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let mut out: HashMap<String, bool> = HashMap::new();
    for (k, v) in &fields {
        let dev = match k.as_str() {
            "Depends" | "Imports" | "LinkingTo" => false,
            "Suggests" => true,
            _ => continue,
        };
        for item in v.split(',') {
            // `dplyr (>= 1.0)` -> `dplyr`; `R (>= 4.1)` is the interpreter.
            let name = item.split(['(', ' ']).find(|s| !s.is_empty()).unwrap_or("");
            if name.is_empty() || name == "R" {
                continue;
            }
            let e = out.entry(name.to_string()).or_insert(dev);
            *e &= dev;
        }
    }
    out
}

pub fn parse(lockfile: &Path, description: Option<&Path>) -> Result<Vec<Dependency>> {
    let bytes =
        std::fs::read(lockfile).with_context(|| format!("reading {}", lockfile.display()))?;
    let lock: Lock = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {} as renv.lock", lockfile.display()))?;
    let declared = description.map(description_deps).unwrap_or_default();

    let mut out: Vec<Dependency> = lock
        .packages
        .iter()
        .map(|(name, p)| {
            let decl = declared.get(name);
            // Where a non-CRAN package came from. Bioconductor is still a
            // registry (and an OSV ecosystem), recognised by this URL.
            let resolved_url = match p.source.as_str() {
                "GitHub" | "GitLab" | "Bitbucket" => {
                    let host = p.remote_host.as_deref().map_or(
                        match p.source.as_str() {
                            "GitLab" => "gitlab.com",
                            "Bitbucket" => "bitbucket.org",
                            _ => "github.com",
                        },
                        |h| h.trim_start_matches("api.").trim_end_matches("/api/v3"),
                    );
                    match (&p.remote_username, &p.remote_repo) {
                        (Some(u), Some(r)) => Some(format!("https://{host}/{u}/{r}")),
                        _ => p.remote_url.clone(),
                    }
                }
                "Git" | "URL" => p.remote_url.clone(),
                "Bioconductor" => Some(format!("https://bioconductor.org/packages/{name}")),
                _ => None,
            };
            Dependency {
                name: name.clone(),
                version: p.version.clone(),
                ecosystem: Ecosystem::R,
                direct: decl.is_some(),
                scope: if decl == Some(&true) {
                    Scope::Dev
                } else {
                    Scope::Prod
                },
                licenses: Vec::new(),
                license_source: LicenseSource::Unknown,
                resolved_url,
                integrity: None,
                parents: Vec::new(),
            }
        })
        .collect();

    let version_of: HashMap<String, String> = out
        .iter()
        .map(|d| (d.name.clone(), d.version.clone()))
        .collect();
    let index: HashMap<String, usize> = out
        .iter()
        .enumerate()
        .map(|(i, d)| (d.name.clone(), i))
        .collect();
    for (name, p) in &lock.packages {
        for child in &p.requirements {
            if let (Some(&ci), Some(v)) = (index.get(child), version_of.get(name)) {
                out[ci].parents.push((name.clone(), v.clone()));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packages_requirements_sources_and_description() {
        let dir = std::env::temp_dir().join(format!("postmortem-r-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (lock, desc) = (dir.join("renv.lock"), dir.join("DESCRIPTION"));
        std::fs::write(
            &lock,
            r#"{"R":{"Version":"4.3.1","Repositories":[{"Name":"CRAN","URL":"https://cloud.r-project.org"}]},
"Packages":{
 "dplyr":{"Package":"dplyr","Version":"1.1.4","Source":"Repository","Repository":"CRAN","Requirements":["R","R6","cli"]},
 "R6":{"Package":"R6","Version":"2.5.1","Source":"Repository","Repository":"CRAN"},
 "cli":{"Package":"cli","Version":"3.6.2","Source":"CRAN"},
 "testthat":{"Package":"testthat","Version":"3.2.1","Source":"Repository","Repository":"RSPM","Requirements":["cli"]},
 "Biobase":{"Package":"Biobase","Version":"2.62.0","Source":"Bioconductor"},
 "flair":{"Package":"flair","Version":"0.0.2","Source":"GitHub","RemoteHost":"api.github.com","RemoteUsername":"r-for-educators","RemoteRepo":"flair"}
}}"#,
        )
        .unwrap();
        std::fs::write(
            &desc,
            "Package: app\nDepends: R (>= 4.1)\nImports:\n    dplyr (>= 1.1),\n    flair\nSuggests: testthat\n",
        )
        .unwrap();
        let deps = parse(&lock, Some(&desc)).unwrap();
        let get = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(deps.len(), 6);
        assert!(get("dplyr").direct && get("flair").direct && !get("cli").direct);
        assert_eq!(get("testthat").scope, Scope::Dev);
        assert_eq!(
            get("cli").parents,
            vec![
                ("dplyr".to_string(), "1.1.4".to_string()),
                ("testthat".to_string(), "3.2.1".to_string())
            ]
        );
        assert_eq!(
            get("flair").resolved_url.as_deref(),
            Some("https://github.com/r-for-educators/flair")
        );
        assert!(
            get("Biobase")
                .resolved_url
                .as_deref()
                .unwrap()
                .contains("bioconductor")
        );
        assert_eq!(get("R6").resolved_url, None);
    }
}
