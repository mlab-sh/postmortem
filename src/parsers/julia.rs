//! Julia: `Manifest.toml` (Pkg), with `Project.toml` for the direct set.
//!
//! The manifest lists every package with its `version`, `uuid` and the names
//! it `deps` on — the full graph. Format 2.0 nests them under `[[deps.Name]]`;
//! format 1 puts `[[Name]]` at the top level. A standard library has no
//! `version` (it ships with Julia): it is not reported, like an SDK.
//!
//! `Project.toml` `[deps]` is the direct set; `[extras]` named by
//! `[targets] test` are development.

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::model::{Dependency, Ecosystem, LicenseSource, Scope};

/// The manifest's entries: name -> (version?, dep names, repo-url?).
fn entries(v: &toml::Value) -> Vec<(String, Option<String>, Vec<String>, Option<String>)> {
    let table = match v.get("deps").and_then(|d| d.as_table()) {
        Some(t) if v.get("manifest_format").is_some() => t,
        // Format 1: every top-level array of tables is a package.
        _ => match v.as_table() {
            Some(t) => t,
            None => return Vec::new(),
        },
    };
    let mut out = Vec::new();
    for (name, list) in table {
        let Some(list) = list.as_array() else {
            continue;
        };
        for e in list {
            let deps = match e.get("deps") {
                Some(toml::Value::Array(a)) => a
                    .iter()
                    .filter_map(|d| d.as_str())
                    .map(String::from)
                    .collect(),
                Some(toml::Value::Table(t)) => t.keys().cloned().collect(),
                _ => Vec::new(),
            };
            out.push((
                name.clone(),
                e.get("version").and_then(|x| x.as_str()).map(String::from),
                deps,
                e.get("repo-url").and_then(|x| x.as_str()).map(String::from),
            ));
        }
    }
    out
}

pub fn parse(lockfile: &Path, project: Option<&Path>) -> Result<Vec<Dependency>> {
    let text = std::fs::read_to_string(lockfile)
        .with_context(|| format!("reading {}", lockfile.display()))?;
    let manifest: toml::Value = toml::from_str(&text)
        .with_context(|| format!("parsing {} as Manifest.toml", lockfile.display()))?;

    let (mut direct, mut test): (HashSet<String>, HashSet<String>) = Default::default();
    if let Some(p) = project.and_then(|p| std::fs::read_to_string(p).ok()) {
        let p: toml::Value = toml::from_str(&p).unwrap_or(toml::Value::Table(Default::default()));
        let keys = |k: &str| -> Vec<String> {
            p.get(k)
                .and_then(|t| t.as_table())
                .map(|t| t.keys().cloned().collect())
                .unwrap_or_default()
        };
        direct.extend(keys("deps"));
        if let Some(t) = p
            .get("targets")
            .and_then(|t| t.get("test"))
            .and_then(|t| t.as_array())
        {
            test.extend(t.iter().filter_map(|x| x.as_str()).map(String::from));
        }
    }

    let entries = entries(&manifest);
    let version_of: HashMap<&str, &str> = entries
        .iter()
        .filter_map(|(n, v, _, _)| Some((n.as_str(), v.as_deref()?)))
        .collect();
    let mut out: Vec<Dependency> = entries
        .iter()
        .filter_map(|(name, version, _, repo)| {
            let version = version.as_deref()?;
            Some(Dependency {
                name: name.clone(),
                version: version.to_string(),
                ecosystem: Ecosystem::Julia,
                direct: direct.contains(name) || test.contains(name),
                scope: if test.contains(name) && !direct.contains(name) {
                    Scope::Dev
                } else {
                    Scope::Prod
                },
                licenses: Vec::new(),
                license_source: LicenseSource::Unknown,
                resolved_url: repo.clone(),
                integrity: None,
                parents: Vec::new(),
            })
        })
        .collect();
    let index: HashMap<String, usize> = out
        .iter()
        .enumerate()
        .map(|(i, d)| (d.name.clone(), i))
        .collect();
    for (name, _, deps, _) in &entries {
        // A stdlib parent is not a node: its children stand on their own.
        let Some(pv) = version_of.get(name.as_str()) else {
            continue;
        };
        for child in deps {
            if let Some(&ci) = index.get(child) {
                out[ci].parents.push((name.clone(), pv.to_string()));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_v2_and_v1_with_project() {
        let dir = std::env::temp_dir().join(format!("postmortem-jl-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (m, p) = (dir.join("Manifest.toml"), dir.join("Project.toml"));
        std::fs::write(
            &m,
            r#"julia_version = "1.10.10"
manifest_format = "2.0"

[[deps.JSON]]
deps = ["Dates", "Mmap", "Parsers", "Unicode"]
uuid = "682c06a0-de6a-54ab-a142-c8b1cf79cde6"
version = "0.21.4"

[[deps.Parsers]]
deps = ["Dates", "PrecompileTools"]
uuid = "69de0a69-1ddd-5017-9359-2bf0b02dc9f0"
version = "2.8.1"

[[deps.PrecompileTools]]
deps = ["Preferences"]
uuid = "aea7be01-6a6a-4083-8856-8a6e6704d82a"
version = "1.2.1"

[[deps.Dates]]
deps = ["Printf"]
uuid = "ade2ca70-3891-5945-98fb-dc099432e06a"

[[deps.Mine]]
repo-rev = "main"
repo-url = "https://github.com/acme/Mine.jl.git"
uuid = "11111111-1111-1111-1111-111111111111"
version = "0.1.0"

[[deps.Aqua]]
uuid = "4c88cf16-eb10-579e-8560-4a9242c79595"
version = "0.8.9"
"#,
        )
        .unwrap();
        std::fs::write(
            &p,
            "name = \"App\"\n[deps]\nJSON = \"682c06a0-de6a-54ab-a142-c8b1cf79cde6\"\nMine = \"11111111-1111-1111-1111-111111111111\"\n[extras]\nAqua = \"4c88cf16-eb10-579e-8560-4a9242c79595\"\n[targets]\ntest = [\"Aqua\"]\n",
        )
        .unwrap();
        let deps = parse(&m, Some(&p)).unwrap();
        let get = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(deps.len(), 5, "the Dates stdlib is not a dependency");
        assert!(get("JSON").direct && !get("Parsers").direct);
        assert_eq!(get("Aqua").scope, Scope::Dev);
        assert_eq!(
            get("Parsers").parents,
            vec![("JSON".to_string(), "0.21.4".to_string())]
        );
        assert_eq!(
            get("Mine").resolved_url.as_deref(),
            Some("https://github.com/acme/Mine.jl.git")
        );

        // Format 1.
        std::fs::write(
            &m,
            "[[JSON]]\ndeps = [\"Parsers\"]\nuuid = \"682c\"\nversion = \"0.21.0\"\n\n[[Parsers]]\nuuid = \"69de\"\nversion = \"2.0.0\"\n",
        )
        .unwrap();
        let deps = parse(&m, None).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(
            deps.iter().find(|d| d.name == "Parsers").unwrap().parents,
            vec![("JSON".to_string(), "0.21.0".to_string())]
        );
    }
}
