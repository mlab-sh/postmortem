//! .NET parsers: NuGet `packages.lock.json` and SDK-style project files
//! (`*.csproj` / `*.fsproj` / `*.vbproj`).
//!
//! * `packages.lock.json` (opt-in via `RestorePackagesWithLockFile`) is a real
//!   lockfile: one section per target framework, each package carrying its
//!   `type` (`Direct` / `Transitive` / `CentralTransitive` / `Project`), the
//!   `resolved` version, a `contentHash` and its own `dependencies` — so the
//!   full graph with parent edges comes back offline.
//! * Without it, the project file is a *manifest*: `<PackageReference>` lists
//!   the direct packages only. With central package management the version
//!   lives in the nearest `Directory.Packages.props` above the project.
//!
//! NuGet ids are case-insensitive, so every lookup folds case.

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::OnceLock;

use crate::model::{DepRef, Dependency, Ecosystem, LicenseSource, Scope};

pub fn parse(manifest: Option<&Path>, lockfile: Option<&Path>) -> Result<Vec<Dependency>> {
    if let Some(lock) = lockfile {
        return parse_lockfile(lock);
    }
    match manifest {
        Some(m) => parse_project(m),
        None => Ok(Vec::new()),
    }
}

// ---------- packages.lock.json ----------

#[derive(Deserialize)]
struct Lock {
    /// target framework (`net8.0`, `net8.0/win-x64`) -> package id -> entry.
    #[serde(default)]
    dependencies: BTreeMap<String, BTreeMap<String, Entry>>,
}

#[derive(Deserialize)]
struct Entry {
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    resolved: Option<String>,
    #[serde(default, rename = "contentHash")]
    content_hash: Option<String>,
    /// child id -> minimum version requested (not the resolved one).
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
}

pub fn parse_lockfile(path: &Path) -> Result<Vec<Dependency>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: Lock = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {} as packages.lock.json", path.display()))?;

    // (lowercased id, version) -> index in `out`: the same package resolved for
    // several target frameworks is one dependency with the union of its parents.
    let mut index: HashMap<(String, String), usize> = HashMap::new();
    let mut out: Vec<Dependency> = Vec::new();

    for packages in lock.dependencies.values() {
        // What each id resolved to *in this framework*: a child's edge points at
        // that version, not at the minimum its parent asked for.
        let resolved: HashMap<String, (&str, &str)> = packages
            .iter()
            .filter(|(_, e)| e.kind != "Project")
            .filter_map(|(id, e)| Some((id.to_lowercase(), (id.as_str(), e.resolved.as_deref()?))))
            .collect();

        for (id, e) in packages {
            if e.kind == "Project" {
                continue;
            }
            let Some(version) = e.resolved.as_deref() else {
                continue;
            };
            let key = (id.to_lowercase(), version.to_string());
            let i = *index.entry(key).or_insert_with(|| {
                out.push(Dependency {
                    name: id.clone(),
                    version: version.to_string(),
                    ecosystem: Ecosystem::Dotnet,
                    direct: false,
                    scope: Scope::Prod,
                    licenses: Vec::new(),
                    license_source: LicenseSource::Unknown,
                    resolved_url: None,
                    // contentHash is a base64 SHA-512 — the npm SRI shape;
                    // filled in below, from whichever framework records it.
                    integrity: None,
                    parents: Vec::new(),
                });
                out.len() - 1
            });
            out[i].direct |= e.kind == "Direct";
            if out[i].integrity.is_none() {
                out[i].integrity = e.content_hash.as_ref().map(|h| format!("sha512-{h}"));
            }
        }

        for (id, e) in packages {
            // A project reference is local code, not a package: what it pulls in
            // is first-level for this project, so its children count as direct.
            let parent: Option<DepRef> = if e.kind == "Project" {
                None
            } else {
                let Some(v) = e.resolved.as_deref() else {
                    continue;
                };
                Some((id.clone(), v.to_string()))
            };
            for child in e.dependencies.keys() {
                let Some((cname, cver)) = resolved.get(&child.to_lowercase()) else {
                    continue;
                };
                let Some(&ci) = index.get(&(cname.to_lowercase(), cver.to_string())) else {
                    continue;
                };
                match &parent {
                    None => out[ci].direct = true,
                    Some(p) if !out[ci].parents.contains(p) => out[ci].parents.push(p.clone()),
                    Some(_) => {}
                }
            }
        }
    }
    Ok(out)
}

// ---------- *.csproj (+ Directory.Packages.props) ----------

fn package_ref_re() -> &'static Regex {
    // Self-closing or with child elements; group 1 = attributes, 2 = body.
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?s)<PackageReference\b([^>]*?)(?:/>|>(.*?)</PackageReference>)").unwrap()
    })
}

fn package_version_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?s)<PackageVersion\b([^>]*?)/?>").unwrap())
}

fn parse_project(path: &Path) -> Result<Vec<Dependency>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let central = path.parent().map(central_versions).unwrap_or_default();

    let mut out = Vec::new();
    for cap in package_ref_re().captures_iter(&text) {
        let attrs = &cap[1];
        // `Update=` amends an item declared elsewhere; only `Include=` adds one.
        let Some(name) = attr(attrs, "Include") else {
            continue;
        };
        let body = cap.get(2).map_or("", |m| m.as_str());
        let version = attr(attrs, "Version")
            .or_else(|| child(body, "Version"))
            .or_else(|| attr(attrs, "VersionOverride"))
            .or_else(|| central.get(&name.to_lowercase()).cloned())
            .unwrap_or_else(|| "managed".to_string());
        out.push(Dependency {
            name,
            version: strip_exact(&version),
            ecosystem: Ecosystem::Dotnet,
            direct: true, // a project file lists direct references only
            scope: Scope::Prod,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url: None,
            integrity: None,
            parents: Vec::new(),
        });
    }
    Ok(out)
}

/// Central package management: the nearest `Directory.Packages.props` at or
/// above the project directory, as MSBuild itself looks it up.
fn central_versions(dir: &Path) -> HashMap<String, String> {
    let Some(text) = dir
        .ancestors()
        .map(|d| d.join("Directory.Packages.props"))
        .find(|p| p.is_file())
        .and_then(|p| std::fs::read_to_string(p).ok())
    else {
        return HashMap::new();
    };
    package_version_re()
        .captures_iter(&text)
        .filter_map(|c| {
            Some((
                attr(&c[1], "Include")?.to_lowercase(),
                attr(&c[1], "Version")?,
            ))
        })
        .collect()
}

/// `[1.2.3]` (an exact-version range) is the pin `1.2.3`; anything else is kept.
fn strip_exact(v: &str) -> String {
    let t = v.trim();
    match t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        Some(inner) if !inner.contains(',') => inner.trim().to_string(),
        _ => t.to_string(),
    }
}

/// The value of `name="..."` (or `'...'`) in an attribute list.
fn attr(attrs: &str, name: &str) -> Option<String> {
    let re = Regex::new(&format!(r#"\b{name}\s*=\s*["']([^"']*)["']"#)).ok()?;
    let v = re.captures(attrs)?[1].trim().to_string();
    (!v.is_empty()).then_some(v)
}

/// The trimmed text of `<name>...</name>` inside `body`.
fn child(body: &str, name: &str) -> Option<String> {
    let start = body.find(&format!("<{name}>"))? + name.len() + 2;
    let end = body[start..].find(&format!("</{name}>"))? + start;
    let v = body[start..end].trim();
    (!v.is_empty()).then(|| v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "postmortem-dotnet-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const LOCK: &str = r#"{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Serilog.Sinks.Console": {
        "type": "Direct", "requested": "[5.0.1, )", "resolved": "5.0.1",
        "contentHash": "AAAA",
        "dependencies": { "serilog": "3.1.1" }
      },
      "Serilog": { "type": "Transitive", "resolved": "3.1.1", "contentHash": "BBBB" },
      "Shared.Lib": {
        "type": "Project",
        "dependencies": { "Newtonsoft.Json": "[13.0.3, )" }
      },
      "Newtonsoft.Json": { "type": "CentralTransitive", "requested": "[13.0.3, )", "resolved": "13.0.3" }
    },
    "net6.0": {
      "Serilog.Sinks.Console": {
        "type": "Direct", "requested": "[5.0.1, )", "resolved": "5.0.1",
        "dependencies": { "Serilog": "3.1.1" }
      },
      "Serilog": { "type": "Transitive", "resolved": "3.1.1" }
    }
  }
}"#;

    #[test]
    fn lockfile_merges_frameworks_and_resolves_edges() {
        let p = tmp_dir().join("packages.lock.json");
        std::fs::write(&p, LOCK).unwrap();
        let deps = parse(None, Some(&p)).unwrap();
        let get = |n: &str| deps.iter().find(|d| d.name == n).unwrap();

        // One entry per (id, version) despite two frameworks; no project node.
        assert_eq!(deps.len(), 3);
        assert!(deps.iter().all(|d| d.name != "Shared.Lib"));

        let console = get("Serilog.Sinks.Console");
        assert!(console.direct && console.parents.is_empty());
        assert_eq!(console.integrity.as_deref(), Some("sha512-AAAA"));

        // Edge found through a differently-cased child id, recorded once.
        let serilog = get("Serilog");
        assert!(!serilog.direct);
        assert_eq!(
            serilog.parents,
            vec![("Serilog.Sinks.Console".to_string(), "5.0.1".to_string())]
        );

        // Pulled in by a project reference: first-level for this project.
        assert!(get("Newtonsoft.Json").direct);
    }

    #[test]
    fn csproj_reads_inline_child_and_central_versions() {
        let root = tmp_dir();
        let proj = root.join("src");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            root.join("Directory.Packages.props"),
            r#"<Project><ItemGroup>
  <PackageVersion Include="Polly" Version="8.4.0" />
</ItemGroup></Project>"#,
        )
        .unwrap();
        let csproj = proj.join("App.csproj");
        std::fs::write(
            &csproj,
            r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>
  <PackageReference Include="Newtonsoft.Json" Version="[13.0.3]" />
  <PackageReference Include="Dapper">
    <Version>2.1.35</Version>
  </PackageReference>
  <PackageReference Include="polly" />
  <PackageReference Update="Ignored" Version="1.0.0" />
  <PackageReference Include="Unpinned" />
</ItemGroup></Project>"#,
        )
        .unwrap();

        let deps = parse(Some(&csproj), None).unwrap();
        let got: Vec<(&str, &str)> = deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("Newtonsoft.Json", "13.0.3"),
                ("Dapper", "2.1.35"),
                ("polly", "8.4.0"),
                ("Unpinned", "managed"),
            ]
        );
        assert!(deps.iter().all(|d| d.direct));
    }
}
