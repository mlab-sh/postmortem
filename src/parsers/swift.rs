//! Apple-platform parsers: CocoaPods `Podfile.lock` and SwiftPM
//! `Package.resolved`.
//!
//! * `Podfile.lock` is YAML. `PODS` lists every resolved pod (subspecs such as
//!   `Firebase/Core` included) with the pods it depends on, so the graph comes
//!   back with edges; `DEPENDENCIES` is what the Podfile asked for — the direct
//!   set.
//! * `Package.resolved` (v1, v2, v3) pins each package to a version or a
//!   revision but records no edges and no direct/transitive split. The direct
//!   set is recovered best-effort from `Package.swift`'s `.package(url:)` calls;
//!   the graph stays flat.
//!
//! A SwiftPM package is named by its repository path (`github.com/apple/
//! swift-nio`), like a Go module: that is its identity, its purl namespace and
//! its source repo all at once.

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::OnceLock;

use crate::model::{Dependency, Ecosystem, LicenseSource, Scope};

fn dep(name: String, version: String, eco: Ecosystem, direct: bool) -> Dependency {
    Dependency {
        name,
        version,
        ecosystem: eco,
        direct,
        scope: Scope::Prod,
        licenses: Vec::new(),
        license_source: LicenseSource::Unknown,
        resolved_url: None,
        integrity: None,
        parents: Vec::new(),
    }
}

// ---------- Podfile.lock ----------

#[derive(Deserialize)]
struct PodLock {
    #[serde(default, rename = "PODS")]
    pods: Vec<serde_yaml::Value>,
    #[serde(default, rename = "DEPENDENCIES")]
    dependencies: Vec<String>,
    /// Pods taken from a repo rather than trunk (`:git:` / `:path:` /
    /// `:podspec:`). `CHECKOUT OPTIONS` pins what was actually checked out.
    #[serde(default, rename = "EXTERNAL SOURCES")]
    external: HashMap<String, HashMap<String, String>>,
    #[serde(default, rename = "CHECKOUT OPTIONS")]
    checkout: HashMap<String, HashMap<String, String>>,
}

/// `"Alamofire (5.9.1)"` -> (`Alamofire`, `5.9.1`); `"Firebase/Core"` -> no
/// version. The parenthesised part is a version in `PODS` keys and a
/// constraint (`~> 5.9`, `from ...`) everywhere else.
fn split_pod(s: &str) -> (&str, Option<&str>) {
    match s.split_once(" (") {
        Some((n, rest)) => (n.trim(), Some(rest.trim_end_matches(')').trim())),
        None => (s.trim(), None),
    }
}

pub fn parse_podfile_lock(path: &Path) -> Result<Vec<Dependency>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: PodLock = serde_yaml::from_str(&text)
        .with_context(|| format!("parsing {} as Podfile.lock", path.display()))?;

    let direct: HashSet<&str> = lock.dependencies.iter().map(|d| split_pod(d).0).collect();

    // (pod, version, children) in document order.
    let mut entries: Vec<(String, String, Vec<String>)> = Vec::new();
    for item in &lock.pods {
        let (key, children) = match item {
            serde_yaml::Value::String(s) => (s.as_str(), Vec::new()),
            serde_yaml::Value::Mapping(m) => {
                let Some((serde_yaml::Value::String(k), v)) = m.iter().next() else {
                    continue;
                };
                let kids = v
                    .as_sequence()
                    .map(|seq| {
                        seq.iter()
                            .filter_map(|c| c.as_str())
                            .map(|c| split_pod(c).0.to_string())
                            .collect()
                    })
                    .unwrap_or_default();
                (k.as_str(), kids)
            }
            _ => continue,
        };
        let (name, version) = split_pod(key);
        entries.push((
            name.to_string(),
            version.unwrap_or_default().to_string(),
            children,
        ));
    }

    let version_of: HashMap<&str, &str> = entries
        .iter()
        .map(|(n, v, _)| (n.as_str(), v.as_str()))
        .collect();
    let mut out: Vec<Dependency> = entries
        .iter()
        .map(|(n, v, _)| {
            let base = n.split('/').next().unwrap_or(n);
            let source = lock.checkout.get(base).or_else(|| lock.external.get(base));
            let mut d = dep(
                n.clone(),
                v.clone(),
                Ecosystem::Cocoapods,
                direct.contains(n.as_str()),
            );
            // A local `:path:` / `:podspec:` pod has no remote: nothing to set.
            d.resolved_url = source.and_then(|o| o.get(":git")).cloned();
            d
        })
        .collect();
    let index: HashMap<String, usize> = out
        .iter()
        .enumerate()
        .map(|(i, d)| (d.name.clone(), i))
        .collect();
    for (parent, pver, children) in &entries {
        for child in children {
            if let Some(&ci) = index.get(child)
                && version_of.contains_key(parent.as_str())
            {
                out[ci].parents.push((parent.clone(), pver.clone()));
            }
        }
    }
    Ok(out)
}

// ---------- Package.resolved ----------

#[derive(Deserialize)]
struct Resolved {
    /// v2 / v3.
    #[serde(default)]
    pins: Vec<Pin>,
    /// v1 nests them under `object`.
    #[serde(default)]
    object: Option<V1>,
}

#[derive(Deserialize)]
struct V1 {
    #[serde(default)]
    pins: Vec<Pin>,
}

#[derive(Deserialize)]
struct Pin {
    /// v2+ `location`, v1 `repositoryURL`.
    #[serde(alias = "repositoryURL")]
    location: String,
    #[serde(default)]
    state: State,
}

#[derive(Deserialize, Default)]
struct State {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    branch: Option<String>,
    #[serde(default)]
    revision: Option<String>,
}

/// `https://github.com/apple/swift-nio.git` / `git@github.com:apple/swift-nio`
/// -> `github.com/apple/swift-nio`. Case is kept: OSV's `SwiftURL` names are
/// case-sensitive. A local path is kept as given.
pub fn package_path(location: &str) -> String {
    let s = location.trim();
    let s = match s.split_once("://") {
        Some((_, rest)) => rest.rsplit_once('@').map_or(rest, |(_, h)| h).to_string(),
        // scp-like `git@host:owner/repo`
        None => match s.split_once('@') {
            Some((_, rest)) => rest.replacen(':', "/", 1),
            None => s.to_string(),
        },
    };
    s.trim_end_matches('/').trim_end_matches(".git").to_string()
}

pub fn parse_package_resolved(path: &Path, manifest: Option<&Path>) -> Result<Vec<Dependency>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let r: Resolved = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {} as Package.resolved", path.display()))?;
    let pins = if r.pins.is_empty() {
        r.object.map(|o| o.pins).unwrap_or_default()
    } else {
        r.pins
    };

    // No manifest (an Xcode project's resolved file): nothing says which pins
    // the app asked for, so none is claimed as direct.
    let direct: HashSet<String> = manifest
        .and_then(|m| std::fs::read_to_string(m).ok())
        .map(|s| {
            package_url_re()
                .captures_iter(&s)
                .map(|c| package_path(&c[1]).to_lowercase())
                .collect()
        })
        .unwrap_or_default();

    Ok(pins
        .into_iter()
        .map(|p| {
            let name = package_path(&p.location);
            let version = p
                .state
                .version
                .or(p.state.branch)
                .or(p.state.revision)
                .unwrap_or_default();
            let is_direct = direct.contains(&name.to_lowercase());
            let mut d = dep(name, version, Ecosystem::Swift, is_direct);
            d.resolved_url = Some(p.location);
            d
        })
        .collect())
}

fn package_url_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"\.package\s*\([^)]*?url:\s*"([^"]+)""#).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str, body: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "postmortem-swift-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn podfile_lock_graph_and_direct_set() {
        let p = tmp(
            "Podfile.lock",
            r#"PODS:
  - Alamofire (5.9.1)
  - FirebaseCore (10.22.0):
    - FirebaseCoreInternal (~> 10.0)
    - GoogleUtilities/Environment (~> 7.12)
  - FirebaseCoreInternal (10.22.0):
    - "GoogleUtilities/NSData+zlib (~> 7.8)"
  - GoogleUtilities/Environment (7.13.0)
  - "GoogleUtilities/NSData+zlib (7.13.0)"

DEPENDENCIES:
  - Alamofire (~> 5.9)
  - FirebaseCore

EXTERNAL SOURCES:
  FirebaseCore:
    :git: https://github.com/acme/firebase-fork.git
    :tag: v10.22.0

CHECKOUT OPTIONS:
  FirebaseCore:
    :git: https://github.com/acme/firebase-fork.git
    :tag: v10.22.0

SPEC CHECKSUMS:
  Alamofire: 3ca42e259043ee0dc5c0cdd76c4bc568b8e42af7

COCOAPODS: 1.15.2
"#,
        );
        let deps = parse_podfile_lock(&p).unwrap();
        let get = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(deps.len(), 5);
        assert!(get("Alamofire").direct && get("FirebaseCore").direct);
        assert_eq!(get("Alamofire").version, "5.9.1");
        assert_eq!(get("Alamofire").resolved_url, None);
        assert_eq!(
            get("FirebaseCore").resolved_url.as_deref(),
            Some("https://github.com/acme/firebase-fork.git")
        );
        let core_internal = get("FirebaseCoreInternal");
        assert!(!core_internal.direct);
        assert_eq!(
            core_internal.parents,
            vec![("FirebaseCore".to_string(), "10.22.0".to_string())]
        );
        assert_eq!(
            get("GoogleUtilities/NSData+zlib").parents,
            vec![("FirebaseCoreInternal".to_string(), "10.22.0".to_string())]
        );
    }

    #[test]
    fn package_resolved_v1_and_v2_with_direct_from_manifest() {
        let v2 = tmp(
            "Package.resolved",
            r#"{"pins":[
  {"identity":"swift-nio","kind":"remoteSourceControl","location":"https://github.com/apple/swift-nio.git","state":{"revision":"abc","version":"2.65.0"}},
  {"identity":"swift-atomics","kind":"remoteSourceControl","location":"https://github.com/apple/swift-atomics","state":{"revision":"def","version":"1.2.0"}},
  {"identity":"tool","kind":"remoteSourceControl","location":"git@gitlab.com:acme/tool.git","state":{"branch":"main","revision":"0123"}}
],"version":2}"#,
        );
        let manifest = v2.with_file_name("Package.swift");
        std::fs::write(
            &manifest,
            r#"dependencies: [ .package(url: "https://github.com/Apple/swift-nio.git", from: "2.0.0") ]"#,
        )
        .unwrap();
        let deps = parse_package_resolved(&v2, Some(&manifest)).unwrap();
        let got: Vec<(&str, &str, bool)> = deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str(), d.direct))
            .collect();
        assert_eq!(
            got,
            vec![
                ("github.com/apple/swift-nio", "2.65.0", true),
                ("github.com/apple/swift-atomics", "1.2.0", false),
                ("gitlab.com/acme/tool", "main", false),
            ]
        );

        let v1 = tmp(
            "Package.resolved",
            r#"{"object":{"pins":[{"package":"Kingfisher","repositoryURL":"https://github.com/onevcat/Kingfisher.git","state":{"branch":null,"revision":"x","version":"7.10.0"}}]},"version":1}"#,
        );
        let deps = parse_package_resolved(&v1, None).unwrap();
        assert_eq!(deps[0].name, "github.com/onevcat/Kingfisher");
        assert_eq!(deps[0].version, "7.10.0");
    }
}
