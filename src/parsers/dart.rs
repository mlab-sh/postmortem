//! Dart / Flutter `pubspec.lock` parser.
//!
//! YAML: under `packages`, every resolved package with its `dependency` kind
//! (`direct main` / `direct dev` / `direct overridden` / `transitive`), its
//! `source` (`hosted` / `git` / `path` / `sdk`) and its `version`. No edges are
//! recorded, so the graph is flat — but the direct set and the dev split of the
//! direct packages come straight from the lockfile.
//!
//! `sdk` (flutter, flutter_test) and `path` packages are the toolchain and the
//! project's own code, not dependencies fetched from anywhere: they are left
//! out.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

use crate::model::{Dependency, Ecosystem, LicenseSource, Scope};

/// The public registry as a hosted package's `description.url` names it:
/// pub.dev, its pre-2023 name, and the Flutter China mirror of it.
const PUB_DEV: [&str; 3] = [
    "https://pub.dev",
    "https://pub.dartlang.org",
    "https://pub.flutter-io.cn",
];

#[derive(Deserialize)]
struct Lock {
    #[serde(default)]
    packages: BTreeMap<String, Package>,
}

#[derive(Deserialize)]
struct Package {
    #[serde(default)]
    dependency: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    version: String,
    /// A map for `hosted` / `git`, a bare string for `sdk` / `path`.
    #[serde(default)]
    description: serde_yaml::Value,
}

pub fn parse_lockfile(path: &Path) -> Result<Vec<Dependency>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: Lock = serde_yaml::from_str(&text)
        .with_context(|| format!("parsing {} as pubspec.lock", path.display()))?;

    let mut out = Vec::with_capacity(lock.packages.len());
    for (name, p) in lock.packages {
        if matches!(p.source.as_str(), "sdk" | "path") {
            continue;
        }
        let desc = |k: &str| p.description.get(k).and_then(|v| v.as_str());
        // Where it came from when that is not pub.dev: a git repo, or a private
        // pub server — which pub.dev must not be asked about.
        let resolved_url = match p.source.as_str() {
            "git" => desc("url").map(String::from),
            _ => desc("url")
                .filter(|u| !PUB_DEV.contains(&u.trim_end_matches('/')))
                .map(String::from),
        };
        out.push(Dependency {
            name,
            version: p.version,
            ecosystem: Ecosystem::Dart,
            direct: p.dependency.starts_with("direct"),
            scope: if p.dependency == "direct dev" {
                Scope::Dev
            } else {
                Scope::Prod
            },
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url,
            integrity: desc("sha256").map(String::from),
            parents: Vec::new(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_sources_and_origins() {
        let dir = std::env::temp_dir().join(format!("postmortem-dart-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("pubspec.lock");
        std::fs::write(
            &p,
            r#"packages:
  http:
    dependency: "direct main"
    description:
      name: http
      sha256: "abc123"
      url: "https://pub.dev"
    source: hosted
    version: "1.2.0"
  mockito:
    dependency: "direct dev"
    description:
      name: mockito
      sha256: "def456"
      url: "https://pub.dev"
    source: hosted
    version: "5.4.4"
  collection:
    dependency: transitive
    description:
      name: collection
      sha256: "0011"
      url: "https://pub.dev"
    source: hosted
    version: "1.18.0"
  cupertino_http:
    dependency: "direct main"
    description:
      path: "pkgs/cupertino_http"
      ref: main
      resolved-ref: "58b03c7"
      url: "https://github.com/mertalev/http"
    source: git
    version: "1.0.6"
  internal_kit:
    dependency: transitive
    description:
      name: internal_kit
      sha256: "99"
      url: "https://pub.acme.corp"
    source: hosted
    version: "2.0.0"
  flutter:
    dependency: "direct main"
    description: flutter
    source: sdk
    version: "0.0.0"
  local_plugin:
    dependency: "direct main"
    description:
      path: "../plugin"
      relative: true
    source: path
    version: "0.1.0"
sdks:
  dart: ">=3.3.0 <4.0.0"
"#,
        )
        .unwrap();
        let deps = parse_lockfile(&p).unwrap();
        let get = |n: &str| deps.iter().find(|d| d.name == n).unwrap();

        assert_eq!(deps.len(), 5, "sdk and path packages are not dependencies");
        let http = get("http");
        assert!(http.direct && http.scope == Scope::Prod);
        assert_eq!(http.resolved_url, None);
        assert_eq!(http.integrity.as_deref(), Some("abc123"));
        assert_eq!(get("mockito").scope, Scope::Dev);
        assert!(!get("collection").direct);
        assert_eq!(
            get("cupertino_http").resolved_url.as_deref(),
            Some("https://github.com/mertalev/http")
        );
        assert_eq!(
            get("internal_kit").resolved_url.as_deref(),
            Some("https://pub.acme.corp")
        );
    }

    #[test]
    fn legacy_pub_dartlang_url_is_the_public_registry() {
        let dir = std::env::temp_dir().join(format!(
            "postmortem-dart-legacy-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("pubspec.lock");
        std::fs::write(
            &p,
            r#"packages:
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dartlang.org/"
    source: hosted
    version: "0.13.5"
"#,
        )
        .unwrap();
        assert_eq!(parse_lockfile(&p).unwrap()[0].resolved_url, None);
    }
}
