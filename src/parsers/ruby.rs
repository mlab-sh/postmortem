//! Gemfile.lock parser (Bundler).
//!
//! Bundler's lockfile is a small indentation-structured text format. The gems
//! and their resolved versions live under `specs:` inside `GEM` / `GIT` / `PATH`
//! sections; each gem's own runtime dependencies are listed one level deeper.
//! The top-level `DEPENDENCIES` section names the gems the project asked for
//! directly. Example:
//!
//! ```text
//! GEM
//!   remote: https://rubygems.org/
//!   specs:
//!     actionpack (7.0.4)
//!       rack (~> 2.0)
//!     rack (2.2.4)
//!
//! DEPENDENCIES
//!   actionpack
//! ```

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::Path;

use crate::model::{Dependency, Ecosystem};

struct Spec {
    name: String,
    version: String,
    remote: Option<String>,
    deps: Vec<String>,
}

pub fn parse_lockfile(path: &Path, _manifest: Option<&Path>) -> Result<Vec<Dependency>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let (specs, direct) = parse_text(&text);
    Ok(build_deps(&specs, &direct))
}

fn build_deps(specs: &[Spec], direct: &HashSet<String>) -> Vec<Dependency> {
    specs
        .iter()
        .map(|spec| Dependency {
            name: spec.name.clone(),
            version: spec.version.clone(),
            ecosystem: Ecosystem::Ruby,
            direct: direct.contains(&spec.name),
            resolved_url: spec.remote.clone(),
            integrity: None,
            parents: specs
                .iter()
                .filter(|o| o.name != spec.name && o.deps.iter().any(|d| d == &spec.name))
                .map(|o| (o.name.clone(), o.version.clone()))
                .collect(),
        })
        .collect()
}

fn parse_text(text: &str) -> (Vec<Spec>, HashSet<String>) {
    let mut specs: Vec<Spec> = Vec::new();
    let mut direct: HashSet<String> = HashSet::new();

    // `section` is the current column-0 header; `in_specs` tracks the `specs:`
    // sub-block within a GEM/GIT/PATH section; `remote` is that section's source.
    let mut section = String::new();
    let mut in_specs = false;
    let mut remote: Option<String> = None;

    for raw in text.lines() {
        if raw.is_empty() {
            continue;
        }
        if !raw.starts_with(' ') {
            section = raw.trim_end().to_string();
            in_specs = false;
            remote = None;
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        let content = raw.trim();

        match section.as_str() {
            "GEM" | "GIT" | "PATH" => {
                if content == "specs:" {
                    in_specs = true;
                    continue;
                }
                if let Some(r) = content.strip_prefix("remote:") {
                    remote = Some(r.trim().to_string());
                    continue;
                }
                if !in_specs {
                    continue; // revision:, ref:, branch:, ...
                }
                if indent == 4 {
                    if let Some((name, version)) = parse_spec_line(content) {
                        specs.push(Spec { name, version, remote: remote.clone(), deps: Vec::new() });
                    }
                } else if indent >= 6 {
                    if let Some(last) = specs.last_mut() {
                        if let Some(dep) = content.split_whitespace().next() {
                            last.deps.push(dep.to_string());
                        }
                    }
                }
            }
            "DEPENDENCIES" => {
                if let Some(name) = content.split_whitespace().next() {
                    // A trailing `!` marks a pinned git/path gem.
                    direct.insert(name.trim_end_matches('!').to_string());
                }
            }
            _ => {}
        }
    }
    (specs, direct)
}

/// `rack (2.2.4)` -> ("rack", "2.2.4"); platform suffixes are kept verbatim
/// (`nokogiri (1.13.9-x86_64-linux)`).
fn parse_spec_line(line: &str) -> Option<(String, String)> {
    let (name, rest) = line.split_once(" (")?;
    let version = rest.strip_suffix(')')?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.4)
      rack (~> 2.0)
      nio4r (~> 2.0)
    nio4r (2.5.8)
    rack (2.2.4)

PLATFORMS
  ruby

DEPENDENCIES
  actionpack
  rspec (~> 3.0)!

BUNDLED WITH
   2.3.7
"#;

    #[test]
    fn parses_specs_versions_and_remote() {
        let (specs, _) = parse_text(SAMPLE);
        assert_eq!(specs.len(), 3);
        let rack = specs.iter().find(|s| s.name == "rack").unwrap();
        assert_eq!(rack.version, "2.2.4");
        assert_eq!(rack.remote.as_deref(), Some("https://rubygems.org/"));
    }

    #[test]
    fn resolves_direct_and_parents() {
        let (specs, direct) = parse_text(SAMPLE);
        let deps = build_deps(&specs, &direct);
        let rack = deps.iter().find(|d| d.name == "rack").unwrap();
        assert!(!rack.direct, "rack is transitive");
        assert!(rack.parents.iter().any(|(n, _)| n == "actionpack"));

        let ap = deps.iter().find(|d| d.name == "actionpack").unwrap();
        assert!(ap.direct, "actionpack is in DEPENDENCIES");
        assert_eq!(ap.ecosystem, Ecosystem::Ruby);
    }

    #[test]
    fn direct_strips_pin_bang() {
        let (_, direct) = parse_text(SAMPLE);
        assert!(direct.contains("rspec"), "trailing ! must be stripped");
    }
}
