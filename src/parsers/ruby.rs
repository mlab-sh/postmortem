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
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::model::{Dependency, Ecosystem, Scope, LicenseSource};

struct Spec {
    name: String,
    version: String,
    remote: Option<String>,
    deps: Vec<String>,
}

pub fn parse_lockfile(path: &Path, manifest: Option<&Path>) -> Result<Vec<Dependency>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let (specs, direct) = parse_text(&text);
    // Gemfile.lock records no groups at all — `DEPENDENCIES` is a flat list. The
    // `:development` / `:test` split lives only in the Gemfile, so read it when
    // one is available; without it every gem stays production.
    let groups = manifest
        .and_then(|m| std::fs::read_to_string(m).ok())
        .map(|t| gemfile_scopes(&t))
        .unwrap_or_default();
    Ok(build_deps(&specs, &direct, &groups))
}

fn build_deps(
    specs: &[Spec],
    direct: &HashSet<String>,
    groups: &HashMap<String, Scope>,
) -> Vec<Dependency> {
    specs
        .iter()
        .map(|spec| Dependency {
            name: spec.name.clone(),
            version: spec.version.clone(),
            ecosystem: Ecosystem::Ruby,
            direct: direct.contains(&spec.name),
            scope: groups.get(&spec.name).copied().unwrap_or(Scope::Prod),
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
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

/// Map each gem named in a Gemfile to the scope its group implies.
///
/// Bundler expresses groups two ways, and both are handled:
///
/// ```ruby
/// group :development, :test do
///   gem "rspec"
/// end
/// gem "pry", group: :development
/// gem "rubocop", groups: [:development, :test]
/// ```
///
/// A gem declared both inside and outside a dev group keeps the strongest scope,
/// and anything we cannot attribute stays production.
fn gemfile_scopes(text: &str) -> HashMap<String, Scope> {
    let mut out: HashMap<String, Scope> = HashMap::new();
    // The `group ... do` blocks currently open, as a stack of scopes.
    let mut block_stack: Vec<Scope> = Vec::new();

    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("group ")
            && (rest.contains(" do") || rest.ends_with("do"))
        {
            block_stack.push(scope_of_symbols(rest));
            continue;
        }
        if line == "end" {
            block_stack.pop();
            continue;
        }
        let Some(rest) = line.strip_prefix("gem ") else { continue };
        let Some(name) = quoted(rest) else { continue };
        // An inline `group:` / `groups:` option overrides the enclosing block.
        let inline = rest.find("group").map(|i| scope_of_symbols(&rest[i..]));
        let scope = inline
            .or_else(|| block_stack.iter().copied().max())
            .unwrap_or(Scope::Prod);
        let e = out.entry(name).or_insert(scope);
        *e = (*e).max(scope);
    }
    out
}

/// The scope implied by the `:symbols` in a group clause: dev only when *every*
/// named group is a dev group, so `group :default, :test` stays production.
fn scope_of_symbols(clause: &str) -> Scope {
    let syms: Vec<String> = clause
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| s != "group" && s != "groups" && s != "do")
        .collect();
    if syms.is_empty() {
        return Scope::Prod;
    }
    if syms.iter().all(|s| matches!(s.as_str(), "development" | "test" | "lint" | "docs" | "cucumber")) {
        Scope::Dev
    } else {
        Scope::Prod
    }
}

/// The first single- or double-quoted string in `s`.
fn quoted(s: &str) -> Option<String> {
    let q = s.chars().find(|c| *c == '"' || *c == '\'')?;
    let start = s.find(q)? + 1;
    let end = s[start..].find(q)? + start;
    Some(s[start..end].to_string())
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
                } else if indent >= 6
                    && let Some(last) = specs.last_mut()
                    && let Some(dep) = content.split_whitespace().next()
                {
                    last.deps.push(dep.to_string());
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
        let deps = build_deps(&specs, &direct, &HashMap::new());
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

    const GEMFILE: &str = r#"source "https://rubygems.org"

gem "rails", "~> 7.0"

group :development, :test do
  gem "rspec-rails"
  gem "factory_bot"
end

group :test do
  gem "simplecov"
end

gem "pry", group: :development
gem "rubocop", groups: [:development, :test]
gem "dotenv", group: :default   # a non-dev group stays production
"#;

    #[test]
    fn gemfile_groups_classify_dev_gems() {
        let s = gemfile_scopes(GEMFILE);
        assert_eq!(s.get("rails"), Some(&Scope::Prod), "an ungrouped gem is production");
        assert_eq!(s.get("rspec-rails"), Some(&Scope::Dev));
        assert_eq!(s.get("factory_bot"), Some(&Scope::Dev));
        assert_eq!(s.get("simplecov"), Some(&Scope::Dev));
    }

    #[test]
    fn gemfile_inline_group_options_classify() {
        let s = gemfile_scopes(GEMFILE);
        assert_eq!(s.get("pry"), Some(&Scope::Dev), "group: :development");
        assert_eq!(s.get("rubocop"), Some(&Scope::Dev), "groups: [:development, :test]");
        assert_eq!(s.get("dotenv"), Some(&Scope::Prod), ":default is not a dev group");
    }

    #[test]
    fn gemfile_block_ends_restore_outer_scope() {
        // A gem declared after the `end` must not inherit the closed block.
        let s = gemfile_scopes("group :test do\n  gem \"rspec\"\nend\ngem \"puma\"\n");
        assert_eq!(s.get("rspec"), Some(&Scope::Dev));
        assert_eq!(s.get("puma"), Some(&Scope::Prod));
    }

    #[test]
    fn mixed_group_stays_production() {
        // `group :default, :test` still ships, so it must not be omittable.
        let s = gemfile_scopes("group :default, :test do\n  gem \"shared\"\nend\n");
        assert_eq!(s.get("shared"), Some(&Scope::Prod));
    }

    #[test]
    fn scopes_reach_the_dependency_list() {
        let (specs, direct) = parse_text(SAMPLE);
        let groups = gemfile_scopes("group :test do\n  gem \"rack\"\nend\n");
        let deps = build_deps(&specs, &direct, &groups);
        assert_eq!(deps.iter().find(|d| d.name == "rack").unwrap().scope, Scope::Dev);
        assert_eq!(
            deps.iter().find(|d| d.name == "actionpack").unwrap().scope,
            Scope::Prod,
            "gems absent from the Gemfile stay production"
        );
    }

    #[test]
    fn absent_gemfile_leaves_everything_production() {
        let (specs, direct) = parse_text(SAMPLE);
        let deps = build_deps(&specs, &direct, &HashMap::new());
        assert!(deps.iter().all(|d| d.scope == Scope::Prod));
    }
}
