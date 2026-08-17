//! `postmortem.conf` — TOML configuration auto-loaded from the scanned project root.
//!
//! Goal: let teams suppress noise without re-running with long flag soup. Anything
//! a config can express, a CLI flag can also express (and merges with the file).
//!
//! Example `postmortem.conf`:
//!
//! ```toml
//! # Drop entire finding categories
//! skip_categories = ["ioc"]
//!
//! # Drop everything attributed to these dependencies (names or "name@version")
//! skip_dependencies = ["lodash", "left-pad@1.3.0"]
//!
//! # Raise the noise floor — findings below this are dropped before rendering
//! min_severity = "medium"
//!
//! # Fine-grained ignore rules. A finding is suppressed when ALL specified fields
//! # match. Globs are allowed in `path` (e.g. "**/test/**", "**/*.min.js").
//! [[ignore]]
//! category = "obfuscation"
//! dependency = "uglify-js"
//! reason = "known minifier, expected high-entropy output"
//!
//! [[ignore]]
//! path = "**/test/**"
//! reason = "test fixtures legitimately contain weird strings"
//! ```

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

use crate::model::{Category, Finding, Severity};

pub const DEFAULT_FILENAME: &str = "postmortem.conf";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub skip_categories: Vec<Category>,
    #[serde(default)]
    pub skip_dependencies: Vec<String>,
    #[serde(default)]
    pub min_severity: Option<Severity>,
    #[serde(default, rename = "ignore")]
    pub ignores: Vec<IgnoreRule>,
    /// CI-gate policy for `tree` (thresholds + allowlist). Ignored by `scan`.
    #[serde(default)]
    pub gate: GateConfig,
    /// License policy for `licenses`. Ignored by every other command.
    #[serde(default)]
    pub license: LicenseConfig,
}

/// The `[license]` table: which licenses the project accepts.
///
/// ```toml
/// [license]
/// deny = ["AGPL-3.0", "SSPL-1.0"]
/// fail_on_unknown = true
/// ```
///
/// `deny` and `allow` are mutually reinforcing rather than exclusive: with an
/// `allow` list, anything absent from it fails; `deny` additionally rejects
/// named identifiers. CLI flags are additive on top of these.
#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LicenseConfig {
    /// SPDX ids that fail the run.
    #[serde(default)]
    pub deny: Vec<String>,
    /// When non-empty, the only SPDX ids permitted.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Treat a package with no resolvable license as a failure. Off by default:
    /// coverage depends on the ecosystem, so this would otherwise fail runs for
    /// a reason the user cannot fix.
    #[serde(default)]
    pub fail_on_unknown: bool,
}

/// The `[gate]` table: thresholds and the allowlist consumed by `tree`'s CI
/// gate. Every threshold is optional; CLI flags override these (see
/// [`crate::gate`]). A threshold is a ceiling — the gate trips when the measured
/// value is strictly greater, so `max_high = 0` tolerates no high-risk deps.
#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GateConfig {
    #[serde(default)]
    pub max_risk: Option<u8>,
    #[serde(default)]
    pub max_dep: Option<u8>,
    #[serde(default)]
    pub max_high: Option<usize>,
    #[serde(default)]
    pub max_sus: Option<usize>,
    #[serde(default)]
    pub max_vulns: Option<usize>,
    #[serde(default)]
    pub fail_on_vuln: Option<Severity>,
    /// Packages exempted from every gate count. Array-of-tables: `[[gate.allow]]`.
    #[serde(default, rename = "allow")]
    pub allow: Vec<AllowEntry>,
}

/// One `[[gate.allow]]` entry: a package (name or `name@version`) to exempt,
/// with an optional human `reason` and an optional `expires` (`YYYY-MM-DD`)
/// after which it stops bypassing and is reported.
#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AllowEntry {
    pub package: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub expires: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IgnoreRule {
    #[serde(default)]
    pub category: Option<Category>,
    #[serde(default)]
    pub dependency: Option<String>,
    #[serde(default)]
    pub path: Option<String>, // glob
    #[serde(default)]
    #[allow(dead_code)]
    pub reason: Option<String>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let cfg: Config = toml::from_str(&text)
            .with_context(|| format!("parsing {}", path.display()))?;
        Ok(cfg)
    }

    /// Merge CLI overrides on top of a (possibly file-loaded) config. CLI wins on
    /// scalars; lists are unioned.
    pub fn merge_cli(
        mut self,
        cli_skip_categories: &[Category],
        cli_min_severity: Option<Severity>,
    ) -> Self {
        for c in cli_skip_categories {
            if !self.skip_categories.contains(c) {
                self.skip_categories.push(*c);
            }
        }
        if cli_min_severity.is_some() {
            self.min_severity = cli_min_severity;
        }
        self
    }

    /// Apply the config to a finding list. Returns (kept, suppressed_count).
    pub fn apply(&self, findings: Vec<Finding>) -> (Vec<Finding>, usize) {
        let before = findings.len();
        let kept: Vec<Finding> = findings
            .into_iter()
            .filter(|f| !self.should_drop(f))
            .collect();
        let suppressed = before - kept.len();
        (kept, suppressed)
    }

    fn should_drop(&self, f: &Finding) -> bool {
        if self.skip_categories.contains(&f.category) {
            return true;
        }
        if let Some(min) = self.min_severity
            && f.severity < min
        {
            return true;
        }
        if self.skip_dependencies.iter().any(|d| dep_matches(d, &f.dependency)) {
            return true;
        }
        for rule in &self.ignores {
            if rule_matches(rule, f) {
                return true;
            }
        }
        false
    }
}

fn dep_matches(pattern: &str, dep: &str) -> bool {
    if pattern == dep {
        return true;
    }
    // pattern is bare name → match name regardless of @version suffix on either side
    let dep_name = dep.split('@').next().unwrap_or(dep);
    let pat_name = pattern.split('@').next().unwrap_or(pattern);
    if !pattern.contains('@') && pat_name == dep_name {
        return true;
    }
    false
}

fn rule_matches(rule: &IgnoreRule, f: &Finding) -> bool {
    if rule.category.is_none() && rule.dependency.is_none() && rule.path.is_none() {
        return false; // empty rule never matches — guards against accidentally muting everything
    }
    if let Some(c) = rule.category
        && c != f.category
    {
        return false;
    }
    if let Some(d) = &rule.dependency
        && !dep_matches(d, &f.dependency)
    {
        return false;
    }
    if let Some(g) = &rule.path {
        let loc = f.location.as_deref().unwrap_or("");
        if !glob_match(g, loc) {
            return false;
        }
    }
    true
}

/// Minimal glob: `*` matches anything except `/`, `**` matches anything including `/`,
/// `?` matches one non-slash char. Anchored at neither end — pattern is matched as
/// a substring inside the location string, which is convenient for path filters.
fn glob_match(pattern: &str, text: &str) -> bool {
    // Compile to a regex
    let mut re = String::with_capacity(pattern.len() * 2);
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' => {
                if chars.peek() == Some(&'*') {
                    chars.next();
                    re.push_str(".*");
                } else {
                    re.push_str("[^/]*");
                }
            }
            '?' => re.push_str("[^/]"),
            '.' | '+' | '(' | ')' | '|' | '^' | '$' | '{' | '}' | '[' | ']' | '\\' => {
                re.push('\\');
                re.push(c);
            }
            _ => re.push(c),
        }
    }
    regex::Regex::new(&re)
        .map(|r| r.is_match(text))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(cat: Category, dep: &str, sev: Severity, loc: &str) -> Finding {
        Finding {
            dependency: dep.to_string(),
            severity: sev,
            category: cat,
            detail: String::new(),
            location: Some(loc.to_string()),
            evidence: None,
            enrich_url: None,
        }
    }

    #[test]
    fn skip_categories_drops_matches() {
        let cfg = Config {
            skip_categories: vec![Category::Ioc],
            ..Default::default()
        };
        let (kept, sup) = cfg.apply(vec![
            finding(Category::Ioc, "foo", Severity::High, ""),
            finding(Category::Obfuscation, "foo", Severity::High, ""),
        ]);
        assert_eq!(kept.len(), 1);
        assert_eq!(sup, 1);
        assert_eq!(kept[0].category, Category::Obfuscation);
    }

    #[test]
    fn dep_pattern_name_only_matches_versioned() {
        let cfg = Config {
            skip_dependencies: vec!["foo".into()],
            ..Default::default()
        };
        let (kept, _) = cfg.apply(vec![
            finding(Category::Ioc, "foo@1.2.3", Severity::High, ""),
            finding(Category::Ioc, "foobar", Severity::High, ""),
        ]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].dependency, "foobar");
    }

    #[test]
    fn dep_pattern_exact_versioned_only_matches_that_version() {
        let cfg = Config {
            skip_dependencies: vec!["foo@1.2.3".into()],
            ..Default::default()
        };
        let (kept, _) = cfg.apply(vec![
            finding(Category::Ioc, "foo@1.2.3", Severity::High, ""),
            finding(Category::Ioc, "foo@2.0.0", Severity::High, ""),
        ]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].dependency, "foo@2.0.0");
    }

    #[test]
    fn min_severity_filters() {
        let cfg = Config {
            min_severity: Some(Severity::High),
            ..Default::default()
        };
        let (kept, _) = cfg.apply(vec![
            finding(Category::Ioc, "foo", Severity::Medium, ""),
            finding(Category::Ioc, "foo", Severity::High, ""),
        ]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].severity, Severity::High);
    }

    #[test]
    fn ignore_path_glob() {
        let cfg = Config {
            ignores: vec![IgnoreRule {
                path: Some("**/test/**".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let (kept, _) = cfg.apply(vec![
            finding(Category::Ioc, "x", Severity::High, "/a/b/test/c.js"),
            finding(Category::Ioc, "x", Severity::High, "/a/b/src/c.js"),
        ]);
        assert_eq!(kept.len(), 1);
        assert!(kept[0].location.as_ref().unwrap().contains("/src/"));
    }

    #[test]
    fn ignore_combines_fields_as_and() {
        let cfg = Config {
            ignores: vec![IgnoreRule {
                category: Some(Category::Obfuscation),
                dependency: Some("uglify-js".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let (kept, _) = cfg.apply(vec![
            // matches both → dropped
            finding(Category::Obfuscation, "uglify-js", Severity::High, ""),
            // wrong category → kept
            finding(Category::Ioc, "uglify-js", Severity::High, ""),
            // wrong dep → kept
            finding(Category::Obfuscation, "elsewhere", Severity::High, ""),
        ]);
        assert_eq!(kept.len(), 2);
    }

    #[test]
    fn empty_ignore_rule_never_matches() {
        let cfg = Config {
            ignores: vec![IgnoreRule::default()],
            ..Default::default()
        };
        let (kept, sup) = cfg.apply(vec![finding(Category::Ioc, "foo", Severity::High, "")]);
        assert_eq!(kept.len(), 1);
        assert_eq!(sup, 0);
    }
}
