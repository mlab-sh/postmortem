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
use chrono::NaiveDate;
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

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IgnoreRule {
    #[serde(default)]
    pub category: Option<Category>,
    #[serde(default)]
    pub dependency: Option<String>,
    #[serde(default)]
    pub path: Option<String>, // glob
    #[serde(default)]
    pub reason: Option<String>,
    /// `YYYY-MM-DD` after which this rule stops suppressing and is reported.
    ///
    /// A suppression without one is permanent, and permanent suppressions are
    /// how a scanner quietly stops finding things. An expiry turns each one into
    /// a dated decision that someone has to renew.
    #[serde(default)]
    pub expires: Option<String>,
}

impl IgnoreRule {
    /// A one-line description, for listings.
    pub fn label(&self) -> String {
        let mut parts = Vec::new();
        if let Some(c) = self.category {
            parts.push(format!("category={}", c.as_str()));
        }
        if let Some(d) = &self.dependency {
            parts.push(format!("dependency={d}"));
        }
        if let Some(p) = &self.path {
            parts.push(format!("path={p}"));
        }
        if parts.is_empty() {
            "(empty rule)".into()
        } else {
            parts.join(" ")
        }
    }
}

/// Where a suppression sits in its lifecycle.
///
/// `Invalid` is deliberately distinct from `Expired`: an unparseable date is a
/// config error, and treating it as "still active" would let a typo grant a
/// permanent exemption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// No `expires` — never lapses.
    Permanent,
    /// Still in force, with this many days left.
    Active(i64),
    /// Lapsed on this date; no longer suppresses.
    Expired(NaiveDate),
    /// The `expires` value could not be parsed; treated as lapsed.
    Invalid(String),
}

impl Status {
    /// Does this suppression still take effect?
    pub fn is_effective(&self) -> bool {
        matches!(self, Status::Permanent | Status::Active(_))
    }

    /// Has it lapsed — by date or by being unusable?
    pub fn is_lapsed(&self) -> bool {
        matches!(self, Status::Expired(_) | Status::Invalid(_))
    }
}

/// Classify an `expires` value against `today`.
///
/// Shared by the scan suppressions and the [`crate::gate`] allowlist so the two
/// cannot drift — a date that lapses in one place must lapse in the other.
pub fn expiry_status(expires: Option<&str>, today: NaiveDate) -> Status {
    let Some(raw) = expires.map(str::trim).filter(|s| !s.is_empty()) else {
        return Status::Permanent;
    };
    match NaiveDate::parse_from_str(raw, "%Y-%m-%d") {
        Ok(d) if d >= today => Status::Active((d - today).num_days()),
        Ok(d) => Status::Expired(d),
        Err(_) => Status::Invalid(raw.to_string()),
    }
}

/// One suppression declared anywhere in the config, with its lifecycle state.
#[derive(Debug, Clone)]
pub struct Suppression {
    /// Which table it came from: `gate.allow`, `ignore`, `skip_dependencies`,
    /// `skip_categories`.
    pub source: &'static str,
    pub target: String,
    pub reason: Option<String>,
    pub expires: Option<String>,
    pub status: Status,
}

/// npm's `allowScripts` approvals, as suppressions.
///
/// They are not in `postmortem.conf` — npm writes them into `package.json` —
/// but they suppress the same way and rot the same way, so a listing that left
/// them out would understate what the project has waved through. They carry no
/// expiry: npm records a name, not a version or a date, so an approval granted
/// once holds for every future release of that package.
pub fn script_approvals(root: &std::path::Path) -> Vec<Suppression> {
    crate::scripts::read_approvals(root)
        .into_iter()
        // `read_approvals` also yields the last path segment of a spec so it can
        // be matched; listing both would double-count the same approval.
        .filter(|spec| !spec.contains('/') || spec.starts_with('@'))
        .map(|spec| Suppression {
            source: "allowScripts",
            target: spec,
            reason: Some("npm approve-scripts — this package may run install code".into()),
            expires: None,
            status: Status::Permanent,
        })
        .collect()
}

/// Every suppression the config declares, in one list.
///
/// The blunt forms (`skip_categories`, `skip_dependencies`) cannot carry an
/// expiry — they are bare strings in the schema — so they are reported as
/// permanent rather than omitted. A listing that showed only the expirable ones
/// would understate how much is being hidden.
pub fn suppressions(cfg: &Config, today: NaiveDate) -> Vec<Suppression> {
    let mut out = Vec::new();
    for a in &cfg.gate.allow {
        out.push(Suppression {
            source: "gate.allow",
            target: a.package.clone(),
            reason: a.reason.clone(),
            expires: a.expires.clone(),
            status: expiry_status(a.expires.as_deref(), today),
        });
    }
    for r in &cfg.ignores {
        out.push(Suppression {
            source: "ignore",
            target: r.label(),
            reason: r.reason.clone(),
            expires: r.expires.clone(),
            status: expiry_status(r.expires.as_deref(), today),
        });
    }
    for d in &cfg.skip_dependencies {
        out.push(Suppression {
            source: "skip_dependencies",
            target: d.clone(),
            reason: None,
            expires: None,
            status: Status::Permanent,
        });
    }
    for c in &cfg.skip_categories {
        out.push(Suppression {
            source: "skip_categories",
            target: c.as_str().to_string(),
            reason: None,
            expires: None,
            status: Status::Permanent,
        });
    }
    out
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
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

    /// Apply the config to a finding list, as of `today`.
    ///
    /// An `[[ignore]]` rule past its `expires` **stops suppressing** and is
    /// reported instead. That is the whole point of the date: an exception
    /// nobody renewed must resurface, not persist by default.
    pub fn apply(&self, findings: Vec<Finding>, today: NaiveDate) -> Applied {
        let expired: Vec<String> = self
            .ignores
            .iter()
            .filter_map(|r| {
                let st = expiry_status(r.expires.as_deref(), today);
                match st {
                    Status::Expired(d) => Some(format!("{} (expired {d})", r.label())),
                    Status::Invalid(raw) => {
                        Some(format!("{} (invalid expires \"{raw}\")", r.label()))
                    }
                    _ => None,
                }
            })
            .collect();

        let before = findings.len();
        let findings: Vec<Finding> = findings
            .into_iter()
            .filter(|f| !self.should_drop(f, today))
            .collect();
        let suppressed = before - findings.len();
        Applied {
            findings,
            suppressed,
            expired,
        }
    }

    fn should_drop(&self, f: &Finding, today: NaiveDate) -> bool {
        if self.skip_categories.contains(&f.category) {
            return true;
        }
        if let Some(min) = self.min_severity
            && f.severity < min
        {
            return true;
        }
        if self
            .skip_dependencies
            .iter()
            .any(|d| dep_matches(d, &f.dependency))
        {
            return true;
        }
        for rule in &self.ignores {
            // A lapsed rule is inert — it no longer hides anything.
            if !expiry_status(rule.expires.as_deref(), today).is_effective() {
                continue;
            }
            if rule_matches(rule, f) {
                return true;
            }
        }
        false
    }
}

/// The outcome of applying a config to a finding list.
pub struct Applied {
    pub findings: Vec<Finding>,
    pub suppressed: usize,
    /// Rules that no longer suppress because their date passed — surfaced so a
    /// stale exception is visible rather than silently inert.
    pub expired: Vec<String>,
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

    fn today() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 8, 17).unwrap()
    }

    /// The existing suppression tests predate expiry, so they run "as of today"
    /// with no dates involved.
    fn apply(cfg: &Config, f: Vec<Finding>) -> (Vec<Finding>, usize) {
        let a = cfg.apply(f, today());
        (a.findings, a.suppressed)
    }

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
        let (kept, sup) = apply(
            &cfg,
            vec![
                finding(Category::Ioc, "foo", Severity::High, ""),
                finding(Category::Obfuscation, "foo", Severity::High, ""),
            ],
        );
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
        let (kept, _) = apply(
            &cfg,
            vec![
                finding(Category::Ioc, "foo@1.2.3", Severity::High, ""),
                finding(Category::Ioc, "foobar", Severity::High, ""),
            ],
        );
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].dependency, "foobar");
    }

    #[test]
    fn dep_pattern_exact_versioned_only_matches_that_version() {
        let cfg = Config {
            skip_dependencies: vec!["foo@1.2.3".into()],
            ..Default::default()
        };
        let (kept, _) = apply(
            &cfg,
            vec![
                finding(Category::Ioc, "foo@1.2.3", Severity::High, ""),
                finding(Category::Ioc, "foo@2.0.0", Severity::High, ""),
            ],
        );
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].dependency, "foo@2.0.0");
    }

    #[test]
    fn min_severity_filters() {
        let cfg = Config {
            min_severity: Some(Severity::High),
            ..Default::default()
        };
        let (kept, _) = apply(
            &cfg,
            vec![
                finding(Category::Ioc, "foo", Severity::Medium, ""),
                finding(Category::Ioc, "foo", Severity::High, ""),
            ],
        );
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
        let (kept, _) = apply(
            &cfg,
            vec![
                finding(Category::Ioc, "x", Severity::High, "/a/b/test/c.js"),
                finding(Category::Ioc, "x", Severity::High, "/a/b/src/c.js"),
            ],
        );
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
        let (kept, _) = apply(
            &cfg,
            vec![
                // matches both → dropped
                finding(Category::Obfuscation, "uglify-js", Severity::High, ""),
                // wrong category → kept
                finding(Category::Ioc, "uglify-js", Severity::High, ""),
                // wrong dep → kept
                finding(Category::Obfuscation, "elsewhere", Severity::High, ""),
            ],
        );
        assert_eq!(kept.len(), 2);
    }

    #[test]
    fn empty_ignore_rule_never_matches() {
        let cfg = Config {
            ignores: vec![IgnoreRule::default()],
            ..Default::default()
        };
        let (kept, sup) = apply(
            &cfg,
            vec![finding(Category::Ioc, "foo", Severity::High, "")],
        );
        assert_eq!(kept.len(), 1);
        assert_eq!(sup, 0);
    }

    // --- expiry ---

    fn rule(dep: &str, expires: Option<&str>) -> IgnoreRule {
        IgnoreRule {
            dependency: Some(dep.into()),
            expires: expires.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn a_rule_without_a_date_never_lapses() {
        assert_eq!(expiry_status(None, today()), Status::Permanent);
        assert_eq!(expiry_status(Some("  "), today()), Status::Permanent);
    }

    #[test]
    fn a_future_date_is_active_with_days_left() {
        assert_eq!(
            expiry_status(Some("2026-08-20"), today()),
            Status::Active(3)
        );
        // The last day still counts — an exception expires *after* its date.
        assert_eq!(
            expiry_status(Some("2026-08-17"), today()),
            Status::Active(0)
        );
    }

    #[test]
    fn a_past_date_is_expired() {
        let st = expiry_status(Some("2026-08-16"), today());
        assert!(matches!(st, Status::Expired(_)));
        assert!(st.is_lapsed());
        assert!(!st.is_effective());
    }

    #[test]
    fn an_unparseable_date_is_invalid_not_permanent() {
        // A typo must not grant a permanent exemption.
        let st = expiry_status(Some("next tuesday"), today());
        assert!(matches!(st, Status::Invalid(_)));
        assert!(
            !st.is_effective(),
            "an unusable date must not keep suppressing"
        );
    }

    #[test]
    fn an_expired_rule_stops_suppressing_and_is_reported() {
        // The whole point of the date: what nobody renewed resurfaces.
        let cfg = Config {
            ignores: vec![rule("uglify-js", Some("2026-08-16"))],
            ..Default::default()
        };
        let a = cfg.apply(
            vec![finding(
                Category::Obfuscation,
                "uglify-js",
                Severity::High,
                "",
            )],
            today(),
        );
        assert_eq!(a.findings.len(), 1, "the finding must come back");
        assert_eq!(a.suppressed, 0);
        assert_eq!(a.expired.len(), 1);
        assert!(a.expired[0].contains("uglify-js"), "got {:?}", a.expired);
    }

    #[test]
    fn a_live_rule_still_suppresses() {
        let cfg = Config {
            ignores: vec![rule("uglify-js", Some("2026-12-31"))],
            ..Default::default()
        };
        let a = cfg.apply(
            vec![finding(
                Category::Obfuscation,
                "uglify-js",
                Severity::High,
                "",
            )],
            today(),
        );
        assert!(a.findings.is_empty());
        assert_eq!(a.suppressed, 1);
        assert!(a.expired.is_empty());
    }

    #[test]
    fn an_invalid_date_also_stops_suppressing() {
        let cfg = Config {
            ignores: vec![rule("uglify-js", Some("soon"))],
            ..Default::default()
        };
        let a = cfg.apply(
            vec![finding(
                Category::Obfuscation,
                "uglify-js",
                Severity::High,
                "",
            )],
            today(),
        );
        assert_eq!(a.findings.len(), 1);
        assert_eq!(a.expired.len(), 1);
        assert!(a.expired[0].contains("invalid"), "got {:?}", a.expired);
    }

    #[test]
    fn the_listing_covers_every_table_including_the_blunt_ones() {
        // A listing showing only the expirable entries would understate how much
        // is being hidden.
        let cfg = Config {
            skip_categories: vec![Category::Ioc],
            skip_dependencies: vec!["left-pad".into()],
            ignores: vec![rule("uglify-js", Some("2026-08-16"))],
            gate: GateConfig {
                allow: vec![AllowEntry {
                    package: "evil".into(),
                    reason: Some("tracked in JIRA-1".into()),
                    expires: Some("2026-09-01".into()),
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let items = suppressions(&cfg, today());
        let sources: Vec<&str> = items.iter().map(|s| s.source).collect();
        assert!(sources.contains(&"gate.allow"));
        assert!(sources.contains(&"ignore"));
        assert!(sources.contains(&"skip_dependencies"));
        assert!(sources.contains(&"skip_categories"));

        let gate = items.iter().find(|s| s.source == "gate.allow").unwrap();
        assert_eq!(gate.status, Status::Active(15));
        assert_eq!(gate.reason.as_deref(), Some("tracked in JIRA-1"));

        let ign = items.iter().find(|s| s.source == "ignore").unwrap();
        assert!(ign.status.is_lapsed());
        assert!(ign.target.contains("uglify-js"));

        // The blunt forms cannot carry a date, so they are permanent by nature.
        assert!(
            items
                .iter()
                .filter(|s| s.source.starts_with("skip_"))
                .all(|s| s.status == Status::Permanent)
        );
    }
}
