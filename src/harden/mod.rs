//! `postmortem harden` — evaluate a project against the CIRSEC dependency
//! baseline (CB-DEP, <https://baselines.cirsec.org/b/dependencies>).
//!
//! The other commands answer *is something bad in my dependencies right now*.
//! The baseline asks the question one step earlier: *is this project set up so
//! that something bad has a hard time getting in* — a release-age gate, frozen
//! installs, scripts off by default, an approved registry, a pipeline that
//! scans. Most of that is configuration, so most of it can be checked offline.
//!
//! The controls ship embedded (`src/data/cirsec-dependencies.yml`, the
//! upstream YAML verbatim), so the titles, severities, profiles and parameter
//! defaults postmortem reports are the baseline's own, never a paraphrase.
//! Each control is evaluated by one function in [`checks`]; a control with no
//! automated check is reported `manual`, never `pass`.

use std::collections::{BTreeMap, HashMap};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::color::Paint;
use crate::config::HardenConfig;
use crate::model::{DepRef, Dependency, Severity};

/// A lazily compiled, cached regex — compiled once, so it is free inside a
/// loop (clippy's `regex_creation_in_loops` cannot see through the cache).
macro_rules! re {
    ($p:expr) => {{
        fn compile() -> regex::Regex {
            regex::Regex::new($p).unwrap()
        }
        static R: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        R.get_or_init(compile)
    }};
}

pub mod checks;
pub mod repo;

const BUNDLE: &str = include_str!("../data/cirsec-dependencies.yml");
pub const STANDARD: &str = "CIRSEC CB-DEP 1.0.0 (draft)";
pub const STANDARD_URL: &str = "https://baselines.cirsec.org/b/dependencies";

/// The baseline profile. `high` is accepted for `hardened`, since that is how
/// people say it.
#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// What every team consuming third-party packages should do (30 controls).
    Baseline,
    /// Critical or exposed software, and publishers others depend on (36).
    #[value(alias = "high")]
    Hardened,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Baseline => "baseline",
            Level::Hardened => "hardened",
        }
    }

    pub fn parse(s: &str) -> Option<Level> {
        match s {
            "baseline" => Some(Level::Baseline),
            "hardened" | "high" => Some(Level::Hardened),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Control {
    pub id: String,
    pub title: String,
    pub profiles: Vec<String>,
    pub risk: Risk,
    pub assessment: String,
    #[serde(default)]
    pub parameters: Vec<Param>,
    #[serde(default)]
    pub remediation: Option<Remediation>,
}

#[derive(Debug, Deserialize)]
pub struct Risk {
    pub severity: Severity,
}

#[derive(Debug, Deserialize)]
pub struct Remediation {
    #[serde(default)]
    pub manual: String,
}

#[derive(Debug, Deserialize)]
pub struct Param {
    pub name: String,
    pub default: i64,
    #[serde(default)]
    pub profile_defaults: BTreeMap<String, i64>,
    #[serde(default)]
    pub minimum: Option<i64>,
    #[serde(default)]
    pub maximum: Option<i64>,
}

impl Control {
    /// Hardened extends baseline, so a baseline control applies to both.
    pub fn applies(&self, level: Level) -> bool {
        self.profiles.iter().any(|p| p == "baseline")
            || (level == Level::Hardened && self.profiles.iter().any(|p| p == "hardened"))
    }

    /// The domain code: `AGE` in `CB-DEP-AGE-001`.
    pub fn domain(&self) -> &str {
        self.id.split('-').nth(2).unwrap_or("")
    }
}

/// Every control in the embedded bundle, in file order.
pub fn controls() -> Vec<Control> {
    serde_yaml::Deserializer::from_str(BUNDLE)
        .map(|doc| Control::deserialize(doc).expect("embedded CIRSEC bundle is valid"))
        .collect()
}

/// The value of every parameter for `level`: the project's override, else the
/// profile's, else the default. An override outside the baseline's bounds, or
/// for a parameter that does not exist, is an error rather than a silent
/// clamp — a typo in a security setting must not read as compliance.
pub fn resolve_params(
    controls: &[Control],
    level: Level,
    overrides: &BTreeMap<String, i64>,
) -> Result<BTreeMap<String, i64>> {
    let mut out = BTreeMap::new();
    for p in controls.iter().flat_map(|c| &c.parameters) {
        let profile = p.profile_defaults.get(level.as_str()).copied();
        let value = match overrides.get(&p.name) {
            Some(&v) => {
                if p.minimum.is_some_and(|m| v < m) || p.maximum.is_some_and(|m| v > m) {
                    bail!(
                        "[harden.params] {} = {v} is outside the baseline's bounds ({}..={})",
                        p.name,
                        p.minimum.map_or("-".into(), |m| m.to_string()),
                        p.maximum.map_or("-".into(), |m| m.to_string()),
                    );
                }
                v
            }
            None => profile.unwrap_or(p.default),
        };
        out.insert(p.name.clone(), value);
    }
    if let Some(unknown) = overrides.keys().find(|k| !out.contains_key(*k)) {
        bail!(
            "[harden.params] {unknown} is not a baseline parameter (known: {})",
            out.keys().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    Ok(out)
}

/// `{{ name }}` → the parameter's value.
pub fn render_template(text: &str, params: &BTreeMap<String, i64>) -> String {
    re!(r"\{\{\s*([a-z_]+)\s*\}\}")
        .replace_all(text, |c: &regex::Captures| {
            params.get(&c[1]).map_or_else(|| c[0].to_string(), i64::to_string)
        })
        .into_owned()
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Fail,
    /// No automated check, or the evidence a human has to judge.
    Manual,
    /// Nothing in the project the control applies to.
    NotApplicable,
    /// Needs data this run did not collect (`--online`, `--vulns`).
    Skipped,
    /// The project declared it does not apply this control (`[[harden.waive]]`).
    Waived,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Manual => "MANUAL",
            Status::NotApplicable => "N/A",
            Status::Skipped => "SKIP",
            Status::Waived => "WAIVED",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub status: Status,
    pub evidence: Vec<String>,
}

impl Outcome {
    pub fn new(status: Status, evidence: Vec<String>) -> Self {
        Outcome { status, evidence }
    }
}

/// Everything a check may look at.
pub struct Ctx<'a> {
    pub repo: &'a repo::Repo,
    pub pms: &'a [repo::PmUse],
    pub level: Level,
    pub params: &'a BTreeMap<String, i64>,
    pub cfg: &'a HardenConfig,
    pub gate_allow: &'a [crate::config::AllowEntry],
    pub deps: &'a [Dependency],
    /// `--online` resolutions; `None` when the run stayed offline.
    pub online: Option<&'a HashMap<DepRef, crate::resolve::Resolution>>,
    /// `--vulns` results; `None` when no scan ran.
    pub vulns: Option<&'a [crate::vuln::VulnPackage]>,
    pub today: chrono::NaiveDate,
}

impl Ctx<'_> {
    pub fn param(&self, name: &str) -> i64 {
        self.params[name]
    }
}

#[derive(Serialize)]
pub struct Row<'a> {
    pub id: &'a str,
    pub title: &'a str,
    pub severity: Severity,
    pub assessment: &'a str,
    pub status: Status,
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

/// Evaluate every control of `level`.
pub fn evaluate<'a>(controls: &'a [Control], ctx: &Ctx) -> Vec<Row<'a>> {
    controls
        .iter()
        .filter(|c| c.applies(ctx.level))
        .map(|c| {
            let waiver = ctx.cfg.waive.iter().find(|w| w.control == c.id).filter(|w| {
                w.expires
                    .as_deref()
                    .and_then(|e| chrono::NaiveDate::parse_from_str(e, "%Y-%m-%d").ok())
                    .is_none_or(|e| e >= ctx.today)
            });
            let out = match waiver {
                Some(w) => Outcome::new(
                    Status::Waived,
                    vec![match &w.expires {
                        Some(e) => format!("{} (until {e})", w.reason),
                        None => w.reason.clone(),
                    }],
                ),
                None => checks::run(&c.id, ctx),
            };
            let remediation = (out.status == Status::Fail)
                .then(|| c.remediation.as_ref().map(|r| render_template(r.manual.trim(), ctx.params)))
                .flatten();
            Row {
                id: &c.id,
                title: &c.title,
                severity: c.risk.severity,
                assessment: &c.assessment,
                status: out.status,
                evidence: out.evidence,
                remediation,
            }
        })
        .collect()
}

pub fn count(rows: &[Row], s: Status) -> usize {
    rows.iter().filter(|r| r.status == s).count()
}

const DOMAINS: &[(&str, &str)] = &[
    ("SRC", "Sources & registries"),
    ("AGE", "Release age & quarantine"),
    ("LOCK", "Locking & integrity"),
    ("EXEC", "Install-time execution"),
    ("VET", "Dependency vetting"),
    ("VULN", "Vulnerabilities & malicious packages"),
    ("UPD", "Updates"),
    ("INV", "Inventory & provenance"),
    ("CI", "Build environment"),
    ("IR", "Incident response"),
];

pub fn render(rows: &[Row], controls: &[Control], root: &str, level: Level, pms: &[repo::PmUse]) {
    let used: Vec<&str> = {
        let mut v: Vec<&str> = pms.iter().map(|p| p.pm.name()).collect();
        v.dedup();
        v
    };
    println!(
        "{} {}  {}",
        "harden".bold(),
        root,
        format!("{STANDARD} · profile {}", level.as_str()).dimmed()
    );
    if !used.is_empty() {
        println!("{}", format!("package managers: {}", used.join(", ")).dimmed());
    }
    for (code, title) in DOMAINS {
        let in_domain: Vec<&Row> =
            rows.iter().filter(|r| controls.iter().any(|c| c.id == r.id && c.domain() == *code)).collect();
        if in_domain.is_empty() {
            continue;
        }
        println!("\n{}", title.bold());
        for r in in_domain {
            let label = format!("{:<6}", r.status.label());
            let label = match r.status {
                Status::Pass => label.green().to_string(),
                Status::Fail => label.red().bold().to_string(),
                Status::Manual => label.yellow().to_string(),
                Status::Waived => label.cyan().to_string(),
                Status::NotApplicable | Status::Skipped => label.dimmed().to_string(),
            };
            let sev = format!("{:<8}", format!("{:?}", r.severity).to_lowercase());
            println!("  {label} {:<15} {} {}", r.id, sev.dimmed(), r.title);
            for e in &r.evidence {
                if let Some(rest) = e.strip_prefix("✗ ") {
                    println!("         {} {rest}", "✗".red());
                } else if let Some(rest) = e.strip_prefix("✓ ") {
                    println!("         {} {rest}", "✓".green());
                } else if let Some(rest) = e.strip_prefix("? ") {
                    println!("         {} {rest}", "?".yellow());
                } else {
                    println!("         {} {}", "·".dimmed(), e.dimmed());
                }
            }
            if let Some(fix) = &r.remediation {
                for line in fix.lines() {
                    println!("         {} {}", "↳".yellow(), line);
                }
            }
        }
    }
    let (pass, fail) = (count(rows, Status::Pass), count(rows, Status::Fail));
    println!(
        "\n{} controls: {} pass, {} fail, {} manual, {} skipped, {} n/a, {} waived",
        rows.len(),
        pass.green(),
        if fail > 0 { fail.red().bold().to_string() } else { fail.to_string() },
        count(rows, Status::Manual),
        count(rows, Status::Skipped),
        count(rows, Status::NotApplicable),
        count(rows, Status::Waived),
    );
    if count(rows, Status::Skipped) > 0 {
        println!("{}", "skipped controls need --online (registry history) or --vulns (advisories)".dimmed());
    }
    println!("{}", STANDARD_URL.dimmed());
}

/// `harden info`: the catalogue — every control, its severity and profile,
/// how CIRSEC rates its assessability, and what postmortem actually checks.
pub fn render_info(controls: &[Control], level: Option<Level>) {
    use checks::Support;
    println!("{} {}", STANDARD.bold(), STANDARD_URL.dimmed());
    println!(
        "{}",
        "profile: baseline = every team (also in hardened) · hardened = critical software only".dimmed()
    );
    println!(
        "{}",
        "postmortem: auto = offline · online = needs --online · partial = part checked · manual = not automated".dimmed()
    );
    let shown: Vec<&Control> = controls.iter().filter(|c| level.is_none_or(|l| c.applies(l))).collect();
    for (code, title) in DOMAINS {
        let in_domain: Vec<&&Control> = shown.iter().filter(|c| c.domain() == *code).collect();
        if in_domain.is_empty() {
            continue;
        }
        println!("\n{}", title.bold());
        for c in in_domain {
            let (sup, note) = checks::support(&c.id).unwrap_or((Support::None, ""));
            let label = format!("{:<7}", sup.as_str());
            let label = match sup {
                Support::Auto => label.green().to_string(),
                Support::Online => label.cyan().to_string(),
                Support::Partial => label.yellow().to_string(),
                Support::None => label.dimmed().to_string(),
            };
            let sev = format!("{:<8}", format!("{:?}", c.risk.severity).to_lowercase());
            let sev = match c.risk.severity {
                Severity::Critical | Severity::High => sev.red().to_string(),
                Severity::Medium => sev.yellow().to_string(),
                _ => sev.dimmed().to_string(),
            };
            let profile = if c.profiles.iter().any(|p| p == "baseline") { "baseline" } else { "hardened" };
            println!("  {label} {:<15} {sev} {:<8} {}", c.id, profile, c.title);
            let params: Vec<String> = c
                .parameters
                .iter()
                .map(|p| match p.profile_defaults.get("hardened") {
                    Some(h) => format!("{} = {} (hardened {h})", p.name, p.default),
                    None => format!("{} = {}", p.name, p.default),
                })
                .collect();
            println!(
                "          {}",
                format!("CIRSEC assessment: {} · postmortem: {note}", c.assessment).dimmed()
            );
            if !params.is_empty() {
                println!("          {}", format!("parameters: {}", params.join(", ")).dimmed());
            }
        }
    }
    let n = |s: Support| shown.iter().filter(|c| checks::support(&c.id).is_some_and(|(x, _)| x == s)).count();
    println!(
        "\n{} controls{}: {} auto, {} online, {} partial, {} manual",
        shown.len(),
        level.map_or(String::new(), |l| format!(" in {}", l.as_str())),
        n(Support::Auto).green(),
        n(Support::Online).cyan(),
        n(Support::Partial).yellow(),
        n(Support::None),
    );
}

pub fn info_json(controls: &[Control], level: Option<Level>) -> serde_json::Value {
    let rows: Vec<serde_json::Value> = controls
        .iter()
        .filter(|c| level.is_none_or(|l| c.applies(l)))
        .map(|c| {
            let (sup, note) = checks::support(&c.id).unwrap_or((checks::Support::None, ""));
            serde_json::json!({
                "id": c.id,
                "title": c.title,
                "domain": c.domain(),
                "severity": c.risk.severity,
                "profile": if c.profiles.iter().any(|p| p == "baseline") { "baseline" } else { "hardened" },
                "cirsec_assessment": c.assessment,
                "postmortem": sup,
                "postmortem_checks": note,
                "parameters": c.parameters.iter().map(|p| serde_json::json!({
                    "name": p.name, "default": p.default, "profile_defaults": p.profile_defaults,
                    "minimum": p.minimum, "maximum": p.maximum,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    serde_json::json!({ "standard": STANDARD, "url": STANDARD_URL, "controls": rows })
}

pub fn to_json(rows: &[Row], root: &str, level: Level, params: &BTreeMap<String, i64>) -> serde_json::Value {
    serde_json::json!({
        "standard": STANDARD,
        "url": STANDARD_URL,
        "root": root,
        "level": level,
        "parameters": params,
        "summary": {
            "controls": rows.len(),
            "pass": count(rows, Status::Pass),
            "fail": count(rows, Status::Fail),
            "manual": count(rows, Status::Manual),
            "skipped": count(rows, Status::Skipped),
            "not_applicable": count(rows, Status::NotApplicable),
            "waived": count(rows, Status::Waived),
        },
        "controls": rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_loads_with_profiles() {
        let c = controls();
        assert_eq!(c.len(), 36);
        assert_eq!(c.iter().filter(|c| c.applies(Level::Baseline)).count(), 30);
        assert_eq!(c.iter().filter(|c| c.applies(Level::Hardened)).count(), 36);
        // Every control has a check or an explicit manual verdict.
        for c in &c {
            assert!(checks::support(&c.id).is_some(), "{} has no entry in checks::SUPPORT", c.id);
        }
    }

    #[test]
    fn params_follow_profile_then_override_with_bounds() {
        let c = controls();
        let none = BTreeMap::new();
        assert_eq!(resolve_params(&c, Level::Baseline, &none).unwrap()["min_release_age_hours"], 48);
        assert_eq!(resolve_params(&c, Level::Hardened, &none).unwrap()["min_release_age_hours"], 72);
        let ok = BTreeMap::from([("min_release_age_hours".to_string(), 96)]);
        assert_eq!(resolve_params(&c, Level::Baseline, &ok).unwrap()["min_release_age_hours"], 96);
        let low = BTreeMap::from([("min_release_age_hours".to_string(), 1)]);
        assert!(resolve_params(&c, Level::Baseline, &low).is_err(), "below the 24h floor");
        let typo = BTreeMap::from([("min_release_age".to_string(), 48)]);
        assert!(resolve_params(&c, Level::Baseline, &typo).is_err());
    }

    #[test]
    fn templates_render() {
        let p = BTreeMap::from([("min_release_age_hours".to_string(), 72)]);
        assert_eq!(render_template("at least {{ min_release_age_hours }} hours", &p), "at least 72 hours");
    }
}
