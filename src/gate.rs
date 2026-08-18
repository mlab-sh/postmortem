//! `postmortem tree` CI gate — turn the online risk scores and the `--vulns`
//! scan into a pass/fail decision with an auditable, expirable allowlist.
//!
//! The gate is intentionally a thin, pure layer over the already-computed
//! [`Tree`]: every threshold maps to a number gochi's recap already prints
//! (overall `risk`/`dep`, the high-risk / suspicious head-counts, the known-vuln
//! total). A threshold is a *ceiling* — the gate trips when the measured value is
//! strictly greater than the limit, so `max_high = 0` means "no high-risk deps
//! tolerated". Allowlisted packages are excluded from every count but stay
//! visible in the tree; an entry past its `expires` date stops bypassing and is
//! surfaced as a warning, so a stale exception can never silently hide a risk.

use std::collections::HashSet;

use anyhow::{Context, Result};
use chrono::NaiveDate;
use serde::Deserialize;

use crate::model::Severity;
use crate::tree::{Node, Tree};

/// A resolved gate policy (config file merged with CLI overrides). Every field
/// is optional: an unset threshold is simply not enforced.
#[derive(Debug, Default, Clone)]
pub struct Policy {
    /// Trip if the worst own-risk score in the forest exceeds this (0–100).
    pub max_risk: Option<u8>,
    /// Trip if any dependency's subtree (`dep`) score exceeds this (0–100).
    pub max_dep: Option<u8>,
    /// Trip if more than this many high-risk deps are present.
    pub max_high: Option<usize>,
    /// Trip if more than this many suspicious deps are present.
    pub max_sus: Option<usize>,
    /// Trip if more than this many known vulnerabilities are present.
    pub max_vulns: Option<usize>,
    /// Trip if any known vulnerability is at least this severe.
    pub fail_on_vuln: Option<Severity>,
    /// Packages exempted from every count (name or `name@version`).
    pub allow: Vec<Allow>,
}

/// One allowlist entry. `expires` is a `YYYY-MM-DD` date; once past, the entry
/// no longer bypasses and is reported so the exception gets revisited.
#[derive(Debug, Clone)]
pub struct Allow {
    pub package: String,
    #[allow(dead_code)]
    pub reason: Option<String>,
    pub expires: Option<String>,
}

impl Policy {
    /// Whether any threshold is set — i.e. the gate should run at all.
    pub fn is_active(&self) -> bool {
        self.max_risk.is_some()
            || self.max_dep.is_some()
            || self.max_high.is_some()
            || self.max_sus.is_some()
            || self.needs_vulns()
    }

    /// The score-based thresholds require `tree --online` to have produced scores.
    pub fn needs_scores(&self) -> bool {
        self.max_risk.is_some()
            || self.max_dep.is_some()
            || self.max_high.is_some()
            || self.max_sus.is_some()
    }

    /// The vuln thresholds require `tree --vulns`.
    pub fn needs_vulns(&self) -> bool {
        self.max_vulns.is_some() || self.fail_on_vuln.is_some()
    }
}

/// The measured state of the forest, after allowlist exclusion.
#[derive(Debug, Default, Clone)]
pub struct Metrics {
    pub risk: u8,
    pub dep: u8,
    pub high: usize,
    pub sus: usize,
    pub unchecked: usize,
    pub vulns: usize,
    pub worst_vuln: Option<Severity>,
    /// Distinct flagged/vulnerable packages an allowlist entry bypassed.
    pub bypassed: usize,
    /// Flagged deps / vulns skipped because they were already in the baseline.
    pub baseline_suppressed: usize,
}

/// A single breached threshold, ready to print.
#[derive(Debug, Clone)]
pub struct Violation {
    pub metric: &'static str,
    pub actual: String,
    pub limit: String,
}

/// The outcome of one gate evaluation.
#[derive(Debug, Default, Clone)]
pub struct Outcome {
    pub metrics: Metrics,
    pub violations: Vec<Violation>,
    /// Allowlist entries ignored because they are past their `expires` date (or
    /// carry an unparseable date) — surfaced as warnings.
    pub expired_allows: Vec<String>,
}

impl Outcome {
    pub fn tripped(&self) -> bool {
        !self.violations.is_empty()
    }
}

/// A prior `tree --json` snapshot, reduced to the risk it already carried. In
/// diff mode the gate counts only risk **absent** from this set — so a build
/// fails on *newly introduced* risk, not on pre-existing debt.
#[derive(Debug, Default)]
pub struct Baseline {
    /// `(name, version)` of deps that were already flagged.
    flagged: HashSet<(String, String)>,
    /// `(name, version, advisory-id)` of vulns already known.
    vulns: HashSet<(String, String, String)>,
}

// Minimal projections of the `tree --json` schema — just the fields the diff
// needs. Kept local so the baseline loader doesn't force `Deserialize` onto the
// whole `Tree`/`Node` surface.
#[derive(Deserialize)]
struct BaseNode {
    name: String,
    version: String,
    #[serde(default)]
    severity: Option<Severity>,
    #[serde(default)]
    children: Vec<BaseNode>,
}
#[derive(Deserialize)]
struct BaseVulnId {
    id: String,
}
#[derive(Deserialize)]
struct BaseVulnPkg {
    name: String,
    version: String,
    #[serde(default)]
    vulns: Vec<BaseVulnId>,
}
#[derive(Deserialize)]
struct BaseTree {
    #[serde(default)]
    roots: Vec<BaseNode>,
    #[serde(default)]
    vulnerabilities: Vec<BaseVulnPkg>,
}

impl Baseline {
    /// Load a baseline from a `tree --json` file.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading baseline {}", path.display()))?;
        let parsed: BaseTree = serde_json::from_str(&text).with_context(|| {
            format!(
                "parsing baseline {} (expected `tree --json` output)",
                path.display()
            )
        })?;
        let mut b = Baseline::default();
        fn walk(n: &BaseNode, b: &mut Baseline) {
            if n.severity.is_some() {
                b.flagged.insert((n.name.clone(), n.version.clone()));
            }
            for c in &n.children {
                walk(c, b);
            }
        }
        for r in &parsed.roots {
            walk(r, &mut b);
        }
        for p in &parsed.vulnerabilities {
            for v in &p.vulns {
                b.vulns
                    .insert((p.name.clone(), p.version.clone(), v.id.clone()));
            }
        }
        Ok(b)
    }

    fn has_flagged(&self, name: &str, version: &str) -> bool {
        self.flagged
            .contains(&(name.to_string(), version.to_string()))
    }
    fn has_vuln(&self, name: &str, version: &str, id: &str) -> bool {
        self.vulns
            .contains(&(name.to_string(), version.to_string(), id.to_string()))
    }
}

/// Split a package spec into `(name, Option<version>)`, tolerating scoped npm
/// names whose own `@` must not be read as a version separator
/// (`@scope/pkg` → no version, `@scope/pkg@1.2.3` → `1.2.3`).
fn split_spec(spec: &str) -> (&str, Option<&str>) {
    match spec.rfind('@') {
        None | Some(0) => (spec, None),
        Some(i) => (&spec[..i], Some(&spec[i + 1..])),
    }
}

/// Does an allowlist `pattern` cover this `name@version`? A bare-name pattern
/// matches every version; a versioned pattern must match exactly.
fn spec_matches(pattern: &str, name: &str, version: &str) -> bool {
    let (pn, pv) = split_spec(pattern);
    pn == name && pv.is_none_or(|v| v == version)
}

/// Evaluate `policy` against `tree` as of `today`, optionally in diff mode
/// against `baseline` (count only newly-introduced risk). Pure: `today` is
/// injected so allowlist-expiry logic stays deterministic in tests.
pub fn evaluate(
    policy: &Policy,
    tree: &Tree,
    today: NaiveDate,
    baseline: Option<&Baseline>,
) -> Outcome {
    // Partition the allowlist into still-effective patterns and expired ones.
    // The date logic is `crate::config`'s, shared with the scan suppressions —
    // a date that lapses in one place must lapse in the other.
    let mut effective: Vec<&str> = Vec::new();
    let mut expired: Vec<String> = Vec::new();
    for a in &policy.allow {
        match crate::config::expiry_status(a.expires.as_deref(), today) {
            crate::config::Status::Permanent | crate::config::Status::Active(_) => {
                effective.push(&a.package)
            }
            crate::config::Status::Expired(d) => {
                expired.push(format!("{} (expired {d})", a.package))
            }
            crate::config::Status::Invalid(raw) => {
                expired.push(format!("{} (invalid expires \"{raw}\")", a.package))
            }
        }
    }
    let allowed = |name: &str, version: &str| -> bool {
        effective.iter().any(|p| spec_matches(p, name, version))
    };

    let mut m = Metrics::default();
    let mut seen = HashSet::new();
    let mut bypassed = HashSet::new();

    fn walk(
        node: &Node,
        allowed: &impl Fn(&str, &str) -> bool,
        baseline: Option<&Baseline>,
        seen: &mut HashSet<(String, String)>,
        bypassed: &mut HashSet<(String, String)>,
        m: &mut Metrics,
    ) {
        let key = (node.name.clone(), node.version.clone());
        if allowed(&node.name, &node.version) {
            // Allowlisted: count it as a bypass only if it *would* have counted.
            if node.severity.is_some() {
                bypassed.insert(key);
            }
        } else if baseline.is_some_and(|b| b.has_flagged(&node.name, &node.version)) {
            // Pre-existing risk in diff mode — not counted, but tracked.
            if node.severity.is_some() {
                m.baseline_suppressed += 1;
            }
        } else if seen.insert(key) {
            m.risk = m.risk.max(node.risk.unwrap_or(0));
            m.dep = m.dep.max(node.dep.unwrap_or(0));
            match node.severity {
                Some(Severity::Critical | Severity::High) => m.high += 1,
                Some(Severity::Medium | Severity::Low) => m.sus += 1,
                Some(Severity::Info) => m.unchecked += 1,
                None => {}
            }
        }
        for c in &node.children {
            walk(c, allowed, baseline, seen, bypassed, m);
        }
    }
    for root in &tree.roots {
        walk(root, &allowed, baseline, &mut seen, &mut bypassed, &mut m);
    }

    // Vulns are keyed by package, independent of the graph walk.
    for p in &tree.vulnerabilities {
        if allowed(&p.name, &p.version) {
            if !p.vulns.is_empty() {
                bypassed.insert((p.name.clone(), p.version.clone()));
            }
            continue;
        }
        for v in &p.vulns {
            if baseline.is_some_and(|b| b.has_vuln(&p.name, &p.version, &v.id)) {
                m.baseline_suppressed += 1;
                continue;
            }
            m.vulns += 1;
            m.worst_vuln = Some(m.worst_vuln.map_or(v.severity, |cur| cur.max(v.severity)));
        }
    }
    m.bypassed = bypassed.len();

    // Compare against the ceilings.
    let mut violations = Vec::new();
    let mut over_count = |metric: &'static str, actual: usize, limit: Option<usize>| {
        if let Some(l) = limit
            && actual > l
        {
            violations.push(Violation {
                metric,
                actual: actual.to_string(),
                limit: l.to_string(),
            });
        }
    };
    over_count("high-risk deps", m.high, policy.max_high);
    over_count("suspicious deps", m.sus, policy.max_sus);
    over_count("known vulns", m.vulns, policy.max_vulns);

    if let Some(l) = policy.max_risk
        && m.risk > l
    {
        violations.push(Violation {
            metric: "risk score",
            actual: format!("{}/100", m.risk),
            limit: format!("{l}/100"),
        });
    }
    if let Some(l) = policy.max_dep
        && m.dep > l
    {
        violations.push(Violation {
            metric: "dep score",
            actual: format!("{}/100", m.dep),
            limit: format!("{l}/100"),
        });
    }
    if let (Some(threshold), Some(worst)) = (policy.fail_on_vuln, m.worst_vuln)
        && worst >= threshold
    {
        violations.push(Violation {
            metric: "vuln severity",
            actual: format!("{worst:?}"),
            limit: format!("≥ {threshold:?}"),
        });
    }

    Outcome {
        metrics: m,
        violations,
        expired_allows: expired,
    }
}

/// Render the gate result to stderr — a compact PASS/FAIL block that keeps the
/// exit-code decision human-readable in CI logs. Written to stderr so it never
/// corrupts `--json` on stdout.
pub fn report(outcome: &Outcome, policy: &Policy) {
    use owo_colors::OwoColorize;

    for e in &outcome.expired_allows {
        eprintln!(
            "  {} allowlist entry {} — no longer bypassing",
            "⚠".yellow().bold(),
            e.yellow()
        );
    }

    let m = &outcome.metrics;
    let head = if outcome.tripped() {
        format!(
            "gate FAIL — {} threshold(s) exceeded",
            outcome.violations.len()
        )
        .red()
        .bold()
        .to_string()
    } else {
        "gate PASS".green().bold().to_string()
    };
    eprintln!("\n  {head}");

    // One grep-friendly line per breached threshold (actual > limit).
    for v in &outcome.violations {
        eprintln!(
            "    {} {:<16} {} {} {}",
            "✗".red().bold(),
            v.metric,
            v.actual.red().bold(),
            ">".dimmed(),
            format!("max {}", v.limit).dimmed(),
        );
    }

    // A compact summary of every gate that was checked, so a PASS still shows
    // the numbers behind it.
    let mut checked: Vec<String> = Vec::new();
    if policy.max_risk.is_some() {
        checked.push(format!("risk {}/100", m.risk));
    }
    if policy.max_dep.is_some() {
        checked.push(format!("dep {}/100", m.dep));
    }
    if policy.max_high.is_some() {
        checked.push(format!("high {}", m.high));
    }
    if policy.max_sus.is_some() {
        checked.push(format!("sus {}", m.sus));
    }
    if policy.max_vulns.is_some() || policy.fail_on_vuln.is_some() {
        let worst = m
            .worst_vuln
            .map(|w| format!(", worst {w:?}"))
            .unwrap_or_default();
        checked.push(format!("vulns {}{worst}", m.vulns));
    }
    if !checked.is_empty() {
        eprintln!("    {}", checked.join(" · ").dimmed());
    }
    if m.bypassed > 0 {
        eprintln!(
            "    {}",
            format!("{} package(s) bypassed via allowlist", m.bypassed).dimmed()
        );
    }
    if m.baseline_suppressed > 0 {
        eprintln!(
            "    {}",
            format!(
                "{} pre-existing item(s) ignored via baseline",
                m.baseline_suppressed
            )
            .dimmed()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::{Node, Stats, Tree};
    use crate::vuln::{Vuln, VulnPackage};

    fn today() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 8, 4).unwrap()
    }

    fn node(name: &str, sev: Option<Severity>, risk: u8, dep: u8) -> Node {
        Node {
            name: name.into(),
            version: "1.0.0".into(),
            ecosystem: "node".into(),
            direct: true,
            deduped: false,
            truncated: false,
            repo: None,
            stars: None,
            signals: if sev.is_some() {
                vec!["low-stars".into()]
            } else {
                vec![]
            },
            severity: sev,
            risk: Some(risk),
            dep: Some(dep),
            language: None,
            languages: None,
            children: vec![],
        }
    }

    fn tree(roots: Vec<Node>, vulns: Vec<VulnPackage>) -> Tree {
        Tree {
            root: "proj".into(),
            ecosystems: vec!["node".into()],
            stats: Stats {
                total: 0,
                direct: 0,
                transitive: 0,
                max_depth: 0,
                deduped: 0,
            },
            diagnostics: vec![],
            vulnerabilities: vulns,
            scored: true,
            roots,
        }
    }

    fn vuln_pkg(name: &str, sev: Severity) -> VulnPackage {
        VulnPackage {
            name: name.into(),
            version: "1.0.0".into(),
            ecosystem: "node".into(),
            vulns: vec![Vuln {
                id: "CVE-0000-0000".into(),
                severity: sev,
                summary: String::new(),
                fixed: None,
            }],
        }
    }

    #[test]
    fn counts_high_and_suspicious_deduped() {
        let t = tree(
            vec![
                node("a", Some(Severity::High), 90, 0),
                node("b", Some(Severity::Medium), 30, 0),
                // duplicate of a — must not double count
                node("a", Some(Severity::High), 90, 0),
            ],
            vec![],
        );
        let p = Policy {
            max_high: Some(0),
            max_sus: Some(5),
            ..Default::default()
        };
        let o = evaluate(&p, &t, today(), None);
        assert_eq!(o.metrics.high, 1);
        assert_eq!(o.metrics.sus, 1);
        assert!(o.tripped()); // max_high=0 but one high present
        assert_eq!(o.violations.len(), 1);
        assert_eq!(o.violations[0].metric, "high-risk deps");
    }

    #[test]
    fn risk_ceiling_is_strict_greater_than() {
        let t = tree(vec![node("a", Some(Severity::High), 80, 0)], vec![]);
        // exactly at the ceiling passes; one above fails.
        assert!(
            !evaluate(
                &Policy {
                    max_risk: Some(80),
                    ..Default::default()
                },
                &t,
                today(),
                None
            )
            .tripped()
        );
        assert!(
            evaluate(
                &Policy {
                    max_risk: Some(79),
                    ..Default::default()
                },
                &t,
                today(),
                None
            )
            .tripped()
        );
    }

    #[test]
    fn allowlist_excludes_from_counts_and_bypass_is_reported() {
        let t = tree(vec![node("evil", Some(Severity::High), 99, 0)], vec![]);
        let p = Policy {
            max_high: Some(0),
            allow: vec![Allow {
                package: "evil".into(),
                reason: None,
                expires: None,
            }],
            ..Default::default()
        };
        let o = evaluate(&p, &t, today(), None);
        assert_eq!(o.metrics.high, 0);
        assert_eq!(o.metrics.risk, 0, "allowlisted risk excluded");
        assert_eq!(o.metrics.bypassed, 1);
        assert!(!o.tripped());
    }

    #[test]
    fn versioned_allow_only_matches_that_version() {
        let mut n = node("evil", Some(Severity::High), 99, 0);
        n.version = "2.0.0".into();
        let t = tree(vec![n], vec![]);
        let p = Policy {
            max_high: Some(0),
            allow: vec![Allow {
                package: "evil@1.0.0".into(),
                reason: None,
                expires: None,
            }],
            ..Default::default()
        };
        // allow is for 1.0.0, dep is 2.0.0 → still counts → trips
        assert!(evaluate(&p, &t, today(), None).tripped());
    }

    #[test]
    fn expired_allow_stops_bypassing_and_is_flagged() {
        let t = tree(vec![node("evil", Some(Severity::High), 99, 0)], vec![]);
        let p = Policy {
            max_high: Some(0),
            allow: vec![Allow {
                package: "evil".into(),
                reason: None,
                expires: Some("2020-01-01".into()),
            }],
            ..Default::default()
        };
        let o = evaluate(&p, &t, today(), None);
        assert_eq!(o.metrics.high, 1, "expired allow no longer excludes");
        assert!(o.tripped());
        assert_eq!(o.expired_allows.len(), 1);
    }

    #[test]
    fn scoped_name_not_split_on_leading_at() {
        // "@scope/pkg" must match a bare-name allow, not be read as version.
        let t = tree(
            vec![node("@scope/pkg", Some(Severity::High), 99, 0)],
            vec![],
        );
        let p = Policy {
            max_high: Some(0),
            allow: vec![Allow {
                package: "@scope/pkg".into(),
                reason: None,
                expires: None,
            }],
            ..Default::default()
        };
        assert!(!evaluate(&p, &t, today(), None).tripped());
    }

    #[test]
    fn vuln_count_and_severity_gates() {
        let t = tree(
            vec![node("a", None, 0, 0)],
            vec![vuln_pkg("a", Severity::High), vuln_pkg("b", Severity::Low)],
        );
        // 2 vulns total; max_vulns=1 → trips on count
        let o = evaluate(
            &Policy {
                max_vulns: Some(1),
                ..Default::default()
            },
            &t,
            today(),
            None,
        );
        assert_eq!(o.metrics.vulns, 2);
        assert!(o.tripped());
        // severity gate: worst is High, fail_on_vuln=High → trips
        let o = evaluate(
            &Policy {
                fail_on_vuln: Some(Severity::High),
                ..Default::default()
            },
            &t,
            today(),
            None,
        );
        assert_eq!(o.metrics.worst_vuln, Some(Severity::High));
        assert!(o.tripped());
        // fail_on_vuln=Critical → High doesn't reach it → passes
        let o = evaluate(
            &Policy {
                fail_on_vuln: Some(Severity::Critical),
                ..Default::default()
            },
            &t,
            today(),
            None,
        );
        assert!(!o.tripped());
    }

    #[test]
    fn allowlisted_vuln_excluded() {
        let t = tree(
            vec![node("a", None, 0, 0)],
            vec![vuln_pkg("a", Severity::Critical)],
        );
        let p = Policy {
            fail_on_vuln: Some(Severity::High),
            allow: vec![Allow {
                package: "a".into(),
                reason: None,
                expires: None,
            }],
            ..Default::default()
        };
        let o = evaluate(&p, &t, today(), None);
        assert_eq!(o.metrics.vulns, 0);
        assert!(!o.tripped());
    }

    #[test]
    fn baseline_counts_only_new_risk() {
        let t = tree(
            vec![
                node("old-bad", Some(Severity::High), 90, 0),
                node("new-bad", Some(Severity::High), 95, 0),
            ],
            vec![],
        );
        let mut base = Baseline::default();
        base.flagged.insert(("old-bad".into(), "1.0.0".into()));
        let p = Policy {
            max_high: Some(0),
            ..Default::default()
        };
        // no baseline: both high deps count → trips on 2 > 0
        assert!(evaluate(&p, &t, today(), None).tripped());
        // with baseline: old-bad is pre-existing → only new-bad counts
        let o = evaluate(&p, &t, today(), Some(&base));
        assert_eq!(o.metrics.high, 1);
        assert_eq!(o.metrics.baseline_suppressed, 1);
        assert!(o.tripped()); // 1 new high > 0
    }

    #[test]
    fn baseline_passes_when_no_new_risk() {
        let t = tree(vec![node("old-bad", Some(Severity::High), 90, 0)], vec![]);
        let mut base = Baseline::default();
        base.flagged.insert(("old-bad".into(), "1.0.0".into()));
        let p = Policy {
            max_high: Some(0),
            max_risk: Some(0),
            ..Default::default()
        };
        let o = evaluate(&p, &t, today(), Some(&base));
        assert_eq!(o.metrics.high, 0);
        assert_eq!(
            o.metrics.risk, 0,
            "a baselined dep's risk score is not counted"
        );
        assert!(!o.tripped());
    }

    #[test]
    fn baseline_ignores_known_vuln_but_catches_new_one() {
        let t = tree(
            vec![node("a", None, 0, 0)],
            vec![vuln_pkg("a", Severity::High), vuln_pkg("b", Severity::High)],
        );
        let mut base = Baseline::default();
        base.vulns
            .insert(("a".into(), "1.0.0".into(), "CVE-0000-0000".into()));
        let p = Policy {
            max_vulns: Some(0),
            ..Default::default()
        };
        let o = evaluate(&p, &t, today(), Some(&base));
        assert_eq!(o.metrics.vulns, 1, "only b's vuln is new");
        assert!(o.tripped());
    }
}
