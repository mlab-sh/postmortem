//! `postmortem diff` — compare the resolved dependency sets of two project states
//! (e.g. two branches / commits checked out side by side) and report what changed:
//! packages **added**, **removed**, or **version-changed**. This is the signal a
//! reviewer actually wants on a lockfile change ("what did this PR pull in?"), and
//! the natural companion to the CI `gate`'s `--baseline` mode.
//!
//! Offline it is a set-diff. With `--online` / `--vulns` it also *assesses what
//! the change introduces* — the reputation signals and known advisories of the
//! packages this branch adds — which is the question a reviewer is actually
//! asking. Only additions and version changes are assessed: a removed package's
//! risk is moot, and the work then scales with the change rather than the tree.

use std::collections::HashMap;

use owo_colors::OwoColorize;

use crate::model::{DepRef, Dependency, Ecosystem, Severity};
use crate::resolve::Resolution;
use crate::vuln::{Vuln, VulnPackage};

/// One package identity across the two sides: its ecosystem + name.
type Key = (Ecosystem, String);

/// What `--online` / `--vulns` found about a package this diff introduces.
///
/// Only additions and version changes carry one. A *removed* package is the one
/// case where its risk does not matter — it is gone, which is the good outcome.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Assessment {
    /// Risk score 0–100 from the source-repo assessment (`--online`).
    pub risk: Option<u8>,
    /// Worst signal severity, which drives the colour.
    pub severity: Option<Severity>,
    /// Signals raised: `typosquat of x`, `new-publisher`, `fresh-release (6h)`, …
    pub signals: Vec<String>,
    /// Known advisories against this exact version (`--vulns`).
    pub vulns: Vec<Vuln>,
}

impl Assessment {
    /// Nothing was measured, or nothing was found.
    pub fn is_quiet(&self) -> bool {
        self.signals.is_empty() && self.vulns.is_empty()
    }

    /// The worst advisory severity, if any.
    pub fn worst_vuln(&self) -> Option<Severity> {
        self.vulns.iter().map(|v| v.severity).max()
    }
}

/// A package present in `new` and absent from `old`.
#[derive(Debug, Clone, PartialEq)]
pub struct Added {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub assessment: Assessment,
}

/// A package present in `old` and absent from `new`.
#[derive(Debug, Clone, PartialEq)]
pub struct Removed {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
}

/// A package present on both sides at a different version.
#[derive(Debug, Clone, PartialEq)]
pub struct Changed {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub from: String,
    pub to: String,
    pub assessment: Assessment,
}

/// The result of comparing two dependency sets.
#[derive(Debug, Default, PartialEq)]
pub struct DiffReport {
    pub added: Vec<Added>,
    pub removed: Vec<Removed>,
    pub changed: Vec<Changed>,
    /// Count of packages present at the same version on both sides.
    pub unchanged: usize,
}

impl DiffReport {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }

    /// Every package this diff *introduces*, as `(ecosystem, name, version)` —
    /// the set worth assessing, since it is the new attack surface.
    pub fn introduced(&self) -> Vec<(Ecosystem, String, String)> {
        self.added
            .iter()
            .map(|a| (a.ecosystem, a.name.clone(), a.version.clone()))
            .chain(self.changed.iter().map(|c| (c.ecosystem, c.name.clone(), c.to.clone())))
            .collect()
    }

    /// Did anything introduced raise a signal or carry an advisory?
    pub fn has_findings(&self) -> bool {
        self.added.iter().any(|a| !a.assessment.is_quiet())
            || self.changed.iter().any(|c| !c.assessment.is_quiet())
    }
}

/// The `diff --json` document.
///
/// The three lists carry the ecosystem alongside the name, because the same
/// package name can legitimately exist in two ecosystems of one project and a
/// consumer must not conflate them.
pub fn to_json(r: &DiffReport, old: &str, new: &str) -> serde_json::Value {
    let assessment = |a: &Assessment| {
        // Absent rather than zeroed when nothing was measured: `--online` and
        // `--vulns` are opt-in, and "not checked" is not "clean".
        let mut m = serde_json::Map::new();
        if let Some(r) = a.risk {
            m.insert("risk".into(), r.into());
        }
        if !a.signals.is_empty() {
            m.insert("signals".into(), serde_json::json!(a.signals));
        }
        if !a.vulns.is_empty() {
            m.insert("vulnerabilities".into(), serde_json::json!(a.vulns));
        }
        (!m.is_empty()).then_some(serde_json::Value::Object(m))
    };
    serde_json::json!({
        "schema_version": 2,
        "old": old,
        "new": new,
        "summary": {
            "added": r.added.len(),
            "removed": r.removed.len(),
            "changed": r.changed.len(),
            "unchanged": r.unchanged,
        },
        "added": r.added.iter().map(|a| serde_json::json!({
            "ecosystem": a.ecosystem,
            "name": a.name,
            "version": a.version,
            "assessment": assessment(&a.assessment),
        })).collect::<Vec<_>>(),
        "removed": r.removed.iter().map(|x| serde_json::json!({
            "ecosystem": x.ecosystem,
            "name": x.name,
            "version": x.version,
        })).collect::<Vec<_>>(),
        "changed": r.changed.iter().map(|c| serde_json::json!({
            "ecosystem": c.ecosystem,
            "name": c.name,
            "from": c.from,
            "to": c.to,
            "assessment": assessment(&c.assessment),
        })).collect::<Vec<_>>(),
    })
}

/// Index a dependency list by `(ecosystem, name)` → version. Duplicate keys (the
/// same package pinned twice) keep the first version seen.
fn index(deps: &[Dependency]) -> std::collections::BTreeMap<Key, String> {
    let mut map = std::collections::BTreeMap::new();
    for d in deps {
        map.entry((d.ecosystem, d.name.clone())).or_insert_with(|| d.version.clone());
    }
    map
}

/// Compare two resolved dependency sets.
pub fn diff(old: &[Dependency], new: &[Dependency]) -> DiffReport {
    let (old, new) = (index(old), index(new));
    let mut report = DiffReport::default();
    for ((eco, name), nv) in &new {
        match old.get(&(*eco, name.clone())) {
            None => report.added.push(Added {
                ecosystem: *eco,
                name: name.clone(),
                version: nv.clone(),
                assessment: Assessment::default(),
            }),
            Some(ov) if ov == nv => report.unchanged += 1,
            Some(ov) => report.changed.push(Changed {
                ecosystem: *eco,
                name: name.clone(),
                from: ov.clone(),
                to: nv.clone(),
                assessment: Assessment::default(),
            }),
        }
    }
    for ((eco, name), ov) in &old {
        if !new.contains_key(&(*eco, name.clone())) {
            report.removed.push(Removed {
                ecosystem: *eco,
                name: name.clone(),
                version: ov.clone(),
            });
        }
    }
    report
}

/// Attach the online assessment and known advisories to everything the diff
/// introduces.
///
/// Only additions and changes are assessed — a removed package's risk is moot.
/// That also keeps the work proportional to the *change*, not to the tree: a
/// one-package bump resolves one package, not five hundred.
pub fn assess(
    report: &mut DiffReport,
    resolutions: &HashMap<DepRef, Resolution>,
    vulns: &[VulnPackage],
) {
    let find = |name: &str, version: &str| -> Assessment {
        let mut a = Assessment::default();
        if let Some(res) = resolutions.get(&(name.to_string(), version.to_string())) {
            a.risk = Some(res.risk);
            a.severity = res.worst;
            a.signals = res.signals.clone();
        }
        if let Some(p) = vulns.iter().find(|p| p.name == name && p.version == version) {
            a.vulns = p.vulns.clone();
        }
        a
    };
    for x in &mut report.added {
        x.assessment = find(&x.name, &x.version);
    }
    for c in &mut report.changed {
        c.assessment = find(&c.name, &c.to);
    }
}

/// Render the diff to stdout (color-coded: `+` added, `-` removed, `~` changed).
///
/// When an assessment is present, each introduced package carries its signals
/// and advisories inline — a reviewer should not have to run a second command to
/// learn that the one package this PR added was published six hours ago.
pub fn render(report: &DiffReport, old_label: &str, new_label: &str) {
    println!("{}  {}  →  {}", "dependency diff".bold(), old_label.dimmed(), new_label.dimmed());

    if report.is_empty() {
        println!();
        crate::gochi::say(crate::gochi::Mood::Happy, "no dependency changes");
        return;
    }

    if !report.added.is_empty() {
        println!("\n{}", format!("+ {} added", report.added.len()).green().bold());
        for a in &report.added {
            println!(
                "  {}{}",
                format!("+ {}@{} ({})", a.name, a.version, a.ecosystem.as_str()).green(),
                inline(&a.assessment)
            );
            print_findings(&a.assessment);
        }
    }
    if !report.removed.is_empty() {
        println!("\n{}", format!("- {} removed", report.removed.len()).red().bold());
        for r in &report.removed {
            println!("  {}", format!("- {}@{} ({})", r.name, r.version, r.ecosystem.as_str()).red());
        }
    }
    if !report.changed.is_empty() {
        println!("\n{}", format!("~ {} changed", report.changed.len()).yellow().bold());
        for c in &report.changed {
            println!(
                "  {} {} {} {} {}{}",
                "~".yellow(),
                c.name.yellow(),
                c.from.dimmed(),
                "→".dimmed(),
                format!("{} ({})", c.to, c.ecosystem.as_str()).yellow(),
                inline(&c.assessment)
            );
            print_findings(&c.assessment);
        }
    }

    // New dependencies are new attack surface, so additions make gochi look up —
    // and anything actually flagged escalates that further.
    let mood = if report.has_findings() {
        crate::gochi::Mood::Bad
    } else if report.added.is_empty() {
        crate::gochi::Mood::Idle
    } else {
        crate::gochi::Mood::Alert
    };
    println!();
    crate::gochi::say(
        mood,
        format!(
            "+{} -{} ~{}  ({} unchanged){}",
            report.added.len(),
            report.removed.len(),
            report.changed.len(),
            report.unchanged,
            findings_summary(report),
        ),
    );
}

/// The compact suffix on a package line: its risk score and advisory count.
fn inline(a: &Assessment) -> String {
    let mut parts = Vec::new();
    if let Some(r) = a.risk
        && r > 0
    {
        parts.push(format!("risk {r}"));
    }
    if !a.vulns.is_empty() {
        let worst = a.worst_vuln().map(sev_word).unwrap_or("");
        parts.push(format!("{} vuln{} ({worst})", a.vulns.len(), plural(a.vulns.len())));
    }
    if parts.is_empty() {
        return String::new();
    }
    let text = format!("  [{}]", parts.join(" · "));
    match a.severity.max(a.worst_vuln()) {
        Some(s) if s >= Severity::High => text.red().bold().to_string(),
        Some(Severity::Medium) => text.truecolor(255, 165, 0).to_string(),
        _ => text.dimmed().to_string(),
    }
}

/// The indented detail under a package: why it was flagged.
fn print_findings(a: &Assessment) {
    for s in &a.signals {
        println!("      {}", format!("⚠ {s}").truecolor(255, 165, 0));
    }
    for v in &a.vulns {
        let line = format!("✗ {} [{}] {}", v.id, sev_word(v.severity), v.summary);
        let line = crate::analyze::util::snippet(&line, 100);
        println!("      {}", if v.severity >= Severity::High { line.red().to_string() } else { line.yellow().to_string() });
    }
}

/// The tail of the recap line, naming what the change introduced.
fn findings_summary(report: &DiffReport) -> String {
    let assessments = report
        .added
        .iter()
        .map(|a| &a.assessment)
        .chain(report.changed.iter().map(|c| &c.assessment));
    let (mut flagged, mut vulns) = (0usize, 0usize);
    for a in assessments {
        if !a.signals.is_empty() {
            flagged += 1;
        }
        vulns += a.vulns.len();
    }
    if flagged == 0 && vulns == 0 {
        return String::new();
    }
    format!("  ⚠ introduces {flagged} flagged package{}, {vulns} advisor{}", plural(flagged), if vulns == 1 { "y" } else { "ies" })
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn sev_word(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(name: &str, ver: &str) -> Dependency {
        Dependency {
            name: name.into(),
            version: ver.into(),
            ecosystem: Ecosystem::Node,
            scope: crate::model::Scope::Prod,
            licenses: Vec::new(),
            license_source: crate::model::LicenseSource::Unknown,
            direct: true,
            resolved_url: None,
            integrity: None,
            parents: vec![],
        }
    }

    fn sample() -> DiffReport {
        let old = vec![dep("keep", "1.0"), dep("gone", "2.0"), dep("bump", "1.0")];
        let new = vec![dep("keep", "1.0"), dep("new", "0.1"), dep("bump", "2.0")];
        diff(&old, &new)
    }

    #[test]
    fn diff_classifies_added_removed_changed() {
        let r = sample();
        assert_eq!(r.added.len(), 1);
        assert_eq!((r.added[0].name.as_str(), r.added[0].version.as_str()), ("new", "0.1"));
        assert_eq!(r.removed.len(), 1);
        assert_eq!((r.removed[0].name.as_str(), r.removed[0].version.as_str()), ("gone", "2.0"));
        assert_eq!(r.changed.len(), 1);
        assert_eq!(
            (r.changed[0].name.as_str(), r.changed[0].from.as_str(), r.changed[0].to.as_str()),
            ("bump", "1.0", "2.0")
        );
        assert_eq!(r.unchanged, 1); // keep
        assert!(!r.is_empty());
    }

    #[test]
    fn diff_identical_is_empty() {
        let a = vec![dep("x", "1.0"), dep("y", "2.0")];
        let r = diff(&a, &a);
        assert!(r.is_empty());
        assert_eq!(r.unchanged, 2);
    }

    #[test]
    fn introduced_is_additions_plus_the_new_side_of_changes() {
        // A version bump introduces the *new* version — assessing the old one
        // would report the risk the change is walking away from.
        let got = sample().introduced();
        assert!(got.contains(&(Ecosystem::Node, "new".into(), "0.1".into())));
        assert!(got.contains(&(Ecosystem::Node, "bump".into(), "2.0".into())));
        assert!(
            !got.iter().any(|(_, n, _)| n == "gone"),
            "a removed package is not introduced"
        );
        assert!(
            !got.iter().any(|(_, n, v)| n == "bump" && v == "1.0"),
            "the superseded version is not introduced"
        );
    }

    fn vuln(id: &str, sev: Severity) -> Vuln {
        Vuln { id: id.into(), severity: sev, summary: "x".into(), fixed: None }
    }

    #[test]
    fn assess_attaches_signals_and_advisories_to_introductions() {
        let mut r = sample();
        let mut res = HashMap::new();
        res.insert(
            ("new".to_string(), "0.1".to_string()),
            Resolution {
                risk: 60,
                worst: Some(Severity::High),
                signals: vec!["new-publisher".into(), "fresh-release (6h)".into()],
                ..Default::default()
            },
        );
        let vulns = vec![VulnPackage {
            name: "new".into(),
            version: "0.1".into(),
            ecosystem: "node".into(),
            vulns: vec![vuln("GHSA-x", Severity::High), vuln("CVE-y", Severity::Low)],
        }];
        assess(&mut r, &res, &vulns);

        let a = &r.added[0].assessment;
        assert_eq!(a.risk, Some(60));
        assert_eq!(a.signals.len(), 2);
        assert_eq!(a.vulns.len(), 2);
        assert_eq!(a.worst_vuln(), Some(Severity::High));
        assert!(!a.is_quiet());
        assert!(r.has_findings());
    }

    #[test]
    fn assess_ignores_the_removed_side() {
        // `gone@2.0` is leaving; an advisory against it is not this change's
        // problem, and reporting it would argue against a fix.
        let mut r = sample();
        let vulns = vec![VulnPackage {
            name: "gone".into(),
            version: "2.0".into(),
            ecosystem: "node".into(),
            vulns: vec![vuln("GHSA-old", Severity::Critical)],
        }];
        assess(&mut r, &HashMap::new(), &vulns);
        assert!(!r.has_findings(), "a removed package must not raise a finding");
    }

    #[test]
    fn assess_matches_the_new_version_of_a_bump() {
        let mut r = sample();
        // An advisory against the version being *left behind* must not attach.
        let stale = vec![VulnPackage {
            name: "bump".into(),
            version: "1.0".into(),
            ecosystem: "node".into(),
            vulns: vec![vuln("GHSA-old", Severity::High)],
        }];
        assess(&mut r, &HashMap::new(), &stale);
        assert!(r.changed[0].assessment.vulns.is_empty(), "1.0 is the old version");

        // One against the version being adopted must.
        let mut r = sample();
        let fresh = vec![VulnPackage {
            name: "bump".into(),
            version: "2.0".into(),
            ecosystem: "node".into(),
            vulns: vec![vuln("GHSA-new", Severity::High)],
        }];
        assess(&mut r, &HashMap::new(), &fresh);
        assert_eq!(r.changed[0].assessment.vulns.len(), 1);
    }

    #[test]
    fn an_unassessed_diff_reports_nothing_rather_than_zero() {
        // Offline, `assessment` must stay absent from the JSON: a zeroed risk
        // would read as "checked, and it is fine".
        let r = sample();
        let doc = to_json(&r, "a", "b");
        assert!(doc["added"][0]["assessment"].is_null());
        assert!(!r.has_findings());
    }

    #[test]
    fn json_carries_the_assessment_when_present() {
        let mut r = sample();
        let mut res = HashMap::new();
        res.insert(
            ("new".to_string(), "0.1".to_string()),
            Resolution { risk: 45, signals: vec!["typosquat of neu".into()], ..Default::default() },
        );
        assess(&mut r, &res, &[]);
        let doc = to_json(&r, "a", "b");
        assert_eq!(doc["schema_version"], 2);
        assert_eq!(doc["added"][0]["assessment"]["risk"], 45);
        assert_eq!(doc["added"][0]["assessment"]["signals"][0], "typosquat of neu");
    }
}
