//! `postmortem audit <path>` — one command, one graded verdict. It unifies the
//! signals the other commands surface separately: the static malware [`scan`], the
//! dependency inventory + graph health from [`tree`], and (opt-in) the online
//! reputation and known-vulnerability layers. The orchestration lives in
//! `main.rs::run_audit`; this module is the pure summary → grade → render.

use owo_colors::OwoColorize;

use crate::model::Severity;

/// The tallied inputs to the verdict.
#[derive(Debug, Default)]
pub struct AuditSummary {
    pub ecosystems: Vec<String>,
    pub total_deps: usize,
    pub direct_deps: usize,
    // Static-scan findings, by severity.
    pub critical: usize,
    pub high_findings: usize,
    pub medium: usize,
    pub low: usize,
    /// Graph diagnostics (incompleteness signals).
    pub diagnostics: usize,
    // --online reputation (None unless --online).
    pub risk: Option<u8>,
    pub high_deps: usize,
    pub sus_deps: usize,
    // --vulns (None unless --vulns).
    pub vulns: Option<usize>,
    pub worst_vuln: Option<Severity>,
}

/// The overall verdict.
#[derive(Debug, PartialEq, Eq, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Grade {
    Clean,
    Warn,
    Critical,
}

/// The `audit --json` document.
///
/// `audit` exits non-zero to be CI-usable, but an exit code alone cannot say
/// *why*, and re-deriving the verdict from `scan --json` plus `tree --json` means
/// re-running both. So the same summary the terminal view renders is emitted
/// verbatim, with the grade and its reason as first-class fields.
///
/// `gate_tripped` is `None` when no policy was configured — distinct from
/// `Some(false)`, which means a policy ran and passed.
pub fn to_json(s: &AuditSummary, root: &str, gate_tripped: Option<bool>) -> serde_json::Value {
    let g = grade(s);
    serde_json::json!({
        "schema_version": 1,
        "root": root,
        "verdict": g,
        "reason": reason(s, g),
        "gate_tripped": gate_tripped,
        "ecosystems": s.ecosystems,
        "dependencies": {
            "total": s.total_deps,
            "direct": s.direct_deps,
        },
        "findings": {
            "critical": s.critical,
            "high": s.high_findings,
            "medium": s.medium,
            "low": s.low,
        },
        "diagnostics": s.diagnostics,
        // `null` distinguishes "not checked" from "checked, found none" — the
        // whole point of the layer being opt-in.
        "reputation": s.risk.map(|r| serde_json::json!({
            "risk": r,
            "high_deps": s.high_deps,
            "sus_deps": s.sus_deps,
        })),
        "vulnerabilities": s.vulns.map(|v| serde_json::json!({
            "count": v,
            "worst": s.worst_vuln,
        })),
    })
}

/// Grade the audit. Malicious code or a severe vuln / high risk is CRITICAL; softer
/// signals (medium findings, incompleteness, any vuln, elevated risk) are WARN.
pub fn grade(s: &AuditSummary) -> Grade {
    let critical = s.critical > 0
        || s.high_findings > 0
        || s.worst_vuln.is_some_and(|v| v >= Severity::High)
        || s.risk.is_some_and(|r| r >= 70);
    if critical {
        return Grade::Critical;
    }
    let warn = s.medium > 0
        || s.low > 0
        || s.diagnostics > 0
        || s.vulns.unwrap_or(0) > 0
        || s.high_deps > 0
        || s.sus_deps > 0
        || s.risk.is_some_and(|r| r >= 40);
    if warn { Grade::Warn } else { Grade::Clean }
}

/// One-line reason for the grade, so the verdict explains itself.
fn reason(s: &AuditSummary, g: Grade) -> &'static str {
    match g {
        Grade::Critical if s.critical + s.high_findings > 0 => "malicious code detected",
        Grade::Critical if s.worst_vuln.is_some_and(|v| v >= Severity::High) => {
            "a high-severity vulnerability is present"
        }
        Grade::Critical => "a high-risk dependency is present",
        Grade::Warn => "review the flagged items below",
        Grade::Clean => "no malicious code, known vulnerabilities, or high-risk dependencies",
    }
}

/// Render the audit report + verdict to stdout.
pub fn render(s: &AuditSummary, root_label: &str) {
    let g = grade(s);
    println!("{}  {}", "audit".bold(), root_label.dimmed());
    println!();

    let eco = if s.ecosystems.is_empty() {
        "none".into()
    } else {
        s.ecosystems.join(", ")
    };
    row("ecosystems", &eco);
    row(
        "packages",
        &format!(
            "{} ({} direct · {} transitive)",
            s.total_deps,
            s.direct_deps,
            s.total_deps.saturating_sub(s.direct_deps)
        ),
    );

    // malware (static scan)
    let mal_total = s.critical + s.high_findings + s.medium + s.low;
    if mal_total == 0 {
        row("malware", &"none".green().to_string());
    } else {
        let sev = format!(
            "{} critical · {} high · {} medium · {} low",
            s.critical, s.high_findings, s.medium, s.low
        );
        let val = format!("{mal_total} finding(s)  ({sev})");
        let colored = if s.critical + s.high_findings > 0 {
            val.red().to_string()
        } else {
            val.yellow().to_string()
        };
        row("malware", &colored);
    }

    if s.diagnostics > 0 {
        row(
            "graph",
            &format!(
                "{} diagnostic(s) — inventory may be incomplete",
                s.diagnostics
            )
            .yellow()
            .to_string(),
        );
    }

    match s.risk {
        Some(r) => {
            let val = format!(
                "risk {r}/100 · {} high-risk · {} suspicious",
                s.high_deps, s.sus_deps
            );
            let colored = if r >= 70 {
                val.red().to_string()
            } else if r >= 40 || s.high_deps > 0 {
                val.yellow().to_string()
            } else {
                val.green().to_string()
            };
            row("reputation", &colored);
        }
        None => row(
            "reputation",
            &"not checked  (pass --online)".dimmed().to_string(),
        ),
    }

    match s.vulns {
        Some(0) => row("vulns", &"none known".green().to_string()),
        Some(n) => {
            let worst = s
                .worst_vuln
                .map(|v| format!(" (worst: {v:?})").to_lowercase())
                .unwrap_or_default();
            row("vulns", &format!("{n} known{worst}").red().to_string());
        }
        None => row("vulns", &"not checked  (pass --vulns)".dimmed().to_string()),
    }

    println!();
    let (mood, colored) = match g {
        Grade::Critical => (crate::gochi::Mood::Bad, "CRITICAL".red().bold().to_string()),
        Grade::Warn => (
            crate::gochi::Mood::Alert,
            "WARN".yellow().bold().to_string(),
        ),
        Grade::Clean => (
            crate::gochi::Mood::Happy,
            "CLEAN".green().bold().to_string(),
        ),
    };
    println!(
        "  {}  {}  {}  {}",
        mood.paint(),
        "verdict".bold(),
        colored,
        reason(s, g).dimmed()
    );
}

fn row(key: &str, val: &str) {
    println!("  {:<11} {}", key.dimmed(), val);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grade_critical_on_malware() {
        let s = AuditSummary {
            high_findings: 1,
            ..Default::default()
        };
        assert_eq!(grade(&s), Grade::Critical);
    }

    #[test]
    fn grade_critical_on_severe_vuln_or_high_risk() {
        assert_eq!(
            grade(&AuditSummary {
                vulns: Some(1),
                worst_vuln: Some(Severity::Critical),
                ..Default::default()
            }),
            Grade::Critical
        );
        assert_eq!(
            grade(&AuditSummary {
                risk: Some(85),
                ..Default::default()
            }),
            Grade::Critical
        );
    }

    #[test]
    fn grade_warn_then_clean() {
        assert_eq!(
            grade(&AuditSummary {
                diagnostics: 1,
                ..Default::default()
            }),
            Grade::Warn
        );
        assert_eq!(
            grade(&AuditSummary {
                medium: 2,
                ..Default::default()
            }),
            Grade::Warn
        );
        assert_eq!(
            grade(&AuditSummary {
                vulns: Some(3),
                worst_vuln: Some(Severity::Low),
                ..Default::default()
            }),
            Grade::Warn
        );
        // Clean: nothing flagged, online + vulns both checked and empty.
        assert_eq!(
            grade(&AuditSummary {
                total_deps: 10,
                direct_deps: 2,
                risk: Some(0),
                vulns: Some(0),
                ..Default::default()
            }),
            Grade::Clean
        );
    }
}
