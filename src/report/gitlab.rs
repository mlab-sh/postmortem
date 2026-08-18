//! GitLab **Dependency Scanning** report.
//!
//! GitLab does not consume SARIF. It defines its own JSON schema, and a report
//! that matches it appears in the merge-request widget and the Security
//! Dashboard; a report that does not is silently ignored. So this is a separate
//! emitter rather than a translation of [`super::sarif`].
//!
//! Shaped against the published schema
//! (`security-report-schemas/dist/dependency-scanning-report-format.json`):
//! `scan`, `version` and `vulnerabilities` are required at the top level, and
//! every vulnerability requires `id`, `identifiers` and `location`.
//!
//! ## Why there is no `remediations` block
//!
//! The schema has one, and [`crate::fix`] computes exactly the sort of thing it
//! describes — but `remediations` **requires a `diff`**: an actual patch GitLab
//! can apply from the MR. postmortem deliberately never writes to a manifest, so
//! it has no patch to offer, and emitting the field without one would fail
//! validation and take the whole report down with it.
//!
//! The fix target goes in `vulnerabilities[].solution` instead, which is free
//! text and is what GitLab renders as "Solution" on the vulnerability. Same
//! information, in the field that can honestly hold it.

use serde_json::{Value, json};

use crate::fix;
use crate::model::Severity;
use crate::tree::Tree;

/// The schema revision this output targets. GitLab rejects a report whose
/// `version` it does not recognise, so this is pinned rather than derived.
const SCHEMA_VERSION: &str = "15.0.6";

/// GitLab's severity vocabulary. It has no `Info` tier below `Low`, so ours maps
/// onto `Info` — GitLab does accept that value even though it is not a finding
/// anyone gates on.
fn severity(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

/// The identifier type GitLab shows, inferred from the advisory id.
///
/// GitLab keys deduplication on `identifiers`, so getting the type right is what
/// stops the same CVE appearing twice when two scanners report it.
fn identifier(id: &str) -> Value {
    let upper = id.to_ascii_uppercase();
    let (kind, name) = if upper.starts_with("CVE-") {
        ("cve", "CVE")
    } else if upper.starts_with("GHSA-") {
        ("ghsa", "GHSA")
    } else if upper.starts_with("RUSTSEC-") {
        ("rustsec", "RUSTSEC")
    } else if upper.starts_with("OSV-") || upper.starts_with("GO-") {
        ("osv", "OSV")
    } else {
        ("postmortem", "postmortem")
    };
    let url = match kind {
        "cve" => format!("https://nvd.nist.gov/vuln/detail/{id}"),
        "ghsa" => format!("https://github.com/advisories/{id}"),
        _ => format!("https://osv.dev/vulnerability/{id}"),
    };
    json!({ "type": kind, "name": format!("{name}-{id}"), "value": id, "url": url })
}

/// GitLab's package-type strings for `location.dependency.package.name`
/// disambiguation. It has no dedicated field, so the ecosystem is carried in
/// the reported file path instead — which is also what a reader needs.
fn lockfile_hint(ecosystem: &str) -> &'static str {
    match ecosystem {
        "npm" | "node" => "package-lock.json",
        "pypi" | "python" | "pip" => "requirements.txt",
        "cargo" | "rust" | "crates.io" => "Cargo.lock",
        "gem" | "rubygems" | "ruby" => "Gemfile.lock",
        "composer" | "packagist" | "php" => "composer.lock",
        "go" | "golang" => "go.sum",
        "maven" | "java" => "pom.xml",
        _ => "lockfile",
    }
}

/// Render a resolved tree as a GitLab Dependency Scanning report.
///
/// `started`/`ended` are RFC-3339 timestamps, passed in so this stays a pure
/// function. `plan` supplies the fix targets when one was computed; without it
/// the `solution` field is simply absent rather than invented.
pub fn render_tree(
    tree: &Tree,
    started: &str,
    ended: &str,
    plan: Option<&fix::Plan>,
) -> Result<String, serde_json::Error> {
    let mut vulns = Vec::new();

    for pkg in &tree.vulnerabilities {
        let file = lockfile_hint(&pkg.ecosystem);
        for v in &pkg.vulns {
            // The fix target, when `fix` computed one for this exact version.
            let solution = v
                .fixed
                .as_deref()
                .map(|t| format!("Upgrade {} to {t} or later.", pkg.name));
            // A plan may know a higher target that clears every advisory on the
            // package at once — better advice than this one advisory's fix.
            let solution = plan
                .and_then(|p| {
                    p.remedies
                        .iter()
                        .find(|r| r.name == pkg.name && r.installed == pkg.version)
                        .and_then(|r| r.target.as_deref())
                        .map(|t| format!("Upgrade {} to {t} or later.", pkg.name))
                })
                .or(solution);

            let mut entry = json!({
                // Stable per (advisory, package, version) so GitLab can track a
                // finding across pipelines rather than re-raising it each run.
                "id": format!("{}:{}:{}", v.id, pkg.name, pkg.version),
                "name": if v.summary.is_empty() {
                    format!("{} in {}", v.id, pkg.name)
                } else {
                    v.summary.clone()
                },
                "description": v.summary,
                "severity": severity(v.severity),
                "identifiers": [identifier(&v.id)],
                "location": {
                    "file": file,
                    "dependency": {
                        "package": { "name": pkg.name },
                        "version": pkg.version,
                    }
                },
            });
            if let Some(s) = solution {
                entry["solution"] = json!(s);
            }
            vulns.push(entry);
        }
    }

    let doc = json!({
        "version": SCHEMA_VERSION,
        "scan": {
            "analyzer": {
                "id": "postmortem",
                "name": "postmortem",
                "version": env!("CARGO_PKG_VERSION"),
                "vendor": { "name": "mlab" },
            },
            "scanner": {
                "id": "postmortem",
                "name": "postmortem",
                "version": env!("CARGO_PKG_VERSION"),
                "vendor": { "name": "mlab" },
            },
            "type": "dependency_scanning",
            "start_time": started,
            "end_time": ended,
            // A tree we could not fully resolve is reported as a failed scan
            // rather than a clean one — the same refusal the diagnostics make
            // elsewhere, expressed in GitLab's vocabulary.
            "status": if tree.diagnostics.iter().any(|d| d.is_incompleteness()) {
                "failure"
            } else {
                "success"
            },
        },
        "vulnerabilities": vulns,
    });
    serde_json::to_string_pretty(&doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vuln::{Vuln, VulnPackage};

    fn tree_with(vulns: Vec<VulnPackage>) -> Tree {
        Tree {
            root: "/p".into(),
            ecosystems: vec!["node".into()],
            stats: crate::tree::Stats {
                total: 1,
                direct: 1,
                transitive: 0,
                max_depth: 1,
                deduped: 0,
            },
            diagnostics: vec![],
            vulnerabilities: vulns,
            scored: false,
            roots: vec![],
        }
    }

    fn vuln(id: &str, sev: Severity, fixed: Option<&str>) -> Vuln {
        Vuln {
            id: id.into(),
            severity: sev,
            summary: "prototype pollution".into(),
            fixed: fixed.map(String::from),
        }
    }

    fn render(t: &Tree, plan: Option<&fix::Plan>) -> Value {
        serde_json::from_str(
            &render_tree(t, "2026-01-01T00:00:00Z", "2026-01-01T00:00:05Z", plan).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn the_document_carries_everything_the_schema_requires() {
        // A report missing a required field is silently ignored by GitLab, so
        // the failure mode is an empty MR widget rather than an error.
        let t = tree_with(vec![VulnPackage {
            name: "lodash".into(),
            version: "4.17.15".into(),
            ecosystem: "npm".into(),
            vulns: vec![vuln("CVE-2020-8203", Severity::High, None)],
        }]);
        let d = render(&t, None);
        for k in ["version", "scan", "vulnerabilities"] {
            assert!(d.get(k).is_some(), "missing top-level `{k}`");
        }
        for k in [
            "analyzer",
            "scanner",
            "type",
            "start_time",
            "end_time",
            "status",
        ] {
            assert!(d["scan"].get(k).is_some(), "missing scan.{k}");
        }
        let v = &d["vulnerabilities"][0];
        for k in ["id", "identifiers", "location"] {
            assert!(v.get(k).is_some(), "missing vulnerability.{k}");
        }
        assert_eq!(d["scan"]["type"], "dependency_scanning");
    }

    #[test]
    fn there_is_never_a_remediations_block() {
        // The schema requires a `diff` inside it — an actual patch. postmortem
        // never writes to a manifest, so emitting one would fail validation and
        // take the whole report down.
        let t = tree_with(vec![VulnPackage {
            name: "lodash".into(),
            version: "4.17.15".into(),
            ecosystem: "npm".into(),
            vulns: vec![vuln("CVE-1", Severity::High, Some("4.18.0"))],
        }]);
        assert!(render(&t, None).get("remediations").is_none());
    }

    #[test]
    fn the_fix_target_lands_in_solution() {
        let t = tree_with(vec![VulnPackage {
            name: "lodash".into(),
            version: "4.17.15".into(),
            ecosystem: "npm".into(),
            vulns: vec![vuln("CVE-1", Severity::High, Some("4.18.0"))],
        }]);
        let d = render(&t, None);
        assert_eq!(
            d["vulnerabilities"][0]["solution"],
            "Upgrade lodash to 4.18.0 or later."
        );
    }

    #[test]
    fn an_advisory_without_a_fix_carries_no_solution() {
        // An absent field is right; inventing "upgrade to a version that does
        // not exist" would be worse than saying nothing.
        let t = tree_with(vec![VulnPackage {
            name: "tar".into(),
            version: "6.2.1".into(),
            ecosystem: "npm".into(),
            vulns: vec![vuln("GHSA-x", Severity::Critical, None)],
        }]);
        assert!(
            render(&t, None)["vulnerabilities"][0]
                .get("solution")
                .is_none()
        );
    }

    #[test]
    fn identifiers_are_typed_so_gitlab_can_deduplicate() {
        // GitLab keys deduplication on these; a wrong type shows one CVE twice
        // when another scanner reports it too.
        let t = tree_with(vec![VulnPackage {
            name: "p".into(),
            version: "1.0.0".into(),
            ecosystem: "npm".into(),
            vulns: vec![
                vuln("CVE-2020-8203", Severity::High, None),
                vuln("GHSA-abcd-1234", Severity::Low, None),
                vuln("RUSTSEC-2021-0001", Severity::Medium, None),
            ],
        }]);
        let d = render(&t, None);
        let types: Vec<&str> = d["vulnerabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["identifiers"][0]["type"].as_str().unwrap())
            .collect();
        assert_eq!(types, ["cve", "ghsa", "rustsec"]);
        assert!(
            d["vulnerabilities"][0]["identifiers"][0]["url"]
                .as_str()
                .unwrap()
                .contains("nvd.nist.gov")
        );
    }

    #[test]
    fn the_id_is_stable_across_runs_so_findings_are_tracked_not_re_raised() {
        let t = tree_with(vec![VulnPackage {
            name: "lodash".into(),
            version: "4.17.15".into(),
            ecosystem: "npm".into(),
            vulns: vec![vuln("CVE-1", Severity::High, None)],
        }]);
        let a = render(&t, None)["vulnerabilities"][0]["id"].clone();
        let b = render(&t, None)["vulnerabilities"][0]["id"].clone();
        assert_eq!(a, b);
        assert_eq!(a, "CVE-1:lodash:4.17.15");
    }

    #[test]
    fn an_incomplete_graph_is_a_failed_scan_not_a_clean_one() {
        // The same refusal the diagnostics make elsewhere, in GitLab's words: a
        // report marked `success` over a graph we could not resolve would read
        // as a passing scan.
        let mut t = tree_with(vec![]);
        t.diagnostics.push(crate::model::Diagnostic {
            ecosystem: "go".into(),
            kind: "flat_graph".into(),
            message: "no transitive edges".into(),
        });
        assert_eq!(render(&t, None)["scan"]["status"], "failure");

        // A deliberate `--omit` is not incompleteness, so it stays a success.
        let mut t2 = tree_with(vec![]);
        t2.diagnostics.push(crate::model::Diagnostic {
            ecosystem: "*".into(),
            kind: crate::model::DIAG_SCOPE_OMITTED.into(),
            message: "2 of 5 omitted".into(),
        });
        assert_eq!(render(&t2, None)["scan"]["status"], "success");
    }

    #[test]
    fn the_lockfile_path_reflects_the_ecosystem() {
        // GitLab has no ecosystem field, so the reported file is what tells a
        // reader which manifest the finding belongs to.
        assert_eq!(lockfile_hint("npm"), "package-lock.json");
        assert_eq!(lockfile_hint("cargo"), "Cargo.lock");
        assert_eq!(lockfile_hint("gem"), "Gemfile.lock");
        assert_eq!(lockfile_hint("something-new"), "lockfile");
    }

    #[test]
    fn a_clean_tree_yields_an_empty_but_valid_report() {
        let d = render(&tree_with(vec![]), None);
        assert_eq!(d["vulnerabilities"].as_array().unwrap().len(), 0);
        assert_eq!(d["scan"]["status"], "success");
        assert_eq!(d["version"], SCHEMA_VERSION);
    }
}
