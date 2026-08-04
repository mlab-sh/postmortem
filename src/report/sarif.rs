//! SARIF 2.1.0 output.
//!
//! Designed to be consumed by GitHub Code Scanning, Azure DevOps, and any other
//! tool that ingests SARIF. One run, one driver (postmortem), one rule per
//! finding category, one result per finding.
//!
//! Reference: <https://sarifweb.azurewebsites.net/>.

use serde_json::{Value, json};

use crate::model::{Category, Finding, Report, Severity};

const SCHEMA_URI: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const INFO_URI: &str = "https://github.com/mlab-sh/postmortem";

pub fn render(report: &Report) -> Result<String, serde_json::Error> {
    let used_categories = collect_used_categories(&report.findings);
    let rules: Vec<Value> = used_categories.iter().map(|c| rule_for(*c)).collect();
    let results: Vec<Value> = report.findings.iter().map(|f| result_for(f, &report.root)).collect();

    let doc = json!({
        "$schema": SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "postmortem",
                        "version": TOOL_VERSION,
                        "semanticVersion": TOOL_VERSION,
                        "informationUri": INFO_URI,
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {
                    "SRCROOT": { "uri": format!("file://{}/", report.root) }
                },
                "results": results,
            }
        ]
    });
    serde_json::to_string_pretty(&doc)
}

fn collect_used_categories(findings: &[Finding]) -> Vec<Category> {
    let mut out = Vec::new();
    for f in findings {
        if !out.contains(&f.category) {
            out.push(f.category);
        }
    }
    out
}

fn rule_for(c: Category) -> Value {
    let id = format!("postmortem.{}", c.as_str());
    let (short, full, level, sev_score) = match c {
        Category::Ioc => (
            "Indicator of compromise embedded in dependency code",
            "An external network indicator (URL, IPv4/IPv6 address, domain, or crypto-wallet address) was found inside dependency source. Legitimate libraries rarely embed network endpoints; these are common in exfil payloads.",
            "warning",
            "5.0",
        ),
        Category::Obfuscation => (
            "Obfuscation pattern in dependency code",
            "The file shows multiple obfuscation signals (high entropy, eval / Function() constructor / charCodeAt chains, long hex or base64 blobs). One signal in isolation is often legitimate minification; multiple combined signals are the classic shape of a hidden payload.",
            "error",
            "8.5",
        ),
        Category::InstallHook => (
            "Dependency executes code at install time",
            "An npm pre/post-install script or a Python setup.py invoking subprocess / os.system / network primitives was detected. These run automatically on dependency install and are the #1 supply-chain vector (event-stream, ctx, ua-parser-js, node-ipc, ...).",
            "error",
            "9.0",
        ),
        Category::SensitiveApi => (
            "Use of sensitive system / network API",
            "The dependency uses primitives typically associated with command execution or network egress (child_process / std::process / subprocess, std::net / requests / urllib, etc.). Informational on its own; combine with the other categories to score risk.",
            "note",
            "3.0",
        ),
    };
    json!({
        "id": id,
        "name": id,
        "shortDescription": { "text": short },
        "fullDescription":  { "text": full },
        "defaultConfiguration": { "level": level },
        "help": {
            "text": format!("See {INFO_URI}#readme for details on the `{}` analyzer.", c.as_str()),
            "markdown": format!("See [postmortem README]({INFO_URI}#readme) for details on the `{}` analyzer.", c.as_str()),
        },
        "properties": {
            "tags": ["security", "supply-chain", c.as_str()],
            "precision": "medium",
            "security-severity": sev_score,
        }
    })
}

fn result_for(f: &Finding, root: &str) -> Value {
    let level = match f.severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        Severity::Info => "none",
    };

    let (uri, start_line) = split_location(f.location.as_deref(), root);

    let mut artifact_location = serde_json::Map::new();
    artifact_location.insert("uri".into(), Value::String(uri.unwrap_or_else(|| ".".into())));
    artifact_location.insert("uriBaseId".into(), Value::String("SRCROOT".into()));

    let mut region = serde_json::Map::new();
    region.insert("startLine".into(), Value::Number(start_line.unwrap_or(1).into()));

    let mut physical = serde_json::Map::new();
    physical.insert("artifactLocation".into(), Value::Object(artifact_location));
    physical.insert("region".into(), Value::Object(region));

    let message = if let Some(ev) = &f.evidence {
        format!("{} — {} (evidence: {})", f.dependency, f.detail, ev)
    } else {
        format!("{} — {}", f.dependency, f.detail)
    };

    let mut result = json!({
        "ruleId": format!("postmortem.{}", f.category.as_str()),
        "level": level,
        "message": { "text": message },
        "locations": [ { "physicalLocation": physical } ],
        "partialFingerprints": {
            "postmortem/finding-fingerprint": fingerprint(f),
        }
    });

    if let Some(url) = &f.enrich_url {
        // Surface the enrichment link as a hyperlink in the message via SARIF
        // "relatedLocations" using a `properties` bag (most viewers ignore
        // unknown properties; GitHub Code Scanning displays them on hover).
        result["properties"] = json!({ "enrichUrl": url });
    }
    result
}

/// Parse `"path:line"` or `"path"` into `(uri, line)` with paths made relative
/// to the scan root when possible. Returns absolute file paths verbatim if they
/// don't sit under the root.
fn split_location(loc: Option<&str>, root: &str) -> (Option<String>, Option<u64>) {
    let Some(s) = loc else { return (None, None) };
    // Split on the LAST `:` only if the suffix is purely digits — otherwise the
    // location is just a path (or a Windows drive `C:` we'd shred).
    let (path, line) = match s.rsplit_once(':') {
        Some((p, n)) if n.chars().all(|c| c.is_ascii_digit()) && !n.is_empty() => {
            (p.to_string(), n.parse::<u64>().ok())
        }
        _ => (s.to_string(), None),
    };
    let relative = path
        .strip_prefix(&format!("{root}/"))
        .map(|s| s.to_string())
        .unwrap_or_else(|| path.clone());
    (Some(relative), line)
}

/// Stable, content-based fingerprint so re-runs don't re-open the same alert
/// in GitHub Code Scanning. Hash inputs: category + dependency + detail + (rel) location.
fn fingerprint(f: &Finding) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    f.category.as_str().hash(&mut hasher);
    f.dependency.hash(&mut hasher);
    f.detail.hash(&mut hasher);
    f.location.as_deref().unwrap_or("").hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, Severity};

    fn rep(findings: Vec<Finding>) -> Report {
        Report {
            schema_version: 2,
            root: "/tmp/repo".into(),
            ecosystems: vec!["node".into()],
            diagnostics: vec![],
            dependencies: vec![],
            findings,
        }
    }

    fn finding(cat: Category, sev: Severity, dep: &str, loc: &str) -> Finding {
        Finding {
            dependency: dep.into(),
            severity: sev,
            category: cat,
            detail: "detail".into(),
            location: Some(loc.into()),
            evidence: None,
            enrich_url: None,
        }
    }

    #[test]
    fn schema_and_version_present() {
        let s = render(&rep(vec![])).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert!(v["$schema"].as_str().unwrap().contains("sarif"));
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "postmortem");
    }

    #[test]
    fn one_rule_per_used_category_only() {
        let s = render(&rep(vec![
            finding(Category::Ioc, Severity::Medium, "x", "/tmp/repo/a.js"),
            finding(Category::Ioc, Severity::High, "y", "/tmp/repo/b.js"),
        ])).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["id"], "postmortem.ioc");
    }

    #[test]
    fn severity_maps_to_sarif_level() {
        let s = render(&rep(vec![
            finding(Category::Obfuscation, Severity::Critical, "x", "/tmp/repo/a.js:10"),
            finding(Category::Ioc, Severity::High, "x", "/tmp/repo/a.js:11"),
            finding(Category::Ioc, Severity::Medium, "x", "/tmp/repo/a.js:12"),
            finding(Category::SensitiveApi, Severity::Low, "x", "/tmp/repo/a.js:13"),
            finding(Category::SensitiveApi, Severity::Info, "x", "/tmp/repo/a.js:14"),
        ])).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "error");
        assert_eq!(results[2]["level"], "warning");
        assert_eq!(results[3]["level"], "note");
        assert_eq!(results[4]["level"], "none");
    }

    #[test]
    fn paths_made_relative_to_root() {
        let s = render(&rep(vec![finding(Category::Ioc, Severity::Medium, "x", "/tmp/repo/sub/a.js:42")])).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        let loc = &v["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert_eq!(loc["artifactLocation"]["uri"], "sub/a.js");
        assert_eq!(loc["artifactLocation"]["uriBaseId"], "SRCROOT");
        assert_eq!(loc["region"]["startLine"], 42);
    }

    #[test]
    fn fingerprints_are_stable() {
        let f = finding(Category::Ioc, Severity::Medium, "x", "/tmp/repo/a.js:1");
        assert_eq!(fingerprint(&f), fingerprint(&f));
    }

    #[test]
    fn enrich_url_surfaces_in_properties() {
        let mut f = finding(Category::Ioc, Severity::Medium, "x", "/tmp/repo/a.js:1");
        f.enrich_url = Some("https://mlab.sh/ip/1.2.3.4".into());
        let s = render(&rep(vec![f])).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(
            v["runs"][0]["results"][0]["properties"]["enrichUrl"],
            "https://mlab.sh/ip/1.2.3.4"
        );
    }

    #[test]
    fn location_without_line_defaults_to_one() {
        let s = render(&rep(vec![finding(Category::SensitiveApi, Severity::Low, "x", "/tmp/repo/a.js")])).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        let loc = &v["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert_eq!(loc["region"]["startLine"], 1);
    }
}
