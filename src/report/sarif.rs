//! SARIF 2.1.0 output.
//!
//! Designed to be consumed by GitHub Code Scanning, Azure DevOps, and any other
//! tool that ingests SARIF. One run, one driver (postmortem), one rule per
//! finding category, one result per finding.
//!
//! Reference: <https://sarifweb.azurewebsites.net/>.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::model::{Category, Finding, Report, Severity};
use crate::tree::{Node, Tree};
use crate::vuln::Vuln;

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

// --- `tree` SARIF -------------------------------------------------------------

/// Render a resolved `tree` (online + `--vulns`) as SARIF: reputation/identity
/// risk signals and known vulnerabilities become Code Scanning alerts. Deps are
/// deduped by `name@version`. Results are attributed to the project root (SARIF
/// requires a physical location; a dependency has no single source line).
pub fn render_tree(tree: &Tree) -> Result<String, serde_json::Error> {
    render_trees(std::slice::from_ref(tree))
}

/// Render several resolved trees into one SARIF document — one `runs[]` entry
/// per target (`tree --allow-multiple`). Each run keeps its own `SRCROOT`, so
/// Code Scanning attributes every alert to the right project.
pub fn render_trees(trees: &[Tree]) -> Result<String, serde_json::Error> {
    let runs: Vec<Value> = trees.iter().map(tree_run).collect();
    let doc = json!({
        "$schema": SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": runs,
    });
    serde_json::to_string_pretty(&doc)
}

/// One SARIF `run` for a single tree.
fn tree_run(tree: &Tree) -> Value {
    // Flagged deps, deduped by name@version (sorted for stable output).
    let mut flagged: BTreeMap<(String, String), &Node> = BTreeMap::new();
    fn walk<'a>(n: &'a Node, out: &mut BTreeMap<(String, String), &'a Node>) {
        if n.severity.is_some() && !n.signals.is_empty() {
            out.entry((n.name.clone(), n.version.clone())).or_insert(n);
        }
        for c in &n.children {
            walk(c, out);
        }
    }
    for r in &tree.roots {
        walk(r, &mut flagged);
    }

    let mut rules: Vec<Value> = Vec::new();
    let mut results: Vec<Value> = Vec::new();
    if !flagged.is_empty() {
        rules.push(tree_rule_risk());
        for ((name, version), n) in &flagged {
            results.push(risk_result(name, version, n));
        }
    }
    if !tree.vulnerabilities.is_empty() {
        rules.push(tree_rule_vuln());
        for p in &tree.vulnerabilities {
            for v in &p.vulns {
                results.push(vuln_result(&p.name, &p.version, v));
            }
        }
    }

    json!({
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
            "SRCROOT": { "uri": format!("file://{}/", tree.root) }
        },
        "results": results,
    })
}

/// SARIF `level` for a severity. Info maps to `none` so it's recorded but silent.
fn level_of(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        Severity::Info => "none",
    }
}

/// GitHub `security-severity` band (a numeric string) for a severity.
fn security_severity(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "9.0",
        Severity::High => "7.5",
        Severity::Medium => "5.0",
        Severity::Low => "3.0",
        Severity::Info => "1.0",
    }
}

fn tree_rule_risk() -> Value {
    let id = "postmortem.dependency-risk";
    json!({
        "id": id,
        "name": id,
        "shortDescription": { "text": "Dependency reputation / identity risk" },
        "fullDescription": { "text": "The dependency raised one or more supply-chain reputation or identity signals — low stars, a freshly-created or transferred repository, a typosquat of a popular name, a newly-added install script, a dormant release, or a new publisher." },
        "defaultConfiguration": { "level": "warning" },
        "help": {
            "text": format!("See {INFO_URI}#--online-reputation--the-riskdep-scores for how tree scores reputation."),
            "markdown": format!("See the [postmortem README]({INFO_URI}#--online-reputation--the-riskdep-scores) for how `tree --online` scores reputation."),
        },
        "properties": { "tags": ["security", "supply-chain", "reputation"], "precision": "medium" }
    })
}

fn tree_rule_vuln() -> Value {
    let id = "postmortem.known-vulnerability";
    json!({
        "id": id,
        "name": id,
        "shortDescription": { "text": "Known vulnerability in dependency" },
        "fullDescription": { "text": "A dependency version matches a published advisory (OSV / GHSA / CVE) from the mlab SBOM scan." },
        "defaultConfiguration": { "level": "error" },
        "help": {
            "text": format!("See {INFO_URI}#--vulns-known-vulnerabilities for the vulnerability source."),
            "markdown": format!("See the [postmortem README]({INFO_URI}#--vulns-known-vulnerabilities) for the vulnerability source."),
        },
        "properties": { "tags": ["security", "supply-chain", "vulnerability"], "precision": "high" }
    })
}

fn root_location() -> Value {
    json!({
        "physicalLocation": {
            "artifactLocation": { "uri": ".", "uriBaseId": "SRCROOT" },
            "region": { "startLine": 1 }
        }
    })
}

fn risk_result(name: &str, version: &str, n: &Node) -> Value {
    let sev = n.severity.unwrap_or(Severity::Info);
    let repo = n.repo.as_deref().unwrap_or("—");
    let message = format!("{name}@{version} [{repo}] — {}", n.signals.join(", "));
    json!({
        "ruleId": "postmortem.dependency-risk",
        "level": level_of(sev),
        "message": { "text": message },
        "locations": [ root_location() ],
        "partialFingerprints": { "postmortem/tree-fingerprint": tree_fingerprint(name, version, &n.signals.join(",")) },
        "properties": {
            "security-severity": security_severity(sev),
            "risk": n.risk.unwrap_or(0),
            "dep": n.dep.unwrap_or(0),
            "repo": n.repo,
            "stars": n.stars,
        }
    })
}

fn vuln_result(name: &str, version: &str, v: &Vuln) -> Value {
    let message = if v.summary.is_empty() {
        format!("{name}@{version}: {}", v.id)
    } else {
        format!("{name}@{version}: {} — {}", v.id, v.summary)
    };
    json!({
        "ruleId": "postmortem.known-vulnerability",
        "level": level_of(v.severity),
        "message": { "text": message },
        "locations": [ root_location() ],
        "partialFingerprints": { "postmortem/tree-fingerprint": tree_fingerprint(name, version, &v.id) },
        "properties": { "security-severity": security_severity(v.severity), "advisory": v.id }
    })
}

/// Stable fingerprint for a tree result so re-runs don't re-open the same alert.
fn tree_fingerprint(name: &str, version: &str, discriminator: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    name.hash(&mut hasher);
    version.hash(&mut hasher);
    discriminator.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
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

    // --- tree SARIF ---

    use crate::tree::{Node, Stats, Tree};
    use crate::vuln::{Vuln, VulnPackage};

    fn tnode(name: &str, sev: Option<Severity>, signals: &[&str]) -> Node {
        Node {
            name: name.into(),
            version: "1.0.0".into(),
            ecosystem: "node".into(),
            direct: true,
            deduped: false,
            truncated: false,
            repo: Some("acme/x".into()),
            stars: Some(3),
            signals: signals.iter().map(|s| s.to_string()).collect(),
            severity: sev,
            risk: Some(80),
            dep: Some(0),
            language: None,
            languages: None,
            children: vec![],
        }
    }

    fn ttree(roots: Vec<Node>, vulns: Vec<VulnPackage>) -> Tree {
        Tree {
            root: "/tmp/repo".into(),
            ecosystems: vec!["node".into()],
            stats: Stats { total: 0, direct: 0, transitive: 0, max_depth: 0, deduped: 0 },
            diagnostics: vec![],
            vulnerabilities: vulns,
            scored: true,
            roots,
        }
    }

    #[test]
    fn tree_sarif_has_risk_and_vuln_rules_and_results() {
        let t = ttree(
            vec![tnode("evil", Some(Severity::High), &["typosquat of event"])],
            vec![VulnPackage {
                name: "lodash".into(),
                version: "4.17.11".into(),
                ecosystem: "node".into(),
                vulns: vec![Vuln { id: "GHSA-x".into(), severity: Severity::Medium, summary: "proto".into() }],
            }],
        );
        let v: Value = serde_json::from_str(&render_tree(&t).unwrap()).unwrap();
        assert_eq!(v["version"], "2.1.0");
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        let ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&"postmortem.dependency-risk"));
        assert!(ids.contains(&"postmortem.known-vulnerability"));

        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        let risk = results.iter().find(|r| r["ruleId"] == "postmortem.dependency-risk").unwrap();
        assert_eq!(risk["level"], "error");
        assert!(risk["message"]["text"].as_str().unwrap().contains("typosquat"));
        assert_eq!(risk["properties"]["security-severity"], "7.5");
    }

    #[test]
    fn tree_sarif_dedups_flagged_by_name_version() {
        let child = tnode("evil", Some(Severity::High), &["low-stars"]);
        let mut root = tnode("root", None, &[]);
        root.children = vec![tnode("evil", Some(Severity::High), &["low-stars"]), child];
        let t = ttree(vec![root], vec![]);
        let v: Value = serde_json::from_str(&render_tree(&t).unwrap()).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1, "evil@1.0.0 collapsed to a single result");
    }

    #[test]
    fn tree_sarif_empty_when_nothing_flagged() {
        let t = ttree(vec![tnode("clean", None, &[])], vec![]);
        let v: Value = serde_json::from_str(&render_tree(&t).unwrap()).unwrap();
        assert!(v["runs"][0]["results"].as_array().unwrap().is_empty());
        assert!(v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().is_empty());
    }
}
