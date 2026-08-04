//! Known-vulnerability intel via the mlab SBOM scan API (`vuln.mlab.sh`).
//!
//! Rather than reimplement OSV/GHSA/CVE matching, we hand the raw lockfile to
//! mlab's `POST /api/v2/scan` — it resolves the tree recursively and returns
//! OSV-schema vulnerabilities per package. Results are cached by lockfile
//! content hash (skip re-scans / respect the 25-req/hr limit), and each
//! vulnerable package is also written to a `name@version`-keyed store.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::cache::Cache;
use crate::model::Severity;

const SCAN_URL: &str = "https://vuln.mlab.sh/api/v2/scan";

/// A blocking HTTP agent for the vuln API.
pub fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).build()
}

/// A single advisory affecting a package (a slim projection of the OSV object).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vuln {
    /// GHSA / CVE / OSV id.
    pub id: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub summary: String,
}

/// A package that has at least one known vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnPackage {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub vulns: Vec<Vuln>,
}

/// Scan one lockfile through mlab. `format` is a mlab format hint
/// (`npm`/`cargo`/`pip`/`composer`/`gem`/`go`) or empty for auto-detect.
/// Returns only the packages that carry vulnerabilities.
pub fn scan(
    agent: &ureq::Agent,
    cache: &Cache,
    token: Option<&str>,
    lockfile: &Path,
    format: &str,
) -> Result<Vec<VulnPackage>> {
    let bytes =
        std::fs::read(lockfile).with_context(|| format!("reading {}", lockfile.display()))?;

    let key = format!("{format}-{}", content_key(&bytes));
    if let Some(hit) = cache.get::<Vec<VulnPackage>>("vuln-scan", &key) {
        return Ok(hit);
    }

    let url = if format.is_empty() {
        SCAN_URL.to_string()
    } else {
        format!("{SCAN_URL}?format={format}")
    };
    let mut req = agent
        .post(&url)
        .timeout(Duration::from_secs(30))
        .set("Content-Type", "application/octet-stream");
    if let Some(t) = token {
        req = req.set("Authorization", &format!("Bearer {t}"));
    }

    let body = match req.send_bytes(&bytes) {
        Ok(resp) => resp.into_string()?,
        Err(ureq::Error::Status(429, _)) => anyhow::bail!("mlab rate limit reached (try a token)"),
        Err(ureq::Error::Status(code, resp)) => {
            anyhow::bail!("mlab scan failed ({code}): {}", resp.into_string().unwrap_or_default())
        }
        Err(e) => return Err(e.into()),
    };

    let doc: serde_json::Value = serde_json::from_str(&body).context("parsing mlab response")?;
    let out = parse_response(&doc);

    // Populate the package-keyed store, then cache the whole scan.
    for vp in &out {
        cache.put("vuln", &format!("{}@{}", vp.name, vp.version), &vp.vulns);
    }
    cache.put("vuln-scan", &key, &out);
    Ok(out)
}

/// Zip mlab's parallel `packages` / `results` arrays into per-package vulns,
/// keeping only packages that actually have advisories.
fn parse_response(doc: &serde_json::Value) -> Vec<VulnPackage> {
    let packages = doc.get("packages").and_then(|p| p.as_array());
    let results = doc.get("results").and_then(|r| r.as_array());
    let (Some(packages), Some(results)) = (packages, results) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for (pkg, res) in packages.iter().zip(results) {
        let vulns: Vec<Vuln> = res
            .get("vulns")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().map(parse_vuln).collect())
            .unwrap_or_default();
        if vulns.is_empty() {
            continue;
        }
        out.push(VulnPackage {
            name: pkg.get("name").and_then(|n| n.as_str()).unwrap_or_default().to_string(),
            version: pkg.get("version").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            ecosystem: pkg.get("ecosystem").and_then(|e| e.as_str()).unwrap_or_default().to_string(),
            vulns,
        });
    }
    out
}

fn parse_vuln(v: &serde_json::Value) -> Vuln {
    let id = v.get("id").and_then(|i| i.as_str()).unwrap_or("UNKNOWN").to_string();
    let summary = v
        .get("summary")
        .or_else(|| v.get("details"))
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .chars()
        .take(120)
        .collect();
    Vuln { id, severity: osv_severity(v), summary }
}

/// Map an OSV vuln's severity to our scale. Prefer the GHSA-style
/// `database_specific.severity` label; fall back to a CVSS score band; default
/// to Medium (a known advisory is never "info").
fn osv_severity(v: &serde_json::Value) -> Severity {
    if let Some(label) = v
        .get("database_specific")
        .and_then(|d| d.get("severity"))
        .and_then(|s| s.as_str())
    {
        return match label.to_ascii_uppercase().as_str() {
            "CRITICAL" | "HIGH" => Severity::High,
            "MODERATE" | "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => Severity::Medium,
        };
    }
    if let Some(score) = v
        .get("severity")
        .and_then(|s| s.as_array())
        .and_then(|a| a.first())
        .and_then(|s| s.get("score"))
        .and_then(|s| s.as_str())
        .and_then(cvss_base)
    {
        return match score {
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            _ => Severity::Low,
        };
    }
    Severity::Medium
}

/// Pull the base score out of a CVSS vector string's trailing number, if any —
/// or parse a bare numeric score. Best-effort.
fn cvss_base(s: &str) -> Option<f64> {
    s.trim().parse::<f64>().ok()
}

fn content_key(bytes: &[u8]) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    format!("{:016x}", h.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_osv_response() {
        let doc = serde_json::json!({
            "count": 2,
            "packages": [
                { "ecosystem": "npm", "name": "clean-pkg", "version": "1.0.0" },
                { "ecosystem": "npm", "name": "lodash", "version": "4.17.11" }
            ],
            "results": [
                { "ok": true, "vulns": [] },
                { "ok": true, "vulns": [
                    { "id": "GHSA-jf85-cpcp-j695",
                      "summary": "Prototype Pollution in lodash",
                      "database_specific": { "severity": "HIGH" } }
                ] }
            ]
        });
        let out = parse_response(&doc);
        assert_eq!(out.len(), 1, "only vulnerable packages are kept");
        assert_eq!(out[0].name, "lodash");
        assert_eq!(out[0].vulns[0].id, "GHSA-jf85-cpcp-j695");
        assert_eq!(out[0].vulns[0].severity, Severity::High);
    }

    #[test]
    fn osv_severity_from_cvss_score() {
        let v = serde_json::json!({
            "id": "CVE-x",
            "severity": [ { "type": "CVSS_V3", "score": "9.8" } ]
        });
        assert_eq!(osv_severity(&v), Severity::High);
    }

    #[test]
    fn osv_severity_defaults_medium() {
        assert_eq!(osv_severity(&serde_json::json!({ "id": "x" })), Severity::Medium);
    }
}
