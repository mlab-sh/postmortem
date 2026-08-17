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

/// The scan endpoint's path, appended to the configured base
/// ([`crate::settings::Endpoints::vuln`]).
const SCAN_PATH: &str = "/api/v2/scan";

/// A blocking HTTP agent for the vuln API.
/// Blocking agents honouring the machine's proxy and `no_proxy` settings.
pub fn agent(net: &crate::settings::NetworkSettings) -> crate::settings::Agents {
    net.agents(Duration::from_secs(30))
}

/// The scan endpoint for the machine's configured base URL.
pub fn scan_url(net: &crate::settings::NetworkSettings) -> String {
    format!("{}{SCAN_PATH}", net.endpoints.vuln())
}

/// A single advisory affecting a package (a slim projection of the OSV object).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vuln {
    /// GHSA / CVE / OSV id.
    pub id: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub summary: String,
    /// The earliest version that fixes this advisory *for the installed
    /// version*, when the database publishes one.
    ///
    /// `None` covers two genuinely different situations that must not be
    /// conflated with "safe": no fix has been released yet, or the ranges could
    /// not be ordered. Both are reported as unfixable rather than silently
    /// dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
}

/// A package that has at least one known vulnerability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    agent: &crate::settings::Agents,
    cache: &Cache,
    token: Option<&str>,
    lockfile: &Path,
    format: &str,
    scan_url: &str,
) -> Result<Vec<VulnPackage>> {
    let bytes =
        std::fs::read(lockfile).with_context(|| format!("reading {}", lockfile.display()))?;

    let key = format!("{format}-{}", content_key(&bytes));
    if let Some(hit) = cache.get::<Vec<VulnPackage>>("vuln-scan", &key) {
        return Ok(hit);
    }

    let url = if format.is_empty() {
        scan_url.to_string()
    } else {
        format!("{scan_url}?format={format}")
    };
    let mut req = agent
        .for_url(&url)
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

/// Scan a pre-resolved coordinate set — `(ecosystem, name, version)` — through
/// mlab's `/api/v2/scan` in its **pre-parsed** mode (`{"packages":[…]}`). Used by
/// the [`crate::osv`] system path, whose packages come from the OS package
/// manager, not a lockfile. The `ecosystem` is forwarded to OSV verbatim (e.g.
/// `Debian:12`), so distro advisories resolve.
///
/// Unlike [`scan`], the pre-parsed response echoes no `packages` array — only
/// `results`, aligned to input order — so we zip against the coordinates we
/// sent. Cached by the coordinate-set content hash.
pub(crate) fn scan_coordinates(
    agent: &crate::settings::Agents,
    cache: &Cache,
    token: Option<&str>,
    coords: &[(String, String, String)],
    scan_url: &str,
) -> Result<Vec<VulnPackage>> {
    if coords.is_empty() {
        return Ok(Vec::new());
    }
    let packages: Vec<_> = coords
        .iter()
        .map(|(eco, name, version)| {
            serde_json::json!({ "ecosystem": eco, "name": name, "version": version })
        })
        .collect();
    let payload = serde_json::to_vec(&serde_json::json!({ "packages": packages }))
        .context("serializing scan coordinates")?;

    let key = format!("sys-{}", content_key(&payload));
    if let Some(hit) = cache.get::<Vec<VulnPackage>>("vuln-scan", &key) {
        return Ok(hit);
    }

    let mut req = agent
        .for_url(scan_url)
        .post(scan_url)
        .timeout(Duration::from_secs(30))
        .set("Content-Type", "application/json");
    if let Some(t) = token {
        req = req.set("Authorization", &format!("Bearer {t}"));
    }
    let body = match req.send_bytes(&payload) {
        Ok(resp) => resp.into_string()?,
        Err(ureq::Error::Status(429, _)) => anyhow::bail!("mlab rate limit reached (try a token)"),
        Err(ureq::Error::Status(code, resp)) => {
            anyhow::bail!("mlab scan failed ({code}): {}", resp.into_string().unwrap_or_default())
        }
        Err(e) => return Err(e.into()),
    };

    let doc: serde_json::Value = serde_json::from_str(&body).context("parsing mlab response")?;
    let out = parse_coordinate_results(coords, &doc);

    for vp in &out {
        cache.put("vuln", &format!("{}@{}", vp.name, vp.version), &vp.vulns);
    }
    cache.put("vuln-scan", &key, &out);
    Ok(out)
}

/// Zip the coordinates we sent against the pre-parsed scan's `results` (aligned
/// to input order), keeping only coordinates that carry advisories. A result
/// with `ok:false` is an outage/unqueryable marker, not "no vulns" — skip it
/// (its `vulns` is absent, so it naturally drops out).
fn parse_coordinate_results(
    coords: &[(String, String, String)],
    doc: &serde_json::Value,
) -> Vec<VulnPackage> {
    let Some(results) = doc.get("results").and_then(|r| r.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for ((eco, name, version), res) in coords.iter().zip(results) {
        let vulns: Vec<Vuln> = res
            .get("vulns")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().map(|v| parse_vuln_for(v, name, version)).collect())
            .unwrap_or_default();
        if vulns.is_empty() {
            continue;
        }
        out.push(VulnPackage {
            name: name.clone(),
            version: version.clone(),
            ecosystem: eco.clone(),
            vulns,
        });
    }
    out
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
        let str_at = |k: &str| {
            pkg.get(k).and_then(|v| v.as_str()).unwrap_or_default().to_string()
        };
        let (name, version) = (str_at("name"), str_at("version"));
        // The name and version are what select this package's ranges out of the
        // advisory's `affected` array, so they must reach the parser — without
        // them every advisory reports as having no published fix.
        let vulns: Vec<Vuln> = res
            .get("vulns")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().map(|v| parse_vuln_for(v, &name, &version)).collect())
            .unwrap_or_default();
        if vulns.is_empty() {
            continue;
        }
        out.push(VulnPackage { name, version, ecosystem: str_at("ecosystem"), vulns });
    }
    out
}

/// Parse one OSV-schema advisory object into our slim [`Vuln`]. Shared with the
/// [`crate::osv`] client (OSV.dev returns the same schema mlab does).
/// Parse an OSV vuln, resolving the fixed version for `name`@`installed`.
///
/// The `affected` array covers every package an advisory touches — the lodash
/// prototype-pollution entry lists `lodash`, `lodash-es`, `lodash-amd` and a
/// dozen more — so it is filtered by name before any range is read. Taking the
/// first entry blindly would report another package's fix version.
pub(crate) fn parse_vuln_for(v: &serde_json::Value, name: &str, installed: &str) -> Vuln {
    let id = v.get("id").and_then(|i| i.as_str()).unwrap_or("UNKNOWN").to_string();
    let summary = v
        .get("summary")
        .or_else(|| v.get("details"))
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .chars()
        .take(120)
        .collect();
    Vuln { id, severity: osv_severity(v), summary, fixed: fixed_version(v, name, installed) }
}

/// The earliest published fix that applies to `installed`.
///
/// OSV expresses affected ranges as an event stream: `introduced` opens a
/// window, `fixed` closes it. A package may carry several windows (a fix
/// back-ported to 1.x and 2.x), so the one containing the installed version is
/// what matters — recommending the 2.x fix to someone on 1.x would be a major
/// upgrade dressed up as a patch.
///
/// Returns `None` when no window contains the installed version, when the window
/// is still open (no fix released), or when the versions cannot be ordered.
fn fixed_version(v: &serde_json::Value, name: &str, installed: &str) -> Option<String> {
    if name.is_empty() || installed.is_empty() {
        return None;
    }
    let affected = v.get("affected")?.as_array()?;
    let mut best: Option<String> = None;

    for a in affected {
        // Only this package's ranges; an advisory routinely lists siblings.
        let a_name = a.get("package").and_then(|p| p.get("name")).and_then(|n| n.as_str());
        if a_name != Some(name) {
            continue;
        }
        for range in a.get("ranges").and_then(|r| r.as_array()).into_iter().flatten() {
            // GIT ranges are commit hashes, not versions — unusable here.
            if range.get("type").and_then(|t| t.as_str()) == Some("GIT") {
                continue;
            }
            let events = range.get("events").and_then(|e| e.as_array())?;
            let mut introduced: Option<String> = None;
            for e in events {
                if let Some(i) = e.get("introduced").and_then(|x| x.as_str()) {
                    introduced = Some(i.to_string());
                    continue;
                }
                let Some(fix) = e.get("fixed").and_then(|x| x.as_str()) else { continue };
                // `introduced: "0"` means "from the beginning".
                let opened = match introduced.as_deref() {
                    Some("0") | None => true,
                    Some(i) => crate::semver::gte(installed, i),
                };
                // The window must actually contain the installed version.
                if opened && crate::semver::lt(installed, fix) {
                    best = Some(match best {
                        Some(b) if crate::semver::lt(&b, fix) => b,
                        _ => fix.to_string(),
                    });
                }
            }
        }
    }
    best
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
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MODERATE" | "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => Severity::Medium,
        };
    }
    // The OSV `severity` array can carry several scorings (CVSS_V3, CVSS_V4…);
    // take the worst score we can parse. Distro feeds (Debian/Ubuntu/Alpine)
    // ship a full CVSS *vector* here, not a bare number, so [`cvss_base`] must
    // compute the base score or every advisory would collapse to the default.
    if let Some(score) = v
        .get("severity")
        .and_then(|s| s.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.get("score").and_then(|s| s.as_str()).and_then(cvss_base))
                .fold(f64::NEG_INFINITY, f64::max)
        })
        .filter(|s| s.is_finite())
    {
        // Standard CVSS v3 qualitative bands.
        return match score {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            _ => Severity::Low,
        };
    }
    Severity::Medium
}

/// Extract a CVSS base score: a bare numeric score (e.g. mlab's `"9.8"`), or the
/// base score computed from a CVSS v3.x vector string (e.g. OSV distro feeds'
/// `"CVSS:3.1/AV:N/AC:L/…"`). `None` for anything we can't score (e.g. a v4.0
/// vector), letting the caller fall back to its default.
fn cvss_base(s: &str) -> Option<f64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<f64>() {
        return Some(n);
    }
    if s.starts_with("CVSS:3") {
        return cvss_v3_base(s);
    }
    None
}

/// Compute a CVSS v3.0/3.1 base score from its vector string, per the spec.
/// Returns `None` if the mandatory base metrics aren't all present.
fn cvss_v3_base(vector: &str) -> Option<f64> {
    let mut m = std::collections::HashMap::new();
    for part in vector.split('/').skip(1) {
        if let Some((k, val)) = part.split_once(':') {
            m.insert(k, val);
        }
    }
    let scope_changed = *m.get("S")? == "C";
    let av = match *m.get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match *m.get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = match (*m.get("PR")?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match *m.get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |v: &str| match v {
        "H" => 0.56,
        "L" => 0.22,
        "N" => 0.0,
        _ => f64::NAN,
    };
    let (c, i, a) = (cia(m.get("C")?), cia(m.get("I")?), cia(m.get("A")?));
    if c.is_nan() || i.is_nan() || a.is_nan() {
        return None;
    }

    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    Some(cvss_roundup(raw))
}

/// The CVSS "Roundup": round *up* to one decimal place, integer-math style to
/// dodge float error (9.760000001 → 9.8).
fn cvss_roundup(x: f64) -> f64 {
    let int_input = (x * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input / 10_000) + 1) as f64 / 10.0
    }
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
    fn coordinate_results_zip_by_input_order() {
        // The pre-parsed `/api/v2/scan` reply carries only `results`, aligned to
        // the coordinates we sent (no `packages` echo). ok:false is an outage,
        // not "clean" — and drops out for having no `vulns`.
        let coords = vec![
            ("Debian:12".into(), "clean-pkg".into(), "1.0".into()),
            ("Debian:12".into(), "curl".into(), "7.74.0".into()),
            ("Debian:12".into(), "outage-pkg".into(), "2.0".into()),
        ];
        let doc = serde_json::json!({
            "results": [
                { "ok": true, "vulns": [] },
                { "ok": true, "vulns": [
                    { "id": "DEBIAN-CVE-2022-32207",
                      "severity": [ { "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } ] }
                ] },
                { "ok": false }
            ]
        });
        let out = parse_coordinate_results(&coords, &doc);
        assert_eq!(out.len(), 1, "only the vulnerable coordinate is kept");
        assert_eq!(out[0].name, "curl");
        assert_eq!(out[0].ecosystem, "Debian:12");
        assert_eq!(out[0].vulns[0].severity, Severity::Critical);
    }

    #[test]
    fn osv_severity_bands() {
        let sev = |s: &str| {
            osv_severity(&serde_json::json!({ "severity": [ { "type": "CVSS_V3", "score": s } ] }))
        };
        assert_eq!(sev("9.8"), Severity::Critical); // >= 9.0
        assert_eq!(sev("7.5"), Severity::High); // 7.0..9.0
        assert_eq!(sev("5.3"), Severity::Medium); // 4.0..7.0
        assert_eq!(sev("2.1"), Severity::Low); // < 4.0
    }

    #[test]
    fn osv_severity_label_critical() {
        let v = serde_json::json!({ "database_specific": { "severity": "CRITICAL" } });
        assert_eq!(osv_severity(&v), Severity::Critical);
    }

    #[test]
    fn osv_severity_defaults_medium() {
        assert_eq!(osv_severity(&serde_json::json!({ "id": "x" })), Severity::Medium);
    }

    #[test]
    fn cvss_v3_vector_scores_correctly() {
        // The canonical 9.8 vector (network, no auth, full impact).
        assert_eq!(cvss_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), Some(9.8));
        // A scope-changed medium.
        assert_eq!(cvss_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), Some(6.1));
        // Bare numeric still parses (mlab path).
        assert_eq!(cvss_base("7.5"), Some(7.5));
        // A v4.0 vector we don't compute → None (caller falls back).
        assert!(cvss_base("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H").is_none());
    }

    #[test]
    fn distro_cvss_vector_maps_to_critical() {
        // A real OSV distro advisory: no `database_specific.severity`, severity
        // carried only as a CVSS vector (9.8) — must resolve to Critical via the
        // computed base score, not collapse to the Medium default.
        let v = serde_json::json!({
            "id": "DEBIAN-CVE-2022-32207",
            "severity": [
                { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }
            ]
        });
        assert_eq!(osv_severity(&v), Severity::Critical);
    }
}
