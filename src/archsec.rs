//! Arch Linux vulnerability intel via the **Arch Security Tracker**
//! (`security.archlinux.org`).
//!
//! Arch isn't in OSV, so pacman can't route through the shared mlab/OSV path
//! ([`crate::osv`]) — this is a separate source. One `issues/all.json` fetch
//! returns every Arch Vulnerability Group (AVG); we match the groups against the
//! installed packages and compare versions with pacman's own `vercmp`, so a
//! package is flagged only when its installed version is actually affected:
//!
//! - a group with no `fixed` version (`status: Vulnerable`, no patch yet) → any
//!   installed version is affected;
//! - a group with a `fixed` version → affected only when
//!   `vercmp(installed, fixed) < 0` (an already-patched box is clean).
//!
//! Vuln data is fetched fresh each run (one request, always current) rather than
//! cached, so a newly-published advisory is never masked by a stale entry.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::model::{Dependency, Severity};
use crate::vuln::{Vuln, VulnPackage};

/// Path of the Arch Vulnerability Group feed, appended to the configured base
/// ([`crate::settings::Endpoints::arch_security`]).
const ALL_PATH: &str = "/issues/all.json";

/// One Arch Vulnerability Group from `all.json`.
#[derive(Debug, Clone, Deserialize)]
struct Group {
    #[serde(default)]
    packages: Vec<String>,
    #[serde(default)]
    status: String,
    #[serde(default)]
    severity: String,
    /// The version carrying the fix, or `null`/absent when no patch exists yet.
    #[serde(default)]
    fixed: Option<String>,
    #[serde(default)]
    issues: Vec<String>,
    #[serde(default, rename = "type")]
    kind: String,
}

/// Scan installed pacman packages against the Arch Security Tracker. Returns only
/// packages whose installed version is actually affected.
pub fn scan(
    agent: &crate::settings::Agents,
    deps: &[Dependency],
    base: &str,
) -> Result<Vec<VulnPackage>> {
    let url = format!("{base}{ALL_PATH}");
    let body = agent
        .for_url(&url)
        .get(&url)
        .timeout(Duration::from_secs(30))
        .call()
        .context("fetching Arch Security Tracker")?
        .into_string()?;
    let groups: Vec<Group> =
        serde_json::from_str(&body).context("parsing Arch Security Tracker all.json")?;

    // Index the groups by affected package name.
    let mut by_pkg: HashMap<&str, Vec<&Group>> = HashMap::new();
    for g in &groups {
        for p in &g.packages {
            by_pkg.entry(p.as_str()).or_default().push(g);
        }
    }

    let mut out = Vec::new();
    for dep in deps {
        let Some(groups) = by_pkg.get(dep.name.as_str()) else { continue };
        let mut vulns: Vec<Vuln> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for g in groups {
            if !affects(&dep.version, g) {
                continue;
            }
            let severity = map_severity(&g.severity);
            for cve in &g.issues {
                if seen.insert(cve.clone()) {
                    vulns.push(Vuln {
                        id: cve.clone(),
                        severity,
                        summary: g.kind.clone(),
                    });
                }
            }
        }
        if vulns.is_empty() {
            continue;
        }
        out.push(VulnPackage {
            name: dep.name.clone(),
            version: dep.version.clone(),
            ecosystem: "Arch".into(),
            vulns,
        });
    }
    Ok(out)
}

/// Whether `installed` is affected by `group`. A group with no `fixed` version
/// (or an explicit not-affected status) is handled first; otherwise the fix
/// version decides via `vercmp`.
fn affects(installed: &str, group: &Group) -> bool {
    if group.status.eq_ignore_ascii_case("Not affected") {
        return false;
    }
    match &group.fixed {
        // No patch exists yet → every installed version is affected.
        None => true,
        // Patched: affected only if we're strictly older than the fix. If we
        // can't run vercmp (missing/unknown), fail safe and treat as affected.
        Some(fixed) => vercmp(installed, fixed).is_none_or(|o| o == Ordering::Less),
    }
}

/// Compare two pacman versions with pacman's own `vercmp` (handles epochs and
/// `pkgrel`). `None` if `vercmp` isn't available or returns something unexpected.
fn vercmp(a: &str, b: &str) -> Option<Ordering> {
    let out = Command::new("vercmp").arg(a).arg(b).output().ok()?;
    match String::from_utf8_lossy(&out.stdout).trim() {
        "-1" => Some(Ordering::Less),
        "0" => Some(Ordering::Equal),
        "1" => Some(Ordering::Greater),
        _ => None,
    }
}

/// Map an Arch severity label to our scale (a known advisory is never "info").
fn map_severity(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(status: &str, fixed: Option<&str>) -> Group {
        Group {
            packages: vec!["pkg".into()],
            status: status.into(),
            severity: "High".into(),
            fixed: fixed.map(String::from),
            issues: vec!["CVE-1".into()],
            kind: "x".into(),
        }
    }

    #[test]
    fn no_fix_means_affected() {
        assert!(affects("1.0-1", &group("Vulnerable", None)));
    }

    #[test]
    fn not_affected_status_is_skipped() {
        assert!(!affects("1.0-1", &group("Not affected", None)));
    }

    #[test]
    fn severity_maps() {
        assert_eq!(map_severity("Critical"), Severity::Critical);
        assert_eq!(map_severity("Unknown"), Severity::Medium);
    }

    #[test]
    fn parses_all_json_group() {
        let g: Vec<Group> = serde_json::from_str(
            r#"[{"name":"AVG-1","packages":["pam"],"status":"Vulnerable",
                 "severity":"High","affected":"1.7.0-2","fixed":null,
                 "issues":["CVE-2025-6020"],"type":"arbitrary filesystem access"}]"#,
        )
        .unwrap();
        assert_eq!(g[0].packages, ["pam"]);
        assert_eq!(g[0].issues, ["CVE-2025-6020"]);
        assert!(g[0].fixed.is_none());
    }
}
