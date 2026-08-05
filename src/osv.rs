//! System-wide known-vulnerability intel for the `system` command.
//!
//! The OS package managers have no lockfile and aren't in mlab's language
//! schema, but OSV.dev indexes distro advisories directly, keyed on the distro
//! package **name** plus an ecosystem string carrying the OS **release** — e.g.
//! `Debian:12`, `Ubuntu:22.04:LTS`, `Alpine:v3.19`, `Rocky Linux:9`. This module
//! owns that distro-specific mapping (release detection + ecosystem string) and
//! then routes the actual lookup through [`crate::vuln::scan_coordinates`], so
//! every vulnerability query — language *and* system — goes through the one
//! `vuln.mlab.sh` service (which proxies OSV with its own cache + local mirror).
//!
//! Get the release wrong and OSV returns a silent zero, so it's resolved
//! explicitly (from `/etc/os-release`, or a `--release` override for
//! cross-scanning), and backends OSV doesn't cover return `None` — the caller
//! emits a [`crate::model::Diagnostic`] rather than letting "0" read as "clean".
//!
//! Phase 1 covers apt (Debian/Ubuntu), apk (Alpine), and dnf on
//! Rocky/AlmaLinux. Fedora isn't in OSV and RHEL is keyed on a translated CPE;
//! both fall through to `None`.

use anyhow::Result;

use crate::cache::Cache;
use crate::model::{Dependency, Ecosystem};
use crate::vuln::VulnPackage;

/// The OS release backing an inventory, used to build the OSV ecosystem string.
/// `id` is the `/etc/os-release` `ID` (e.g. `debian`), `version_id` its
/// `VERSION_ID` (e.g. `12`, or `3.19.1` on Alpine).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub id: String,
    pub version_id: String,
}

impl Release {
    /// Read `/etc/os-release`. `None` off Linux or when the file is absent.
    pub fn detect() -> Option<Release> {
        let text = std::fs::read_to_string("/etc/os-release").ok()?;
        let mut id = String::new();
        let mut version_id = String::new();
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else { continue };
            let v = v.trim().trim_matches('"').to_string();
            match k.trim() {
                "ID" => id = v,
                "VERSION_ID" => version_id = v,
                _ => {}
            }
        }
        if id.is_empty() {
            return None;
        }
        Some(Release { id, version_id })
    }

    /// Parse a `--release` override of the form `id:version` (e.g. `debian:12`,
    /// `alpine:3.19`). A bare `id` leaves the version empty.
    pub fn parse_override(s: &str) -> Release {
        match s.split_once(':') {
            Some((id, ver)) => Release {
                id: id.trim().to_ascii_lowercase(),
                version_id: ver.trim().to_string(),
            },
            None => Release { id: s.trim().to_ascii_lowercase(), version_id: String::new() },
        }
    }

    /// The leading major component of `version_id` (`9.3` → `9`).
    fn major(&self) -> &str {
        self.version_id.split('.').next().unwrap_or(&self.version_id)
    }

    /// `major.minor` of `version_id` — Alpine's release branch (`3.19.1` → `3.19`).
    fn major_minor(&self) -> String {
        let mut it = self.version_id.split('.');
        match (it.next(), it.next()) {
            (Some(a), Some(b)) => format!("{a}.{b}"),
            (Some(a), None) => a.to_string(),
            _ => self.version_id.clone(),
        }
    }
}

/// The OSV ecosystem string for a backend + release, or `None` when OSV doesn't
/// cover it (brew/nix/pacman, and dnf on Fedora/RHEL). Returning `None` is the
/// signal for the caller to record a "not scanned" diagnostic.
pub fn osv_ecosystem(eco: Ecosystem, release: &Release) -> Option<String> {
    match eco {
        Ecosystem::Apt => match release.id.as_str() {
            "debian" => Some(format!("Debian:{}", release.major())),
            // OSV keys Ubuntu on the LTS-suffixed release; non-LTS point
            // releases are not separately tracked.
            "ubuntu" => Some(format!("Ubuntu:{}:LTS", release.version_id)),
            _ => None,
        },
        Ecosystem::Apk => Some(format!("Alpine:v{}", release.major_minor())),
        Ecosystem::Dnf => match release.id.as_str() {
            "rocky" => Some(format!("Rocky Linux:{}", release.major())),
            "almalinux" => Some(format!("AlmaLinux:{}", release.major())),
            // Fedora isn't in OSV; RHEL is keyed on a translated CPE (out of
            // phase-1 scope).
            _ => None,
        },
        // Homebrew, Nix and pacman have no OSV coverage.
        _ => None,
    }
}

/// Scan installed packages for a single distro `ecosystem`. Every dependency
/// shares the one ecosystem string (a `system` inventory is one backend). The
/// lookup is delegated to the shared mlab transport, which proxies OSV. Returns
/// only packages carrying advisories.
pub fn scan(
    agent: &ureq::Agent,
    cache: &Cache,
    token: Option<&str>,
    deps: &[Dependency],
    ecosystem: &str,
) -> Result<Vec<VulnPackage>> {
    let coords: Vec<(String, String, String)> = deps
        .iter()
        .map(|d| (ecosystem.to_string(), d.name.clone(), d.version.clone()))
        .collect();
    crate::vuln::scan_coordinates(agent, cache, token, &coords)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(id: &str, ver: &str) -> Release {
        Release { id: id.into(), version_id: ver.into() }
    }

    #[test]
    fn debian_ecosystem_uses_major() {
        assert_eq!(
            osv_ecosystem(Ecosystem::Apt, &rel("debian", "12")),
            Some("Debian:12".into())
        );
    }

    #[test]
    fn ubuntu_ecosystem_is_lts_suffixed() {
        assert_eq!(
            osv_ecosystem(Ecosystem::Apt, &rel("ubuntu", "22.04")),
            Some("Ubuntu:22.04:LTS".into())
        );
    }

    #[test]
    fn alpine_ecosystem_takes_branch_with_v_prefix() {
        assert_eq!(
            osv_ecosystem(Ecosystem::Apk, &rel("alpine", "3.19.1")),
            Some("Alpine:v3.19".into())
        );
    }

    #[test]
    fn dnf_covers_rocky_and_alma_only() {
        assert_eq!(
            osv_ecosystem(Ecosystem::Dnf, &rel("rocky", "9.3")),
            Some("Rocky Linux:9".into())
        );
        assert_eq!(
            osv_ecosystem(Ecosystem::Dnf, &rel("almalinux", "9")),
            Some("AlmaLinux:9".into())
        );
        // Fedora / RHEL are not covered in phase 1.
        assert_eq!(osv_ecosystem(Ecosystem::Dnf, &rel("fedora", "40")), None);
        assert_eq!(osv_ecosystem(Ecosystem::Dnf, &rel("rhel", "9")), None);
    }

    #[test]
    fn uncovered_backends_return_none() {
        for eco in [Ecosystem::Brew, Ecosystem::Nix, Ecosystem::Pacman] {
            assert_eq!(osv_ecosystem(eco, &rel("whatever", "1")), None);
        }
    }

    #[test]
    fn override_parses_id_and_version() {
        assert_eq!(Release::parse_override("debian:12"), rel("debian", "12"));
        assert_eq!(Release::parse_override("Alpine:3.19"), rel("alpine", "3.19"));
        assert_eq!(Release::parse_override("debian"), rel("debian", ""));
    }
}
