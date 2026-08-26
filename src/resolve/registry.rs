//! Reading a registry's *current* view of a package: which endpoint holds it,
//! and how to get a repository, a license and a language split back out.

use std::collections::HashMap;

use super::repo::{extract_repo_url, urlencode};
use super::*;
use crate::model::{DepRef, Dependency, Ecosystem};

/// The registry endpoint that carries `dep`'s source-repo metadata. `None` for
/// ecosystems resolved without a registry call (Go, whose module path is the
/// repo). One endpoint per ecosystem:
/// - **npm** (Node): the immutable version manifest.
/// - **PyPI** (Python): the project JSON (`project_urls` + `home_page`).
/// - **crates.io** (Rust): the crate record (`repository`).
/// - **RubyGems** (Ruby): the gem JSON (`source_code_uri` / `homepage_uri`).
/// - **Packagist** (PHP): the package JSON (`repository`).
/// - **deps.dev** (Java/Maven): the version's `links` (avoids POM XML parsing).
pub(super) fn registry_url(dep: &Dependency, ep: &crate::settings::Endpoints) -> Option<String> {
    Some(match dep.ecosystem {
        Ecosystem::Node => format!("{}/{}/{}", ep.npm(), dep.name, dep.version),
        // Version-pinned: the name-only document describes the *latest* release,
        // whose license may differ from the pinned one. `registry_url_fallback`
        // covers versions these endpoints never served.
        Ecosystem::Python => format!("{}/pypi/{}/{}/json", ep.pypi(), dep.name, dep.version),
        Ecosystem::Rust => format!("{}/api/v1/crates/{}", ep.crates(), dep.name),
        Ecosystem::Ruby => format!(
            "{}/api/v2/rubygems/{}/versions/{}.json",
            ep.rubygems(),
            dep.name,
            dep.version
        ),
        Ecosystem::Php => format!("{}/packages/{}.json", ep.packagist(), dep.name),
        Ecosystem::Java => format!(
            "{}/v3/systems/maven/packages/{}/versions/{}",
            ep.deps_dev(),
            urlencode(&dep.name),
            urlencode(&dep.version),
        ),
        // Homebrew: the formula JSON carries `homepage` (often a GitHub repo).
        // The name can contain `@` (`openssl@3`); the API path takes it verbatim.
        Ecosystem::Brew => format!("{}/api/formula/{}.json", ep.brew(), dep.name),
        // Go's module path and Pacman's package URL resolve without a registry
        // call (repo parsed from the name / `resolved_url`).
        Ecosystem::Go
        | Ecosystem::Pacman
        | Ecosystem::Apt
        | Ecosystem::Dnf
        | Ecosystem::Nix
        | Ecosystem::Apk
        | Ecosystem::Winget
        | Ecosystem::Msix
        | Ecosystem::Choco
        | Ecosystem::Scoop
        | Ecosystem::Arp
        | Ecosystem::Asep
        | Ecosystem::Task
        | Ecosystem::Service
        | Ecosystem::Job
        | Ecosystem::Posture => return None,
    })
}

/// A second endpoint to try when [`registry_url`] 404s.
///
/// PyPI and RubyGems are the two registries whose *name-only* document describes
/// the **latest** version rather than the pinned one — so [`registry_url`] asks
/// for the exact version, and this is the name-only form to fall back on when
/// that version was never served under that spelling (a yanked release, or a
/// platform-suffixed gem like `nokogiri-1.13.9-x86_64-linux`).
pub(super) fn registry_url_fallback(
    dep: &Dependency,
    ep: &crate::settings::Endpoints,
) -> Option<String> {
    Some(match dep.ecosystem {
        Ecosystem::Python => format!("{}/pypi/{}/json", ep.pypi(), dep.name),
        Ecosystem::Ruby => format!("{}/api/v1/gems/{}.json", ep.rubygems(), dep.name),
        _ => return None,
    })
}

/// The **raw** license strings a registry document declares for `dep`.
///
/// Deliberately returns registry text rather than [`crate::model::License`]:
/// this result is cached forever, so it must record what the registry said, not
/// how we currently read it. Interpretation happens in
/// [`crate::license::resolve_raw`] on every read.
///
/// Version matching is the subtlety here. A project can relicense between
/// releases — Redis, Terraform, Elasticsearch, MongoDB and Sentry all did — so
/// reading the license off the *latest* version while the lockfile pins an older
/// one is wrong in exactly the cases that matter legally. Where a document
/// carries every version (crates.io, Packagist) the pinned one is looked up;
/// where it does not, [`registry_url`] already asked for the pinned version.
///
/// Several values mean "alternatives", except for PyPI where they are ranked
/// candidates — `resolve_raw` prefers whichever maps to SPDX, which handles both.
pub(super) fn raw_licenses_from(dep: &Dependency, v: &serde_json::Value) -> Vec<String> {
    let str_at = |val: &serde_json::Value, key: &str| {
        val.get(key).and_then(|x| x.as_str()).map(String::from)
    };
    let arr_at = |val: &serde_json::Value, key: &str| -> Vec<String> {
        val.get(key)
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    /// npm values may be a bare string or a `{type, url}` object.
    fn as_text(v: &serde_json::Value) -> Option<String> {
        v.as_str()
            .map(String::from)
            .or_else(|| v.get("type").and_then(|t| t.as_str()).map(String::from))
    }

    match dep.ecosystem {
        // The versioned manifest. `license` is usually an SPDX string; ancient
        // packages used `{type: ...}` or a `licenses` array.
        Ecosystem::Node => {
            if let Some(l) = v.get("license") {
                if let Some(t) = as_text(l) {
                    return vec![t];
                }
                if let Some(a) = l.as_array() {
                    return a.iter().filter_map(as_text).collect();
                }
            }
            v.get("licenses")
                .and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(as_text).collect())
                .unwrap_or_default()
        }
        // PyPI's `license` is hand-written prose. PEP 639 added the SPDX-valued
        // `license_expression`, still empty for most projects, so offer it first,
        // then the free text, then the trove classifiers — whose last segment is
        // the license name (`License :: OSI Approved :: MIT License`).
        Ecosystem::Python => {
            let Some(info) = v.get("info") else {
                return Vec::new();
            };
            let mut out = Vec::new();
            out.extend(str_at(info, "license_expression"));
            out.extend(str_at(info, "license"));
            out.extend(
                arr_at(info, "classifiers")
                    .iter()
                    .filter(|c| c.starts_with("License ::"))
                    .filter_map(|c| c.rsplit("::").next().map(|s| s.trim().to_string())),
            );
            out
        }
        // `crate.license` is null on crates.io: the license lives per version.
        Ecosystem::Rust => {
            let pinned = v
                .get("versions")
                .and_then(|a| a.as_array())
                .and_then(|a| {
                    a.iter()
                        .find(|ver| str_at(ver, "num").as_deref() == Some(&dep.version))
                })
                .and_then(|ver| str_at(ver, "license"));
            pinned
                .or_else(|| v.get("crate").and_then(|c| str_at(c, "license")))
                .into_iter()
                .collect()
        }
        // v2 (version-pinned) and v1 (latest) both expose a `licenses` array.
        Ecosystem::Ruby => arr_at(v, "licenses"),
        // Packagist returns every version; the key may or may not carry a `v`.
        Ecosystem::Php => {
            let Some(versions) = v.get("package").and_then(|p| p.get("versions")) else {
                return Vec::new();
            };
            versions
                .get(&dep.version)
                .or_else(|| versions.get(format!("v{}", dep.version)))
                .map(|ver| arr_at(ver, "license"))
                .unwrap_or_default()
        }
        // deps.dev is already version-pinned and returns SPDX identifiers.
        Ecosystem::Java | Ecosystem::Go => arr_at(v, "licenses"),
        // OS packages: licensing is a distro concern, not resolved here.
        _ => Vec::new(),
    }
}

/// Candidate repo URLs from a registry manifest, in priority order. `repo_for`
/// takes the first that parses to a known host, so listing a homepage last is a
/// safe fallback — a non-repo homepage simply fails to parse and is skipped.
pub(super) fn repo_candidates(eco: Ecosystem, v: &serde_json::Value) -> Vec<String> {
    let s = |val: &serde_json::Value, key: &str| {
        val.get(key).and_then(|x| x.as_str()).map(String::from)
    };
    match eco {
        Ecosystem::Node => extract_repo_url(v).into_iter().collect(),
        Ecosystem::Python => {
            let Some(info) = v.get("info") else {
                return Vec::new();
            };
            let mut out = Vec::new();
            // Prefer explicitly repo-labelled project URLs, then any URL, then
            // the home page.
            if let Some(urls) = info.get("project_urls").and_then(|u| u.as_object()) {
                for key in [
                    "Source",
                    "Source Code",
                    "Repository",
                    "Code",
                    "GitHub",
                    "Git",
                ] {
                    if let Some(u) = urls.get(key).and_then(|x| x.as_str()) {
                        out.push(u.to_string());
                    }
                }
                out.extend(urls.values().filter_map(|x| x.as_str()).map(String::from));
            }
            out.extend(s(info, "home_page"));
            out
        }
        Ecosystem::Rust => v
            .get("crate")
            .and_then(|c| s(c, "repository"))
            .into_iter()
            .collect(),
        Ecosystem::Ruby => [s(v, "source_code_uri"), s(v, "homepage_uri")]
            .into_iter()
            .flatten()
            .collect(),
        Ecosystem::Php => v
            .get("package")
            .and_then(|p| s(p, "repository"))
            .into_iter()
            .collect(),
        Ecosystem::Java => v
            .get("links")
            .and_then(|l| l.as_array())
            .map(|links| {
                let mut out = Vec::new();
                // deps.dev labels the canonical repo SOURCE_REPO; fall back to
                // any other link (HOMEPAGE, etc.) that happens to be a repo.
                for label in ["SOURCE_REPO"] {
                    for l in links {
                        if l.get("label").and_then(|x| x.as_str()) == Some(label)
                            && let Some(u) = l.get("url").and_then(|x| x.as_str())
                        {
                            out.push(u.to_string());
                        }
                    }
                }
                out.extend(links.iter().filter_map(|l| s(l, "url")));
                out
            })
            .unwrap_or_default(),
        // Homebrew: `homepage`, then the stable source URL as a fallback (some
        // formulae point `urls.stable` straight at a GitHub release tarball).
        Ecosystem::Brew => [
            s(v, "homepage"),
            v.get("urls")
                .and_then(|u| u.get("stable"))
                .and_then(|st| s(st, "url")),
        ]
        .into_iter()
        .flatten()
        .collect(),
        // Resolved directly from the name / resolved_url, never via a registry.
        Ecosystem::Go
        | Ecosystem::Pacman
        | Ecosystem::Apt
        | Ecosystem::Dnf
        | Ecosystem::Nix
        | Ecosystem::Apk
        | Ecosystem::Winget
        | Ecosystem::Msix
        | Ecosystem::Choco
        | Ecosystem::Scoop
        | Ecosystem::Arp
        | Ecosystem::Asep
        | Ecosystem::Task
        | Ecosystem::Service
        | Ecosystem::Job
        | Ecosystem::Posture => Vec::new(),
    }
}

/// Normalize a host `/languages` object (`{name: bytes|percent}`) into a
/// `(name, percent)` list, biggest first, capped to the top 3 with a rolled-up
/// `Other`. `None` for an empty repo.
pub(super) fn normalize_languages(v: &serde_json::Value) -> Option<Vec<(String, f64)>> {
    const TOP: usize = 3;
    let obj = v.as_object()?;
    let mut items: Vec<(String, f64)> = obj
        .iter()
        .filter_map(|(k, val)| val.as_f64().map(|n| (k.clone(), n)))
        .filter(|(_, n)| *n > 0.0)
        .collect();
    let total: f64 = items.iter().map(|(_, n)| n).sum();
    if items.is_empty() || total <= 0.0 {
        return None;
    }
    items.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut out: Vec<(String, f64)> = items
        .iter()
        .take(TOP)
        .map(|(n, w)| (n.clone(), w / total * 100.0))
        .collect();
    if items.len() > TOP {
        let other = (100.0 - out.iter().map(|(_, p)| p).sum::<f64>()).max(0.0);
        if other >= 0.05 {
            out.push(("Other".to_string(), other));
        }
    }
    Some(out)
}

/// Copy registry-resolved licenses back onto the dependency list.
///
/// A lockfile declaration always wins: npm and composer record the license for
/// the exact artifact that was installed, whereas a registry describes what the
/// publisher currently says about that version. So this only fills packages that
/// have none, and never overwrites a [`crate::model::LicenseSource::Lockfile`] value.
pub fn apply_licenses(deps: &mut [Dependency], resolutions: &HashMap<DepRef, Resolution>) {
    for d in deps.iter_mut() {
        if !d.licenses.is_empty() {
            continue;
        }
        if let Some(res) = resolutions.get(&(d.name.clone(), d.version.clone()))
            && !res.licenses.is_empty()
        {
            d.licenses = res.licenses.clone();
            d.license_source = crate::model::LicenseSource::Registry;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_languages_percentages_and_other() {
        // Bytes (GitHub/Codeberg shape): normalized to %, top-3 + Other.
        let bytes = serde_json::json!({
            "Rust": 9000, "Shell": 600, "Ruby": 300, "Roff": 90, "Lua": 10
        });
        let out = normalize_languages(&bytes).unwrap();
        assert_eq!(out[0].0, "Rust");
        assert!((out[0].1 - 90.0).abs() < 0.1, "Rust ~90%");
        assert_eq!(out.len(), 4, "top 3 + Other");
        assert_eq!(out[3].0, "Other");
        let sum: f64 = out.iter().map(|(_, p)| p).sum();
        assert!((sum - 100.0).abs() < 0.01, "sums to 100");

        // Already-percentages (GitLab shape) with ≤3 langs: no Other appended.
        let pct = serde_json::json!({ "Go": 98.34, "Shell": 1.66 });
        let out = normalize_languages(&pct).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0, "Go");

        assert!(normalize_languages(&serde_json::json!({})).is_none());
    }

    #[test]
    fn extracts_repo_candidates_per_ecosystem() {
        let py = serde_json::json!({
            "info": { "project_urls": { "Homepage": "https://x.dev", "Source": "https://github.com/psf/requests" } }
        });
        assert_eq!(
            repo_candidates(Ecosystem::Python, &py)
                .iter()
                .find_map(|u| parse_repo(u))
                .unwrap()
                .slug(),
            "psf/requests"
        );
        let rs =
            serde_json::json!({ "crate": { "repository": "https://github.com/serde-rs/serde" } });
        assert_eq!(
            repo_candidates(Ecosystem::Rust, &rs)
                .iter()
                .find_map(|u| parse_repo(u))
                .unwrap()
                .slug(),
            "serde-rs/serde"
        );
        let rb = serde_json::json!({ "source_code_uri": "https://gitlab.com/o/r" });
        assert_eq!(
            repo_candidates(Ecosystem::Ruby, &rb),
            vec!["https://gitlab.com/o/r"]
        );
        let php = serde_json::json!({ "package": { "repository": "https://github.com/laravel/framework" } });
        assert_eq!(
            repo_candidates(Ecosystem::Php, &php)
                .iter()
                .find_map(|u| parse_repo(u))
                .unwrap()
                .slug(),
            "laravel/framework"
        );
        let java = serde_json::json!({
            "links": [ { "label": "HOMEPAGE", "url": "https://guava.dev" },
                       { "label": "SOURCE_REPO", "url": "https://github.com/google/guava" } ]
        });
        assert_eq!(
            repo_candidates(Ecosystem::Java, &java)
                .iter()
                .find_map(|u| parse_repo(u))
                .unwrap()
                .slug(),
            "google/guava"
        );
    }
}
