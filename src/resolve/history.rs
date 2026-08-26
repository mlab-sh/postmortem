//! Reading a registry's *release history*: what changed between the installed
//! version and the one before it. One reader per registry document shape.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::*;
use crate::model::{Dependency, Ecosystem};

/// Provenance anomalies for one installed version vs its predecessors, derived
/// from whichever document a registry publishes a release history in: npm's
/// packument, crates.io's crate record, PyPI's project JSON. Immutable per
/// `(name, version)`, so it's cached.
///
/// The `Option<bool>` fields carry three states, not two. `Some(true)` is the
/// anomaly, `Some(false)` is *compared, and it is not there*, and `None` is
/// *this registry does not publish what the comparison needs*. A plain `false`
/// standing for both of the last two would let a report imply a check nobody
/// ran — which is precisely the risk of widening this struct past the one
/// ecosystem it was written for. What each registry can answer:
///
/// | signal               | npm | crates.io | PyPI |
/// |----------------------|-----|-----------|------|
/// | install script added | yes | no        | no   |
/// | dormant release      | yes | yes       | yes  |
/// | new publisher        | yes | yes       | no   |
/// | provenance removed   | yes | yes       | no   |
/// | fresh / newborn      | yes | yes       | yes  |
/// | maintainers          | yes | no        | yes  |
///
/// PyPI's per-file attestations (PEP 740) are reachable, but only through an
/// `/integrity/{project}/{version}/{file}/provenance` request per file — a cost
/// the shared resolve path does not pay for a signal that isn't in a document it
/// already holds. crates.io's owner list is the same trade (`/owners`).
#[derive(Serialize, Deserialize, Default, Clone)]
pub(super) struct VersionMeta {
    /// An install lifecycle script is present here but not in the prior version.
    /// npm only — no other registry records what a package runs at install time.
    #[serde(default)]
    pub(super) install_script_added: Option<bool>,
    /// Gap since the prior release, in days, when it exceeds the dormancy bar.
    pub(super) dormant_gap_days: Option<i64>,
    /// The publisher differs from every earlier version's publisher. `None`
    /// where the registry records no per-release publisher (PyPI), or where
    /// neither side of the comparison names one.
    #[serde(default)]
    pub(super) new_publisher: Option<bool>,
    /// Unix seconds the installed version was published (immutable, so safe to
    /// cache). The age-relative "fresh-release" decision is made at use-time
    /// against the current clock, never cached.
    #[serde(default)]
    pub(super) published_ts: Option<i64>,
    /// Unix seconds of the package's first-ever release (`time.created`,
    /// immutable). The "newborn" decision is made at use-time against the clock.
    #[serde(default)]
    pub(super) first_release_ts: Option<i64>,
    /// This version has no provenance attestation but the prior one did — a
    /// publish that skipped the trusted OIDC/CI flow (the axios pattern). Read
    /// from `dist.attestations` on npm and `trustpub_data` on crates.io; `None`
    /// on PyPI, whose attestations need a per-file request.
    #[serde(default)]
    pub(super) provenance_removed: Option<bool>,
    /// Every account that can publish this package.
    ///
    /// The *control* surface, not the publish history: any maintainer can push a
    /// new version, so a compromise of any one of them reaches the package. That
    /// is the unit a maintainer graph has to count.
    #[serde(default)]
    pub(super) maintainers: Vec<String>,
}

/// Where a package's release history lives: the cache namespace to file it
/// under, the document's URL, and the reader for that document's shape. See
/// [`Resolver::history_source`].
type HistorySource = (
    &'static str,
    String,
    fn(&serde_json::Value, &str) -> VersionMeta,
);

/// Flag a gap this large (days) between releases as a dormancy anomaly.
const DORMANT_DAYS: i64 = 365;

/// Cooldown window: a version published within this many hours hasn't had time
/// for the ecosystem to catch a malicious release. 48h is the middle of the
/// 24–72h the supply-chain guidance converges on.
const FRESH_HOURS: i64 = 48;

/// A package whose first-ever release is younger than this has no track record —
/// the delivery vehicle for typosquats and slopsquatted (AI-hallucinated) names.
const NEWBORN_DAYS: i64 = 30;

/// Age in hours of a version published at `published_ts`, but only if it falls
/// inside the [`FRESH_HOURS`] cooldown window — otherwise `None`. Kept pure (now
/// is passed in) so the cooldown threshold is unit-testable. A future publish
/// time (clock skew) yields age 0, still "fresh".
pub(super) fn fresh_age_hours(published_ts: Option<i64>, now: i64) -> Option<i64> {
    let ts = published_ts?;
    let hours = (now - ts).max(0) / 3_600;
    (hours < FRESH_HOURS).then_some(hours)
}

/// Days since the package's first-ever release, only within the [`NEWBORN_DAYS`]
/// window — else `None`. Pure (now passed in) for unit-testing.
pub(super) fn newborn_age_days(first_release_ts: Option<i64>, now: i64) -> Option<i64> {
    let ts = first_release_ts?;
    let days = (now - ts).max(0) / 86_400;
    (days < NEWBORN_DAYS).then_some(days)
}

/// RFC3339 (GitHub timestamps) → unix seconds.
pub(super) fn parse_ts(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.timestamp())
}

/// Derive provenance anomalies for `version` from an npm packument. Compares the
/// installed version against its immediate time-predecessor: an install script
/// that wasn't there before, a suspiciously long dormancy, and a publisher that
/// never shipped an earlier version (account-takeover / trojanized-update tells,
/// à la event-stream and ua-parser-js).
fn compute_version_meta(doc: &serde_json::Value, version: &str) -> VersionMeta {
    // The maintainer set is a property of the package, not of a version, so it
    // is recorded before any of the version-comparison logic can return early.
    let mut meta = VersionMeta {
        maintainers: maintainer_names(doc.get("maintainers")),
        ..Default::default()
    };
    let (Some(times), Some(versions)) = (
        doc.get("time").and_then(|t| t.as_object()),
        doc.get("versions").and_then(|v| v.as_object()),
    ) else {
        return meta;
    };
    let Some(inst_ts) = times
        .get(version)
        .and_then(|t| t.as_str())
        .and_then(parse_ts)
    else {
        return meta;
    };
    // Record the (immutable) publish time up front — even a brand-new *first*
    // release is "fresh", and that decision happens at use-time, not here.
    meta.published_ts = Some(inst_ts);
    // `time.created` is the package's first-ever publish — the newborn clock.
    meta.first_release_ts = times
        .get("created")
        .and_then(|t| t.as_str())
        .and_then(parse_ts);

    // Prior version = the one published closest before the installed one.
    let is_version = |k: &str| k != "created" && k != "modified" && k != version;
    let mut prior: Option<(&str, i64)> = None;
    let mut prior_publishers: Vec<String> = Vec::new();
    for (v, t) in times {
        if !is_version(v) {
            continue;
        }
        let Some(ts) = t.as_str().and_then(parse_ts) else {
            continue;
        };
        if ts >= inst_ts {
            continue;
        }
        if let Some(p) = versions.get(v).and_then(publisher) {
            prior_publishers.push(p.to_string());
        }
        if prior.is_none_or(|(_, pt)| ts > pt) {
            prior = Some((v.as_str(), ts));
        }
    }

    let Some((prior_v, prior_ts)) = prior else {
        return meta; // first release — nothing to compare against
    };

    let inst = versions.get(version);
    let inst_hook = inst.is_some_and(has_install_hook);
    let prior_hook = versions.get(prior_v).is_some_and(has_install_hook);

    meta.install_script_added = Some(inst_hook && !prior_hook);
    // Provenance regression: the prior version was published with an OIDC/CI
    // attestation and this one wasn't (the axios pattern — a direct token push
    // that skipped Trusted Publishing).
    meta.provenance_removed = Some(
        versions.get(prior_v).is_some_and(has_provenance) && !inst.is_some_and(has_provenance),
    );
    let gap = (inst_ts - prior_ts) / 86_400;
    if gap >= DORMANT_DAYS {
        meta.dormant_gap_days = Some(gap);
    }
    // npm has not always recorded `_npmUser`. A publisher missing on either side
    // leaves the comparison unanswerable, which is not the same as answering no.
    meta.new_publisher = match inst.and_then(publisher) {
        Some(ip) if !prior_publishers.is_empty() => Some(!prior_publishers.iter().any(|p| p == ip)),
        _ => None,
    };
    meta
}

/// Derive the same anomalies from a **crates.io** crate record
/// (`/api/v1/crates/{name}`), whose `versions` array is the entire release
/// history: `created_at`, the `published_by` account, and `trustpub_data` — the
/// Trusted Publishing record, crates.io's equivalent of an npm attestation.
///
/// This reads the document already fetched for the repository and the license,
/// so the Rust path pays no request of its own — see `registry_record`.
fn compute_version_meta_crates(doc: &serde_json::Value, version: &str) -> VersionMeta {
    // crates.io publishes no owner list in this document (`/owners` is its own
    // request), so `maintainers` stays empty — meaning unknown, never "nobody".
    let mut meta = VersionMeta::default();
    let Some(versions) = doc.get("versions").and_then(|v| v.as_array()) else {
        return meta;
    };
    let at = |v: &serde_json::Value| {
        v.get("created_at")
            .and_then(|t| t.as_str())
            .and_then(parse_ts)
    };
    // Items, not closures: both borrow out of their argument, and a closure's
    // elided return lifetime does not tie back to it.
    fn num(v: &serde_json::Value) -> Option<&str> {
        v.get("num").and_then(|n| n.as_str())
    }
    fn by(v: &serde_json::Value) -> Option<&str> {
        v.get("published_by")
            .and_then(|u| u.get("login"))
            .and_then(|l| l.as_str())
    }
    // A crate version is never unpublished, only yanked, so the oldest entry in
    // the record really is the package's first release.
    meta.first_release_ts = versions.iter().filter_map(at).min();

    let Some(inst) = versions.iter().find(|v| num(v) == Some(version)) else {
        return meta;
    };
    let Some(inst_ts) = at(inst) else {
        return meta;
    };
    meta.published_ts = Some(inst_ts);

    // Prior release = the one published closest before the installed one. Yanked
    // versions count: a yank is a withdrawal, not an un-publish, so it is still
    // the release a dormancy gap should be measured from.
    let mut prior: Option<(&serde_json::Value, i64)> = None;
    let mut prior_publishers: Vec<&str> = Vec::new();
    for v in versions {
        let Some(ts) = at(v) else { continue };
        if ts >= inst_ts {
            continue;
        }
        if let Some(p) = by(v) {
            prior_publishers.push(p);
        }
        if prior.is_none_or(|(_, pt)| ts > pt) {
            prior = Some((v, ts));
        }
    }
    let Some((prior, prior_ts)) = prior else {
        return meta; // first release — nothing to compare against
    };

    let gap = (inst_ts - prior_ts) / 86_400;
    if gap >= DORMANT_DAYS {
        meta.dormant_gap_days = Some(gap);
    }
    // Trusted Publishing is recent, so most history carries no `trustpub_data`
    // on either side: this fires on the regression only — attested, then not.
    let attested = |v: &serde_json::Value| {
        !matches!(v.get("trustpub_data"), None | Some(serde_json::Value::Null))
    };
    meta.provenance_removed = Some(attested(prior) && !attested(inst));
    meta.new_publisher = match by(inst) {
        Some(ip) if !prior_publishers.is_empty() => Some(!prior_publishers.contains(&ip)),
        _ => None,
    };
    // Whether a crate runs a `build.rs` is not in the registry record, so
    // `install_script_added` stays unevaluated rather than reporting a clean
    // comparison nobody made.
    meta
}

/// Derive what a **PyPI** project JSON (`/pypi/{name}/json`) can answer: the
/// release timeline from `releases[version][].upload_time_iso_8601`, and the
/// account set from `ownership.roles`.
///
/// A release is dated by its *first* file — an sdist and its wheels land seconds
/// to hours apart, and the first upload is when the version became installable.
/// Yanked releases are kept, for the same reason as crates.io's.
///
/// PyPI records no per-release uploader, so `new_publisher` is unanswerable
/// here; PEP 740 attestations need a per-file `/integrity/` request, so
/// `provenance_removed` is too. Both stay `None` — see [`VersionMeta`].
fn compute_version_meta_pypi(doc: &serde_json::Value, version: &str) -> VersionMeta {
    let mut meta = VersionMeta {
        maintainers: pypi_owners(doc.get("ownership")),
        ..Default::default()
    };
    let Some(releases) = doc.get("releases").and_then(|r| r.as_object()) else {
        return meta;
    };
    let released_at = |files: &serde_json::Value| -> Option<i64> {
        files
            .as_array()?
            .iter()
            .filter_map(|f| {
                f.get("upload_time_iso_8601")
                    .and_then(|t| t.as_str())
                    .and_then(parse_ts)
            })
            .min()
    };
    meta.first_release_ts = releases.values().filter_map(released_at).min();

    // A release with no files (every artifact deleted) has no date, and a pinned
    // version can be spelled differently from its release key. Either way the
    // timeline is unreadable for this version — the owner set still stands.
    let Some(inst_ts) = releases.get(version).and_then(released_at) else {
        return meta;
    };
    meta.published_ts = Some(inst_ts);

    let prior_ts = releases
        .iter()
        .filter(|(v, _)| v.as_str() != version)
        .filter_map(|(_, files)| released_at(files))
        .filter(|ts| *ts < inst_ts)
        .max();
    if let Some(prior_ts) = prior_ts {
        let gap = (inst_ts - prior_ts) / 86_400;
        if gap >= DORMANT_DAYS {
            meta.dormant_gap_days = Some(gap);
        }
    }
    meta
}

/// Accounts on a PyPI project's `ownership` block (`roles: [{role, user}]`).
///
/// Owner and Maintainer alike: both can publish, so both are part of the control
/// surface a compromise would reach — the same reading as npm's maintainer set.
fn pypi_owners(v: Option<&serde_json::Value>) -> Vec<String> {
    let mut out: Vec<String> = v
        .and_then(|o| o.get("roles"))
        .and_then(|r| r.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|r| r.get("user").and_then(|u| u.as_str()).map(str::to_string))
                .filter(|n| !n.trim().is_empty())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out.dedup();
    out
}

/// Does a version manifest carry an npm provenance attestation (published via
/// Trusted Publishing / `--provenance`, i.e. `dist.attestations`)?
fn has_provenance(manifest: &serde_json::Value) -> bool {
    manifest
        .get("dist")
        .and_then(|d| d.get("attestations"))
        .is_some()
}

/// Does a version manifest declare an install lifecycle script?
fn has_install_hook(manifest: &serde_json::Value) -> bool {
    manifest
        .get("scripts")
        .and_then(|s| s.as_object())
        .is_some_and(|s| {
            ["preinstall", "install", "postinstall"]
                .iter()
                .any(|k| s.contains_key(*k))
        })
}

/// The npm user who published this version (`_npmUser.name`).
/// Account names from an npm/Packagist `maintainers` array (`[{name, email}]`),
/// deduplicated and sorted so the graph is stable across runs.
pub(super) fn maintainer_names(v: Option<&serde_json::Value>) -> Vec<String> {
    let mut out: Vec<String> = v
        .and_then(|m| m.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|m| {
                    m.get("name")
                        .and_then(|n| n.as_str())
                        .or_else(|| m.as_str())
                        .map(str::to_string)
                })
                .filter(|n| !n.trim().is_empty())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out.dedup();
    out
}

pub(super) fn publisher(manifest: &serde_json::Value) -> Option<&str> {
    manifest
        .get("_npmUser")
        .and_then(|u| u.get("name"))
        .and_then(|n| n.as_str())
}

impl Resolver {
    /// Where a package's release history lives: the cache namespace to file it
    /// under, the document's URL, and the reader for that document's shape.
    ///
    /// `None` for the registries that publish only a *current* view of a package
    /// (RubyGems, Packagist, deps.dev) and for the ecosystems with no registry
    /// call at all (Go, the OS package managers) — there is no history to read,
    /// which is a different thing from a history that came back clean.
    pub(super) fn history_source(&self, dep: &Dependency) -> Option<HistorySource> {
        Some(match dep.ecosystem {
            Ecosystem::Node => (
                "npm-meta",
                format!("{}/{}", self.endpoints.npm(), dep.name),
                compute_version_meta as fn(&serde_json::Value, &str) -> VersionMeta,
            ),
            // The crate record carries every version. It is also the document
            // `registry_url` already fetches, so `registry_record` fills this
            // namespace itself — this URL is the fallback for a cache written
            // before it did, not the normal path.
            Ecosystem::Rust => (
                "crates-meta",
                format!("{}/api/v1/crates/{}", self.endpoints.crates(), dep.name),
                compute_version_meta_crates,
            ),
            // PyPI splits the two: the *version-pinned* document `registry_url`
            // asks for (because a license is per-version) carries no `releases`
            // map, so the history costs one extra request against the name-only
            // document — derived once and cached per version forever.
            Ecosystem::Python => (
                "pypi-meta",
                format!("{}/pypi/{}/json", self.endpoints.pypi(), dep.name),
                compute_version_meta_pypi,
            ),
            _ => return None,
        })
    }

    /// Provenance anomalies for the installed version, from whichever document
    /// its registry publishes a release history in. Cached per `(name, version)`
    /// (the history up to a published version is immutable). `Ok(None)` means
    /// the ecosystem has no such document; a fetch failure caches as "clean".
    pub(super) fn version_meta(&self, dep: &Dependency) -> Result<Option<VersionMeta>> {
        let Some((ns, url, read)) = self.history_source(dep) else {
            return Ok(None);
        };
        let key = format!("{}@{}", dep.name, dep.version);
        if let Some(hit) = self.cache.get::<VersionMeta>(ns, &key) {
            return Ok(Some(hit));
        }
        let meta = match self.get_json(&url, &[])? {
            Some(doc) => read(&doc, &dep.version),
            None => VersionMeta::default(),
        };
        self.cache.put(ns, &key, &meta);
        Ok(Some(meta))
    }

    /// The raw npm packument for a package — its whole publish history.
    ///
    /// Deliberately **not** cached. Everything else read from a packument is
    /// derived per `(name, version)` and immutable once published, but a history
    /// gains an entry every time someone publishes; a cached copy would go quiet
    /// exactly when a new release is the thing worth seeing.
    pub fn packument(&self, name: &str) -> Result<Option<serde_json::Value>> {
        let url = format!("{}/{}", self.endpoints.npm(), name);
        self.get_json(&url, &[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_meta_catches_event_stream_pattern() {
        // v1 by alice, no install script, 2016; v2 by eve, postinstall, 2018.
        let doc = serde_json::json!({
            "time": {
                "created": "2016-01-01T00:00:00.000Z",
                "1.0.0": "2016-01-01T00:00:00.000Z",
                "2.0.0": "2018-06-01T00:00:00.000Z",
            },
            "versions": {
                "1.0.0": { "_npmUser": { "name": "alice" } },
                "2.0.0": { "_npmUser": { "name": "eve" }, "scripts": { "postinstall": "node ./x.js" } },
            }
        });
        let m = compute_version_meta(&doc, "2.0.0");
        assert_eq!(
            m.install_script_added,
            Some(true),
            "postinstall added vs prior"
        );
        assert_eq!(
            m.new_publisher,
            Some(true),
            "eve never shipped an earlier version"
        );
        assert!(
            m.dormant_gap_days.unwrap() > 365,
            "long dormancy before the release"
        );
    }

    #[test]
    fn version_meta_clean_release() {
        let doc = serde_json::json!({
            "time": {
                "1.0.0": "2023-01-01T00:00:00.000Z",
                "1.0.1": "2023-02-01T00:00:00.000Z",
            },
            "versions": {
                "1.0.0": { "_npmUser": { "name": "alice" } },
                "1.0.1": { "_npmUser": { "name": "alice" } },
            }
        });
        let m = compute_version_meta(&doc, "1.0.1");
        assert_eq!(m.install_script_added, Some(false), "compared, and absent");
        assert_eq!(m.new_publisher, Some(false));
        assert!(m.dormant_gap_days.is_none());
        assert_eq!(
            m.published_ts,
            parse_ts("2023-02-01T00:00:00.000Z"),
            "publish time recorded"
        );
    }

    #[test]
    fn fresh_release_cooldown_window() {
        let now = 1_700_000_000;
        assert_eq!(
            fresh_age_hours(Some(now - 10 * 3600), now),
            Some(10),
            "10h old → fresh"
        );
        assert_eq!(
            fresh_age_hours(Some(now - 47 * 3600), now),
            Some(47),
            "just inside 48h"
        );
        assert_eq!(
            fresh_age_hours(Some(now - 49 * 3600), now),
            None,
            "aged out of window"
        );
        assert_eq!(
            fresh_age_hours(None, now),
            None,
            "no publish time → not fresh"
        );
        assert_eq!(
            fresh_age_hours(Some(now + 3600), now),
            Some(0),
            "clock skew → age 0, still fresh"
        );
    }

    #[test]
    fn newborn_window() {
        let now = 1_700_000_000;
        assert_eq!(
            newborn_age_days(Some(now - 5 * 86_400), now),
            Some(5),
            "5d old → newborn"
        );
        assert_eq!(
            newborn_age_days(Some(now - 29 * 86_400), now),
            Some(29),
            "just inside 30d"
        );
        assert_eq!(
            newborn_age_days(Some(now - 45 * 86_400), now),
            None,
            "established package"
        );
        assert_eq!(newborn_age_days(None, now), None);
    }

    #[test]
    fn version_meta_provenance_regression() {
        // Prior version was attested; this one isn't → regression (axios pattern).
        let doc = serde_json::json!({
            "time": {
                "1.0.0": "2024-01-01T00:00:00.000Z",
                "1.0.1": "2024-02-01T00:00:00.000Z",
            },
            "versions": {
                "1.0.0": { "dist": { "attestations": { "url": "x" } } },
                "1.0.1": { "dist": {} },
            }
        });
        assert_eq!(
            compute_version_meta(&doc, "1.0.1").provenance_removed,
            Some(true)
        );

        // Both attested (or neither) → not a regression.
        let steady = serde_json::json!({
            "time": {
                "1.0.0": "2024-01-01T00:00:00.000Z",
                "1.0.1": "2024-02-01T00:00:00.000Z",
            },
            "versions": {
                "1.0.0": { "dist": { "attestations": {} } },
                "1.0.1": { "dist": { "attestations": {} } },
            }
        });
        assert_eq!(
            compute_version_meta(&steady, "1.0.1").provenance_removed,
            Some(false)
        );
    }

    #[test]
    fn version_meta_first_release_is_quiet() {
        let doc = serde_json::json!({
            "time": { "1.0.0": "2023-01-01T00:00:00.000Z" },
            "versions": { "1.0.0": { "scripts": { "postinstall": "x" } } }
        });
        let m = compute_version_meta(&doc, "1.0.0");
        // No predecessor → neither question has an answer. Unevaluated, not
        // clean: a first release *does* ship a postinstall here.
        assert!(m.install_script_added.is_none());
        assert!(m.new_publisher.is_none());
    }

    #[test]
    fn crates_version_meta_catches_takeover_pattern() {
        // 1.0.0 by alice in 2016; 2.0.0 by eve in 2018 — the crates.io shape of
        // the same story as event-stream.
        let doc = serde_json::json!({
            "versions": [
                { "num": "2.0.0", "created_at": "2018-06-01T00:00:00.000000Z",
                  "published_by": { "login": "eve" }, "trustpub_data": null },
                { "num": "1.0.0", "created_at": "2016-01-01T00:00:00.000000Z",
                  "published_by": { "login": "alice" }, "trustpub_data": null },
            ]
        });
        let m = compute_version_meta_crates(&doc, "2.0.0");
        assert_eq!(m.new_publisher, Some(true), "eve is new to this crate");
        assert!(m.dormant_gap_days.unwrap() > 365, "dormant since 2016");
        assert_eq!(m.published_ts, parse_ts("2018-06-01T00:00:00.000000Z"));
        assert_eq!(
            m.first_release_ts,
            parse_ts("2016-01-01T00:00:00.000000Z"),
            "oldest entry is the first release"
        );
        assert!(
            m.install_script_added.is_none(),
            "a build.rs is not in the crate record — unevaluated, not clean"
        );
        assert!(m.maintainers.is_empty(), "owners need their own request");
    }

    #[test]
    fn crates_version_meta_provenance_regression() {
        let versions = |inst_trustpub: serde_json::Value| {
            serde_json::json!({
                "versions": [
                    { "num": "1.0.1", "created_at": "2026-02-01T00:00:00.000000Z",
                      "published_by": { "login": "alice" }, "trustpub_data": inst_trustpub },
                    { "num": "1.0.0", "created_at": "2026-01-01T00:00:00.000000Z",
                      "published_by": { "login": "alice" },
                      "trustpub_data": { "provider": "github" } },
                ]
            })
        };
        // Published through Trusted Publishing, then not: the axios pattern.
        assert_eq!(
            compute_version_meta_crates(&versions(serde_json::Value::Null), "1.0.1")
                .provenance_removed,
            Some(true)
        );
        // Still attested → compared, and not a regression.
        assert_eq!(
            compute_version_meta_crates(
                &versions(serde_json::json!({ "provider": "github" })),
                "1.0.1"
            )
            .provenance_removed,
            Some(false)
        );
        // Steady publisher → answered, and no change.
        assert_eq!(
            compute_version_meta_crates(&versions(serde_json::Value::Null), "1.0.1").new_publisher,
            Some(false)
        );
    }

    #[test]
    fn crates_version_meta_unrecorded_publisher_is_unanswered() {
        // Pre-2017 crates carry no `published_by`. Nothing to compare against is
        // not the same as nothing changed.
        let doc = serde_json::json!({
            "versions": [
                { "num": "2.0.0", "created_at": "2016-06-01T00:00:00.000000Z", "published_by": null },
                { "num": "1.0.0", "created_at": "2016-01-01T00:00:00.000000Z", "published_by": null },
            ]
        });
        assert!(
            compute_version_meta_crates(&doc, "2.0.0")
                .new_publisher
                .is_none()
        );
    }

    #[test]
    fn pypi_version_meta_reads_timeline_and_owners() {
        let doc = serde_json::json!({
            "ownership": { "roles": [
                { "role": "Owner", "user": "nate" },
                { "role": "Maintainer", "user": "alice" },
            ]},
            "releases": {
                "1.0.0": [{ "upload_time_iso_8601": "2016-01-01T00:00:00.000000Z" }],
                // Wheel published after the sdist: the release is dated by the
                // first file, not the last.
                "2.0.0": [
                    { "upload_time_iso_8601": "2018-06-01T12:00:00.000000Z" },
                    { "upload_time_iso_8601": "2018-06-01T09:00:00.000000Z" },
                ],
            }
        });
        let m = compute_version_meta_pypi(&doc, "2.0.0");
        assert_eq!(
            m.published_ts,
            parse_ts("2018-06-01T09:00:00.000000Z"),
            "dated by its first file"
        );
        assert_eq!(m.first_release_ts, parse_ts("2016-01-01T00:00:00.000000Z"));
        assert!(m.dormant_gap_days.unwrap() > 365);
        assert_eq!(
            m.maintainers,
            vec!["alice", "nate"],
            "owners and maintainers"
        );
        assert!(
            m.new_publisher.is_none(),
            "PyPI records no per-release uploader"
        );
        assert!(
            m.provenance_removed.is_none(),
            "attestations need a per-file request"
        );
    }

    #[test]
    fn pypi_version_meta_keeps_owners_when_the_version_is_missing() {
        // A pinned version absent from `releases` (a different spelling, or every
        // file deleted) still leaves the owner set readable.
        let doc = serde_json::json!({
            "ownership": { "roles": [{ "role": "Owner", "user": "nate" }] },
            "releases": { "1.0.0": [{ "upload_time_iso_8601": "2020-01-01T00:00:00.000000Z" }] }
        });
        let m = compute_version_meta_pypi(&doc, "9.9.9");
        assert!(m.published_ts.is_none());
        assert_eq!(m.maintainers, vec!["nate"]);
        assert_eq!(m.first_release_ts, parse_ts("2020-01-01T00:00:00.000000Z"));
    }
}
