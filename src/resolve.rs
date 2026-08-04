//! Online repository resolution — **the only networked part of postmortem**.
//!
//! For `postmortem tree --online`. Per dependency:
//! 1. ask the **registry** for the source repository (npm's `repository` field),
//! 2. resolve it to a GitHub `owner/repo` and pull **reputation stats** (stars,
//!    created-at, last push, archived),
//! 3. score against risk thresholds and surface the suspicious ones — a fresh
//!    package version now pointing at a low-star / days-old / stale / archived
//!    repo, a classic supply-chain tell.
//!
//! Networking is blocking (`ureq`); responses are cached under
//! `$HOME/.postmortem/cache/` (see [`crate::cache`]). A published npm version's
//! manifest is immutable, so its repo resolution is cached forever.
//!
//! First (and currently only) registry: **npm**. Non-node dependencies are
//! skipped by [`Resolver::resolve_all`].

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::cache::Cache;
use crate::model::{DepRef, Dependency, Ecosystem, Severity};
use crate::settings::TreeSettings;
use crate::ui::Ui;

const NPM_REGISTRY: &str = "https://registry.npmjs.org";
const GITHUB_API: &str = "https://api.github.com";
const USER_AGENT: &str = concat!("postmortem/", env!("CARGO_PKG_VERSION"));

/// A source repository a dependency resolves to (GitHub only, today).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoRef {
    pub host: String,
    pub owner: String,
    pub name: String,
}

impl RepoRef {
    pub fn slug(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

/// Reputation stats pulled from the hosting provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoStats {
    pub stars: u64,
    /// Repository creation time (unix seconds), when known.
    pub created_at: Option<i64>,
    /// Last push time (unix seconds), when known.
    pub pushed_at: Option<i64>,
    pub archived: bool,
    /// When postmortem fetched this record (unix seconds) — for the future
    /// `cache` command / TTL policy.
    pub fetched_at: i64,
}

/// A risk tell attached to a resolved node. Each carries a [`Severity`] that
/// drives the output color: the reputation risks (few stars, freshly created)
/// are red; inactivity (stale, archived, no repo) is amber; and purely
/// operational hiccups (couldn't resolve/fetch) are neutral.
#[derive(Debug, Clone)]
pub enum RiskSignal {
    LowStars(u64),
    RecentlyCreated(i64),
    Stale(i64),
    Archived,
    NoRepository,
    ResolveFailed,
    StatsFailed,
    StatsUnavailable,
    // --- identity / provenance (P2) ---
    /// Name is a near-miss of a popular package (typosquat).
    Typosquat { target: String, kind: &'static str },
    /// An install lifecycle script appears in this version but not the prior one.
    InstallScriptAdded,
    /// Published after a long dormancy (the event-stream pattern).
    DormantRelease(i64),
    /// A different publisher than the package's earlier versions.
    NewPublisher,
}

impl RiskSignal {
    /// Short human label, also used in JSON output.
    pub fn label(&self) -> String {
        match self {
            RiskSignal::LowStars(n) => format!("low-stars ({n}★)"),
            RiskSignal::RecentlyCreated(d) => format!("recently-created ({d}d ago)"),
            RiskSignal::Stale(d) => format!("stale ({d}d idle)"),
            RiskSignal::Archived => "archived".into(),
            RiskSignal::NoRepository => "no-repository".into(),
            RiskSignal::ResolveFailed => "resolve-failed".into(),
            RiskSignal::StatsFailed => "stats-failed".into(),
            RiskSignal::StatsUnavailable => "stats-unavailable".into(),
            RiskSignal::Typosquat { target, kind } => format!("typosquat of {target} ({kind})"),
            RiskSignal::InstallScriptAdded => "install-script-added".into(),
            RiskSignal::DormantRelease(d) => format!("dormant-release ({d}d gap)"),
            RiskSignal::NewPublisher => "new-publisher".into(),
        }
    }

    /// Risk weight, used to color the node by its worst signal.
    pub fn severity(&self) -> Severity {
        match self {
            // Reputation + identity red flags.
            RiskSignal::LowStars(_)
            | RiskSignal::RecentlyCreated(_)
            | RiskSignal::Typosquat { .. }
            | RiskSignal::InstallScriptAdded => Severity::High,
            // Inactivity / missing source / provenance drift — amber.
            RiskSignal::Stale(_)
            | RiskSignal::Archived
            | RiskSignal::NoRepository
            | RiskSignal::DormantRelease(_)
            | RiskSignal::NewPublisher => Severity::Medium,
            // Operational — we simply couldn't check. Neutral.
            RiskSignal::ResolveFailed | RiskSignal::StatsFailed | RiskSignal::StatsUnavailable => {
                Severity::Info
            }
        }
    }

    /// Points this signal adds to a package's own risk score (summed, capped at
    /// 100). Identity attacks (typosquat, install-script-added) and a fresh repo
    /// weigh heaviest; operational hiccups add nothing.
    pub fn risk_points(&self) -> u32 {
        match self {
            RiskSignal::Typosquat { .. } => 45,
            RiskSignal::InstallScriptAdded => 40,
            RiskSignal::RecentlyCreated(_) => 40,
            RiskSignal::LowStars(_) => 30,
            RiskSignal::Archived => 30,
            RiskSignal::NoRepository => 25,
            RiskSignal::NewPublisher => 25,
            RiskSignal::Stale(_) => 20,
            RiskSignal::DormantRelease(_) => 20,
            RiskSignal::ResolveFailed | RiskSignal::StatsFailed | RiskSignal::StatsUnavailable => 0,
        }
    }
}

/// The resolution attached to one dependency node.
#[derive(Debug, Clone, Default)]
pub struct Resolution {
    pub repo: Option<RepoRef>,
    pub stats: Option<RepoStats>,
    pub signals: Vec<String>,
    /// The worst signal severity — drives node color. `None` when healthy.
    pub worst: Option<Severity>,
    /// The package's own risk score, 0–100 (summed signal points).
    pub risk: u8,
}

/// Cached npm-version → repository resolution (an explicit `None` means the
/// version declared no usable GitHub repo — cached so we don't refetch).
#[derive(Serialize, Deserialize)]
struct CachedRepo {
    repo: Option<RepoRef>,
}

/// Provenance anomalies for one installed version vs its predecessors, derived
/// from the npm packument. Immutable per `(name, version)`, so it's cached.
#[derive(Serialize, Deserialize, Default, Clone)]
struct VersionMeta {
    /// An install lifecycle script is present here but not in the prior version.
    install_script_added: bool,
    /// Gap since the prior release, in days, when it exceeds the dormancy bar.
    dormant_gap_days: Option<i64>,
    /// The publisher differs from every earlier version's publisher.
    new_publisher: bool,
}

/// Flag a gap this large (days) between releases as a dormancy anomaly.
const DORMANT_DAYS: i64 = 365;

pub struct Resolver {
    agent: ureq::Agent,
    cache: Cache,
    token: Option<String>,
    thresholds: TreeSettings,
    now: i64,
}

impl Resolver {
    pub fn new(token: Option<String>, thresholds: TreeSettings) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(15))
            .build();
        Resolver {
            agent,
            cache: Cache::open(),
            token,
            thresholds,
            now: chrono::Utc::now().timestamp(),
        }
    }

    /// How many packages to resolve concurrently. Each unit is a blocking
    /// npm+GitHub round-trip (I/O-bound), so we oversubscribe cores. With a
    /// token GitHub allows 5000 req/h, so we fan out wide; anonymously it's
    /// 60/h plus secondary abuse limits, so we stay gentle.
    fn concurrency(&self) -> usize {
        if self.token.is_some() { 8 } else { 2 }
    }

    /// Resolve every unique **node** dependency to its repo + stats, keyed by
    /// `(name, version)`, across a small pool of worker threads. Best-effort: a
    /// failure on one package degrades to a `resolve-failed`/`stats-*` signal,
    /// never aborts the run.
    pub fn resolve_all(&self, deps: &[Dependency], ui: &Ui) -> HashMap<DepRef, Resolution> {
        let mut unique: Vec<&Dependency> = deps
            .iter()
            .filter(|d| d.ecosystem == Ecosystem::Node)
            .collect();
        unique.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
        unique.dedup_by(|a, b| a.name == b.name && a.version == b.version);

        let total = unique.len();
        // gochi rides the loading line, eyes darting while data streams in.
        let bar = crate::gochi::Loader::start(total as u64, ui.animating());
        bar.step("fetching repos");

        // Shared work cursor + result sink. `&Resolver` is `Sync` (its ureq
        // agent and cache are safe to share), and `Loader`'s counters are atomic,
        // so scoped threads can pull work and report progress concurrently.
        let cursor = AtomicUsize::new(0);
        let flagged = AtomicUsize::new(0);
        let out: Mutex<HashMap<DepRef, Resolution>> = Mutex::new(HashMap::with_capacity(total));
        let workers = self.concurrency().min(total);

        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    loop {
                        let i = cursor.fetch_add(1, Ordering::Relaxed);
                        if i >= total {
                            break;
                        }
                        let dep = unique[i];
                        let res = self.resolve_one(dep);
                        if res.worst.is_some_and(|s| s >= crate::model::Severity::Medium) {
                            flagged.fetch_add(1, Ordering::Relaxed);
                        }
                        out.lock()
                            .unwrap()
                            .insert((dep.name.clone(), dep.version.clone()), res);
                        bar.inc();
                    }
                });
            }
        });

        let out = out.into_inner().unwrap();
        let face = if flagged.load(Ordering::Relaxed) > 0 {
            crate::gochi::ALERT
        } else {
            crate::gochi::HAPPY
        };
        bar.finish(face, &format!("resolved {} package(s)", out.len()));
        out
    }

    fn resolve_one(&self, dep: &Dependency) -> Resolution {
        let mut res = Resolution::default();
        let mut signals: Vec<RiskSignal> = match self.repo_for(dep) {
            Ok(Some(repo)) => {
                let signals = match self.stats_for(&repo) {
                    Ok(Some(stats)) => {
                        let assessed = self.assess(&stats);
                        res.stats = Some(stats);
                        assessed
                    }
                    Ok(None) => vec![RiskSignal::StatsUnavailable],
                    Err(_) => vec![RiskSignal::StatsFailed],
                };
                res.repo = Some(repo);
                signals
            }
            Ok(None) => vec![RiskSignal::NoRepository],
            Err(_) => vec![RiskSignal::ResolveFailed],
        };

        // Identity / provenance signals (P2). Typosquat is offline; the version
        // anomalies read the npm packument (cached).
        if let Some(m) = crate::typosquat::check(&dep.name) {
            signals.push(RiskSignal::Typosquat { target: m.target, kind: m.kind });
        }
        if let Ok(Some(meta)) = self.version_meta(dep) {
            if meta.install_script_added {
                signals.push(RiskSignal::InstallScriptAdded);
            }
            if let Some(gap) = meta.dormant_gap_days {
                signals.push(RiskSignal::DormantRelease(gap));
            }
            if meta.new_publisher {
                signals.push(RiskSignal::NewPublisher);
            }
        }

        res.worst = signals.iter().map(RiskSignal::severity).max();
        res.risk = signals
            .iter()
            .map(RiskSignal::risk_points)
            .sum::<u32>()
            .min(100) as u8;
        res.signals = signals.iter().map(RiskSignal::label).collect();
        res
    }

    /// npm version manifest → GitHub repo. Cached forever per `(name, version)`.
    fn repo_for(&self, dep: &Dependency) -> Result<Option<RepoRef>> {
        let key = format!("{}@{}", dep.name, dep.version);
        if let Some(hit) = self.cache.get::<CachedRepo>("npm", &key) {
            return Ok(hit.repo);
        }
        let url = format!("{NPM_REGISTRY}/{}/{}", dep.name, dep.version);
        let repo = match self.get_json(&url, false)? {
            Some(v) => extract_repo_url(&v).and_then(|u| parse_github(&u)),
            None => None, // 404 — unpublished/private version
        };
        self.cache.put("npm", &key, &CachedRepo { repo: repo.clone() });
        Ok(repo)
    }

    /// Provenance anomalies for the installed version, from the npm packument.
    /// Cached per `(name, version)` (the history up to a published version is
    /// immutable). `Ok(None)` never happens today — failures cache as "clean".
    fn version_meta(&self, dep: &Dependency) -> Result<Option<VersionMeta>> {
        let key = format!("{}@{}", dep.name, dep.version);
        if let Some(hit) = self.cache.get::<VersionMeta>("npm-meta", &key) {
            return Ok(Some(hit));
        }
        let url = format!("{NPM_REGISTRY}/{}", dep.name);
        let meta = match self.get_json(&url, false)? {
            Some(doc) => compute_version_meta(&doc, &dep.version),
            None => VersionMeta::default(),
        };
        self.cache.put("npm-meta", &key, &meta);
        Ok(Some(meta))
    }

    /// GitHub repo stats. Cached per `owner/repo`.
    fn stats_for(&self, repo: &RepoRef) -> Result<Option<RepoStats>> {
        let key = repo.slug();
        if let Some(hit) = self.cache.get::<RepoStats>("github", &key) {
            return Ok(Some(hit));
        }
        let url = format!("{GITHUB_API}/repos/{}/{}", repo.owner, repo.name);
        let Some(v) = self.get_json(&url, true)? else {
            return Ok(None); // 404 — repo gone/renamed
        };
        let stats = RepoStats {
            stars: v.get("stargazers_count").and_then(|s| s.as_u64()).unwrap_or(0),
            created_at: v.get("created_at").and_then(|s| s.as_str()).and_then(parse_ts),
            pushed_at: v.get("pushed_at").and_then(|s| s.as_str()).and_then(parse_ts),
            archived: v.get("archived").and_then(|s| s.as_bool()).unwrap_or(false),
            fetched_at: self.now,
        };
        self.cache.put("github", &key, &stats);
        Ok(Some(stats))
    }

    fn assess(&self, stats: &RepoStats) -> Vec<RiskSignal> {
        let mut signals = Vec::new();
        if stats.stars < self.thresholds.min_stars {
            signals.push(RiskSignal::LowStars(stats.stars));
        }
        if let Some(created) = stats.created_at {
            let age_days = (self.now - created) / 86_400;
            if age_days <= self.thresholds.recent_days {
                signals.push(RiskSignal::RecentlyCreated(age_days));
            }
        }
        if let Some(pushed) = stats.pushed_at {
            let idle_days = (self.now - pushed) / 86_400;
            if idle_days >= self.thresholds.stale_days {
                signals.push(RiskSignal::Stale(idle_days));
            }
        }
        if stats.archived {
            signals.push(RiskSignal::Archived);
        }
        signals
    }

    /// GET + JSON. `Ok(None)` on 404 (a missing package/repo, not an error);
    /// any other non-2xx or transport failure is an `Err`.
    fn get_json(&self, url: &str, auth: bool) -> Result<Option<serde_json::Value>> {
        let mut req = self.agent.get(url).set("User-Agent", USER_AGENT);
        if auth && let Some(token) = &self.token {
            req = req.set("Authorization", &format!("Bearer {token}"));
        }
        match req.call() {
            Ok(resp) => Ok(Some(serde_json::from_str(&resp.into_string()?)?)),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

/// Pull a repository URL out of an npm version manifest's `repository` field,
/// which is either a string or an object `{ "type": "git", "url": "…" }`.
fn extract_repo_url(manifest: &serde_json::Value) -> Option<String> {
    match manifest.get("repository")? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(o) => o.get("url").and_then(|u| u.as_str()).map(String::from),
        _ => None,
    }
}

/// Parse the many shapes of a GitHub repo URL into `owner/repo`:
/// `git+https://github.com/o/r.git`, `git://…`, `https://github.com/o/r`,
/// `git+ssh://git@github.com/o/r.git`, and npm's `github:o/r` shorthand.
/// Non-GitHub hosts return `None` (only GitHub stats are supported today).
fn parse_github(url: &str) -> Option<RepoRef> {
    let url = url.trim();
    let rest = if let Some(short) = url.strip_prefix("github:") {
        short.to_string()
    } else {
        let idx = url.find("github.com")?;
        url[idx + "github.com".len()..]
            .trim_start_matches([':', '/'])
            .to_string()
    };

    let rest = rest.trim_end_matches('/');
    let rest = rest.strip_suffix(".git").unwrap_or(rest);
    let mut parts = rest.split('/');
    let owner = parts.next()?.trim();
    let name = parts.next()?.trim();
    // A trailing `#ref` or `?query` can cling to the repo segment.
    let name = name.split(['#', '?']).next().unwrap_or(name);
    if owner.is_empty() || name.is_empty() {
        return None;
    }
    Some(RepoRef {
        host: "github.com".into(),
        owner: owner.to_string(),
        name: name.to_string(),
    })
}

/// RFC3339 (GitHub timestamps) → unix seconds.
fn parse_ts(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|d| d.timestamp())
}

/// Derive provenance anomalies for `version` from an npm packument. Compares the
/// installed version against its immediate time-predecessor: an install script
/// that wasn't there before, a suspiciously long dormancy, and a publisher that
/// never shipped an earlier version (account-takeover / trojanized-update tells,
/// à la event-stream and ua-parser-js).
fn compute_version_meta(doc: &serde_json::Value, version: &str) -> VersionMeta {
    let mut meta = VersionMeta::default();
    let (Some(times), Some(versions)) = (
        doc.get("time").and_then(|t| t.as_object()),
        doc.get("versions").and_then(|v| v.as_object()),
    ) else {
        return meta;
    };
    let Some(inst_ts) = times.get(version).and_then(|t| t.as_str()).and_then(parse_ts) else {
        return meta;
    };

    // Prior version = the one published closest before the installed one.
    let is_version = |k: &str| k != "created" && k != "modified" && k != version;
    let mut prior: Option<(&str, i64)> = None;
    let mut prior_publishers: Vec<String> = Vec::new();
    for (v, t) in times {
        if !is_version(v) {
            continue;
        }
        let Some(ts) = t.as_str().and_then(parse_ts) else { continue };
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

    if inst_hook && !prior_hook {
        meta.install_script_added = true;
    }
    let gap = (inst_ts - prior_ts) / 86_400;
    if gap >= DORMANT_DAYS {
        meta.dormant_gap_days = Some(gap);
    }
    if let Some(ip) = inst.and_then(publisher)
        && !prior_publishers.is_empty()
        && !prior_publishers.iter().any(|p| p == ip)
    {
        meta.new_publisher = true;
    }
    meta
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
fn publisher(manifest: &serde_json::Value) -> Option<&str> {
    manifest.get("_npmUser").and_then(|u| u.get("name")).and_then(|n| n.as_str())
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
        assert!(m.install_script_added, "postinstall added vs prior");
        assert!(m.new_publisher, "eve never shipped an earlier version");
        assert!(m.dormant_gap_days.unwrap() > 365, "long dormancy before the release");
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
        assert!(!m.install_script_added);
        assert!(!m.new_publisher);
        assert!(m.dormant_gap_days.is_none());
    }

    #[test]
    fn version_meta_first_release_is_quiet() {
        let doc = serde_json::json!({
            "time": { "1.0.0": "2023-01-01T00:00:00.000Z" },
            "versions": { "1.0.0": { "scripts": { "postinstall": "x" } } }
        });
        let m = compute_version_meta(&doc, "1.0.0");
        // No predecessor → "added" can't be asserted, no publisher change.
        assert!(!m.install_script_added);
        assert!(!m.new_publisher);
    }

    #[test]
    fn parses_github_url_shapes() {
        let cases = [
            "git+https://github.com/expressjs/express.git",
            "https://github.com/expressjs/express",
            "git://github.com/expressjs/express.git",
            "git+ssh://git@github.com/expressjs/express.git",
            "github:expressjs/express",
            "https://github.com/expressjs/express/tree/master#readme",
        ];
        for c in cases {
            let r = parse_github(c).unwrap_or_else(|| panic!("failed to parse {c}"));
            assert_eq!(r.owner, "expressjs", "owner for {c}");
            assert_eq!(r.name, "express", "name for {c}");
            assert_eq!(r.slug(), "expressjs/express");
        }
    }

    #[test]
    fn rejects_non_github() {
        assert!(parse_github("https://gitlab.com/o/r.git").is_none());
        assert!(parse_github("not a url").is_none());
    }

    #[test]
    fn extracts_repository_string_and_object() {
        let s = serde_json::json!({ "repository": "github:a/b" });
        assert_eq!(extract_repo_url(&s).as_deref(), Some("github:a/b"));
        let o = serde_json::json!({ "repository": { "type": "git", "url": "https://github.com/a/b.git" } });
        assert_eq!(extract_repo_url(&o).as_deref(), Some("https://github.com/a/b.git"));
        let none = serde_json::json!({ "name": "x" });
        assert_eq!(extract_repo_url(&none), None);
    }

    #[test]
    fn assess_flags_thresholds() {
        let r = Resolver {
            agent: ureq::agent(),
            cache: Cache::open(),
            token: None,
            thresholds: TreeSettings { min_stars: 20, recent_days: 30, stale_days: 365 },
            now: 1_000_000_000,
        };
        let fresh_lowstar = RepoStats {
            stars: 1,
            created_at: Some(1_000_000_000 - 5 * 86_400), // 5 days old
            pushed_at: Some(1_000_000_000),
            archived: false,
            fetched_at: 0,
        };
        let labels: Vec<String> = r.assess(&fresh_lowstar).iter().map(RiskSignal::label).collect();
        assert!(labels.iter().any(|l| l.contains("low-stars")));
        assert!(labels.iter().any(|l| l.contains("recently-created")));

        let healthy = RepoStats {
            stars: 5000,
            created_at: Some(0),
            pushed_at: Some(1_000_000_000),
            archived: false,
            fetched_at: 0,
        };
        assert!(r.assess(&healthy).is_empty());
    }
}
