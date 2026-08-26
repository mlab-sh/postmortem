//! Online repository resolution — **the only networked part of postmortem**.
//!
//! For `postmortem tree --online`. Per dependency:
//! 1. ask the dependency's **registry** for its source repository (npm's
//!    `repository`, PyPI's `project_urls`, crates.io's `repository`, …),
//! 2. resolve it to a `host/owner/repo` and pull **reputation stats** (stars,
//!    created-at, last activity, archived) from that host's API,
//! 3. score against risk thresholds and surface the suspicious ones — a fresh
//!    package version now pointing at a low-star / days-old / stale / archived
//!    repo, a classic supply-chain tell.
//!
//! Networking is blocking (`ureq`); responses are cached under
//! `$HOME/.postmortem/cache/` (see [`crate::cache`]). A published version's
//! manifest is immutable, so its repo resolution is cached forever.
//!
//! **Registries**, one per ecosystem: npm (Node), PyPI (Python), crates.io
//! (Rust), RubyGems (Ruby), Packagist (PHP), deps.dev (Java/Maven). Go modules
//! carry their repo in the module path itself, so they need no registry call.
//!
//! **Hosts** we pull reputation stats from: GitHub, GitLab, and Codeberg
//! (Forgejo). A repo on any other host still resolves (the slug is shown) but
//! its stats come back unavailable.
//!
//! Split by concern: `repo` is what a repository *is*, and every URL shape that
//! has to reduce to one; `registry` reads a package's current view; `history`
//! reads its release history; `signal` decides what counts as risky; `net` is
//! the single JSON GET all of them ride on. This file holds the resolver
//! itself — the cache, the worker pool, and the per-package sequence.

mod history;
mod net;
mod registry;
mod repo;
mod signal;
pub use registry::apply_licenses;
pub use repo::{Host, RepoRef};
pub use signal::RiskSignal;

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
use history::{fresh_age_hours, maintainer_names, newborn_age_days};
use registry::{raw_licenses_from, registry_url, registry_url_fallback, repo_candidates};
use repo::{parse_repo, urlencode};

/// Per-host API tokens. All optional — public repos resolve anonymously, a token
/// only raises the rate limit (and GitHub's anonymous 60/h is the tight one).
#[derive(Debug, Clone, Default)]
pub struct Tokens {
    pub github: Option<String>,
    pub gitlab: Option<String>,
    pub codeberg: Option<String>,
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
    /// Primary language, when the host advertises one in the repo object (GitHub
    /// does, for free; GitLab/Codeberg don't). `None` for an empty repo.
    #[serde(default)]
    pub language: Option<String>,
    /// When postmortem fetched this record (unix seconds) — for the future
    /// `cache` command / TTL policy.
    pub fetched_at: i64,
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
    /// Repo primary language (free, GitHub only).
    pub language: Option<String>,
    /// Repo language breakdown as `(name, percent)`, biggest first — only when
    /// `--languages` asked for it (one extra, cached, per-host call).
    pub languages: Option<Vec<(String, f64)>>,
    /// License(s) the registry declares for this exact version. Empty when the
    /// registry says nothing — never assume permissive.
    pub licenses: Vec<crate::model::License>,
    /// Accounts that can publish this package. Empty means *unknown* — the
    /// registry did not tell us — never "nobody".
    pub maintainers: Vec<String>,
}

/// Cached registry facts for one `name@version` (an explicit `None` repo means
/// the version declared no usable repo — cached so we don't refetch).
///
/// `licenses` was added after this struct first shipped; the cache's
/// [`crate::cache::FORMAT_VERSION`] was bumped at the same time, because a
/// missing `Option`/`Vec` field deserializes silently and every pre-existing
/// entry would otherwise report "no license" forever.
///
/// It holds the **raw** strings the registry served, not normalized [`crate::model::License`]
/// values. Entries are cached forever, so caching our interpretation would
/// freeze it: improving the SPDX tables would leave every already-cached package
/// stuck on the old reading. Normalization happens on every read, in
/// [`crate::license::resolve_raw`].
#[derive(Serialize, Deserialize, Default)]
struct CachedRepo {
    repo: Option<RepoRef>,
    #[serde(default)]
    licenses: Vec<String>,
    /// Accounts that can publish the package, where the registry document we
    /// already fetch carries them (Packagist). npm's come from the packument via
    /// [`history::VersionMeta`] instead.
    #[serde(default)]
    maintainers: Vec<String>,
}

pub struct Resolver {
    agents: crate::settings::Agents,
    cache: Cache,
    tokens: Tokens,
    /// Base URLs, overridable for internal mirrors / GitHub Enterprise.
    endpoints: crate::settings::Endpoints,
    /// Resolve licenses (adds a deps.dev call for Go only — see `with_licenses`).
    want_licenses: bool,
    thresholds: TreeSettings,
    now: i64,
    /// Also fetch each repo's full language breakdown (one extra, cached,
    /// per-host `/languages` call). Off by default.
    languages: bool,
}

impl Resolver {
    /// Build a resolver honouring the machine's `network` settings: the proxy
    /// and `no_proxy` on the agents, and the endpoint overrides for every service
    /// it talks to. Pass `&NetworkSettings::default()` for the public defaults.
    pub fn with_network(
        tokens: Tokens,
        thresholds: TreeSettings,
        net: &crate::settings::NetworkSettings,
    ) -> Self {
        Resolver {
            agents: net.agents(Duration::from_secs(15)),
            cache: Cache::open(),
            tokens,
            endpoints: net.endpoints.clone(),
            thresholds,
            now: chrono::Utc::now().timestamp(),
            languages: false,
            want_licenses: false,
        }
    }

    /// Enable the per-repo language breakdown (`--languages`).
    pub fn with_languages(mut self, on: bool) -> Self {
        self.languages = on;
        self
    }

    /// Resolve licenses too.
    ///
    /// For every ecosystem but Go this is free — the license rides along in the
    /// registry document the repo lookup already fetches. Go is the exception:
    /// its repo comes straight from the module path with no request at all, so a
    /// license there costs a deps.dev call that would otherwise never happen.
    /// Hence the opt-in, rather than always paying it.
    pub fn with_licenses(mut self, on: bool) -> Self {
        self.want_licenses = on;
        self
    }

    /// How many packages to resolve concurrently. Each unit is a blocking
    /// registry+host round-trip (I/O-bound), so we oversubscribe cores. GitHub's
    /// anonymous 60/h (plus secondary abuse limits) is the tightest budget, so
    /// without a GitHub token we stay gentle; with one we fan out wide.
    fn concurrency(&self) -> usize {
        if self.tokens.github.is_some() { 8 } else { 2 }
    }

    /// Resolve every unique dependency to its repo + stats, keyed by
    /// `(name, version)`, across a small pool of worker threads. Best-effort: a
    /// failure on one package degrades to a `resolve-failed`/`stats-*` signal,
    /// never aborts the run.
    pub fn resolve_all(&self, deps: &[Dependency], ui: &Ui) -> HashMap<DepRef, Resolution> {
        let mut unique: Vec<&Dependency> = deps.iter().collect();
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
                        if res
                            .worst
                            .is_some_and(|s| s >= crate::model::Severity::Medium)
                        {
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
        let mood = if flagged.load(Ordering::Relaxed) > 0 {
            crate::gochi::Mood::Alert
        } else {
            crate::gochi::Mood::Happy
        };
        bar.finish(mood, format!("resolved {} package(s)", out.len()));
        out
    }

    fn resolve_one(&self, dep: &Dependency) -> Resolution {
        let mut res = Resolution::default();
        let record = self.registry_record(dep);
        if let Ok(r) = &record {
            // Normalized here, never in the cache — see `CachedRepo`.
            res.licenses = crate::license::resolve_raw(&r.licenses);
        }
        let mut signals: Vec<RiskSignal> = match record.map(|r| r.repo) {
            Ok(Some(repo)) => {
                let signals = match self.stats_for(&repo) {
                    Ok(Some(stats)) => {
                        let assessed = self.assess(&stats);
                        res.stats = Some(stats);
                        assessed
                    }
                    // A declared repo that 404s: on GitHub that means deleted or
                    // renamed, so the handle is re-registerable (repojacking).
                    // Elsewhere keep it neutral — a 404 could be a private repo.
                    Ok(None) if repo.kind() == Some(Host::GitHub) => {
                        vec![RiskSignal::DanglingRepo { repo: repo.slug() }]
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

        // Typosquat proximity, against the corpus for this dependency's own
        // ecosystem. Offline, and a no-op where no corpus exists.
        if let Some(m) = crate::typosquat::check(&dep.name, dep.ecosystem) {
            signals.push(RiskSignal::Typosquat {
                target: m.target,
                kind: m.kind,
            });
        }

        // Version/provenance anomalies, for every registry that publishes a
        // release history rather than a current view. Which of these a given
        // ecosystem can actually answer is `VersionMeta`'s table — a signal it
        // cannot evaluate is absent, never a clean `false`.
        if let Ok(Some(meta)) = self.version_meta(dep) {
            if !meta.maintainers.is_empty() {
                res.maintainers = meta.maintainers.clone();
            }
            if meta.install_script_added == Some(true) {
                signals.push(RiskSignal::InstallScriptAdded);
            }
            if let Some(gap) = meta.dormant_gap_days {
                signals.push(RiskSignal::DormantRelease(gap));
            }
            if meta.new_publisher == Some(true) {
                signals.push(RiskSignal::NewPublisher);
            }
            if meta.provenance_removed == Some(true) {
                signals.push(RiskSignal::ProvenanceRemoved);
            }
            // Release-age cooldown + newborn: both time-relative, so computed
            // here against the current clock (never cached — see VersionMeta).
            let now = chrono::Utc::now().timestamp();
            if let Some(h) = fresh_age_hours(meta.published_ts, now) {
                signals.push(RiskSignal::FreshRelease(h));
            }
            if let Some(d) = newborn_age_days(meta.first_release_ts, now) {
                signals.push(RiskSignal::NewbornPackage(d));
            }
        }

        // Starjacking stays npm-specific: it plays the packument's repository
        // claim off against a *popular* repo's own package declaration, and the
        // corpus of popular-repo ownership is npm-shaped.
        if dep.ecosystem == Ecosystem::Node
            && let Some(sj) = self.starjack_signal(dep, &res)
        {
            signals.push(sj);
        }

        res.worst = signals.iter().map(RiskSignal::severity).max();
        res.risk = signals
            .iter()
            .map(RiskSignal::risk_points)
            .sum::<u32>()
            .min(100) as u8;
        res.signals = signals.iter().map(RiskSignal::label).collect();

        // Primary language rides along free in the repo stats; the full
        // breakdown is one extra (cached) call, only when `--languages`.
        res.language = res.stats.as_ref().and_then(|s| s.language.clone());
        if self.languages
            && let Some(repo) = &res.repo
        {
            res.languages = self.languages_for(repo).ok().flatten();
        }
        res
    }

    /// Registry manifest → source repo. Cached forever per
    /// `(ecosystem, name, version)`. Dispatches to the ecosystem's registry and
    /// pulls the first candidate URL that parses to a known [`Host`].
    ///
    /// Go is special: a module path *is* its repo (`github.com/gin-gonic/gin`),
    /// so it's parsed directly with no network call.
    /// The registry-derived facts for a dependency: its source repo and its
    /// declared license. Both come from the *same* document, so adding licenses
    /// costs no extra request — and both are cached together under one key.
    fn registry_record(&self, dep: &Dependency) -> Result<CachedRepo> {
        // Go's module path *is* its repo, so the repo needs no request at all.
        // The license does: it is the one ecosystem where postmortem makes a
        // call it would not otherwise make, so it is skipped unless the caller
        // asked for licenses.
        if dep.ecosystem == Ecosystem::Go {
            let repo = parse_repo(&dep.name);
            if !self.want_licenses {
                return Ok(CachedRepo {
                    repo,
                    licenses: Vec::new(),
                    maintainers: Vec::new(),
                });
            }
            let key = format!("go:{}@{}", dep.name, dep.version);
            if let Some(hit) = self.cache.get::<CachedRepo>("registry", &key) {
                return Ok(hit);
            }
            let url = format!(
                "{}/v3/systems/go/packages/{}/versions/{}",
                self.endpoints.deps_dev(),
                urlencode(&dep.name),
                urlencode(&dep.version),
            );
            let licenses = match self.get_json(&url, &[]) {
                Ok(Some(v)) => raw_licenses_from(dep, &v),
                // deps.dev not knowing a module is normal (private, or too new);
                // a transport failure is not cached, so it retries next run.
                Ok(None) => Vec::new(),
                Err(_) => {
                    return Ok(CachedRepo {
                        repo,
                        licenses: Vec::new(),
                        maintainers: Vec::new(),
                    });
                }
            };
            // Go resolves through deps.dev, which publishes no maintainer set.
            let record = CachedRepo {
                repo,
                licenses,
                maintainers: Vec::new(),
            };
            self.cache.put("registry", &key, &record);
            return Ok(record);
        }
        let key = format!("{}:{}@{}", dep.ecosystem.as_str(), dep.name, dep.version);
        if let Some(hit) = self.cache.get::<CachedRepo>("registry", &key) {
            return Ok(hit);
        }
        let Some(url) = registry_url(dep, &self.endpoints) else {
            return Ok(CachedRepo::default());
        };
        let doc = match self.get_json(&url, &[])? {
            Some(v) => Some(v),
            // Some registries only expose the *pinned* version through a second
            // endpoint, and that one 404s for versions they never served (yanked
            // releases, platform-suffixed gems). Fall back to the name-only
            // document rather than lose the repo entirely — the license it
            // carries is then the latest version's, which `licenses_from` knows.
            None => match registry_url_fallback(dep, &self.endpoints) {
                Some(fb) => self.get_json(&fb, &[])?,
                None => None,
            },
        };
        // crates.io answers both "where is the repo" and "what did the release
        // history look like" out of the one document just fetched, so derive the
        // history here and file it under `version_meta`'s namespace: the Rust
        // path then costs no second request. npm and PyPI keep their history in
        // a *different* document, so they stay `version_meta`'s business.
        if dep.ecosystem == Ecosystem::Rust
            && let Some(v) = &doc
            && let Some((ns, _, read)) = self.history_source(dep)
        {
            let meta_key = format!("{}@{}", dep.name, dep.version);
            self.cache.put(ns, &meta_key, &read(v, &dep.version));
        }
        let licenses = doc
            .as_ref()
            .map(|v| raw_licenses_from(dep, v))
            .unwrap_or_default();
        // Packagist publishes the maintainer set in the same document; npm's
        // comes from the packument, and the other registries need a call we do
        // not make — those stay empty, meaning *unknown*, never "nobody".
        let maintainers = doc
            .as_ref()
            .filter(|_| dep.ecosystem == Ecosystem::Php)
            .and_then(|v| v.get("package"))
            .map(|p| maintainer_names(p.get("maintainers")))
            .unwrap_or_default();
        let mut repo = match &doc {
            Some(v) => repo_candidates(dep.ecosystem, v)
                .iter()
                .find_map(|u| parse_repo(u)),
            None => None, // 404 — unpublished/private/unknown package
        };
        // Homebrew third-party taps aren't on formulae.brew.sh (404 above), but
        // the tap *is* a repo — fall back to it (carried in `resolved_url`) so we
        // assess the tap rather than flag "no repository". Pacman has no registry
        // and carries the package's upstream URL the same way. Gated to these two:
        // other ecosystems' `resolved_url` is a tarball/registry URL, not a repo.
        if repo.is_none()
            && matches!(
                dep.ecosystem,
                Ecosystem::Brew
                    | Ecosystem::Pacman
                    | Ecosystem::Apt
                    | Ecosystem::Dnf
                    | Ecosystem::Nix
                    | Ecosystem::Apk
            )
        {
            repo = dep.resolved_url.as_deref().and_then(parse_repo);
        }
        let record = CachedRepo {
            repo,
            licenses,
            maintainers,
        };
        self.cache.put("registry", &key, &record);
        Ok(record)
    }
}
