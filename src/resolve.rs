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

const USER_AGENT: &str = concat!("postmortem/", env!("CARGO_PKG_VERSION"));

/// A code-hosting provider we know how to pull reputation stats from. Each has
/// its own API shape and auth header (see [`Resolver::stats_for`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    GitHub,
    GitLab,
    Codeberg,
}

/// Every host we recognize, paired with the domain that identifies it in a repo
/// URL. Order is the match priority when scanning a URL.
const HOSTS: &[(&str, Host)] = &[
    ("github.com", Host::GitHub),
    ("gitlab.com", Host::GitLab),
    ("codeberg.org", Host::Codeberg),
];

impl Host {
    fn domain(self) -> &'static str {
        match self {
            Host::GitHub => "github.com",
            Host::GitLab => "gitlab.com",
            Host::Codeberg => "codeberg.org",
        }
    }
}

/// Per-host API tokens. All optional — public repos resolve anonymously, a token
/// only raises the rate limit (and GitHub's anonymous 60/h is the tight one).
#[derive(Debug, Clone, Default)]
pub struct Tokens {
    pub github: Option<String>,
    pub gitlab: Option<String>,
    pub codeberg: Option<String>,
}

/// A source repository a dependency resolves to, on one of the known [`Host`]s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoRef {
    /// Host domain, e.g. `github.com`. Kept as a string so cached records stay
    /// readable and forward-compatible.
    pub host: String,
    /// Namespace: `owner`, or a nested `group/subgroup` on GitLab.
    pub owner: String,
    pub name: String,
}

impl RepoRef {
    pub fn slug(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }

    /// Classify the host domain back into a [`Host`], if we recognize it.
    fn kind(&self) -> Option<Host> {
        HOSTS.iter().find(|(d, _)| *d == self.host).map(|(_, h)| *h)
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
    /// Primary language, when the host advertises one in the repo object (GitHub
    /// does, for free; GitLab/Codeberg don't). `None` for an empty repo.
    #[serde(default)]
    pub language: Option<String>,
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
    /// Installed version was published very recently (< the cooldown window) — no
    /// time for the ecosystem to catch a malicious release. The release-age /
    /// cooldown tell (Socket caught keyv ~6 min after publish; a 48h cooldown
    /// would have aged it out before adoption).
    FreshRelease(i64),
    /// The package's *first-ever* release is very recent — a zero-track-record
    /// package being depended upon (typosquat delivery, slopsquatting).
    NewbornPackage(i64),
    /// The linked source repo doesn't declare this package — its stars are being
    /// borrowed to manufacture reputation (starjacking).
    Starjacking { repo: String },
    /// This version dropped the provenance attestation an earlier version carried
    /// — published outside the trusted OIDC/CI flow (the axios pattern).
    ProvenanceRemoved,
    /// The declared source repo returns 404 (deleted/renamed) — its handle is
    /// re-registerable, i.e. repojacking-exposed.
    DanglingRepo { repo: String },
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
            RiskSignal::FreshRelease(h) => format!("fresh-release ({h}h old)"),
            RiskSignal::NewbornPackage(d) => format!("newborn-package ({d}d old)"),
            RiskSignal::Starjacking { repo } => format!("starjacking ({repo} doesn't own it)"),
            RiskSignal::ProvenanceRemoved => "provenance-removed".into(),
            RiskSignal::DanglingRepo { repo } => format!("dangling-repo ({repo} not found)"),
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
            // Inactivity / provenance drift — amber.
            // Borrowed reputation / dropped attestation are active deceptions → high.
            RiskSignal::Starjacking { .. } | RiskSignal::ProvenanceRemoved => Severity::High,
            RiskSignal::Stale(_)
            | RiskSignal::Archived
            | RiskSignal::DormantRelease(_)
            | RiskSignal::NewPublisher
            | RiskSignal::NewbornPackage(_)
            | RiskSignal::DanglingRepo { .. } => Severity::Medium,
            // A fresh release is a caution, not an accusation — every new version
            // is fresh for a while. Amber-low, and it earns its weight in
            // combination (fresh + install-script-added is the real tell).
            RiskSignal::FreshRelease(_) => Severity::Low,
            // "Couldn't verify" — no source repo to assess, or a fetch we
            // couldn't complete. Neutral: a missing GitHub repo is normal for a
            // curated OS core (project-site homepages) and common for legit
            // packages, so on its own it's unchecked, not suspicious.
            RiskSignal::NoRepository
            | RiskSignal::ResolveFailed
            | RiskSignal::StatsFailed
            | RiskSignal::StatsUnavailable => Severity::Info,
        }
    }

    /// Points this signal adds to a package's own risk score (summed, capped at
    /// 100). Identity attacks (typosquat, install-script-added) and a fresh repo
    /// weigh heaviest; operational hiccups add nothing.
    pub fn risk_points(&self) -> u32 {
        match self {
            RiskSignal::Typosquat { .. } => 45,
            RiskSignal::Starjacking { .. } => 45,
            RiskSignal::InstallScriptAdded => 40,
            RiskSignal::ProvenanceRemoved => 30,
            RiskSignal::DanglingRepo { .. } => 25,
            RiskSignal::RecentlyCreated(_) => 40,
            RiskSignal::LowStars(_) => 30,
            RiskSignal::Archived => 30,
            RiskSignal::NewPublisher => 25,
            RiskSignal::Stale(_) => 20,
            RiskSignal::DormantRelease(_) => 20,
            RiskSignal::NewbornPackage(_) => 20,
            RiskSignal::FreshRelease(_) => 15,
            // "Couldn't verify" signals carry no risk weight on their own.
            RiskSignal::NoRepository
            | RiskSignal::ResolveFailed
            | RiskSignal::StatsFailed
            | RiskSignal::StatsUnavailable => 0,
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
    /// Repo primary language (free, GitHub only).
    pub language: Option<String>,
    /// Repo language breakdown as `(name, percent)`, biggest first — only when
    /// `--languages` asked for it (one extra, cached, per-host call).
    pub languages: Option<Vec<(String, f64)>>,
    /// License(s) the registry declares for this exact version. Empty when the
    /// registry says nothing — never assume permissive.
    pub licenses: Vec<crate::model::License>,
}

/// Cached registry facts for one `name@version` (an explicit `None` repo means
/// the version declared no usable repo — cached so we don't refetch).
///
/// `licenses` was added after this struct first shipped; the cache's
/// [`crate::cache::FORMAT_VERSION`] was bumped at the same time, because a
/// missing `Option`/`Vec` field deserializes silently and every pre-existing
/// entry would otherwise report "no license" forever.
///
/// It holds the **raw** strings the registry served, not normalized [`License`]
/// values. Entries are cached forever, so caching our interpretation would
/// freeze it: improving the SPDX tables would leave every already-cached package
/// stuck on the old reading. Normalization happens on every read, in
/// [`crate::license::resolve_raw`].
#[derive(Serialize, Deserialize, Default)]
struct CachedRepo {
    repo: Option<RepoRef>,
    #[serde(default)]
    licenses: Vec<String>,
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
    /// Unix seconds the installed version was published (immutable, so safe to
    /// cache). The age-relative "fresh-release" decision is made at use-time
    /// against the current clock, never cached.
    #[serde(default)]
    published_ts: Option<i64>,
    /// Unix seconds of the package's first-ever release (`time.created`,
    /// immutable). The "newborn" decision is made at use-time against the clock.
    #[serde(default)]
    first_release_ts: Option<i64>,
    /// This version has no provenance attestation but the prior one did — a
    /// publish that skipped the trusted OIDC/CI flow (the axios pattern).
    #[serde(default)]
    provenance_removed: bool,
}

/// Flag a gap this large (days) between releases as a dormancy anomaly.
const DORMANT_DAYS: i64 = 365;
/// Cooldown window: a version published within this many hours hasn't had time
/// for the ecosystem to catch a malicious release. 48h is the middle of the
/// 24–72h the supply-chain guidance converges on.
const FRESH_HOURS: i64 = 48;
/// A package whose first-ever release is younger than this has no track record —
/// the delivery vehicle for typosquats and slopsquatted (AI-hallucinated) names.
const NEWBORN_DAYS: i64 = 30;
/// A linked repo needs at least this many stars for a name mismatch to read as
/// *borrowed* reputation (starjacking) rather than an ordinary rename/monorepo.
const STARJACK_MIN_STARS: u64 = 500;

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
            signals.push(RiskSignal::Typosquat { target: m.target, kind: m.kind });
        }

        // Version/provenance anomalies stay npm-specific: they read the npm
        // packument, which has no equivalent elsewhere.
        if dep.ecosystem == Ecosystem::Node {
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
                if meta.provenance_removed {
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

            // Starjacking: does the linked repo actually declare this package?
            if let Some(sj) = self.starjack_signal(dep, &res) {
                signals.push(sj);
            }
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
                return Ok(CachedRepo { repo, licenses: Vec::new() });
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
                Err(_) => return Ok(CachedRepo { repo, licenses: Vec::new() }),
            };
            let record = CachedRepo { repo, licenses };
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
        let licenses = doc.as_ref().map(|v| raw_licenses_from(dep, v)).unwrap_or_default();
        let mut repo = match &doc {
            Some(v) => repo_candidates(dep.ecosystem, v).iter().find_map(|u| parse_repo(u)),
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
                Ecosystem::Brew | Ecosystem::Pacman | Ecosystem::Apt | Ecosystem::Dnf | Ecosystem::Nix | Ecosystem::Apk
            )
        {
            repo = dep.resolved_url.as_deref().and_then(parse_repo);
        }
        let record = CachedRepo { repo, licenses };
        self.cache.put("registry", &key, &record);
        Ok(record)
    }

    /// Provenance anomalies for the installed version, from the npm packument.
    /// Cached per `(name, version)` (the history up to a published version is
    /// immutable). `Ok(None)` never happens today — failures cache as "clean".
    fn version_meta(&self, dep: &Dependency) -> Result<Option<VersionMeta>> {
        let key = format!("{}@{}", dep.name, dep.version);
        if let Some(hit) = self.cache.get::<VersionMeta>("npm-meta", &key) {
            return Ok(Some(hit));
        }
        let url = format!("{}/{}", self.endpoints.npm(), dep.name);
        let meta = match self.get_json(&url, &[])? {
            Some(doc) => compute_version_meta(&doc, &dep.version),
            None => VersionMeta::default(),
        };
        self.cache.put("npm-meta", &key, &meta);
        Ok(Some(meta))
    }

    /// Starjacking check (npm): a package linking to a **popular** GitHub repo
    /// (≥ [`STARJACK_MIN_STARS`]) that doesn't actually declare it is borrowing
    /// that repo's stars. Conservative — fires only when the repo's own
    /// `package.json` name shares no token with the package (or the repo slug),
    /// and never when the manifest can't be read (skip, don't guess).
    fn starjack_signal(&self, dep: &Dependency, res: &Resolution) -> Option<RiskSignal> {
        let repo = res.repo.as_ref()?;
        let stats = res.stats.as_ref()?;
        if stats.stars < STARJACK_MIN_STARS || repo.kind() != Some(Host::GitHub) {
            return None;
        }
        let declared = self.repo_pkg_name(repo)?;
        let owns = shares_token(&dep.name, &declared) || shares_token(&dep.name, &repo.slug());
        (!owns).then(|| RiskSignal::Starjacking { repo: repo.slug() })
    }

    /// The `name` in a GitHub repo's root `package.json`, cached per slug (the
    /// `None` result is cached too, so a repo without one isn't re-fetched).
    fn repo_pkg_name(&self, repo: &RepoRef) -> Option<String> {
        let key = repo.slug();
        if let Some(hit) = self.cache.get::<Option<String>>("repo-pkgname", &key) {
            return hit;
        }
        let url = format!(
            "{}/{}/{}/HEAD/package.json",
            self.endpoints.github_raw(),
            repo.owner,
            repo.name
        );
        let name = self
            .get_json(&url, &[])
            .ok()
            .flatten()
            .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(str::to_string));
        self.cache.put("repo-pkgname", &key, &name);
        name
    }

    /// Repo reputation stats. Cached per `host/owner/repo` (host-qualified so an
    /// `owner/repo` on GitHub never collides with the same slug on GitLab).
    /// Dispatches to the host's API; an unrecognized host has no stats.
    fn stats_for(&self, repo: &RepoRef) -> Result<Option<RepoStats>> {
        let key = format!("{}/{}", repo.host, repo.slug());
        if let Some(hit) = self.cache.get::<RepoStats>("repo", &key) {
            return Ok(Some(hit));
        }
        let stats = match repo.kind() {
            Some(Host::GitHub) => self.host_stats(
                &format!("{}/repos/{}/{}", self.endpoints.github(), repo.owner, repo.name),
                self.tokens.github.as_deref().map(|t| ("Authorization", format!("Bearer {t}"))),
                "stargazers_count",
                "pushed_at",
            )?,
            Some(Host::GitLab) => self.host_stats(
                &format!("{}/projects/{}", self.endpoints.gitlab(), urlencode(&repo.slug())),
                self.tokens.gitlab.as_deref().map(|t| ("PRIVATE-TOKEN", t.to_string())),
                "star_count",
                "last_activity_at",
            )?,
            Some(Host::Codeberg) => self.host_stats(
                &format!("{}/repos/{}/{}", self.endpoints.codeberg(), repo.owner, repo.name),
                self.tokens.codeberg.as_deref().map(|t| ("Authorization", format!("token {t}"))),
                "stars_count",
                "updated_at",
            )?,
            None => return Ok(None), // host we don't pull stats from
        };
        if let Some(s) = &stats {
            self.cache.put("repo", &key, s);
        }
        Ok(stats)
    }

    /// Fetch and normalize repo stats from a host API. The three hosts share a
    /// JSON shape up to two field names: the star count and the "last activity"
    /// timestamp. `created_at` and `archived` are spelled the same across all
    /// three. `auth` is the host's optional auth header.
    fn host_stats(
        &self,
        url: &str,
        auth: Option<(&'static str, String)>,
        stars_field: &str,
        activity_field: &str,
    ) -> Result<Option<RepoStats>> {
        let headers: Vec<(&str, String)> = auth.into_iter().collect();
        let Some(v) = self.get_json(url, &headers)? else {
            return Ok(None); // 404 — repo gone/renamed/private
        };
        Ok(Some(RepoStats {
            stars: v.get(stars_field).and_then(|s| s.as_u64()).unwrap_or(0),
            created_at: v.get("created_at").and_then(|s| s.as_str()).and_then(parse_ts),
            pushed_at: v.get(activity_field).and_then(|s| s.as_str()).and_then(parse_ts),
            archived: v.get("archived").and_then(|s| s.as_bool()).unwrap_or(false),
            // GitHub carries `language` in the repo object for free; the others
            // omit it (`None`), and fill it via `--languages` if requested.
            language: v.get("language").and_then(|s| s.as_str()).map(String::from),
            fetched_at: self.now,
        }))
    }

    /// The repo's language breakdown as `(name, percent)`, biggest first, capped
    /// to a top-N + `Other`. One extra `/languages` call per repo, dispatched by
    /// host and cached per `host/owner/repo` (so it's paid once per repo, ever).
    /// GitHub/Codeberg report bytes, GitLab reports percentages — we normalize
    /// both by the total, so the maths is uniform.
    fn languages_for(&self, repo: &RepoRef) -> Result<Option<Vec<(String, f64)>>> {
        let key = format!("{}/{}", repo.host, repo.slug());
        if let Some(hit) = self.cache.get::<Vec<(String, f64)>>("languages", &key) {
            return Ok(Some(hit));
        }
        let (url, auth) = match repo.kind() {
            Some(Host::GitHub) => (
                format!("{}/repos/{}/{}/languages", self.endpoints.github(), repo.owner, repo.name),
                self.tokens.github.as_deref().map(|t| ("Authorization", format!("Bearer {t}"))),
            ),
            Some(Host::GitLab) => (
                format!("{}/projects/{}/languages", self.endpoints.gitlab(), urlencode(&repo.slug())),
                self.tokens.gitlab.as_deref().map(|t| ("PRIVATE-TOKEN", t.to_string())),
            ),
            Some(Host::Codeberg) => (
                format!("{}/repos/{}/{}/languages", self.endpoints.codeberg(), repo.owner, repo.name),
                self.tokens.codeberg.as_deref().map(|t| ("Authorization", format!("token {t}"))),
            ),
            None => return Ok(None),
        };
        let headers: Vec<(&str, String)> = auth.into_iter().collect();
        let Some(v) = self.get_json(&url, &headers)? else {
            return Ok(None);
        };
        let breakdown = normalize_languages(&v);
        if let Some(b) = &breakdown {
            self.cache.put("languages", &key, b);
        }
        Ok(breakdown)
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

    /// GET + JSON, with arbitrary request headers (auth, etc.). `Ok(None)` on 404
    /// (a missing package/repo, not an error); any other non-2xx or transport
    /// failure is an `Err`. A `User-Agent` is always set — crates.io and the
    /// GitHub API reject requests without one.
    fn get_json(&self, url: &str, headers: &[(&str, String)]) -> Result<Option<serde_json::Value>> {
        let mut req = self.agents.for_url(url).get(url).set("User-Agent", USER_AGENT);
        for (k, v) in headers {
            req = req.set(k, v);
        }
        match req.call() {
            Ok(resp) => Ok(Some(serde_json::from_str(&resp.into_string()?)?)),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

/// The registry endpoint that carries `dep`'s source-repo metadata. `None` for
/// ecosystems resolved without a registry call (Go, whose module path is the
/// repo). One endpoint per ecosystem:
/// - **npm** (Node): the immutable version manifest.
/// - **PyPI** (Python): the project JSON (`project_urls` + `home_page`).
/// - **crates.io** (Rust): the crate record (`repository`).
/// - **RubyGems** (Ruby): the gem JSON (`source_code_uri` / `homepage_uri`).
/// - **Packagist** (PHP): the package JSON (`repository`).
/// - **deps.dev** (Java/Maven): the version's `links` (avoids POM XML parsing).
fn registry_url(dep: &Dependency, ep: &crate::settings::Endpoints) -> Option<String> {
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
        Ecosystem::Go | Ecosystem::Pacman | Ecosystem::Apt | Ecosystem::Dnf | Ecosystem::Nix | Ecosystem::Apk => return None,
    })
}

/// Copy registry-resolved licenses back onto the dependency list.
///
/// A lockfile declaration always wins: npm and composer record the license for
/// the exact artifact that was installed, whereas a registry describes what the
/// publisher currently says about that version. So this only fills packages that
/// have none, and never overwrites a [`LicenseSource::Lockfile`] value.
pub fn apply_licenses(
    deps: &mut [Dependency],
    resolutions: &HashMap<DepRef, Resolution>,
) {
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

/// A second endpoint to try when [`registry_url`] 404s.
///
/// PyPI and RubyGems are the two registries whose *name-only* document describes
/// the **latest** version rather than the pinned one — so [`registry_url`] asks
/// for the exact version, and this is the name-only form to fall back on when
/// that version was never served under that spelling (a yanked release, or a
/// platform-suffixed gem like `nokogiri-1.13.9-x86_64-linux`).
fn registry_url_fallback(dep: &Dependency, ep: &crate::settings::Endpoints) -> Option<String> {
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
fn raw_licenses_from(dep: &Dependency, v: &serde_json::Value) -> Vec<String> {
    let str_at = |val: &serde_json::Value, key: &str| {
        val.get(key).and_then(|x| x.as_str()).map(String::from)
    };
    let arr_at = |val: &serde_json::Value, key: &str| -> Vec<String> {
        val.get(key)
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
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
            let Some(info) = v.get("info") else { return Vec::new() };
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
                    a.iter().find(|ver| str_at(ver, "num").as_deref() == Some(&dep.version))
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
fn repo_candidates(eco: Ecosystem, v: &serde_json::Value) -> Vec<String> {
    let s = |val: &serde_json::Value, key: &str| {
        val.get(key).and_then(|x| x.as_str()).map(String::from)
    };
    match eco {
        Ecosystem::Node => extract_repo_url(v).into_iter().collect(),
        Ecosystem::Python => {
            let Some(info) = v.get("info") else { return Vec::new() };
            let mut out = Vec::new();
            // Prefer explicitly repo-labelled project URLs, then any URL, then
            // the home page.
            if let Some(urls) = info.get("project_urls").and_then(|u| u.as_object()) {
                for key in ["Source", "Source Code", "Repository", "Code", "GitHub", "Git"] {
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
            v.get("urls").and_then(|u| u.get("stable")).and_then(|st| s(st, "url")),
        ]
        .into_iter()
        .flatten()
        .collect(),
        // Resolved directly from the name / resolved_url, never via a registry.
        Ecosystem::Go | Ecosystem::Pacman | Ecosystem::Apt | Ecosystem::Dnf | Ecosystem::Nix | Ecosystem::Apk => Vec::new(),
    }
}

/// Normalize a host `/languages` object (`{name: bytes|percent}`) into a
/// `(name, percent)` list, biggest first, capped to the top 3 with a rolled-up
/// `Other`. `None` for an empty repo.
fn normalize_languages(v: &serde_json::Value) -> Option<Vec<(String, f64)>> {
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

    let mut out: Vec<(String, f64)> =
        items.iter().take(TOP).map(|(n, w)| (n.clone(), w / total * 100.0)).collect();
    if items.len() > TOP {
        let other = (100.0 - out.iter().map(|(_, p)| p).sum::<f64>()).max(0.0);
        if other >= 0.05 {
            out.push(("Other".to_string(), other));
        }
    }
    Some(out)
}

/// Minimal RFC-3986 percent-encoding for a single path component (encodes `/`,
/// `:`, and everything else outside the unreserved set). Used for the GitLab
/// project path (`group/sub/project` → `group%2Fsub%2Fproject`) and the
/// deps.dev Maven coordinate (`group:artifact` → `group%3Aartifact`).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
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

/// Parse the many shapes of a repo URL on a known [`Host`] into a [`RepoRef`]:
/// `git+https://github.com/o/r.git`, `git://…`, `https://gitlab.com/o/r`,
/// `git+ssh://git@codeberg.org/o/r.git`, and the npm `github:o/r` /
/// `gitlab:o/r` shorthands. Hosts we don't recognize return `None`.
///
/// GitLab allows nested groups (`gitlab.com/group/sub/project`); the leading
/// segments become the `owner` and the last is the `name`, so `slug()`
/// round-trips the full project path. GitHub/Codeberg are always `owner/repo`.
fn parse_repo(url: &str) -> Option<RepoRef> {
    let url = url.trim();

    // Some canonical SCM hosts have no reputation API but mirror to GitHub:
    // Apache's gitbox, and Go's well-known vanity import paths. Rewrite to the
    // mirror (recurses once; the mirror URL no longer matches, so it terminates).
    if let Some(mirror) = apache_mirror(url).or_else(|| vanity_mirror(url)) {
        return parse_repo(&mirror);
    }

    // npm-style `host:owner/repo` shorthands.
    let (host, rest) = if let Some(r) = url.strip_prefix("github:") {
        (Host::GitHub, r.to_string())
    } else if let Some(r) = url.strip_prefix("gitlab:") {
        (Host::GitLab, r.to_string())
    } else {
        // Otherwise find whichever known host domain appears in the URL.
        let (host, idx) = HOSTS
            .iter()
            .find_map(|(d, h)| url.find(d).map(|i| (*h, i + d.len())))?;
        (host, url[idx..].trim_start_matches([':', '/']).to_string())
    };

    // Trim GitLab's `/-/` sub-path marker, any trailing slash / `.git`, and a
    // clinging `#ref` or `?query`.
    let rest = rest.split("/-/").next().unwrap_or(&rest);
    let rest = rest.split(['#', '?']).next().unwrap_or(rest);
    let rest = rest.trim_end_matches('/');
    let rest = rest.strip_suffix(".git").unwrap_or(rest);

    let segs: Vec<&str> = rest.split('/').map(str::trim).filter(|s| !s.is_empty()).collect();
    if segs.len() < 2 {
        return None;
    }
    let (owner, name) = match host {
        // GitLab: everything up to the last segment is the (possibly nested)
        // namespace.
        Host::GitLab => (segs[..segs.len() - 1].join("/"), segs[segs.len() - 1]),
        // GitHub / Codeberg: always exactly owner/repo; ignore deeper path.
        _ => (segs[0].to_string(), segs[1]),
    };
    let name = name.strip_suffix(".git").unwrap_or(name);
    if owner.is_empty() || name.is_empty() {
        return None;
    }
    Some(RepoRef {
        host: host.domain().to_string(),
        owner,
        name: name.to_string(),
    })
}

/// Map an Apache gitbox URL to its `github.com/apache/<repo>` mirror. Apache
/// projects publish their SCM through `gitbox.apache.org` (a GitWeb frontend
/// with no reputation API) but mirror every repo to GitHub, where the stars
/// live. Forms handled:
///   `https://gitbox.apache.org/repos/asf?p=commons-lang.git` (GitWeb `?p=`)
///   `https://gitbox.apache.org/repos/asf/commons-lang.git`   (path)
///   `git-wip-us.apache.org` is the old alias of the same host.
fn apache_mirror(url: &str) -> Option<String> {
    if !url.contains("gitbox.apache.org") && !url.contains("git-wip-us.apache.org") {
        return None;
    }
    let repo = if let Some(i) = url.find("?p=") {
        url[i + 3..].split(['&', '#']).next()?
    } else if let Some(i) = url.find("/repos/asf/") {
        url[i + "/repos/asf/".len()..].split(['/', '?', '#']).next()?
    } else {
        return None;
    };
    let repo = repo.trim().trim_end_matches(".git");
    if repo.is_empty() {
        return None;
    }
    Some(format!("github.com/apache/{repo}"))
}

/// Map a well-known Go **vanity import path** to the GitHub repo it stands for.
/// These custom domains (`golang.org/x/…`, `k8s.io/…`, …) serve a `go-get` meta
/// redirect rather than being real hosts; resolving them properly would need an
/// extra fetch, but the common ones have fixed, documented mappings we can apply
/// offline. Anything unrecognized returns `None` (stays `no-repository`).
///
/// Works on both a bare module path (`golang.org/x/net`, as Go deps arrive) and
/// a full URL (`https://golang.org/x/net`). Only the leading domain segment is
/// matched, so `google.golang.org/grpc` (irregular mapping) is left alone.
fn vanity_mirror(url: &str) -> Option<String> {
    let rest = url.rsplit("://").next().unwrap_or(url);
    let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    let (host, tail) = segs.split_first()?;
    match *host {
        // golang.org/x/<repo> → github.com/golang/<repo>
        "golang.org" if tail.first() == Some(&"x") && tail.len() >= 2 => {
            Some(format!("github.com/golang/{}", tail[1]))
        }
        // k8s.io/<repo> → github.com/kubernetes/<repo>
        "k8s.io" if !tail.is_empty() => Some(format!("github.com/kubernetes/{}", tail[0])),
        // sigs.k8s.io/<repo> → github.com/kubernetes-sigs/<repo>
        "sigs.k8s.io" if !tail.is_empty() => {
            Some(format!("github.com/kubernetes-sigs/{}", tail[0]))
        }
        // The `.vN` suffix marks which segment is the package (a subpath can
        // follow either form, so segment *count* can't disambiguate):
        //   gopkg.in/<pkg>.vN[/…]        → github.com/go-<pkg>/<pkg>
        //   gopkg.in/<user>/<pkg>.vN[/…] → github.com/<user>/<pkg>
        "gopkg.in" => {
            if let Some(name) = tail.first().and_then(|s| strip_gopkg_version(s)) {
                Some(format!("github.com/go-{name}/{name}"))
            } else if let (Some(user), Some(name)) =
                (tail.first(), tail.get(1).and_then(|s| strip_gopkg_version(s)))
            {
                Some(format!("github.com/{user}/{name}"))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Strip gopkg.in's `.vN` version suffix: `yaml.v2` → `yaml`. `None` if there's
/// no such suffix (used to tell a `user/pkg.vN` path from a bare `pkg.vN`).
fn strip_gopkg_version(seg: &str) -> Option<&str> {
    let (name, ver) = seg.rsplit_once(".v")?;
    if !name.is_empty() && ver.bytes().all(|b| b.is_ascii_digit()) && !ver.is_empty() {
        Some(name)
    } else {
        None
    }
}

/// Age in hours of a version published at `published_ts`, but only if it falls
/// inside the [`FRESH_HOURS`] cooldown window — otherwise `None`. Kept pure (now
/// is passed in) so the cooldown threshold is unit-testable. A future publish
/// time (clock skew) yields age 0, still "fresh".
fn fresh_age_hours(published_ts: Option<i64>, now: i64) -> Option<i64> {
    let ts = published_ts?;
    let hours = (now - ts).max(0) / 3_600;
    (hours < FRESH_HOURS).then_some(hours)
}

/// Days since the package's first-ever release, only within the [`NEWBORN_DAYS`]
/// window — else `None`. Pure (now passed in) for unit-testing.
fn newborn_age_days(first_release_ts: Option<i64>, now: i64) -> Option<i64> {
    let ts = first_release_ts?;
    let days = (now - ts).max(0) / 86_400;
    (days < NEWBORN_DAYS).then_some(days)
}

/// Do two names share a meaningful (≥3-char) alphanumeric token? Used to decide
/// whether a repo plausibly "owns" a package before crying starjacking.
fn shares_token(a: &str, b: &str) -> bool {
    let tokens = |s: &str| -> Vec<String> {
        s.to_lowercase()
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|t| t.len() >= 3)
            .map(str::to_string)
            .collect()
    };
    let (ta, tb) = (tokens(a), tokens(b));
    ta.iter().any(|t| tb.contains(t))
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
    // Record the (immutable) publish time up front — even a brand-new *first*
    // release is "fresh", and that decision happens at use-time, not here.
    meta.published_ts = Some(inst_ts);
    // `time.created` is the package's first-ever publish — the newborn clock.
    meta.first_release_ts = times.get("created").and_then(|t| t.as_str()).and_then(parse_ts);

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
    // Provenance regression: the prior version was published with an OIDC/CI
    // attestation and this one wasn't (the axios pattern — a direct token push
    // that skipped Trusted Publishing).
    if versions.get(prior_v).is_some_and(has_provenance) && !inst.is_some_and(has_provenance) {
        meta.provenance_removed = true;
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

/// Does a version manifest carry an npm provenance attestation (published via
/// Trusted Publishing / `--provenance`, i.e. `dist.attestations`)?
fn has_provenance(manifest: &serde_json::Value) -> bool {
    manifest.get("dist").and_then(|d| d.get("attestations")).is_some()
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
        assert_eq!(m.published_ts, parse_ts("2023-02-01T00:00:00.000Z"), "publish time recorded");
    }

    #[test]
    fn fresh_release_cooldown_window() {
        let now = 1_700_000_000;
        assert_eq!(fresh_age_hours(Some(now - 10 * 3600), now), Some(10), "10h old → fresh");
        assert_eq!(fresh_age_hours(Some(now - 47 * 3600), now), Some(47), "just inside 48h");
        assert_eq!(fresh_age_hours(Some(now - 49 * 3600), now), None, "aged out of window");
        assert_eq!(fresh_age_hours(None, now), None, "no publish time → not fresh");
        assert_eq!(fresh_age_hours(Some(now + 3600), now), Some(0), "clock skew → age 0, still fresh");
    }

    #[test]
    fn newborn_window() {
        let now = 1_700_000_000;
        assert_eq!(newborn_age_days(Some(now - 5 * 86_400), now), Some(5), "5d old → newborn");
        assert_eq!(newborn_age_days(Some(now - 29 * 86_400), now), Some(29), "just inside 30d");
        assert_eq!(newborn_age_days(Some(now - 45 * 86_400), now), None, "established package");
        assert_eq!(newborn_age_days(None, now), None);
    }

    #[test]
    fn shares_token_guards_starjacking() {
        // A monorepo/scoped package legitimately shares a token with its repo.
        assert!(shares_token("@babel/core", "babel/babel"));
        assert!(shares_token("react-dom", "facebook/react"));
        // A borrowed-reputation squat shares nothing with the popular repo.
        assert!(!shares_token("cutie-stealer", "facebook/react"));
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
        assert!(compute_version_meta(&doc, "1.0.1").provenance_removed);

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
        assert!(!compute_version_meta(&steady, "1.0.1").provenance_removed);
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
            let r = parse_repo(c).unwrap_or_else(|| panic!("failed to parse {c}"));
            assert_eq!(r.host, "github.com", "host for {c}");
            assert_eq!(r.owner, "expressjs", "owner for {c}");
            assert_eq!(r.name, "express", "name for {c}");
            assert_eq!(r.slug(), "expressjs/express");
        }
    }

    #[test]
    fn parses_gitlab_and_codeberg() {
        // GitLab, including a nested group and the `/-/` sub-path marker.
        let gl = parse_repo("https://gitlab.com/gitlab-org/gitlab.git").unwrap();
        assert_eq!(gl.kind(), Some(Host::GitLab));
        assert_eq!(gl.slug(), "gitlab-org/gitlab");
        let nested = parse_repo("https://gitlab.com/group/sub/proj/-/tree/main").unwrap();
        assert_eq!(nested.owner, "group/sub");
        assert_eq!(nested.name, "proj");
        assert_eq!(nested.slug(), "group/sub/proj");
        assert_eq!(parse_repo("gitlab:group/proj").unwrap().slug(), "group/proj");

        // Codeberg (Forgejo) is always owner/repo.
        let cb = parse_repo("https://codeberg.org/forgejo/forgejo").unwrap();
        assert_eq!(cb.kind(), Some(Host::Codeberg));
        assert_eq!(cb.slug(), "forgejo/forgejo");
    }

    #[test]
    fn go_module_path_is_its_repo() {
        // A Go module path resolves directly, no registry call.
        let r = parse_repo("github.com/gin-gonic/gin").unwrap();
        assert_eq!(r.slug(), "gin-gonic/gin");
    }

    #[test]
    fn apache_gitbox_maps_to_github_mirror() {
        // Both the GitWeb `?p=` form (what deps.dev reports) and the path form
        // resolve to github.com/apache/<repo>.
        let gitweb = parse_repo("https://gitbox.apache.org/repos/asf?p=commons-lang.git").unwrap();
        assert_eq!(gitweb.slug(), "apache/commons-lang");
        assert_eq!(gitweb.kind(), Some(Host::GitHub));
        let path = parse_repo("scm:git:https://gitbox.apache.org/repos/asf/kafka.git").unwrap();
        assert_eq!(path.slug(), "apache/kafka");
        // Old alias host, too.
        let old = parse_repo("https://git-wip-us.apache.org/repos/asf?p=maven.git").unwrap();
        assert_eq!(old.slug(), "apache/maven");
    }

    #[test]
    fn go_vanity_paths_map_to_github() {
        let cases = [
            ("golang.org/x/net", "golang/net"),
            ("https://golang.org/x/crypto", "golang/crypto"),
            ("k8s.io/client-go", "kubernetes/client-go"),
            ("sigs.k8s.io/yaml", "kubernetes-sigs/yaml"),
            ("gopkg.in/yaml.v2", "go-yaml/yaml"),
            ("gopkg.in/yaml.v3/subpkg", "go-yaml/yaml"), // subpath, bare form
            ("gopkg.in/check.v1", "go-check/check"),
            ("gopkg.in/square/go-jose.v2", "square/go-jose"), // user form
        ];
        for (path, want) in cases {
            let r = parse_repo(path).unwrap_or_else(|| panic!("failed to resolve {path}"));
            assert_eq!(r.slug(), want, "for {path}");
            assert_eq!(r.kind(), Some(Host::GitHub));
        }
        // google.golang.org/* has an irregular mapping — deliberately left alone.
        assert!(vanity_mirror("google.golang.org/grpc").is_none());
        // A plain GitHub path isn't a vanity host.
        assert!(vanity_mirror("github.com/golang/net").is_none());
    }

    #[test]
    fn rejects_unknown_host() {
        // A host we don't pull stats from doesn't resolve.
        assert!(parse_repo("https://bitbucket.org/o/r.git").is_none());
        assert!(parse_repo("https://sr.ht/~o/r").is_none());
        assert!(parse_repo("not a url").is_none());
    }

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
    fn urlencodes_path_and_coordinate() {
        assert_eq!(urlencode("group/sub/proj"), "group%2Fsub%2Fproj");
        assert_eq!(urlencode("com.google.guava:guava"), "com.google.guava%3Aguava");
    }

    #[test]
    fn extracts_repo_candidates_per_ecosystem() {
        let py = serde_json::json!({
            "info": { "project_urls": { "Homepage": "https://x.dev", "Source": "https://github.com/psf/requests" } }
        });
        assert_eq!(
            repo_candidates(Ecosystem::Python, &py).iter().find_map(|u| parse_repo(u)).unwrap().slug(),
            "psf/requests"
        );
        let rs = serde_json::json!({ "crate": { "repository": "https://github.com/serde-rs/serde" } });
        assert_eq!(
            repo_candidates(Ecosystem::Rust, &rs).iter().find_map(|u| parse_repo(u)).unwrap().slug(),
            "serde-rs/serde"
        );
        let rb = serde_json::json!({ "source_code_uri": "https://gitlab.com/o/r" });
        assert_eq!(repo_candidates(Ecosystem::Ruby, &rb), vec!["https://gitlab.com/o/r"]);
        let php = serde_json::json!({ "package": { "repository": "https://github.com/laravel/framework" } });
        assert_eq!(
            repo_candidates(Ecosystem::Php, &php).iter().find_map(|u| parse_repo(u)).unwrap().slug(),
            "laravel/framework"
        );
        let java = serde_json::json!({
            "links": [ { "label": "HOMEPAGE", "url": "https://guava.dev" },
                       { "label": "SOURCE_REPO", "url": "https://github.com/google/guava" } ]
        });
        assert_eq!(
            repo_candidates(Ecosystem::Java, &java).iter().find_map(|u| parse_repo(u)).unwrap().slug(),
            "google/guava"
        );
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
            agents: crate::settings::NetworkSettings::default().agents(Duration::from_secs(15)),
            cache: Cache::open(),
            tokens: Tokens::default(),
            endpoints: crate::settings::Endpoints::default(),
            thresholds: TreeSettings { min_stars: 20, recent_days: 30, stale_days: 365 },
            now: 1_000_000_000,
            languages: false,
            want_licenses: false,
        };
        let fresh_lowstar = RepoStats {
            stars: 1,
            created_at: Some(1_000_000_000 - 5 * 86_400), // 5 days old
            pushed_at: Some(1_000_000_000),
            archived: false,
            language: None,
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
            language: None,
            fetched_at: 0,
        };
        assert!(r.assess(&healthy).is_empty());
    }
}
