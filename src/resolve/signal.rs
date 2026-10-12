//! What counts as risky: the signal vocabulary, its severities and points,
//! and the two assessments that read a repository rather than a registry.

use super::repo::Host;
use super::*;
use crate::model::{Dependency, Severity};

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
    Typosquat {
        target: String,
        kind: &'static str,
    },
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
    Starjacking {
        repo: String,
    },
    /// This version dropped the provenance attestation an earlier version carried
    /// — published outside the trusted OIDC/CI flow (the axios pattern).
    ProvenanceRemoved,
    /// The declared source repo returns 404 (deleted/renamed) — its handle is
    /// re-registerable, i.e. repojacking-exposed.
    DanglingRepo {
        repo: String,
    },
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

/// A linked repo needs at least this many stars for a name mismatch to read as
/// *borrowed* reputation (starjacking) rather than an ordinary rename/monorepo.
const STARJACK_MIN_STARS: u64 = 500;

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

impl Resolver {
    pub(super) fn assess(&self, dep: &Dependency, stats: &RepoStats) -> Vec<RiskSignal> {
        let mut signals = Vec::new();
        // A Julia `_jll` is a generated binary wrapper in JuliaBinaryWrappers:
        // its repo has no stars by construction, whatever it wraps.
        let generated = dep.ecosystem == crate::model::Ecosystem::Julia && dep.name.ends_with("_jll");
        if let Some(min) = self.thresholds.min_stars_for(dep.ecosystem)
            && stats.stars < min
            && !generated
        {
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

    /// Starjacking check (npm): a package linking to a **popular** GitHub repo
    /// (≥ [`STARJACK_MIN_STARS`]) that doesn't actually declare it is borrowing
    /// that repo's stars. Conservative — fires only when the repo's own
    /// `package.json` name shares no token with the package (or the repo slug),
    /// and never when the manifest can't be read (skip, don't guess).
    pub(super) fn starjack_signal(&self, dep: &Dependency, res: &Resolution) -> Option<RiskSignal> {
        let repo = res.repo.as_ref()?;
        let stats = res.stats.as_ref()?;
        if stats.stars < STARJACK_MIN_STARS || repo.kind() != Some(Host::GitHub) {
            return None;
        }
        let declared = self.repo_pkg_name(repo)?;
        let owns = shares_token(&dep.name, &declared) || shares_token(&dep.name, &repo.slug());
        (!owns).then(|| RiskSignal::Starjacking { repo: repo.slug() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shares_token_guards_starjacking() {
        // A monorepo/scoped package legitimately shares a token with its repo.
        assert!(shares_token("@babel/core", "babel/babel"));
        assert!(shares_token("react-dom", "facebook/react"));
        // A borrowed-reputation squat shares nothing with the popular repo.
        assert!(!shares_token("cutie-stealer", "facebook/react"));
    }

    #[test]
    fn assess_flags_thresholds() {
        let r = Resolver {
            agents: crate::settings::NetworkSettings::default().agents(Duration::from_secs(15)),
            gates: super::net::Gates::new(false),
            inflight: Default::default(),
            cache: Cache::open(),
            tokens: Tokens::default(),
            endpoints: crate::settings::Endpoints::default(),
            thresholds: TreeSettings {
                min_stars: 20,
                recent_days: 30,
                stale_days: 365,
                ..Default::default()
            },
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
        let npm = dep(crate::model::Ecosystem::Node, "left-pad");
        let labels: Vec<String> = r
            .assess(&npm, &fresh_lowstar)
            .iter()
            .map(RiskSignal::label)
            .collect();
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
        assert!(r.assess(&npm, &healthy).is_empty());
    }

    fn dep(ecosystem: crate::model::Ecosystem, name: &str) -> Dependency {
        Dependency {
            name: name.into(),
            version: "1.0.0".into(),
            ecosystem,
            scope: crate::model::Scope::Prod,
            licenses: Vec::new(),
            license_source: crate::model::LicenseSource::Unknown,
            direct: true,
            resolved_url: None,
            integrity: None,
            parents: Vec::new(),
        }
    }

    #[test]
    fn low_stars_bar_is_per_ecosystem_and_can_be_turned_off() {
        use crate::model::Ecosystem;
        let mut t = TreeSettings::default();
        assert_eq!(t.min_stars_for(Ecosystem::Node), Some(20));
        assert_eq!(t.min_stars_for(Ecosystem::Elixir), Some(5));
        assert_eq!(t.min_stars_for(Ecosystem::Perl), None);
        // A lower global bar is not raised back to the niche default.
        t.min_stars = 3;
        assert_eq!(t.min_stars_for(Ecosystem::Haskell), Some(3));
        // The per-ecosystem table wins, and 0 turns it off.
        t.min_stars_by_ecosystem.insert("perl".into(), 2);
        t.min_stars_by_ecosystem.insert("node".into(), 0);
        assert_eq!(t.min_stars_for(Ecosystem::Perl), Some(2));
        assert_eq!(t.min_stars_for(Ecosystem::Node), None);
        // `low_stars: false` / `--no-low-stars` silences all of it.
        t.low_stars = false;
        assert_eq!(t.min_stars_for(Ecosystem::Perl), None);
        assert_eq!(t.min_stars_for(Ecosystem::Rust), None);
    }

    #[test]
    fn a_julia_jll_is_never_low_stars() {
        let r = Resolver {
            agents: crate::settings::NetworkSettings::default().agents(Duration::from_secs(15)),
            gates: super::net::Gates::new(false),
            inflight: Default::default(),
            cache: Cache::open(),
            tokens: Tokens::default(),
            endpoints: crate::settings::Endpoints::default(),
            thresholds: TreeSettings::default(),
            now: 1_000_000_000,
            languages: false,
            want_licenses: false,
        };
        let zero = RepoStats {
            stars: 0,
            created_at: Some(0),
            pushed_at: Some(1_000_000_000),
            archived: false,
            language: None,
            fetched_at: 0,
        };
        let jl = crate::model::Ecosystem::Julia;
        assert!(r.assess(&dep(jl, "OpenSSL_jll"), &zero).is_empty());
        assert_eq!(r.assess(&dep(jl, "Tiny"), &zero).len(), 1);
    }
}
