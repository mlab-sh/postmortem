//! The networked edge: one JSON GET, and the host API calls built on it.
//! Everything here is best-effort — a failure degrades to a signal, never an abort.

use anyhow::Result;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use super::history::parse_ts;
use super::registry::normalize_languages;
use super::repo::{Host, RepoRef, urlencode};
use super::*;

const USER_AGENT: &str = concat!("postmortem/", env!("CARGO_PKG_VERSION"));

/// Largest JSON body read. ureq's `into_string` stops at 10 MB, which the
/// packument of a package with thousands of releases passes: the fetch failed,
/// was never cached, and was paid again every run. Still bounded — the body is
/// attacker-controlled.
const MAX_JSON: u64 = 64 << 20;

/// A counting semaphore: at most `max` requests to one host in flight.
pub(super) struct Gate {
    max: usize,
    used: Mutex<usize>,
    freed: Condvar,
}

impl Gate {
    fn new(max: usize) -> Self {
        Gate {
            max,
            used: Mutex::new(0),
            freed: Condvar::new(),
        }
    }

    fn enter(&self) -> impl Drop + '_ {
        struct Slot<'g>(&'g Gate);
        impl Drop for Slot<'_> {
            fn drop(&mut self) {
                *self.0.used.lock().unwrap() -= 1;
                self.0.freed.notify_one();
            }
        }
        let mut used = self.used.lock().unwrap();
        while *used >= self.max {
            used = self.freed.wait(used).unwrap();
        }
        *used += 1;
        Slot(self)
    }
}

/// Concurrency per host, applied to requests actually sent — never to cache
/// hits, which is what the old per-package worker cap throttled.
pub(super) struct Gates {
    /// GitHub's API: anonymous is 60/h plus secondary abuse limits.
    github: Gate,
    /// crates.io's crawler policy asks for one request at a time.
    crates: Gate,
    /// npm, PyPI, deps.dev, RubyGems, Packagist, GitLab, Codeberg, raw GitHub.
    other: Gate,
    /// Set once GitHub reports the rate limit spent: the rest of the run skips
    /// it rather than sending requests that can only come back 403.
    github_spent: AtomicBool,
}

impl Gates {
    pub(super) fn new(github_token: bool) -> Self {
        Gates {
            github: Gate::new(if github_token { 8 } else { 2 }),
            crates: Gate::new(1),
            other: Gate::new(8),
            github_spent: AtomicBool::new(false),
        }
    }
}

/// In-run singleflight: the first caller for a key computes the answer, and
/// every other caller — concurrent or later — waits for it and shares it.
///
/// The packages of one monorepo (`@babel/*`, dozens in a typical lockfile)
/// all point at the same repo and resolve on different workers at once. Each
/// missed the disk cache before any had written it, and each sent its own
/// GitHub request — up to one per worker of the anonymous 60/h spent on one
/// answer.
pub(super) struct Flights<T>(Mutex<HashMap<String, Arc<OnceLock<T>>>>);

impl<T> Default for Flights<T> {
    fn default() -> Self {
        Flights(Mutex::new(HashMap::new()))
    }
}

impl<T: Clone> Flights<T> {
    pub(super) fn run(&self, key: &str, compute: impl FnOnce() -> T) -> T {
        let cell = self
            .0
            .lock()
            .unwrap()
            .entry(key.to_string())
            .or_default()
            .clone();
        // The map lock is released: only callers of *this* key wait, inside
        // `get_or_init`, while the first one computes.
        cell.get_or_init(compute).clone()
    }
}

/// The per-repo lookups worth sharing within a run. Errors are shared as text
/// (`anyhow::Error` is not `Clone`): a failure is as much the answer for this
/// run as a success, and retrying it per package only multiplies the failure.
#[derive(Default)]
pub(super) struct InFlight {
    stats: Flights<Shared<RepoStats>>,
    languages: Flights<Shared<Vec<(String, f64)>>>,
    pkg_name: Flights<Option<String>>,
}

/// A lookup's answer as shared between callers — see [`InFlight`].
type Shared<T> = std::result::Result<Option<T>, String>;

/// How long a repo that 404'd stays known-missing. A dangling repo is a signal
/// worth re-checking — a private repo can go public, a renamed one can come
/// back — but not on every run: a lockfile with 30 dangling repos spent half
/// the anonymous GitHub hour re-asking the same question.
const MISSING_REPO_TTL: Duration = Duration::from_secs(86_400);

/// Worth one more try: a gateway error or a connection that failed or was
/// reset (a pooled keep-alive socket the server had already closed). Never a
/// 403/429 — that is a limit, and asking again only spends more of it — and
/// never a read timeout: that is a slow server, and a retry doubles the wait.
fn retryable(e: &ureq::Error) -> bool {
    match e {
        ureq::Error::Status(code, _) => matches!(code, 502..=504),
        ureq::Error::Transport(t) => match t.kind() {
            ureq::ErrorKind::ConnectionFailed => true,
            ureq::ErrorKind::Io => !std::error::Error::source(t)
                .and_then(|s| s.downcast_ref::<std::io::Error>())
                .is_some_and(|io| {
                    matches!(
                        io.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    )
                }),
            _ => false,
        },
    }
}

impl Resolver {
    /// GET + JSON, with arbitrary request headers (auth, etc.). `Ok(None)` on 404
    /// (a missing package/repo, not an error); any other non-2xx or transport
    /// failure is an `Err`. A `User-Agent` is always set — crates.io and the
    /// GitHub API reject requests without one.
    pub(super) fn get_json(
        &self,
        url: &str,
        headers: &[(&str, String)],
    ) -> Result<Option<serde_json::Value>> {
        self.get_typed(url, headers)
    }

    /// [`Self::get_json`] straight into `T`. A struct naming only the fields
    /// read lets serde skip the rest without allocating it: an npm packument's
    /// every-version `dependencies`, `readme` and `description` are most of
    /// its size, and none of them is read.
    pub(super) fn get_typed<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        headers: &[(&str, String)],
    ) -> Result<Option<T>> {
        match self.fetch(url, headers, MAX_JSON)? {
            Some(body) => Ok(Some(serde_json::from_slice(&body)?)),
            None => Ok(None),
        }
    }

    /// GET raw bytes (a registry tarball), refusing anything over `max` — the
    /// body is attacker-controlled. `Ok(None)` on 404.
    pub fn get_bytes(&self, url: &str, max: u64) -> Result<Option<Vec<u8>>> {
        self.fetch(url, &[], max)
    }

    /// The one GET under everything above: the host's [`Gates`] slot, one retry
    /// of a [`retryable`] failure, and a body capped at `max`.
    fn fetch(&self, url: &str, headers: &[(&str, String)], max: u64) -> Result<Option<Vec<u8>>> {
        use std::io::Read;
        let github = url.starts_with(&self.endpoints.github());
        if github && self.gates.github_spent.load(Ordering::Relaxed) {
            anyhow::bail!("GitHub API rate limit spent");
        }
        let _slot = if github {
            self.gates.github.enter()
        } else if url.starts_with(&self.endpoints.crates()) {
            self.gates.crates.enter()
        } else {
            self.gates.other.enter()
        };
        let mut req = self
            .agents
            .for_url(url)
            .get(url)
            .set("User-Agent", USER_AGENT);
        for (k, v) in headers {
            req = req.set(k, v);
        }
        let sent = match req.clone().call() {
            Err(e) if retryable(&e) => {
                std::thread::sleep(Duration::from_millis(250));
                req.call()
            }
            sent => sent,
        };
        match sent {
            Ok(resp) => {
                let mut body = Vec::new();
                resp.into_reader().take(max + 1).read_to_end(&mut body)?;
                if body.len() as u64 > max {
                    anyhow::bail!("{url} is over {} MiB", max >> 20);
                }
                Ok(Some(body))
            }
            Err(ureq::Error::Status(404, resp)) => {
                // Read the (small) error page to its end: ureq hands the
                // connection back to the pool only once its body is consumed,
                // and a 404 is common here — dangling repos, a repo without a
                // `package.json` — so each one otherwise cost a new TLS handshake.
                let _ = std::io::copy(&mut resp.into_reader().take(64 << 10), &mut std::io::sink());
                Ok(None)
            }
            Err(ureq::Error::Status(code, resp))
                if github
                    && (code == 429
                        || (code == 403 && resp.header("x-ratelimit-remaining") == Some("0"))) =>
            {
                self.gates.github_spent.store(true, Ordering::Relaxed);
                anyhow::bail!("GitHub API rate limit spent ({code})")
            }
            Err(e) => Err(e.into()),
        }
    }

    /// The npm version manifest for `name@version` — immutable once published,
    /// so cached forever (a 404 is not: the version may yet be published).
    pub fn npm_manifest(&self, name: &str, version: &str) -> Result<Option<serde_json::Value>> {
        let key = format!("{name}@{version}");
        if let Some(hit) = self.cache.get::<serde_json::Value>("npm-manifest", &key) {
            return Ok(Some(hit));
        }
        let manifest = self.get_json(&format!("{}/{name}/{version}", self.endpoints.npm()), &[])?;
        if let Some(m) = &manifest {
            self.cache.put("npm-manifest", &key, m);
        }
        Ok(manifest)
    }

    /// Repo reputation stats. Cached per `host/owner/repo` (host-qualified so an
    /// `owner/repo` on GitHub never collides with the same slug on GitLab), and
    /// asked at most once per run however many packages share the repo.
    /// Dispatches to the host's API; an unrecognized host has no stats.
    pub(super) fn stats_for(&self, repo: &RepoRef) -> Result<Option<RepoStats>> {
        let key = format!("{}/{}", repo.host, repo.slug());
        self.inflight
            .stats
            .run(&key, || {
                self.stats_uncached(repo, &key)
                    .map_err(|e| format!("{e:#}"))
            })
            .map_err(anyhow::Error::msg)
    }

    fn stats_uncached(&self, repo: &RepoRef, key: &str) -> Result<Option<RepoStats>> {
        if let Some(hit) = self.cache.get::<RepoStats>("repo", key) {
            return Ok(Some(hit));
        }
        if self
            .cache
            .get_fresh::<bool>("repo-404", key, MISSING_REPO_TTL)
            .is_some()
        {
            return Ok(None);
        }
        let stats = match repo.kind() {
            Some(Host::GitHub) => self.host_stats(
                &format!(
                    "{}/repos/{}/{}",
                    self.endpoints.github(),
                    repo.owner,
                    repo.name
                ),
                self.tokens
                    .github
                    .as_deref()
                    .map(|t| ("Authorization", format!("Bearer {t}"))),
                "stargazers_count",
                "pushed_at",
            )?,
            Some(Host::GitLab) => self.host_stats(
                &format!(
                    "{}/projects/{}",
                    self.endpoints.gitlab(),
                    urlencode(&repo.slug())
                ),
                self.tokens
                    .gitlab
                    .as_deref()
                    .map(|t| ("PRIVATE-TOKEN", t.to_string())),
                "star_count",
                "last_activity_at",
            )?,
            Some(Host::Codeberg) => self.host_stats(
                &format!(
                    "{}/repos/{}/{}",
                    self.endpoints.codeberg(),
                    repo.owner,
                    repo.name
                ),
                self.tokens
                    .codeberg
                    .as_deref()
                    .map(|t| ("Authorization", format!("token {t}"))),
                "stars_count",
                "updated_at",
            )?,
            None => return Ok(None), // host we don't pull stats from
        };
        match &stats {
            Some(s) => self.cache.put("repo", key, s),
            None => self.cache.put("repo-404", key, &true),
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
            created_at: v
                .get("created_at")
                .and_then(|s| s.as_str())
                .and_then(parse_ts),
            pushed_at: v
                .get(activity_field)
                .and_then(|s| s.as_str())
                .and_then(parse_ts),
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
    pub(super) fn languages_for(&self, repo: &RepoRef) -> Result<Option<Vec<(String, f64)>>> {
        let key = format!("{}/{}", repo.host, repo.slug());
        self.inflight
            .languages
            .run(&key, || {
                self.languages_uncached(repo, &key)
                    .map_err(|e| format!("{e:#}"))
            })
            .map_err(anyhow::Error::msg)
    }

    fn languages_uncached(&self, repo: &RepoRef, key: &str) -> Result<Option<Vec<(String, f64)>>> {
        if let Some(hit) = self.cache.get::<Vec<(String, f64)>>("languages", key) {
            return Ok(Some(hit));
        }
        let (url, auth) = match repo.kind() {
            Some(Host::GitHub) => (
                format!(
                    "{}/repos/{}/{}/languages",
                    self.endpoints.github(),
                    repo.owner,
                    repo.name
                ),
                self.tokens
                    .github
                    .as_deref()
                    .map(|t| ("Authorization", format!("Bearer {t}"))),
            ),
            Some(Host::GitLab) => (
                format!(
                    "{}/projects/{}/languages",
                    self.endpoints.gitlab(),
                    urlencode(&repo.slug())
                ),
                self.tokens
                    .gitlab
                    .as_deref()
                    .map(|t| ("PRIVATE-TOKEN", t.to_string())),
            ),
            Some(Host::Codeberg) => (
                format!(
                    "{}/repos/{}/{}/languages",
                    self.endpoints.codeberg(),
                    repo.owner,
                    repo.name
                ),
                self.tokens
                    .codeberg
                    .as_deref()
                    .map(|t| ("Authorization", format!("token {t}"))),
            ),
            None => return Ok(None),
        };
        let headers: Vec<(&str, String)> = auth.into_iter().collect();
        let Some(v) = self.get_json(&url, &headers)? else {
            return Ok(None);
        };
        let breakdown = normalize_languages(&v);
        if let Some(b) = &breakdown {
            self.cache.put("languages", key, b);
        }
        Ok(breakdown)
    }

    /// The `name` in a GitHub repo's root `package.json`, cached per slug (the
    /// `None` result is cached too, so a repo without one isn't re-fetched),
    /// and asked once per run for all the packages that claim the repo.
    pub(super) fn repo_pkg_name(&self, repo: &RepoRef) -> Option<String> {
        let key = repo.slug();
        self.inflight
            .pkg_name
            .run(&key, || self.repo_pkg_name_uncached(repo, &key))
    }

    fn repo_pkg_name_uncached(&self, repo: &RepoRef, key: &str) -> Option<String> {
        if let Some(hit) = self.cache.get::<Option<String>>("repo-pkgname", key) {
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
        self.cache.put("repo-pkgname", key, &name);
        name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn a_flight_computes_once_and_everyone_shares_it() {
        let flights: Flights<std::result::Result<Option<u32>, String>> = Flights::default();
        let calls = AtomicUsize::new(0);
        let answers: Vec<_> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..8)
                .map(|_| {
                    s.spawn(|| {
                        flights.run("github/babel/babel", || {
                            calls.fetch_add(1, Ordering::SeqCst);
                            // Long enough that every thread arrives mid-flight.
                            std::thread::sleep(Duration::from_millis(50));
                            Err("rate limit spent".to_string())
                        })
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "one request for eight packages"
        );
        assert!(
            answers
                .iter()
                .all(|a| *a == Err("rate limit spent".to_string()))
        );
        // A later caller shares the answer too — errors included, for this run.
        assert_eq!(
            flights.run("github/babel/babel", || Ok(Some(1))),
            Err("rate limit spent".to_string())
        );
        // Another key is its own flight, and `Ok(None)` is an answer like any other.
        assert_eq!(flights.run("github/o/gone", || Ok(None)), Ok(None));
        assert_eq!(flights.run("github/o/gone", || Ok(Some(2))), Ok(None));
    }

    #[test]
    fn only_gateway_errors_are_retried() {
        let status = |code| ureq::Error::Status(code, ureq::Response::new(code, "x", "").unwrap());
        for code in [502, 503, 504] {
            assert!(retryable(&status(code)), "{code}");
        }
        for code in [403, 404, 429, 500] {
            assert!(!retryable(&status(code)), "{code}: a limit or an answer");
        }
    }
}
