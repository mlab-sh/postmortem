//! The networked edge: one JSON GET, and the host API calls built on it.
//! Everything here is best-effort — a failure degrades to a signal, never an abort.

use anyhow::Result;

use super::history::parse_ts;
use super::registry::normalize_languages;
use super::repo::{Host, RepoRef, urlencode};
use super::*;

const USER_AGENT: &str = concat!("postmortem/", env!("CARGO_PKG_VERSION"));

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
        let mut req = self
            .agents
            .for_url(url)
            .get(url)
            .set("User-Agent", USER_AGENT);
        for (k, v) in headers {
            req = req.set(k, v);
        }
        match req.call() {
            Ok(resp) => Ok(Some(serde_json::from_str(&resp.into_string()?)?)),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Repo reputation stats. Cached per `host/owner/repo` (host-qualified so an
    /// `owner/repo` on GitHub never collides with the same slug on GitLab).
    /// Dispatches to the host's API; an unrecognized host has no stats.
    pub(super) fn stats_for(&self, repo: &RepoRef) -> Result<Option<RepoStats>> {
        let key = format!("{}/{}", repo.host, repo.slug());
        if let Some(hit) = self.cache.get::<RepoStats>("repo", &key) {
            return Ok(Some(hit));
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
        if let Some(hit) = self.cache.get::<Vec<(String, f64)>>("languages", &key) {
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
            self.cache.put("languages", &key, b);
        }
        Ok(breakdown)
    }

    /// The `name` in a GitHub repo's root `package.json`, cached per slug (the
    /// `None` result is cached too, so a repo without one isn't re-fetched).
    pub(super) fn repo_pkg_name(&self, repo: &RepoRef) -> Option<String> {
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
}
