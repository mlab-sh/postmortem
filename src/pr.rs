//! Resolve a GitHub pull-request URL into the two project states it compares.
//!
//! `postmortem diff <pr-url>` answers the question a reviewer actually has —
//! *what does this PR do to my dependency tree* — without them checking out two
//! branches by hand.
//!
//! Only the manifests and lockfiles are fetched, never the repository. A
//! dependency diff needs nothing else, and cloning a large repo twice to read
//! two JSON files would dominate the runtime. Each side costs one tree listing
//! plus one download per manifest found, so a typical project is a handful of
//! requests.
//!
//! Both sides are read from the **base** repository even when the PR comes from
//! a fork: GitHub keeps the PR head reachable there, so the fork's name is never
//! needed and a deleted fork does not break the lookup.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::settings::{Endpoints, Settings};

/// Manifests and lockfiles worth fetching — the set [`crate::detect`] knows how
/// to read. Anything else in the tree is irrelevant to a dependency diff.
///
/// Manifests are included alongside lockfiles because several parsers need both:
/// yarn reads `package.json` for the direct set, Cargo reads `Cargo.toml` for
/// dev/build scopes, Bundler reads `Gemfile` for groups.
const WANTED: &[&str] = &[
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "poetry.lock",
    "Pipfile.lock",
    "pyproject.toml",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
    "go.mod",
    "go.sum",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
];

/// Directories whose manifests describe someone else's project, not this one.
/// A vendored `node_modules/*/package.json` would otherwise be materialized by
/// the thousand and parsed as a project of its own.
const SKIP_DIRS: &[&str] =
    &["node_modules/", "vendor/", ".git/", "test/fixtures/", "tests/fixtures/", "testdata/"];

/// A parsed pull-request reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrRef {
    pub owner: String,
    pub repo: String,
    pub number: u64,
}

/// What the PR compares, as GitHub reports it.
#[derive(Debug, Clone)]
pub struct PrMeta {
    pub title: String,
    pub base_ref: String,
    pub base_sha: String,
    pub head_ref: String,
    pub head_sha: String,
    /// The head repository's `owner/name`, when it differs from the base — i.e.
    /// the PR comes from a fork. Reported so the user knows whose code this is.
    pub head_repo: Option<String>,
}

/// Recognise a GitHub pull-request URL.
///
/// Accepts the forms people actually paste: with or without a scheme, with a
/// trailing `/files` or `#discussion_r…` from the review UI, and with a `www.`
/// host. Anything else returns `None` so the argument falls through to being
/// treated as a directory path.
pub fn parse_url(s: &str) -> Option<PrRef> {
    let s = s.trim();
    // Reject an existing path early: a local directory called `github.com` would
    // otherwise be misread as a URL.
    if Path::new(s).exists() {
        return None;
    }
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let rest = rest.strip_prefix("www.").unwrap_or(rest);
    let rest = rest.strip_prefix("github.com/")?;

    let mut parts = rest.split('/');
    let owner = parts.next().filter(|s| !s.is_empty())?;
    let repo = parts.next().filter(|s| !s.is_empty())?;
    // GitHub's web UI says `pull`; the API says `pulls`. Accept both.
    let kind = parts.next()?;
    if kind != "pull" && kind != "pulls" {
        return None;
    }
    let number: u64 = parts
        .next()?
        .split(['#', '?'])
        .next()?
        .parse()
        .ok()?;

    Some(PrRef {
        owner: owner.to_string(),
        repo: repo.trim_end_matches(".git").to_string(),
        number,
    })
}

/// The two project states of a pull request, materialized on disk.
///
/// The temporary tree is removed when this is dropped, so callers cannot leak it
/// by returning early on an error.
pub struct Sides {
    pub meta: PrMeta,
    pub base: PathBuf,
    pub head: PathBuf,
    /// How many files were written per side — surfaced so a PR that yielded
    /// nothing reads as "no manifests found", not as "no changes".
    pub files: usize,
    root: PathBuf,
}

impl Drop for Sides {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Fetch both sides of `pr` into a temporary directory.
pub fn materialize(pr: &PrRef, settings: &mut Settings, ui: &crate::ui::Ui) -> Result<Sides> {
    let net = settings.network.clone();
    let agents = net.agents(std::time::Duration::from_secs(30));
    let ep = &net.endpoints;
    // A token is optional for public repositories, but the anonymous GitHub
    // limit is 60/h and this makes several calls — so reuse the one the online
    // paths already resolve.
    let token = settings.resolve_github_token()?;

    let phase = ui.phase(format!("resolving PR #{}", pr.number));
    let meta = fetch_meta(&agents, ep, token.as_deref(), pr)?;
    phase.done(format!(
        "PR #{} — {} ({} → {})",
        pr.number, meta.title, meta.head_ref, meta.base_ref
    ));

    let root = std::env::temp_dir().join(format!(
        "postmortem-pr-{}-{}-{}",
        pr.repo,
        pr.number,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    // Built before any fetch so that an error partway through still drops it and
    // removes whatever was written.
    let mut sides = Sides {
        base: root.join("base"),
        head: root.join("head"),
        meta: meta.clone(),
        files: 0,
        root: root.clone(),
    };

    let fetch_phase = ui.phase("fetching manifests");
    let mut files = 0;
    for (sha, dir) in [(&meta.base_sha, &sides.base), (&meta.head_sha, &sides.head)] {
        let paths = list_manifests(&agents, ep, token.as_deref(), pr, sha)?;
        for p in &paths {
            let body = fetch_file(&agents, ep, token.as_deref(), pr, sha, p)?;
            let dest = dir.join(p);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            std::fs::write(&dest, body)
                .with_context(|| format!("writing {}", dest.display()))?;
            files += 1;
        }
    }
    // Both sides must exist as directories even when one has no manifests, so
    // the diff reads as "everything was added" rather than failing to open.
    std::fs::create_dir_all(&sides.base)?;
    std::fs::create_dir_all(&sides.head)?;
    fetch_phase.done(format!("fetched {files} manifest file(s)"));

    sides.files = files;
    Ok(sides)
}

fn api_get(
    agents: &crate::settings::Agents,
    token: Option<&str>,
    url: &str,
) -> Result<serde_json::Value> {
    let mut req = agents
        .for_url(url)
        .get(url)
        .set("User-Agent", concat!("postmortem/", env!("CARGO_PKG_VERSION")))
        .set("Accept", "application/vnd.github+json");
    if let Some(t) = token {
        req = req.set("Authorization", &format!("Bearer {t}"));
    }
    match req.call() {
        Ok(resp) => Ok(serde_json::from_str(&resp.into_string()?)?),
        Err(ureq::Error::Status(404, _)) => {
            anyhow::bail!("not found (private repository, or no such pull request)")
        }
        Err(ureq::Error::Status(403, r)) => {
            let body = r.into_string().unwrap_or_default();
            if body.contains("rate limit") {
                anyhow::bail!(
                    "GitHub rate limit reached — set GITHUB_TOKEN or github_token in \
                     ~/.postmortem/config.yml to raise it from 60/h to 5000/h"
                );
            }
            anyhow::bail!("GitHub refused the request (403): {body}")
        }
        Err(e) => Err(e.into()),
    }
}

fn fetch_meta(
    agents: &crate::settings::Agents,
    ep: &Endpoints,
    token: Option<&str>,
    pr: &PrRef,
) -> Result<PrMeta> {
    let url = format!("{}/repos/{}/{}/pulls/{}", ep.github(), pr.owner, pr.repo, pr.number);
    let v = api_get(agents, token, &url)
        .with_context(|| format!("reading pull request {}/{} #{}", pr.owner, pr.repo, pr.number))?;

    let s = |path: [&str; 2]| -> String {
        v.get(path[0]).and_then(|x| x.get(path[1])).and_then(|x| x.as_str()).unwrap_or("").to_string()
    };
    let base_sha = s(["base", "sha"]);
    let head_sha = s(["head", "sha"]);
    if base_sha.is_empty() || head_sha.is_empty() {
        anyhow::bail!("pull request {} has no base/head commit", pr.number);
    }
    let base_repo = v
        .get("base")
        .and_then(|b| b.get("repo"))
        .and_then(|r| r.get("full_name"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let head_repo = v
        .get("head")
        .and_then(|h| h.get("repo"))
        .and_then(|r| r.get("full_name"))
        .and_then(|x| x.as_str())
        .filter(|f| *f != base_repo)
        .map(String::from);

    Ok(PrMeta {
        title: v.get("title").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        base_ref: s(["base", "ref"]),
        base_sha,
        head_ref: s(["head", "ref"]),
        head_sha,
        head_repo,
    })
}

/// The manifest/lockfile paths present in the tree at `sha`.
fn list_manifests(
    agents: &crate::settings::Agents,
    ep: &Endpoints,
    token: Option<&str>,
    pr: &PrRef,
    sha: &str,
) -> Result<Vec<String>> {
    let url =
        format!("{}/repos/{}/{}/git/trees/{sha}?recursive=1", ep.github(), pr.owner, pr.repo);
    let v = api_get(agents, token, &url)
        .with_context(|| format!("listing the tree at {sha}"))?;

    // GitHub caps a recursive tree; say so rather than silently diff a subset.
    if v.get("truncated").and_then(|x| x.as_bool()) == Some(true) {
        eprintln!(
            "warn: the repository tree at {} is too large for one listing — manifests below \
             the cut are missing from this side of the diff",
            &sha[..sha.len().min(8)]
        );
    }

    let mut out: Vec<String> = Vec::new();
    for e in v.get("tree").and_then(|t| t.as_array()).into_iter().flatten() {
        if e.get("type").and_then(|x| x.as_str()) != Some("blob") {
            continue;
        }
        let Some(path) = e.get("path").and_then(|x| x.as_str()) else { continue };
        if SKIP_DIRS.iter().any(|d| path.starts_with(d) || path.contains(&format!("/{d}"))) {
            continue;
        }
        let name = path.rsplit('/').next().unwrap_or(path);
        if WANTED.contains(&name) {
            out.push(path.to_string());
        }
    }
    out.sort();
    Ok(out)
}

fn fetch_file(
    agents: &crate::settings::Agents,
    ep: &Endpoints,
    token: Option<&str>,
    pr: &PrRef,
    sha: &str,
    path: &str,
) -> Result<String> {
    let url = format!("{}/{}/{}/{sha}/{path}", ep.github_raw(), pr.owner, pr.repo);
    let mut req = agents
        .for_url(&url)
        .get(&url)
        .set("User-Agent", concat!("postmortem/", env!("CARGO_PKG_VERSION")));
    if let Some(t) = token {
        req = req.set("Authorization", &format!("Bearer {t}"));
    }
    req.call()
        .with_context(|| format!("fetching {path} at {sha}"))?
        .into_string()
        .with_context(|| format!("reading {path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pr(owner: &str, repo: &str, number: u64) -> Option<PrRef> {
        Some(PrRef { owner: owner.into(), repo: repo.into(), number })
    }

    #[test]
    fn parses_the_canonical_url() {
        assert_eq!(parse_url("https://github.com/mlab-sh/postmortem/pull/42"), pr("mlab-sh", "postmortem", 42));
    }

    #[test]
    fn parses_the_forms_people_actually_paste() {
        // Straight from the review UI, or typed without a scheme.
        for s in [
            "https://github.com/o/r/pull/7/files",
            "http://github.com/o/r/pull/7",
            "https://www.github.com/o/r/pull/7",
            "github.com/o/r/pull/7",
            "https://github.com/o/r/pull/7#discussion_r123",
            "https://github.com/o/r/pull/7?w=1",
            // The API spelling, in case someone copies a link from a tool.
            "https://github.com/o/r/pulls/7",
        ] {
            assert_eq!(parse_url(s), pr("o", "r", 7), "failed on {s}");
        }
    }

    #[test]
    fn rejects_non_pr_urls_so_they_fall_through_to_paths() {
        for s in [
            "https://github.com/o/r",
            "https://github.com/o/r/issues/7",
            "https://github.com/o/r/pull/notanumber",
            "https://gitlab.com/o/r/-/merge_requests/7",
            "./some/dir",
            "/absolute/path",
            "",
        ] {
            assert_eq!(parse_url(s), None, "should not parse: {s}");
        }
    }

    #[test]
    fn an_existing_path_is_never_a_url() {
        // A directory really named like a URL must stay a path — the argument is
        // overwhelmingly a path, so ambiguity resolves that way.
        let dir = std::env::temp_dir().join(format!("pm-pr-path-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(parse_url(dir.to_str().unwrap()), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn strips_a_git_suffix_from_the_repo() {
        assert_eq!(parse_url("https://github.com/o/r.git/pull/7"), pr("o", "r", 7));
    }

    #[test]
    fn wanted_covers_every_ecosystem_we_parse() {
        // A manifest missing here is silently absent from both sides of the
        // diff, which reads as "no dependencies" rather than as an error.
        for name in [
            "package-lock.json", "pnpm-lock.yaml", "yarn.lock", // node
            "requirements.txt", "poetry.lock", "Pipfile.lock",  // python
            "Cargo.lock",                                        // rust
            "Gemfile.lock",                                      // ruby
            "composer.lock",                                     // php
            "go.mod", "go.sum",                                  // go
            "pom.xml", "gradle.lockfile",                        // java
        ] {
            assert!(WANTED.contains(&name), "{name} is not fetched");
        }
    }

    #[test]
    fn manifests_are_fetched_alongside_lockfiles() {
        // Several parsers need both: yarn reads package.json for the direct set,
        // Cargo reads Cargo.toml for dev/build scopes, Bundler reads Gemfile.
        for name in ["package.json", "Cargo.toml", "Gemfile", "composer.json"] {
            assert!(WANTED.contains(&name), "{name} is needed by its parser");
        }
    }
}
