//! Source-repository identity: the hosts postmortem understands, the
//! `host/owner/repo` reference, and every URL shape that has to be reduced to one.

use serde::{Deserialize, Serialize};

/// A code-hosting provider we know how to pull reputation stats from. Each has
/// its own API shape and auth header (see [`super::Resolver`]'s `stats_for`).
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
    pub(super) fn kind(&self) -> Option<Host> {
        HOSTS.iter().find(|(d, _)| *d == self.host).map(|(_, h)| *h)
    }
}

/// Pull a repository URL out of an npm version manifest's `repository` field,
/// which is either a string or an object `{ "type": "git", "url": "…" }`.
pub(super) fn extract_repo_url(manifest: &serde_json::Value) -> Option<String> {
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
pub(super) fn parse_repo(url: &str) -> Option<RepoRef> {
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

    let segs: Vec<&str> = rest
        .split('/')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
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
        url[i + "/repos/asf/".len()..]
            .split(['/', '?', '#'])
            .next()?
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
            } else if let (Some(user), Some(name)) = (
                tail.first(),
                tail.get(1).and_then(|s| strip_gopkg_version(s)),
            ) {
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

/// Minimal RFC-3986 percent-encoding for a single path component (encodes `/`,
/// `:`, and everything else outside the unreserved set). Used for the GitLab
/// project path (`group/sub/project` → `group%2Fsub%2Fproject`) and the
/// deps.dev Maven coordinate (`group:artifact` → `group%3Aartifact`).
pub(super) fn urlencode(s: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            parse_repo("gitlab:group/proj").unwrap().slug(),
            "group/proj"
        );

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
    fn urlencodes_path_and_coordinate() {
        assert_eq!(urlencode("group/sub/proj"), "group%2Fsub%2Fproj");
        assert_eq!(
            urlencode("com.google.guava:guava"),
            "com.google.guava%3Aguava"
        );
    }

    #[test]
    fn extracts_repository_string_and_object() {
        let s = serde_json::json!({ "repository": "github:a/b" });
        assert_eq!(extract_repo_url(&s).as_deref(), Some("github:a/b"));
        let o = serde_json::json!({ "repository": { "type": "git", "url": "https://github.com/a/b.git" } });
        assert_eq!(
            extract_repo_url(&o).as_deref(),
            Some("https://github.com/a/b.git")
        );
        let none = serde_json::json!({ "name": "x" });
        assert_eq!(extract_repo_url(&none), None);
    }
}
