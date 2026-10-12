//! Elixir / Hex `mix.lock` parser.
//!
//! `mix.lock` is an Elixir map literal, one entry per dependency:
//!
//! ```text
//! "cowboy": {:hex, :cowboy, "2.10.0", "<inner sha>", [:make, :rebar3],
//!            [{:cowlib, "2.12.1", [hex: :cowlib, repo: "hexpm", optional: false]}],
//!            "hexpm", "<outer sha>"},
//! "phoenix": {:git, "https://github.com/phoenixframework/phoenix.git", "<rev>", [branch: "main"]},
//! ```
//!
//! A Hex entry lists its own dependencies, so the graph comes back with edges.
//! The direct set (and the dev/test split) comes from `mix.exs`'s `deps`,
//! best-effort. The key is the OTP app name; the package name (second element)
//! is what Hex and OSV know it by, and is what is reported.

use anyhow::{Context, Result, bail};
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

use crate::model::{Dependency, Ecosystem, LicenseSource, Scope};

// ---------- a reader for the Elixir terms mix.lock uses ----------

#[derive(Debug, Clone, PartialEq)]
enum Term {
    Atom(String),
    Str(String),
    /// Integers, booleans, `nil` — kept as text, never needed as values.
    Other(String),
    List(Vec<Term>),
    Tuple(Vec<Term>),
    Map(Vec<(Term, Term)>),
}

impl Term {
    fn text(&self) -> Option<&str> {
        match self {
            Term::Atom(s) | Term::Str(s) => Some(s),
            _ => None,
        }
    }
}

struct Reader<'a> {
    s: &'a [u8],
    i: usize,
    /// Open `[` / `{` / `%{` — bounded, or a hostile lock overflows the stack.
    depth: usize,
}

/// Far deeper than any real mix.lock nests.
const MAX_DEPTH: usize = 128;

impl Reader<'_> {
    fn ws(&mut self) {
        while let Some(&c) = self.s.get(self.i) {
            if c.is_ascii_whitespace() {
                self.i += 1;
            } else if c == b'#' {
                while self.s.get(self.i).is_some_and(|&c| c != b'\n') {
                    self.i += 1;
                }
            } else {
                break;
            }
        }
    }

    fn eat(&mut self, c: u8) -> bool {
        self.ws();
        if self.s.get(self.i) == Some(&c) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn string(&mut self) -> Result<String> {
        // At the opening quote.
        self.i += 1;
        let mut out = Vec::new();
        while let Some(&c) = self.s.get(self.i) {
            self.i += 1;
            match c {
                b'"' => return Ok(String::from_utf8_lossy(&out).into_owned()),
                b'\\' => {
                    if let Some(&n) = self.s.get(self.i) {
                        out.push(n);
                        self.i += 1;
                    }
                }
                _ => out.push(c),
            }
        }
        bail!("unterminated string")
    }

    fn bare(&mut self) -> String {
        let start = self.i;
        while self.s.get(self.i).is_some_and(|&c| {
            c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'?' | b'!' | b'@' | b'-')
        }) {
            self.i += 1;
        }
        String::from_utf8_lossy(&self.s[start..self.i]).into_owned()
    }

    /// A sequence of terms up to `close`, where `key: value` / `"key": value`
    /// is a keyword pair.
    fn items(&mut self, close: u8) -> Result<Vec<Term>> {
        let mut out = Vec::new();
        loop {
            if self.eat(close) {
                return Ok(out);
            }
            let t = self.term()?;
            // `key: value` (keyword) — the colon follows the key directly.
            let t = if self.s.get(self.i) == Some(&b':') {
                self.i += 1;
                let key = match t {
                    Term::Other(k) => Term::Atom(k),
                    other => other,
                };
                Term::Tuple(vec![key, self.term()?])
            } else {
                t
            };
            out.push(t);
            if !self.eat(b',') {
                if self.eat(close) {
                    return Ok(out);
                }
                bail!("expected `,` or `{}` at byte {}", close as char, self.i);
            }
        }
    }

    fn term(&mut self) -> Result<Term> {
        self.ws();
        if !matches!(self.s.get(self.i), Some(b'[' | b'{' | b'%')) {
            return self.term_inner();
        }
        if self.depth >= MAX_DEPTH {
            bail!("nested deeper than {MAX_DEPTH} at byte {}", self.i);
        }
        self.depth += 1;
        let t = self.term_inner();
        self.depth -= 1;
        t
    }

    fn term_inner(&mut self) -> Result<Term> {
        match self.s.get(self.i) {
            Some(b'"') => Ok(Term::Str(self.string()?)),
            Some(b':') => {
                self.i += 1;
                if self.s.get(self.i) == Some(&b'"') {
                    Ok(Term::Atom(self.string()?))
                } else {
                    Ok(Term::Atom(self.bare()))
                }
            }
            Some(b'[') => {
                self.i += 1;
                Ok(Term::List(self.items(b']')?))
            }
            Some(b'{') => {
                self.i += 1;
                Ok(Term::Tuple(self.items(b'}')?))
            }
            Some(b'%') if self.s.get(self.i + 1) == Some(&b'{') => {
                self.i += 2;
                let pairs = self
                    .items(b'}')?
                    .into_iter()
                    .filter_map(|t| match t {
                        Term::Tuple(mut kv) if kv.len() == 2 => {
                            let v = kv.pop()?;
                            Some((kv.pop()?, v))
                        }
                        _ => None,
                    })
                    .collect();
                Ok(Term::Map(pairs))
            }
            Some(_) => {
                let word = self.bare();
                if word.is_empty() {
                    bail!("unexpected byte at {}", self.i);
                }
                Ok(Term::Other(word))
            }
            None => bail!("unexpected end of input"),
        }
    }
}

// ---------- mix.lock ----------

/// One lock entry, before edges are resolved.
struct Entry {
    name: String,
    version: String,
    /// (child app, requirement) pairs.
    children: Vec<String>,
    integrity: Option<String>,
    resolved_url: Option<String>,
}

fn entry(app: &str, t: &Term) -> Option<Entry> {
    let Term::Tuple(f) = t else { return None };
    match f.first()?.text()? {
        // {:hex, :pkg, version, inner, tools, deps, repo, outer}
        "hex" => {
            let pkg = f.get(1)?.text()?;
            let repo = f.get(6).and_then(Term::text).unwrap_or("hexpm");
            let children = match f.get(5) {
                Some(Term::List(deps)) => deps
                    .iter()
                    .filter_map(|d| match d {
                        Term::Tuple(dt) => dt.first()?.text().map(String::from),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            };
            Some(Entry {
                // A private organisation's package is `org/pkg`, as its purl
                // spells it — and hex.pm's public API is never asked about it.
                name: if repo == "hexpm" {
                    pkg.to_string()
                } else {
                    format!("{repo}/{pkg}")
                },
                version: f.get(2)?.text()?.to_string(),
                children,
                integrity: f.get(7).and_then(Term::text).map(String::from),
                resolved_url: None,
            })
        }
        // {:git, url, rev, opts}
        "git" => Some(Entry {
            name: app.to_string(),
            version: f.get(2)?.text()?.to_string(),
            children: Vec::new(),
            integrity: None,
            resolved_url: Some(f.get(1)?.text()?.to_string()),
        }),
        _ => None,
    }
}

pub fn parse_lockfile(path: &Path, manifest: Option<&Path>) -> Result<Vec<Dependency>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut reader = Reader {
        s: text.as_bytes(),
        i: 0,
        depth: 0,
    };
    let Term::Map(pairs) = reader
        .term()
        .with_context(|| format!("parsing {} as mix.lock", path.display()))?
    else {
        bail!("{}: not a map", path.display());
    };

    let declared = manifest.map(declared_deps).unwrap_or_default();

    let entries: Vec<(String, Entry)> = pairs
        .iter()
        .filter_map(|(k, v)| {
            let app = k.text()?;
            Some((app.to_string(), entry(app, v)?))
        })
        .collect();
    let by_app: HashMap<&str, (&str, &str)> = entries
        .iter()
        .map(|(app, e)| (app.as_str(), (e.name.as_str(), e.version.as_str())))
        .collect();

    let mut out: Vec<Dependency> = entries
        .iter()
        .map(|(app, e)| {
            let decl = declared.get(app.as_str());
            Dependency {
                name: e.name.clone(),
                version: e.version.clone(),
                ecosystem: Ecosystem::Elixir,
                direct: decl.is_some(),
                scope: match decl {
                    Some(true) => Scope::Dev,
                    _ => Scope::Prod,
                },
                licenses: Vec::new(),
                license_source: LicenseSource::Unknown,
                resolved_url: e.resolved_url.clone(),
                integrity: e.integrity.clone(),
                parents: Vec::new(),
            }
        })
        .collect();
    let index: HashMap<&str, usize> = entries
        .iter()
        .enumerate()
        .map(|(i, (app, _))| (app.as_str(), i))
        .collect();
    for (app, e) in &entries {
        let parent = by_app[app.as_str()];
        for child in &e.children {
            if let Some(&ci) = index.get(child.as_str()) {
                let p = (parent.0.to_string(), parent.1.to_string());
                if !out[ci].parents.contains(&p) {
                    out[ci].parents.push(p);
                }
            }
        }
    }
    Ok(out)
}

fn dep_tuple_re() -> &'static Regex {
    // `{:name, ...}` — the dependency tuples of `defp deps`.
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\{\s*:([a-z0-9_]+)\s*,([^{}]*)\}").unwrap())
}

fn apps_path_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"apps_path:\s*"([^"]+)""#).unwrap())
}

/// Declared deps of the project at `manifest`. An umbrella's root `mix.exs`
/// (`apps_path:`) declares none itself: its apps' `mix.exs` do.
fn declared_deps(manifest: &Path) -> HashMap<String, bool> {
    let Ok(src) = std::fs::read_to_string(manifest) else {
        return HashMap::new();
    };
    let mut out = mix_exs_deps(&src);
    if src.contains("apps_path") {
        let apps = apps_path_re()
            .captures(&src)
            .and_then(|c| c.get(1))
            .map_or("apps", |m| m.as_str());
        let dir = manifest.parent().unwrap_or(Path::new(".")).join(apps);
        for app in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let Ok(s) = std::fs::read_to_string(app.path().join("mix.exs")) else {
                continue;
            };
            for (name, dev) in mix_exs_deps(&s) {
                // Production in any app wins.
                out.entry(name).and_modify(|d| *d &= dev).or_insert(dev);
            }
        }
    }
    out
}

fn deps_fn_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\bdefp?\s+deps\b").unwrap())
}

fn next_def_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\n\s*(?:defp?|defmacrop?)\s").unwrap())
}

fn deps_kw_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\bdeps:\s*\[").unwrap())
}

/// Where the dependency tuples are: the `deps` function (up to the next
/// `def`), else an inline `deps: [...]` list. Anything else in the file — a
/// release's `{:runtime_tools, :permanent}` — is not a dependency.
fn deps_body(src: &str) -> Option<&str> {
    if let Some(m) = deps_fn_re().find(src) {
        let rest = &src[m.start()..];
        let end = next_def_re().find(rest).map_or(rest.len(), |n| n.start());
        return Some(&rest[..end]);
    }
    let start = deps_kw_re().find(src)?.end() - 1;
    let mut depth = 0usize;
    for (i, c) in src[start..].char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&src[start..=start + i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Declared deps in `mix.exs`, app -> dev/test only. `only:` without `:prod`
/// keeps a dependency out of the production release. An `in_umbrella: true`
/// sibling is the project's own code, not a Hex dependency.
fn mix_exs_deps(src: &str) -> HashMap<String, bool> {
    let Some(body) = deps_body(src) else {
        return HashMap::new();
    };
    dep_tuple_re()
        .captures_iter(body)
        .filter(|c| !c[2].contains("in_umbrella:"))
        .map(|c| {
            let dev_only = c[2].split_once("only:").is_some_and(|(_, only)| {
                let only = only.trim_start();
                // `only: [:dev, :test]` or `only: :test`
                let envs = match only.strip_prefix('[') {
                    Some(list) => list.split(']').next().unwrap_or(list),
                    None => only.split(',').next().unwrap_or(only),
                };
                !envs.contains(":prod")
            });
            (c[1].to_string(), dev_only)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"%{
  "cowboy": {:hex, :cowboy, "2.10.0", "ff9f", [:make, :rebar3], [{:cowlib, "2.12.1", [hex: :cowlib, repo: "hexpm", optional: false]}, {:ranch, "1.8.0", [hex: :ranch, repo: "hexpm", optional: false]}], "hexpm", "3afd"},
  "cowlib": {:hex, :cowlib, "2.12.1", "a9fa", [:make, :rebar3], [], "hexpm", "163b"},
  "ranch": {:hex, :ranch, "1.8.0", "8c7a", [:make, :rebar3], [], "hexpm", "49fb"},
  "plug_cowboy": {:hex, :plug_cowboy, "2.7.0", "3ae9", [:mix], [{:cowboy, "~> 2.7", [hex: :cowboy, repo: "hexpm", optional: false]}], "hexpm", "d85b"},
  "billing": {:hex, :billing, "0.3.0", "aa", [:mix], [], "acme", "bb"},
  "con_cache": {:git, "https://github.com/aerosol/con_cache", "d050e13", [branch: "main"]},
  "credo": {:hex, :credo, "1.7.5", "643", [:mix], [], "hexpm", "f79"},
}
"#;

    const MIX_EXS: &str = r#"
  defp deps do
    [
      {:plug_cowboy, "~> 2.7"},
      {:con_cache, git: "https://github.com/aerosol/con_cache", branch: "main"},
      {:billing, "~> 0.3", organization: "acme"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
"#;

    #[test]
    fn graph_direct_set_and_sources() {
        let dir =
            std::env::temp_dir().join(format!("postmortem-elixir-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (lock, exs) = (dir.join("mix.lock"), dir.join("mix.exs"));
        std::fs::write(&lock, LOCK).unwrap();
        std::fs::write(&exs, MIX_EXS).unwrap();
        let deps = parse_lockfile(&lock, Some(&exs)).unwrap();
        let get = |n: &str| deps.iter().find(|d| d.name == n).unwrap();

        assert_eq!(deps.len(), 7);
        assert!(get("plug_cowboy").direct && !get("cowboy").direct);
        assert_eq!(
            get("cowboy").parents,
            vec![("plug_cowboy".to_string(), "2.7.0".to_string())]
        );
        assert_eq!(
            get("ranch").parents,
            vec![("cowboy".to_string(), "2.10.0".to_string())]
        );
        assert_eq!(get("cowboy").integrity.as_deref(), Some("3afd"));
        assert_eq!(get("credo").scope, Scope::Dev);
        assert_eq!(get("plug_cowboy").scope, Scope::Prod);

        let git = get("con_cache");
        assert_eq!(git.version, "d050e13");
        assert_eq!(
            git.resolved_url.as_deref(),
            Some("https://github.com/aerosol/con_cache")
        );
        assert!(get("acme/billing").direct);
    }

    #[test]
    fn deep_nesting_is_an_error_not_a_stack_overflow() {
        let hostile = "[".repeat(200_000);
        let mut r = Reader {
            s: hostile.as_bytes(),
            i: 0,
            depth: 0,
        };
        assert!(r.term().unwrap_err().to_string().contains("nested deeper"));
    }

    #[test]
    fn umbrella_apps_declare_the_direct_set() {
        let dir = std::env::temp_dir().join(format!(
            "postmortem-elixir-umbrella-test-{}",
            std::process::id()
        ));
        let web = dir.join("services").join("web");
        std::fs::create_dir_all(&web).unwrap();
        let (lock, exs) = (dir.join("mix.lock"), dir.join("mix.exs"));
        std::fs::write(&lock, LOCK).unwrap();
        std::fs::write(
            &exs,
            r#"def project do
    [apps_path: "services", deps: []]
  end"#,
        )
        .unwrap();
        std::fs::write(
            web.join("mix.exs"),
            r#"defp deps do
    [{:plug_cowboy, "~> 2.7"}, {:core, in_umbrella: true}]
  end"#,
        )
        .unwrap();
        let deps = parse_lockfile(&lock, Some(&exs)).unwrap();
        let get = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert!(get("plug_cowboy").direct);
        assert!(!get("credo").direct);
    }

    #[test]
    fn tuples_outside_deps_are_not_direct() {
        // No `defp deps`: a release's `{:runtime_tools, :permanent}` is not one.
        let src = r#"def project do
    [deps: [{:jason, "~> 1.4"}], releases: [app: [applications: [{:runtime_tools, :permanent}]]]]
  end"#;
        let got = mix_exs_deps(src);
        assert_eq!(got.len(), 1);
        assert!(got.contains_key("jason"));
        assert!(mix_exs_deps("releases: [{:runtime_tools, :permanent}]").is_empty());
    }
}
