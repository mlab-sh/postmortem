//! C / C++ package managers: Conan and vcpkg.
//!
//! **Conan**
//! * `conan.lock` v2 (`"version": "0.5"`) — flat lists of references:
//!   `requires` (host, shipped), `build_requires` / `python_requires` (tools
//!   run at build time). No edges. A reference is
//!   `name/version[@user/channel][#revision[%timestamp]]`.
//! * `conan.lock` v1 — a `graph_lock.nodes` graph keyed by id, node `"0"` the
//!   consumer: edges and the direct set come back.
//! * Without a lock, `conanfile.txt` `[requires]` / `[tool_requires]` or the
//!   `self.requires("...")` calls of `conanfile.py` give the direct set.
//!
//! **vcpkg** has no lockfile: versions come from a registry baseline. What a
//! build actually installed is recorded in `vcpkg_installed/vcpkg/status`
//! (dpkg-style paragraphs, with `Depends`) — the full graph when present.
//! Otherwise `vcpkg.json` gives the direct names, versioned only where an
//! override or a `version>=` says so.

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::OnceLock;

use crate::model::{DepRef, Dependency, Ecosystem, LicenseSource, Scope};

fn dep(name: &str, version: &str, eco: Ecosystem, direct: bool, scope: Scope) -> Dependency {
    Dependency {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem: eco,
        direct,
        scope,
        licenses: Vec::new(),
        license_source: LicenseSource::Unknown,
        resolved_url: None,
        integrity: None,
        parents: Vec::new(),
    }
}

/// Merge `d` into `out`, keyed by (name, version): the scope that ships wins,
/// directness and parents accumulate.
fn merge(out: &mut Vec<Dependency>, index: &mut HashMap<(String, String), usize>, d: Dependency) {
    match index.get(&(d.name.clone(), d.version.clone())) {
        Some(&i) => {
            let e = &mut out[i];
            e.scope = e.scope.max(d.scope);
            e.direct |= d.direct;
            for p in d.parents {
                if !e.parents.contains(&p) {
                    e.parents.push(p);
                }
            }
        }
        None => {
            index.insert((d.name.clone(), d.version.clone()), out.len());
            out.push(d);
        }
    }
}

// ---------- Conan ----------

/// `zlib/1.3.1@user/channel#rev%ts` -> (`zlib`, `1.3.1`).
pub fn conan_ref(r: &str) -> Option<(&str, &str)> {
    let r = r.split(['#', '%']).next()?;
    let r = r.split('@').next()?;
    let (name, version) = r.split_once('/')?;
    (!name.is_empty() && !version.is_empty()).then_some((name.trim(), version.trim()))
}

/// A conan dependency. A `@user/channel` reference is not ConanCenter's: the
/// full reference is kept as `resolved_url`, which keeps the resolver from
/// describing it with the same-named ConanCenter recipe.
fn conan_dep(r: &str, direct: bool, scope: Scope) -> Option<Dependency> {
    let (name, version) = conan_ref(r)?;
    let mut d = dep(name, version, Ecosystem::Conan, direct, scope);
    let bare = r.split(['#', '%']).next().unwrap_or(r);
    if bare.contains('@') {
        d.resolved_url = Some(bare.to_string());
    }
    Some(d)
}

#[derive(Deserialize)]
struct ConanLock {
    #[serde(default)]
    requires: Vec<String>,
    #[serde(default)]
    build_requires: Vec<String>,
    #[serde(default)]
    python_requires: Vec<String>,
    /// v1 only.
    #[serde(default)]
    graph_lock: Option<GraphLock>,
}

#[derive(Deserialize)]
struct GraphLock {
    #[serde(default)]
    nodes: BTreeMap<String, Node>,
}

#[derive(Deserialize)]
struct Node {
    #[serde(default)]
    r#ref: Option<String>,
    /// Set on the consumer only (its conanfile's path).
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    requires: Vec<String>,
    #[serde(default)]
    build_requires: Vec<String>,
}

pub fn parse_conan(lockfile: Option<&Path>, manifest: Option<&Path>) -> Result<Vec<Dependency>> {
    let declared = manifest
        .and_then(|m| std::fs::read_to_string(m).ok().map(|s| (m, s)))
        .map(|(m, s)| conan_declared(m, &s))
        .unwrap_or_default();

    let Some(lockfile) = lockfile else {
        // No lock: the declared references are all there is.
        return Ok(declared
            .values()
            .filter_map(|(raw, build)| {
                conan_dep(raw, true, if *build { Scope::Dev } else { Scope::Prod })
            })
            .collect());
    };

    let bytes =
        std::fs::read(lockfile).with_context(|| format!("reading {}", lockfile.display()))?;
    let lock: ConanLock = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {} as conan.lock", lockfile.display()))?;

    let mut out = Vec::new();
    let mut index = HashMap::new();

    if let Some(graph) = lock.graph_lock {
        // v1: walk the node graph. Node "0" (the one with a `path`) is the
        // consumer itself — even when its `ref` names the project.
        let refs: HashMap<&str, &str> = graph
            .nodes
            .iter()
            .filter(|(id, n)| id.as_str() != "0" && n.path.is_none())
            .filter_map(|(id, n)| {
                let r = n.r#ref.as_deref()?;
                conan_ref(r).map(|_| (id.as_str(), r))
            })
            .collect();
        for (id, n) in &graph.nodes {
            let parent: Option<DepRef> = refs
                .get(id.as_str())
                .and_then(|r| conan_ref(r))
                .map(|(name, v)| (name.to_string(), v.to_string()));
            let edges = n
                .requires
                .iter()
                .map(|c| (c, Scope::Prod))
                .chain(n.build_requires.iter().map(|c| (c, Scope::Dev)));
            for (child, scope) in edges {
                let Some(mut d) = refs
                    .get(child.as_str())
                    .and_then(|r| conan_dep(r, parent.is_none(), scope))
                else {
                    continue;
                };
                // Only the consumer's own edges seed a scope; propagation does
                // the rest from there.
                if parent.is_some() {
                    d.scope = Scope::Prod;
                }
                d.parents.extend(parent.clone());
                merge(&mut out, &mut index, d);
            }
        }
        return Ok(out);
    }

    // v2: flat. What ships is `requires`; tools only run at build time.
    let lists = [
        (&lock.requires, Scope::Prod),
        (&lock.build_requires, Scope::Dev),
        (&lock.python_requires, Scope::Dev),
    ];
    for (refs, scope) in lists {
        for r in refs {
            let direct = conan_ref(r).is_some_and(|(n, _)| declared.contains_key(n));
            if let Some(d) = conan_dep(r, direct, scope) {
                merge(&mut out, &mut index, d);
            }
        }
    }
    Ok(out)
}

fn conanfile_py_re() -> &'static Regex {
    // self.requires("zlib/1.3"), self.tool_requires(...), self.build_requires(...)
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"self\.(requires|tool_requires|build_requires|test_requires)\(\s*["']([^"']+)["']"#,
        )
        .unwrap()
    })
}

fn quoted_ref_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"["']([A-Za-z0-9_.+-]+/[^"'\s]+)["']"#).unwrap())
}

/// Declared references: name -> (the reference as written, build-time only).
/// Sorted, so a lockless run reports them in a stable order.
fn conan_declared(path: &Path, src: &str) -> BTreeMap<String, (String, bool)> {
    let mut out = BTreeMap::new();
    let mut add = |r: &str, build: bool| {
        if let Some((n, _)) = conan_ref(r) {
            out.entry(n.to_string())
                .or_insert((r.trim().to_string(), build));
        }
    };
    if path.extension().and_then(|e| e.to_str()) == Some("py") {
        for c in conanfile_py_re().captures_iter(src) {
            add(&c[2], &c[1] != "requires");
        }
        // Class attributes: `requires = "a/1", "b/2"` / `tool_requires = [...]`,
        // a `[`/`(` value running to its closer over the lines below.
        let mut lines = src.lines();
        while let Some(line) = lines.next() {
            let t = line.trim_start();
            let Some(&(_, build)) = [
                ("requires", false),
                ("tool_requires", true),
                ("build_requires", true),
                ("test_requires", true),
                ("python_requires", true),
            ]
            .iter()
            .find(|(attr, _)| t.starts_with(attr) && t[attr.len()..].trim_start().starts_with('='))
            else {
                continue;
            };
            let mut value = t.to_string();
            if let Some(o) = t.find(['[', '(']) {
                let close = if t.as_bytes()[o] == b'[' { ']' } else { ')' };
                while !value[o..].contains(close) {
                    let Some(next) = lines.next().map(str::trim_start) else {
                        break;
                    };
                    if !next.starts_with('#') {
                        value.push_str(next);
                    }
                }
            }
            for c in quoted_ref_re().captures_iter(&value) {
                add(&c[1], build);
            }
        }
    } else {
        // conanfile.txt: INI-like sections.
        let mut section = "";
        for line in src.lines().map(str::trim) {
            if line.starts_with('[') {
                section = line;
            } else if !line.is_empty() && !line.starts_with('#') {
                match section {
                    "[requires]" => add(line, false),
                    "[tool_requires]" | "[build_requires]" | "[test_requires]" => add(line, true),
                    _ => {}
                }
            }
        }
    }
    out
}

// ---------- vcpkg ----------

#[derive(Deserialize, Default)]
struct VcpkgManifest {
    #[serde(default)]
    dependencies: Vec<serde_json::Value>,
    /// A feature's dependencies install when it is enabled, which the manifest
    /// alone cannot tell — they are all counted, rather than missed.
    #[serde(default)]
    features: BTreeMap<String, Feature>,
    #[serde(default)]
    overrides: Vec<Override>,
    #[serde(default, rename = "vcpkg-configuration")]
    configuration: Option<VcpkgConfiguration>,
    #[serde(default, rename = "builtin-baseline")]
    builtin_baseline: Option<String>,
}

#[derive(Deserialize, Default)]
struct Feature {
    #[serde(default)]
    dependencies: Vec<serde_json::Value>,
}

#[derive(Deserialize, Default)]
struct VcpkgConfiguration {
    #[serde(default, rename = "overlay-ports")]
    overlay_ports: Vec<String>,
    #[serde(default, rename = "default-registry")]
    default_registry: Option<VcpkgRegistry>,
}

#[derive(Deserialize, Default)]
struct VcpkgRegistry {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    repository: String,
    baseline: Option<String>,
}

#[derive(Deserialize)]
struct Override {
    name: String,
    #[serde(
        default,
        alias = "version-semver",
        alias = "version-date",
        alias = "version-string"
    )]
    version: Option<String>,
}

/// The manifest's dependencies: name -> (host tool, `version>=`). The first
/// declaration wins: a top-level entry over a feature's plain name.
fn vcpkg_declared(m: &VcpkgManifest) -> HashMap<String, (bool, Option<String>)> {
    let mut out = HashMap::new();
    for (name, v) in m
        .dependencies
        .iter()
        .chain(m.features.values().flat_map(|f| &f.dependencies))
        .filter_map(|d| match d {
            serde_json::Value::String(n) => Some((n.clone(), (false, None))),
            serde_json::Value::Object(o) => Some((
                o.get("name")?.as_str()?.to_string(),
                (
                    o.get("host").and_then(|h| h.as_bool()).unwrap_or(false),
                    o.get("version>=")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                ),
            )),
            _ => None,
        })
    {
        out.entry(name).or_insert(v);
    }
    out
}

/// `vcpkg-cmake:x64-osx` / `curl[core,ssl]` / `zlib (!windows)` -> the port name.
fn vcpkg_port(s: &str) -> &str {
    let s = s.trim();
    let end = s.find([':', '[', '(', ' ']).unwrap_or(s.len());
    &s[..end]
}

/// A build helper port (`vcpkg-cmake`, `vcpkg-cmake-config`, `vcpkg-tool-*`)
/// runs at build time and is not shipped.
fn vcpkg_helper(name: &str) -> bool {
    name.starts_with("vcpkg-")
}

/// Ports overridden by an overlay directory (`vcpkg-configuration` in the
/// manifest, or a sibling `vcpkg-configuration.json`): port name -> its path.
fn vcpkg_overlays(dir: &Path, m: &VcpkgManifest) -> HashMap<String, String> {
    let sibling: VcpkgConfiguration = std::fs::read_to_string(dir.join("vcpkg-configuration.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    m.configuration
        .iter()
        .flat_map(|c| &c.overlay_ports)
        .chain(&sibling.overlay_ports)
        .filter_map(|p| std::fs::read_dir(dir.join(p)).ok())
        .flat_map(|rd| rd.flatten())
        .filter(|e| {
            e.path().join("vcpkg.json").is_file() || e.path().join("portfile.cmake").is_file()
        })
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                e.path().display().to_string(),
            )
        })
        .collect()
}

/// An overlay port is the project's own recipe, not the registry's: its path is
/// kept as `resolved_url`, which keeps the resolver from describing it with the
/// same-named port of microsoft/vcpkg.
/// The microsoft/vcpkg commit that versions an unbuilt manifest's ports:
/// `builtin-baseline`, else the `default-registry` baseline of its
/// configuration when that registry is the official one. `None` for another
/// registry, whose baseline postmortem cannot read.
pub fn vcpkg_baseline(manifest: &Path) -> Option<String> {
    let m: VcpkgManifest = serde_json::from_str(&std::fs::read_to_string(manifest).ok()?).ok()?;
    if let Some(sha) = m.builtin_baseline {
        return Some(sha);
    }
    let sibling: Option<VcpkgConfiguration> =
        std::fs::read_to_string(manifest.with_file_name("vcpkg-configuration.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok());
    let reg = m.configuration.or(sibling)?.default_registry?;
    let official = reg.kind == "builtin" || reg.repository.contains("github.com/microsoft/vcpkg");
    official.then_some(reg.baseline).flatten()
}

/// Version unbuilt ports from the baseline's `port -> version` map, as vcpkg
/// resolves them: an override wins, a `version>=` is a floor under the
/// baseline's version, and a port the baseline lacks keeps what it had.
pub fn vcpkg_apply_baseline(manifest: &Path, deps: &mut [Dependency], baseline: &HashMap<String, String>) {
    let overridden: Vec<String> = std::fs::read_to_string(manifest)
        .ok()
        .and_then(|s| serde_json::from_str::<VcpkgManifest>(&s).ok())
        .map(|m| m.overrides.into_iter().map(|o| o.name).collect())
        .unwrap_or_default();
    for d in deps.iter_mut().filter(|d| !overridden.contains(&d.name)) {
        let Some(base) = baseline.get(&d.name) else { continue };
        let floor_wins = d.version != "baseline"
            && crate::semver::compare(&d.version, base) == Some(std::cmp::Ordering::Greater);
        if !floor_wins {
            d.version = base.clone();
        }
    }
}

pub fn parse_vcpkg(manifest: &Path, status: Option<&Path>) -> Result<Vec<Dependency>> {
    let text = std::fs::read_to_string(manifest)
        .with_context(|| format!("reading {}", manifest.display()))?;
    let m: VcpkgManifest = serde_json::from_str(&text)
        .with_context(|| format!("parsing {} as vcpkg.json", manifest.display()))?;
    let overlays = vcpkg_overlays(manifest.parent().unwrap_or(Path::new(".")), &m);
    let mut deps = vcpkg_deps(&m, status)?;
    for d in &mut deps {
        if let Some(path) = overlays.get(&d.name) {
            d.resolved_url = Some(path.clone());
        }
    }
    Ok(deps)
}

fn vcpkg_deps(m: &VcpkgManifest, status: Option<&Path>) -> Result<Vec<Dependency>> {
    let declared = vcpkg_declared(m);
    let seed = |name: &str| match declared.get(name) {
        Some((true, _)) => Scope::Dev,
        _ if vcpkg_helper(name) => Scope::Dev,
        _ => Scope::Prod,
    };

    let Some(status) = status else {
        let overrides: HashMap<&str, &str> = m
            .overrides
            .iter()
            .filter_map(|o| Some((o.name.as_str(), o.version.as_deref()?)))
            .collect();
        let mut names: Vec<&String> = declared.keys().collect();
        names.sort();
        return Ok(names
            .into_iter()
            .map(|n| {
                let version = overrides
                    .get(n.as_str())
                    .map(|v| v.to_string())
                    .or_else(|| declared[n].1.clone())
                    .unwrap_or_else(|| "baseline".to_string());
                dep(n, &version, Ecosystem::Vcpkg, true, seed(n))
            })
            .collect());
    };

    let text =
        std::fs::read_to_string(status).with_context(|| format!("reading {}", status.display()))?;
    // (package, feature?, version?, depends, installed)
    let mut paras: Vec<(String, bool, Option<String>, Vec<String>)> = Vec::new();
    for para in text.split("\n\n") {
        let field = |k: &str| {
            para.lines()
                .find_map(|l| l.strip_prefix(k)?.strip_prefix(':'))
                .map(|v| v.trim().to_string())
        };
        let Some(pkg) = field("Package") else {
            continue;
        };
        let installed = field("Status").is_some_and(|s| {
            let w: Vec<&str> = s.split_whitespace().collect();
            matches!(w.first(), Some(&"install") | Some(&"hold")) && w.last() == Some(&"installed")
        });
        if !installed {
            continue;
        }
        let depends = field("Depends")
            .map(|d| {
                d.split(',')
                    .map(vcpkg_port)
                    .filter(|n| !n.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();
        paras.push((pkg, field("Feature").is_some(), field("Version"), depends));
    }

    let version_of: HashMap<&str, &str> = paras
        .iter()
        .filter_map(|(p, feature, v, _)| (!feature).then_some((p.as_str(), v.as_deref()?)))
        .collect();
    let mut out = Vec::new();
    let mut index = HashMap::new();
    for (pkg, _, _, _) in &paras {
        if let Some(v) = version_of.get(pkg.as_str()) {
            merge(
                &mut out,
                &mut index,
                dep(
                    pkg,
                    v,
                    Ecosystem::Vcpkg,
                    declared.contains_key(pkg),
                    seed(pkg),
                ),
            );
        }
    }
    // Feature paragraphs add their dependencies to the package's own.
    let mut seen: HashSet<(String, String)> = HashSet::new();
    for (pkg, _, _, depends) in &paras {
        let Some(pv) = version_of.get(pkg.as_str()) else {
            continue;
        };
        for child in depends {
            let Some(cv) = version_of.get(child.as_str()) else {
                continue;
            };
            if child == pkg || !seen.insert((pkg.clone(), child.clone())) {
                continue;
            }
            if let Some(&ci) = index.get(&(child.clone(), cv.to_string())) {
                let e: &mut Dependency = &mut out[ci];
                e.parents.push((pkg.clone(), pv.to_string()));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcpkg_baseline_resolves_like_vcpkg() {
        let dir = std::env::temp_dir().join(format!("pm-vcpkg-bl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = dir.join("vcpkg.json");
        std::fs::write(
            &manifest,
            r#"{"dependencies": ["zlib", {"name": "curl", "version>=": "9.0.0"},
                {"name": "openssl", "version>=": "1.0.0"}, "fmt", "nothere"],
                "overrides": [{"name": "fmt", "version": "9.1.0"}],
                "builtin-baseline": "abc123"}"#,
        )
        .unwrap();
        assert_eq!(vcpkg_baseline(&manifest).as_deref(), Some("abc123"));
        let mut deps = parse_vcpkg(&manifest, None).unwrap();
        let baseline: HashMap<String, String> = [("zlib", "1.3.1"), ("curl", "8.9.1"), ("openssl", "3.3.2"), ("fmt", "11.0.2")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        vcpkg_apply_baseline(&manifest, &mut deps, &baseline);
        let v = |n: &str| deps.iter().find(|d| d.name == n).unwrap().version.clone();
        assert_eq!(v("zlib"), "1.3.1"); // the baseline's
        assert_eq!(v("curl"), "9.0.0"); // a floor above the baseline wins
        assert_eq!(v("openssl"), "3.3.2"); // a floor below it does not
        assert_eq!(v("fmt"), "9.1.0"); // an override wins, even downward
        assert_eq!(v("nothere"), "baseline"); // not in the baseline: unchanged

        // The official registry through vcpkg-configuration.json; another one
        // has a baseline postmortem cannot read.
        std::fs::write(&manifest, r#"{"dependencies": ["zlib"]}"#).unwrap();
        let conf = dir.join("vcpkg-configuration.json");
        std::fs::write(&conf, r#"{"default-registry": {"kind": "git", "repository": "https://github.com/microsoft/vcpkg", "baseline": "def456"}}"#).unwrap();
        assert_eq!(vcpkg_baseline(&manifest).as_deref(), Some("def456"));
        std::fs::write(&conf, r#"{"default-registry": {"kind": "git", "repository": "https://example.com/corp/registry", "baseline": "x"}}"#).unwrap();
        assert_eq!(vcpkg_baseline(&manifest), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    fn tmp_dir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "postmortem-cpp-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn conan_v1_consumer_with_a_real_ref() {
        let dir = tmp_dir();
        let lock = dir.join("conan.lock");
        std::fs::write(
            &lock,
            r#"{"graph_lock":{"nodes":{
  "0":{"ref":"user-management/1.0.0-dev.1","path":"conanfile.py","requires":["1"]},
  "1":{"ref":"fmt/10.2.1#r1","requires":["2"]},
  "2":{"ref":"zlib/1.3.1#r2"}}},"version":"0.4"}"#,
        )
        .unwrap();
        let deps = parse_conan(Some(&lock), None).unwrap();
        let get = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(deps.len(), 2, "the project is not its own dependency");
        assert!(get("fmt").direct && get("fmt").parents.is_empty());
        assert_eq!(get("zlib").parents, vec![("fmt".to_string(), "10.2.1".to_string())]);
    }

    #[test]
    fn conanfile_py_multiline_attributes() {
        let src = r#"class App(ConanFile):
    requires = [
        "fmt/10.2.1",
        # "commented/1.0",
        "spdlog/1.13.0",
    ]
    test_requires = ("gtest/1.14.0",
                     "catch2/3.5.0")
    python_requires = "pyreq/0.1"
    tool_requires = "cmake/3.28.1"
"#;
        let got: Vec<(String, bool)> = conan_declared(Path::new("conanfile.py"), src)
            .into_iter()
            .map(|(n, (_, build))| (n, build))
            .collect();
        let want = [
            ("catch2", true),
            ("cmake", true),
            ("fmt", false),
            ("gtest", true),
            ("pyreq", true),
            ("spdlog", false),
        ];
        assert_eq!(
            got,
            want.iter().map(|(n, b)| (n.to_string(), *b)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn conan_without_lock_is_sorted() {
        let dir = tmp_dir();
        let txt = dir.join("conanfile.txt");
        std::fs::write(&txt, "[requires]\nzlib/1\nboost/2\nmsgpack/3\nabseil/4\nfmt/5\n").unwrap();
        let names: Vec<String> = parse_conan(None, Some(&txt))
            .unwrap()
            .into_iter()
            .map(|d| d.name)
            .collect();
        assert_eq!(names, ["abseil", "boost", "fmt", "msgpack", "zlib"]);
    }

    #[test]
    fn vcpkg_top_level_wins_and_override_version_variants() {
        let m: VcpkgManifest = serde_json::from_str(
            r#"{"dependencies":[{"name":"openssl","version>=":"3.0.8"},"fmt"],
  "features":{"tls":{"dependencies":["openssl"]}},
  "overrides":[{"name":"fmt","version-semver":"9.1.0"}]}"#,
        )
        .unwrap();
        let got: Vec<(String, String)> = vcpkg_deps(&m, None)
            .unwrap()
            .into_iter()
            .map(|d| (d.name, d.version))
            .collect();
        assert_eq!(
            got,
            vec![
                ("fmt".to_string(), "9.1.0".to_string()),
                ("openssl".to_string(), "3.0.8".to_string())
            ]
        );
    }

    #[test]
    fn conan_ref_shapes() {
        assert_eq!(conan_ref("zlib/1.3.2#1cb8%1777.5"), Some(("zlib", "1.3.2")));
        assert_eq!(
            conan_ref("poco/1.9.4@acme/stable#r"),
            Some(("poco", "1.9.4"))
        );
        assert_eq!(conan_ref("xorg/system"), Some(("xorg", "system")));
        assert_eq!(conan_ref("conanfile"), None);
    }

    #[test]
    fn conan_v2_lock_merges_lists_and_reads_direct_set() {
        let dir = tmp_dir();
        let (lock, py) = (dir.join("conan.lock"), dir.join("conanfile.py"));
        std::fs::write(
            &lock,
            r#"{"version":"0.5",
  "requires":["zlib/1.3.2#a%1","opencv/4.12.0#b%2","tensorflow-lite/2.15.0#c%3","poco/1.9.4@acme/stable#r%5"],
  "build_requires":["zlib/1.3.2#a%1","cmake/3.31.12#d%4"],
  "python_requires":[],"config_requires":[]}"#,
        )
        .unwrap();
        std::fs::write(
            &py,
            "    def requirements(self):\n        self.requires(\"tensorflow-lite/2.15.0\")\n        self.requires(\"opencv/4.12.0\")\n        self.tool_requires(\"cmake/3.31.12\")\n",
        )
        .unwrap();
        let deps = parse_conan(Some(&lock), Some(&py)).unwrap();
        let get = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(deps.len(), 5, "zlib in both lists is one package");
        assert_eq!(get("zlib").resolved_url, None);
        assert_eq!(
            get("poco").resolved_url.as_deref(),
            Some("poco/1.9.4@acme/stable")
        );
        assert_eq!(get("zlib").scope, Scope::Prod, "shipped beats build-only");
        assert_eq!(get("cmake").scope, Scope::Dev);
        assert!(get("opencv").direct && get("cmake").direct && !get("zlib").direct);
    }

    #[test]
    fn conan_v1_graph_and_txt_manifest() {
        let dir = tmp_dir();
        let lock = dir.join("conan.lock");
        std::fs::write(
            &lock,
            r#"{"graph_lock":{"nodes":{
  "0":{"ref":"conanfile","requires":["1"],"build_requires":["3"]},
  "1":{"ref":"libcurl/7.79.0#r1","requires":["2"]},
  "2":{"ref":"openssl/1.1.1k#r2"},
  "3":{"ref":"cmake/3.21.0#r3"}},"revisions_enabled":true},"version":"0.4"}"#,
        )
        .unwrap();
        let deps = parse_conan(Some(&lock), None).unwrap();
        let get = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert!(get("libcurl").direct && get("cmake").direct && !get("openssl").direct);
        assert_eq!(get("cmake").scope, Scope::Dev);
        assert_eq!(
            get("openssl").parents,
            vec![("libcurl".to_string(), "7.79.0".to_string())]
        );

        let txt = dir.join("conanfile.txt");
        std::fs::write(
            &txt,
            "[requires]\nfmt/10.2.1\n# comment\nspdlog/1.13.0\n\n[tool_requires]\nninja/1.11.1\n\n[generators]\nCMakeDeps\n",
        )
        .unwrap();
        let mut deps = parse_conan(None, Some(&txt)).unwrap();
        deps.sort_by(|a, b| a.name.cmp(&b.name));
        let got: Vec<(&str, &str, Scope)> = deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str(), d.scope))
            .collect();
        assert_eq!(
            got,
            vec![
                ("fmt", "10.2.1", Scope::Prod),
                ("ninja", "1.11.1", Scope::Dev),
                ("spdlog", "1.13.0", Scope::Prod),
            ]
        );
    }

    const MANIFEST: &str = r#"{
  "name": "app",
  "dependencies": [
    "fmt",
    { "name": "curl", "features": ["ssl"] },
    { "name": "vcpkg-cmake", "host": true },
    { "name": "zlib", "version>=": "1.3.1" }
  ],
  "features": { "tls": { "description": "", "dependencies": [ "openssl" ] } },
  "overrides": [ { "name": "fmt", "version": "10.1.1" } ],
  "builtin-baseline": "abc",
  "vcpkg-configuration": { "overlay-ports": [ "./ports" ] }
}"#;

    #[test]
    fn vcpkg_status_gives_versions_and_edges() {
        let dir = tmp_dir();
        let (m, status) = (dir.join("vcpkg.json"), dir.join("status"));
        std::fs::write(&m, MANIFEST).unwrap();
        std::fs::write(
            &status,
            "Package: vcpkg-cmake\nVersion: 2024-04-23\nArchitecture: arm64-osx\nMulti-Arch: same\nStatus: install ok installed\n\n\
Package: zlib\nVersion: 1.3.1\nDepends: vcpkg-cmake:arm64-osx\nArchitecture: arm64-osx\nMulti-Arch: same\nStatus: install ok installed\n\n\
Package: curl\nVersion: 8.8.0\nPort-Version: 2\nDepends: vcpkg-cmake:arm64-osx, zlib\nArchitecture: arm64-osx\nMulti-Arch: same\nStatus: install ok installed\n\n\
Package: curl\nFeature: ssl\nDepends: curl[openssl], openssl\nArchitecture: arm64-osx\nMulti-Arch: same\nStatus: install ok installed\n\n\
Package: openssl\nVersion: 3.3.0\nArchitecture: arm64-osx\nMulti-Arch: same\nStatus: install ok installed\n\n\
Package: fmt\nVersion: 10.1.1\nArchitecture: arm64-osx\nMulti-Arch: same\nStatus: install ok installed\n\n\
Package: gone\nVersion: 1.0\nArchitecture: arm64-osx\nMulti-Arch: same\nStatus: purge ok not-installed\n",
        )
        .unwrap();
        let deps = parse_vcpkg(&m, Some(&status)).unwrap();
        let get = |n: &str| deps.iter().find(|d| d.name == n).unwrap();
        assert_eq!(deps.len(), 5, "not-installed is not a dependency");
        assert_eq!(get("curl").version, "8.8.0");
        assert!(get("curl").direct);
        // Declared by the manifest's `tls` feature: direct, whether or not the
        // feature was enabled for this build.
        assert!(get("openssl").direct);
        assert_eq!(
            get("openssl").parents,
            vec![("curl".to_string(), "8.8.0".to_string())],
            "a feature's dependencies are the package's"
        );
        assert_eq!(get("vcpkg-cmake").scope, Scope::Dev);
        assert_eq!(
            get("zlib").parents,
            vec![("curl".to_string(), "8.8.0".to_string())]
        );
    }

    #[test]
    fn vcpkg_manifest_alone_is_flat_and_versioned_where_stated() {
        let dir = tmp_dir();
        let m = dir.join("vcpkg.json");
        std::fs::write(&m, MANIFEST).unwrap();
        std::fs::create_dir_all(dir.join("ports/curl")).unwrap();
        std::fs::write(dir.join("ports/curl/portfile.cmake"), "").unwrap();
        let deps = parse_vcpkg(&m, None).unwrap();
        let curl = deps.iter().find(|d| d.name == "curl").unwrap();
        assert!(
            curl.resolved_url
                .as_deref()
                .is_some_and(|u| u.ends_with("ports/curl"))
        );
        assert!(
            deps.iter()
                .all(|d| d.name == "curl" || d.resolved_url.is_none())
        );
        let got: Vec<(&str, &str)> = deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("curl", "baseline"),
                ("fmt", "10.1.1"),
                ("openssl", "baseline"),
                ("vcpkg-cmake", "baseline"),
                ("zlib", "1.3.1"),
            ]
        );
    }
}
