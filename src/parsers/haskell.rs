//! Haskell: Cabal and Stack.
//!
//! * `cabal.project.freeze` — `constraints: any.aeson ==2.2.3.0, ...`: every
//!   package of the build plan, pinned. Flat (no edges).
//! * `stack.yaml.lock` — Stack locks only the `extra-deps` and the snapshot
//!   (`lts-24.48`) by name: every other package's version is the snapshot's,
//!   which is not resolved offline (`managed`).
//! * The direct set (and the test/benchmark split) comes from the package's
//!   `*.cabal` `build-depends`, or hpack's `package.yaml`.

use anyhow::{Context, Result};
use regex::Regex;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::OnceLock;

use crate::model::{Dependency, Ecosystem, LicenseSource, Scope};

fn freeze_re() -> &'static Regex {
    // `any.aeson ==2.2.3.0` (also an unqualified `aeson ==2.2.3.0`).
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?:any\.)?([A-Za-z][A-Za-z0-9-]*)\s*==\s*([0-9][0-9.]*)").unwrap()
    })
}

/// `aeson-jsonpath-0.4.2.0@sha256:...` -> (`aeson-jsonpath`, `0.4.2.0`).
fn split_pkgid(id: &str) -> Option<(&str, &str)> {
    let id = id.split('@').next()?;
    let (name, version) = id.rsplit_once('-')?;
    version
        .chars()
        .next()?
        .is_ascii_digit()
        .then_some((name, version))
}

/// Declared dependencies: name -> test/benchmark only.
pub fn declared(manifest: &Path) -> HashMap<String, bool> {
    let Ok(src) = std::fs::read_to_string(manifest) else {
        return HashMap::new();
    };
    let mut out: HashMap<String, bool> = HashMap::new();
    let mut add = |name: &str, dev: bool| {
        let e = out.entry(name.to_string()).or_insert(dev);
        *e &= dev; // shipped by any stanza: shipped
    };
    if manifest.extension().and_then(|e| e.to_str()) == Some("yaml") {
        let Ok(v) = serde_yaml::from_str::<serde_yaml::Value>(&src) else {
            return out;
        };
        let names = |deps: Option<&serde_yaml::Value>| -> Vec<String> {
            match deps {
                Some(serde_yaml::Value::Sequence(s)) => s
                    .iter()
                    .filter_map(|d| d.as_str())
                    .filter_map(|d| d.split_whitespace().next())
                    .map(String::from)
                    .collect(),
                Some(serde_yaml::Value::Mapping(m)) => m
                    .keys()
                    .filter_map(|k| k.as_str())
                    .map(String::from)
                    .collect(),
                Some(serde_yaml::Value::String(d)) => d
                    .split(',')
                    .filter_map(|x| x.split_whitespace().next())
                    .map(String::from)
                    .collect(),
                _ => Vec::new(),
            }
        };
        for n in names(v.get("dependencies")) {
            add(&n, false);
        }
        if let Some(lib) = v.get("library") {
            for n in names(lib.get("dependencies")) {
                add(&n, false);
            }
        }
        for (section, dev) in [
            ("executables", false),
            ("tests", true),
            ("benchmarks", true),
        ] {
            if let Some(serde_yaml::Value::Mapping(m)) = v.get(section) {
                for comp in m.values() {
                    for n in names(comp.get("dependencies")) {
                        add(&n, dev);
                    }
                }
            }
        }
        // An executable or test depending on the package's own library.
        if let Some(own) = v.get("name").and_then(|n| n.as_str()) {
            out.remove(own);
        }
        return out;
    }

    // .cabal: stanzas start at column 0; `build-depends:` may continue on
    // more-indented lines.
    let mut dev = false;
    // Indent of the open `build-depends:` line, if any.
    let mut in_deps: Option<usize> = None;
    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("--") {
            continue;
        }
        if !line.starts_with([' ', '\t']) {
            let head = trimmed.to_lowercase();
            dev = head.starts_with("test-suite") || head.starts_with("benchmark");
            in_deps = None;
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let lower = trimmed.to_lowercase();
        let rest = match lower.strip_prefix("build-depends:") {
            Some(_) => {
                in_deps = Some(indent);
                &trimmed["build-depends:".len()..]
            }
            // A continuation is indented deeper; `if os(...)` / `else` is not one.
            None if in_deps.is_some_and(|d| indent > d)
                && !lower.starts_with("if ")
                && lower != "else" =>
            {
                trimmed
            }
            None => {
                in_deps = None;
                continue;
            }
        };
        for item in rest.split(',') {
            let item = item.trim().trim_start_matches(['(', '{']);
            let name: String = item
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect();
            // `foo:sublib` and internal libraries still name a package.
            if !name.is_empty() && name.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
                add(&name, dev);
            }
        }
    }
    out
}

pub fn parse(manifest: Option<&Path>, lockfile: Option<&Path>) -> Result<Vec<Dependency>> {
    let mut declared = manifest.map(declared).unwrap_or_default();
    // The package itself is not its own dependency.
    if let Some(own) = manifest
        .and_then(|m| m.file_stem())
        .and_then(|s| s.to_str())
    {
        declared.remove(own);
    }

    // name -> (version, source URL of a git / url / archive entry).
    let mut pinned: BTreeMap<String, (String, Option<String>)> = BTreeMap::new();
    if let Some(lock) = lockfile {
        let text =
            std::fs::read_to_string(lock).with_context(|| format!("reading {}", lock.display()))?;
        if lock.file_name().is_some_and(|n| n == "stack.yaml.lock") {
            let v: serde_yaml::Value = serde_yaml::from_str(&text)
                .with_context(|| format!("parsing {} as stack.yaml.lock", lock.display()))?;
            for p in v
                .get("packages")
                .and_then(|p| p.as_sequence())
                .into_iter()
                .flatten()
            {
                let Some(c) = p.get("completed") else {
                    continue;
                };
                let field = |k: &str| c.get(k).and_then(|h| h.as_str());
                if let Some((n, ver)) = field("hackage").and_then(split_pkgid) {
                    pinned.insert(n.to_string(), (ver.to_string(), None));
                } else if let Some(n) = field("name") {
                    // A git / url / archive source: not from Hackage.
                    let ver = field("version")
                        .or_else(|| field("commit").map(|c| c.get(..12).unwrap_or(c)))
                        .unwrap_or("unknown");
                    let url = field("git").or_else(|| field("url")).map(String::from);
                    pinned.insert(n.to_string(), (ver.to_string(), url));
                }
            }
        } else {
            for c in freeze_re().captures_iter(&text) {
                pinned.insert(c[1].to_string(), (c[2].to_string(), None));
            }
        }
    }

    let dep = |name: &str, version: &str, direct: bool, dev: bool| Dependency {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem: Ecosystem::Haskell,
        direct,
        scope: if dev { Scope::Dev } else { Scope::Prod },
        licenses: Vec::new(),
        license_source: LicenseSource::Unknown,
        resolved_url: None,
        integrity: None,
        parents: Vec::new(),
    };
    let mut out: Vec<Dependency> = pinned
        .iter()
        .map(|(n, (v, url))| {
            let decl = declared.get(n);
            Dependency {
                resolved_url: url.clone(),
                ..dep(n, v, decl.is_some(), decl.copied().unwrap_or(false))
            }
        })
        .collect();
    // Declared but not pinned (a Stack snapshot package): the version is the
    // snapshot's.
    let mut rest: Vec<(&String, &bool)> = declared
        .iter()
        .filter(|(n, _)| !pinned.contains_key(*n))
        .collect();
    rest.sort();
    out.extend(
        rest.into_iter()
            .map(|(n, dev)| dep(n, "managed", true, *dev)),
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "postmortem-hs-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const CABAL: &str = "cabal-version: 3.0\nname: app\nversion: 1.0\n\nlibrary\n  exposed-modules: App\n  build-depends:  base >=4 && <5\n               , aeson ^>=2.2\n               , text\n  default-language: Haskell2010\n\nexecutable app\n  main-is: Main.hs\n  build-depends: base, app\n\ntest-suite spec\n  type: exitcode-stdio-1.0\n  build-depends: base, app, hspec ==2.*, aeson\n";

    #[test]
    fn freeze_with_cabal_direct_set() {
        let dir = tmp_dir();
        let (freeze, cabal) = (dir.join("cabal.project.freeze"), dir.join("app.cabal"));
        std::fs::write(
            &freeze,
            "active-repositories: hackage.haskell.org:merge\nconstraints: any.aeson ==2.2.3.0,\n             any.base ==4.18.0.0,\n             any.hspec ==2.11.7,\n             any.text ==2.0.2,\n             any.vector ==0.13.1.0,\n             aeson +ordered-keymap\nindex-state: hackage.haskell.org 2026-06-01T12:22:50Z\n",
        )
        .unwrap();
        std::fs::write(&cabal, CABAL).unwrap();
        let deps = parse(Some(&cabal), Some(&freeze)).unwrap();
        let got: Vec<(&str, &str, bool, Scope)> = deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str(), d.direct, d.scope))
            .collect();
        assert_eq!(
            got,
            vec![
                ("aeson", "2.2.3.0", true, Scope::Prod),
                ("base", "4.18.0.0", true, Scope::Prod),
                ("hspec", "2.11.7", true, Scope::Dev),
                ("text", "2.0.2", true, Scope::Prod),
                ("vector", "0.13.1.0", false, Scope::Prod),
            ]
        );
    }

    #[test]
    fn stack_lock_pins_extra_deps_only() {
        let dir = tmp_dir();
        let (lock, yaml) = (dir.join("stack.yaml.lock"), dir.join("package.yaml"));
        std::fs::write(
            &lock,
            "packages:\n- completed:\n    hackage: fuzzyset-0.2.4@sha256:f1b6,1618\n    pantry-tree:\n      sha256: cee6\n      size: 574\n  original:\n    hackage: fuzzyset-0.2.4\nsnapshots:\n- completed:\n    sha256: abc\n    size: 1\n    url: https://example/lts-24.48.yaml\n  original: lts-24.48\n",
        )
        .unwrap();
        std::fs::write(
            &yaml,
            "name: app\ndependencies:\n- base >= 4.7 && < 5\n- fuzzyset\nlibrary:\n  dependencies: [aeson]\ntests:\n  spec:\n    dependencies: [hspec, app]\n",
        )
        .unwrap();
        let deps = parse(Some(&yaml), Some(&lock)).unwrap();
        let got: Vec<(&str, &str, Scope)> = deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str(), d.scope))
            .collect();
        assert_eq!(
            got,
            vec![
                ("fuzzyset", "0.2.4", Scope::Prod),
                ("aeson", "managed", Scope::Prod),
                ("base", "managed", Scope::Prod),
                ("hspec", "managed", Scope::Dev),
            ]
        );
    }

    #[test]
    fn stack_lock_keeps_git_and_url_sources() {
        let dir = tmp_dir();
        let lock = dir.join("stack.yaml.lock");
        std::fs::write(
            &lock,
            "packages:\n- completed:\n    commit: 7a8cf00\n    git: https://github.com/evil/bar\n    name: bar\n    version: 0.1.0\n  original:\n    git: https://github.com/evil/bar\n- completed:\n    name: baz\n    url: https://example/baz.tar.gz\n    subdir: baz\n  original:\n    url: https://example/baz.tar.gz\n",
        )
        .unwrap();
        let deps = parse(None, Some(&lock)).unwrap();
        let got: Vec<(&str, &str, Option<&str>)> = deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str(), d.resolved_url.as_deref()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("bar", "0.1.0", Some("https://github.com/evil/bar")),
                ("baz", "unknown", Some("https://example/baz.tar.gz")),
            ]
        );
    }

    #[test]
    fn cabal_conditionals_and_sublibs() {
        let dir = tmp_dir();
        let cabal = dir.join("app.cabal");
        std::fs::write(
            &cabal,
            "name: app\n\nlibrary\n  build-depends:\n      base >=4 && <5\n    , mylib:sublib\n    , text\n  if os(windows)\n    build-depends: Win32\n  else\n    build-depends: unix\n  default-language: Haskell2010\n",
        )
        .unwrap();
        let mut names: Vec<String> = declared(&cabal).into_keys().collect();
        names.sort();
        assert_eq!(names, ["Win32", "base", "mylib", "text", "unix"]);
    }
}
