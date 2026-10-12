//! Perl: Carton's `cpanfile.snapshot`, and `cpanfile`.
//!
//! The snapshot lists every **distribution** (`Moo-2.005005`) with the modules
//! it `provides` and the modules it `requires` — edges, once each required
//! module is mapped back to the distribution providing it. Modules nobody
//! provides there (core modules, `perl` itself) have no node.
//!
//! The `cpanfile` names *modules* (`requires 'Moo', '2.0';`): mapped through
//! the snapshot's `provides`, they are the direct set. Phases `test`,
//! `develop`, `build`, `configure` (and `test_requires`, ...) are development.
//! Without a snapshot the cpanfile alone is the declared set, flat, named by
//! module.

use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

use crate::model::{Dependency, Ecosystem, LicenseSource, Scope};

fn requires_re() -> &'static Regex {
    // requires 'Moo', '2.0';  test_requires "X";  requires 'Y' => '1';
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"(?m)^\s*(requires|test_requires|author_requires|build_requires|configure_requires)\s*\(?\s*['"]([\w:]+)['"]\s*(?:(?:,|=>)\s*['"]?([^'";\s)]+)['"]?)?"#,
        )
        .unwrap()
    })
}

/// `cpanfile` modules: module -> (minimum version, development only).
fn cpanfile_modules(src: &str) -> HashMap<String, (Option<String>, bool)> {
    let mut out: HashMap<String, (Option<String>, bool)> = HashMap::new();
    // `on 'test' => sub { ... };` blocks: track the open phase by braces.
    let phase_re = Regex::new(r#"^\s*on\s*\(?\s*['"]?(\w+)['"]?\s*=>\s*sub\s*\{"#).unwrap();
    let mut phase: Option<String> = None;
    let mut depth = 0i32;
    for line in src.lines() {
        let code = line.split('#').next().unwrap_or("");
        if let Some(c) = phase_re.captures(code) {
            phase = Some(c[1].to_string());
            depth = 0;
        }
        if let Some(c) = requires_re().captures(code) {
            let dev = &c[1] != "requires" || phase.as_deref().is_some_and(|p| p != "runtime");
            let e = out
                .entry(c[2].to_string())
                .or_insert((c.get(3).map(|v| v.as_str().to_string()), dev));
            e.1 &= dev;
        }
        if phase.is_some() {
            depth += code.matches('{').count() as i32 - code.matches('}').count() as i32;
            if depth <= 0 && code.contains('}') {
                phase = None;
            }
        }
    }
    out
}

/// `Moo-2.005005` -> (`Moo`, `2.005005`); the version is after the last `-`.
fn split_dist(id: &str) -> Option<(&str, &str)> {
    let (name, version) = id.rsplit_once('-')?;
    let v = version.trim_start_matches('v');
    v.chars()
        .next()?
        .is_ascii_digit()
        .then_some((name, version))
}

struct Dist {
    name: String,
    version: String,
    provides: Vec<String>,
    requires: Vec<String>,
}

fn snapshot(src: &str) -> Vec<Dist> {
    let mut out: Vec<Dist> = Vec::new();
    let mut section = "";
    for line in src.lines() {
        let indent = line.len() - line.trim_start().len();
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') || indent == 0 {
            continue;
        }
        match indent {
            2 => {
                if let Some((n, v)) = split_dist(t) {
                    out.push(Dist {
                        name: n.to_string(),
                        version: v.to_string(),
                        provides: Vec::new(),
                        requires: Vec::new(),
                    });
                }
                section = "";
            }
            4 => section = t.trim_end_matches(':'),
            _ => {
                let Some(d) = out.last_mut() else { continue };
                let module = t.split_whitespace().next().unwrap_or("").to_string();
                match section {
                    "provides" => d.provides.push(module),
                    "requirements" => d.requires.push(module),
                    _ => {}
                }
            }
        }
    }
    out
}

pub fn parse(manifest: Option<&Path>, lockfile: Option<&Path>) -> Result<Vec<Dependency>> {
    let modules = match manifest {
        Some(m) => cpanfile_modules(
            &std::fs::read_to_string(m).with_context(|| format!("reading {}", m.display()))?,
        ),
        None => HashMap::new(),
    };
    let dep = |name: &str, version: &str, direct: bool, dev: bool| Dependency {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem: Ecosystem::Perl,
        direct,
        scope: if dev { Scope::Dev } else { Scope::Prod },
        licenses: Vec::new(),
        license_source: LicenseSource::Unknown,
        resolved_url: None,
        integrity: None,
        parents: Vec::new(),
    };

    let Some(lock) = lockfile else {
        let mut names: Vec<_> = modules.iter().collect();
        names.sort();
        return Ok(names
            .into_iter()
            .map(|(m, (v, dev))| dep(m, v.as_deref().unwrap_or("managed"), true, *dev))
            .collect());
    };

    let text =
        std::fs::read_to_string(lock).with_context(|| format!("reading {}", lock.display()))?;
    let dists = snapshot(&text);
    let provider: HashMap<&str, usize> = dists
        .iter()
        .enumerate()
        .flat_map(|(i, d)| d.provides.iter().map(move |m| (m.as_str(), i)))
        .collect();
    // A distribution is direct when the cpanfile names one of its modules.
    let mut decl: HashMap<usize, bool> = HashMap::new();
    for (module, (_, dev)) in &modules {
        if let Some(&i) = provider.get(module.as_str()) {
            let e = decl.entry(i).or_insert(*dev);
            *e &= *dev;
        }
    }
    let mut out: Vec<Dependency> = dists
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let dev = decl.get(&i);
            dep(
                &d.name,
                &d.version,
                dev.is_some(),
                dev.copied().unwrap_or(false),
            )
        })
        .collect();
    for (i, d) in dists.iter().enumerate() {
        let mut seen = Vec::new();
        for module in &d.requires {
            let Some(&ci) = provider.get(module.as_str()) else {
                continue;
            };
            if ci != i && !seen.contains(&ci) {
                seen.push(ci);
                out[ci].parents.push((d.name.clone(), d.version.clone()));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_edges_and_cpanfile_phases() {
        let dir = std::env::temp_dir().join(format!("postmortem-perl-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cpanfile, snap) = (dir.join("cpanfile"), dir.join("cpanfile.snapshot"));
        std::fs::write(
            &cpanfile,
            "use strict;\nrequires 'Catalyst', '5.90103';\nrequires 'Moo' => '2.0';\n\non test => sub {\n    requires 'Test::More', '0.96';\n};\n\non 'develop' => sub {\n    requires 'Perl::Tidy' => '20250311';\n};\ntest_requires 'Test::Deep';\n",
        )
        .unwrap();
        std::fs::write(
            &snap,
            "# carton snapshot format: version 1.0\nDISTRIBUTIONS\n  Catalyst-Runtime-5.90132\n    pathname: J/JJ/JJNAPIORK/Catalyst-Runtime-5.90132.tar.gz\n    provides:\n      Catalyst 5.90132\n      Catalyst::Action 5.90132\n    requirements:\n      Moo 2.0\n      ExtUtils::MakeMaker 0\n      perl 5.008003\n  Moo-2.005005\n    pathname: H/HA/HAARG/Moo-2.005005.tar.gz\n    provides:\n      Moo 2.005005\n    requirements:\n      perl 5.006\n  Test-Simple-1.302198\n    pathname: E/EX/EXODIST/Test-Simple-1.302198.tar.gz\n    provides:\n      Test::More 1.302198\n    requirements:\n  Perl-Tidy-20250311\n    pathname: S/SH/SHANCOCK/Perl-Tidy-20250311.tar.gz\n    provides:\n      Perl::Tidy 20250311\n",
        )
        .unwrap();
        let deps = parse(Some(&cpanfile), Some(&snap)).unwrap();
        let got: Vec<(&str, &str, bool, Scope)> = deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str(), d.direct, d.scope))
            .collect();
        assert_eq!(
            got,
            vec![
                ("Catalyst-Runtime", "5.90132", true, Scope::Prod),
                ("Moo", "2.005005", true, Scope::Prod),
                ("Test-Simple", "1.302198", true, Scope::Dev),
                ("Perl-Tidy", "20250311", true, Scope::Dev),
            ]
        );
        assert_eq!(
            deps[1].parents,
            vec![("Catalyst-Runtime".to_string(), "5.90132".to_string())]
        );

        let alone = parse(Some(&cpanfile), None).unwrap();
        let names: Vec<(&str, &str, Scope)> = alone
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str(), d.scope))
            .collect();
        assert_eq!(
            names,
            vec![
                ("Catalyst", "5.90103", Scope::Prod),
                ("Moo", "2.0", Scope::Prod),
                ("Perl::Tidy", "20250311", Scope::Dev),
                ("Test::Deep", "managed", Scope::Dev),
                ("Test::More", "0.96", Scope::Dev),
            ]
        );
    }
}
