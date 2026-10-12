//! Scala / sbt: `build.sbt` plus the build definition in `project/*.scala`.
//!
//! sbt has no standard lockfile, so — like a Maven `pom.xml` — this is the
//! **declared** set, flat. A dependency is the expression
//! `org %% artifact % version [% config]`, where each part is a string literal
//! or a `val` naming one:
//!
//! * `%%` appends the Scala binary version (`cats-core` -> `cats-core_2.13`,
//!   `_3` for Scala 3), from `scalaVersion`; sbt 1's default 2.12 when unset.
//! * an identifier resolves to the nearest `val` **above** it in the same file
//!   — which is how `object chess: val version = ...` blocks read in practice.
//!   An unresolvable version is `managed`; an unresolvable org/artifact (an
//!   interpolated `s"..."`) drops the expression rather than guess a name.
//! * `% Test` / `% "test"` is development; `% "provided"` still runs in
//!   production, as in Maven.
//!
//! Identity is the Maven coordinate `group:artifact`, reported as `java`.

use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

use crate::model::{Dependency, Ecosystem, LicenseSource, Scope};

/// One term of a dependency expression: a string literal, or an identifier.
const TERM: &str = r#"(?:s?"[^"\n]*"|[A-Za-z_][\w.]*)"#;

fn dep_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(&format!(
            r"({TERM})\s*(%%%|%%|%)\s*({TERM})\s*%\s*({TERM})(?:\s*%\s*({TERM}))?"
        ))
        .unwrap()
    })
}

fn val_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // Group 3 marks a literal that opens a dependency expression
        // (`val cats = "org.typelevel" %% ...`): that val is not a string.
        Regex::new(
            r#"(?:^|[\s;{(])(?:lazy\s+)?val\s+([A-Za-z_]\w*)\s*(?::\s*String\s*)?=\s*"([^"\n]*)"(\s*%)?"#,
        )
        .unwrap()
    })
}

fn scala_version_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(&format!(r"scalaVersion\s*:=\s*({TERM})")).unwrap())
}

/// The build files of the project whose root holds `build_sbt`.
fn build_files(build_sbt: &Path) -> Vec<(std::path::PathBuf, String)> {
    let mut paths = vec![build_sbt.to_path_buf()];
    if let Some(dir) = build_sbt.parent().map(|d| d.join("project"))
        && let Ok(rd) = std::fs::read_dir(dir)
    {
        let mut scala: Vec<_> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("scala"))
            .collect();
        scala.sort();
        paths.extend(scala);
    }
    paths
        .into_iter()
        .filter_map(|p| {
            std::fs::read_to_string(&p)
                .ok()
                .map(|s| (p, strip_comments(&s)))
        })
        .collect()
}

/// `src` with `//` and `/* */` comments blanked out — offsets kept, string
/// literals (a URL's `//`) left alone. A commented-out `val org = ...` must not
/// resolve anything.
fn strip_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let (mut i, mut in_str) = (0, false);
    while i < b.len() {
        match (b[i], b.get(i + 1)) {
            (b'"', _) => in_str = !in_str,
            (b'\\', _) if in_str => i += 1,
            (b'/', Some(b'/')) if !in_str => {
                while i < b.len() && b[i] != b'\n' {
                    out[i] = b' ';
                    i += 1;
                }
                continue;
            }
            (b'/', Some(b'*')) if !in_str => {
                while i < b.len() && !(b[i] == b'*' && b.get(i + 1) == Some(&b'/')) {
                    if b[i] != b'\n' {
                        out[i] = b' ';
                    }
                    i += 1;
                }
                // The closing `*/`.
                for c in out.iter_mut().skip(i).take(2) {
                    *c = b' ';
                }
                i += 2;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

/// The string a term stands for at byte `at` of `src`: a literal, or the
/// nearest `val` above. An interpolated literal stands for nothing knowable.
fn resolve(term: &str, src: &str, at: usize, all_vals: &HashMap<String, String>) -> Option<String> {
    if let Some(lit) = term.strip_prefix('"') {
        return Some(lit.trim_end_matches('"').to_string());
    }
    if term.starts_with("s\"") {
        return None;
    }
    // `V.cats` / `Versions.cats` -> `cats`.
    let name = term.rsplit('.').next().unwrap_or(term);
    val_re()
        .captures_iter(&src[..at])
        .filter(|c| &c[1] == name && c.get(3).is_none())
        .last()
        .map(|c| c[2].to_string())
        .or_else(|| all_vals.get(name).cloned())
}

/// `3.3.1` -> `3`, `2.13.12` -> `2.13`.
fn binary_version(v: &str) -> String {
    if v.starts_with("3.") || v == "3" {
        return "3".to_string();
    }
    v.split('.').take(2).collect::<Vec<_>>().join(".")
}

pub fn parse(build_sbt: &Path) -> Result<Vec<Dependency>> {
    std::fs::metadata(build_sbt).with_context(|| format!("reading {}", build_sbt.display()))?;
    let files = build_files(build_sbt);

    // Every `val` of every build file, for references across files (a version
    // object in project/, used from build.sbt). A same-file definition above
    // the use wins.
    let mut all_vals: HashMap<String, String> = HashMap::new();
    for (_, src) in &files {
        for c in val_re().captures_iter(src).filter(|c| c.get(3).is_none()) {
            all_vals
                .entry(c[1].to_string())
                .or_insert_with(|| c[2].to_string());
        }
    }
    let scala = files
        .iter()
        .find_map(|(_, src)| {
            let c = scala_version_re().captures(src)?;
            resolve(&c[1], src, c.get(0)?.start(), &all_vals)
        })
        .unwrap_or_else(|| "2.12".to_string());
    let suffix = format!("_{}", binary_version(&scala));

    let mut out: Vec<Dependency> = Vec::new();
    for (_, src) in &files {
        for c in dep_re().captures_iter(src) {
            let at = c.get(0).map_or(0, |m| m.start());
            let (Some(group), Some(mut artifact)) = (
                resolve(&c[1], src, at, &all_vals),
                resolve(&c[3], src, at, &all_vals),
            ) else {
                continue;
            };
            if group.is_empty() || artifact.is_empty() || group.contains(' ') {
                continue;
            }
            // ponytail: `%%%` (Scala.js / Native) is read as the JVM `%%`; the
            // platform suffix (`_sjs1`) needs the project's platform.
            if &c[2] != "%" {
                artifact.push_str(&suffix);
            }
            let version =
                resolve(&c[4], src, at, &all_vals).unwrap_or_else(|| "managed".to_string());
            // `Test` (an sbt config object) or a `"test"` / `"it,test"` string.
            let config = c.get(5).map_or("", |m| m.as_str()).to_lowercase();
            let scope = if config.contains("test") && !config.contains("compile") {
                Scope::Dev
            } else {
                Scope::Prod
            };
            let name = format!("{group}:{artifact}");
            if out.iter().any(|d| d.name == name && d.version == version) {
                continue;
            }
            out.push(Dependency {
                name,
                version,
                ecosystem: Ecosystem::Java,
                direct: true,
                scope,
                licenses: Vec::new(),
                license_source: LicenseSource::Unknown,
                resolved_url: None,
                integrity: None,
                parents: Vec::new(),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_val_scoped_and_cross_file_terms() {
        let dir = std::env::temp_dir().join(format!("postmortem-sbt-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("project")).unwrap();
        std::fs::write(
            dir.join("project/Dependencies.scala"),
            r#"object Dependencies {
  val cats = "org.typelevel" %% "cats-core" % "2.13.0"
  val munit = "org.scalameta" %% "munit" % "1.3.6" % Test
  object chess:
    val version = "18.0.0"
    val org = "com.github.lichess-org.scalachess"
    // val org = "org.lichess" // for publishLocal
    /* val version = "0.0.1" */
    val docs = "https://example.org/a//b"
    val core = org %% "scalachess" % version
  object kamon:
    val version = "2.8.1"
    val core = "io.kamon" %% "kamon-core" % version
  val flex = "com.vladsch.flexmark" % s"flexmark-$ext" % "0.64.8"
  val macros = "com.softwaremill.macwire" %% "macros" % "2.6.7" % "provided"
  val play = liplay %% "play" % playVersion
  val v = cats
}
"#,
        )
        .unwrap();
        let build = dir.join("build.sbt");
        std::fs::write(
            &build,
            r#"val V = new { val circe = "0.14.6" }
scalaVersion := "3.7.1"
libraryDependencies ++= Seq(
  "io.circe" %% "circe-core" % V.circe,
  "com.google.guava" % "guava" % "33.0.0-jre"
)
"#,
        )
        .unwrap();
        let deps = parse(&build).unwrap();
        let got: Vec<(&str, &str, Scope)> = deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str(), d.scope))
            .collect();
        assert_eq!(
            got,
            vec![
                ("io.circe:circe-core_3", "0.14.6", Scope::Prod),
                ("com.google.guava:guava", "33.0.0-jre", Scope::Prod),
                ("org.typelevel:cats-core_3", "2.13.0", Scope::Prod),
                ("org.scalameta:munit_3", "1.3.6", Scope::Dev),
                (
                    "com.github.lichess-org.scalachess:scalachess_3",
                    "18.0.0",
                    Scope::Prod
                ),
                ("io.kamon:kamon-core_3", "2.8.1", Scope::Prod),
                ("com.softwaremill.macwire:macros_3", "2.6.7", Scope::Prod),
            ],
            "interpolated names and unknown orgs are dropped, not guessed"
        );
        assert_eq!(binary_version("2.13.12"), "2.13");
    }
}
