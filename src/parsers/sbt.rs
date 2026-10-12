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
use std::collections::{HashMap, HashSet};
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
    // `scalaVersion := ...`, `ThisBuild / scalaVersion := ...`,
    // `scalaVersion in ThisBuild := ...`.
    R.get_or_init(|| {
        Regex::new(&format!(r"scalaVersion\s*(?:in\s+\w+\s*)?:=\s*({TERM})")).unwrap()
    })
}

fn cross_versions_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(&format!(
            r"crossScalaVersions\s*(?:in\s+\w+\s*)?:=\s*(?:Seq|List)\(\s*({TERM})"
        ))
        .unwrap()
    })
}

/// The first element of `val name = Seq(...)` — for `scalaVersion := name.head`.
fn seq_head(name: &str, src: &str) -> Option<(String, usize)> {
    let re = Regex::new(&format!(
        r"val\s+{}\s*(?::[^=\n]*)?=\s*(?:Seq|List)\(\s*({TERM})",
        regex::escape(name)
    ))
    .ok()?;
    let c = re.captures(src)?;
    Some((c[1].to_string(), c.get(0)?.end()))
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
            // A char literal — `'"'`, `'x'`, `'\n'`, `'\u0041'` — opens no string.
            (b'\'', Some(b'\\')) if !in_str => {
                let rest = b.get(i + 3..).unwrap_or_default();
                if let Some(n) = rest.iter().take(5).position(|&c| c == b'\'') {
                    i += n + 4;
                    continue;
                }
            }
            (b'\'', Some(_)) if !in_str && b.get(i + 2) == Some(&b'\'') => {
                i += 3;
                continue;
            }
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

/// A file's string `val`s: name -> (end offset, value), in file order.
type FileVals<'a> = HashMap<&'a str, Vec<(usize, &'a str)>>;

fn file_vals(src: &str) -> FileVals<'_> {
    let mut out: FileVals = HashMap::new();
    for c in val_re().captures_iter(src).filter(|c| c.get(3).is_none()) {
        let (name, value) = (c.get(1).unwrap(), c.get(2).unwrap());
        out.entry(name.as_str())
            .or_default()
            .push((c.get(0).unwrap().end(), value.as_str()));
    }
    out
}

/// The string a term stands for at byte `at` of a file: a literal, or the
/// nearest `val` above. An interpolated literal stands for nothing knowable.
fn resolve(
    term: &str,
    vals: &FileVals,
    at: usize,
    all_vals: &HashMap<String, String>,
) -> Option<String> {
    if let Some(lit) = term.strip_prefix('"') {
        return Some(lit.trim_end_matches('"').to_string());
    }
    if term.starts_with("s\"") {
        return None;
    }
    // `V.cats` / `Versions.cats` -> `cats`.
    let name = term.rsplit('.').next().unwrap_or(term);
    vals.get(name)
        .and_then(|defs| {
            let above = defs.partition_point(|&(end, _)| end <= at);
            above.checked_sub(1).map(|i| defs[i].1.to_string())
        })
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
    let vals: Vec<FileVals> = files.iter().map(|(_, src)| file_vals(src)).collect();
    // `scalaVersion` (a literal, a val, or `someSeq.head`), else the first of
    // `crossScalaVersions`. ponytail: unresolvable falls back to 2.12 silently —
    // the parser has no diagnostics channel.
    let scala = files
        .iter()
        .zip(&vals)
        .find_map(|((_, src), fv)| {
            let c = scala_version_re().captures(src)?;
            let at = c.get(0)?.start();
            match c[1].strip_suffix(".head") {
                Some(seq) => {
                    let (term, at) = seq_head(seq.rsplit('.').next()?, src)?;
                    resolve(&term, fv, at, &all_vals)
                }
                None => resolve(&c[1], fv, at, &all_vals),
            }
        })
        .or_else(|| {
            files.iter().zip(&vals).find_map(|((_, src), fv)| {
                let c = cross_versions_re().captures(src)?;
                resolve(&c[1], fv, c.get(0)?.start(), &all_vals)
            })
        })
        .unwrap_or_else(|| "2.12".to_string());
    let suffix = format!("_{}", binary_version(&scala));

    let mut out: Vec<Dependency> = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    for ((_, src), fv) in files.iter().zip(&vals) {
        for c in dep_re().captures_iter(src) {
            let at = c.get(0).map_or(0, |m| m.start());
            let (Some(group), Some(mut artifact)) = (
                resolve(&c[1], fv, at, &all_vals),
                resolve(&c[3], fv, at, &all_vals),
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
                resolve(&c[4], fv, at, &all_vals).unwrap_or_else(|| "managed".to_string());
            // `Test` (an sbt config object) or a `"test"` / `"it,test"` string.
            let config = c.get(5).map_or("", |m| m.as_str()).to_lowercase();
            let scope = if config.contains("test") && !config.contains("compile") {
                Scope::Dev
            } else {
                Scope::Prod
            };
            let name = format!("{group}:{artifact}");
            if !seen.insert((name.clone(), version.clone())) {
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

    /// The dependency names `build_sbt` (alone in its directory) declares.
    fn names(build_sbt: &str) -> Vec<String> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "postmortem-sbt-src-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("build.sbt");
        std::fs::write(&p, build_sbt).unwrap();
        parse(&p).unwrap().into_iter().map(|d| d.name).collect()
    }

    #[test]
    fn scala_version_forms() {
        let cats = "\nlibraryDependencies += \"org.typelevel\" %% \"cats-core\" % \"2.9.0\"\n";
        for (build, want) in [
            ("scalaVersion in ThisBuild := \"2.13.8\"", "_2.13"),
            ("ThisBuild / scalaVersion := \"3.3.1\"", "_3"),
            ("val scala213 = \"2.13.12\"\nscalaVersion := scala213", "_2.13"),
            ("val versions = Seq(\"2.13.12\", \"2.12.18\")\nscalaVersion := versions.head", "_2.13"),
            ("crossScalaVersions := Seq(\"2.13.12\", \"2.12.18\")", "_2.13"),
            ("name := \"x\"", "_2.12"),
        ] {
            assert_eq!(
                names(&format!("{build}{cats}")),
                vec![format!("org.typelevel:cats-core{want}")],
                "{build}"
            );
        }
    }

    #[test]
    fn char_literal_quote_opens_no_string() {
        let got = names(
            "val sep = '\"'\nval esc = '\\''\nval org = \"good\"\n// val org = \"bad\"\nlibraryDependencies += org % \"a\" % \"1\"\n",
        );
        assert_eq!(got, vec!["good:a"]);
    }

    #[test]
    fn thousands_of_val_deps_parse() {
        let n = 3000;
        let mut build = String::from("scalaVersion := \"2.13.12\"\n");
        for i in 0..n {
            build.push_str(&format!("val v{i} = \"1.{i}\"\n"));
        }
        build.push_str("libraryDependencies ++= Seq(\n");
        for i in 0..n {
            build.push_str(&format!("  \"org.x{i}\" %% \"lib{i}\" % v{i},\n"));
        }
        build.push_str(")\n");
        let got = names(&build);
        assert_eq!(got.len(), n);
        assert_eq!(got[n - 1], format!("org.x{}:lib{}_2.13", n - 1, n - 1));
    }

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
