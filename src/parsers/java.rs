//! JVM parsers: Maven `pom.xml` and Gradle `gradle.lockfile`.
//!
//! These two build systems expose very different things:
//!
//! * `pom.xml` is a *manifest*: it lists direct dependencies only (transitive
//!   resolution needs the Maven resolver, which we don't run). Versions may be
//!   inherited from a parent/BOM, so some are absent ("managed").
//! * `gradle.lockfile` is a *lockfile*: the full flat resolved set with exact
//!   versions, but no direct/transitive split and no parent edges. When a
//!   `build.gradle` is present we recover the direct set from it, best-effort.
//!
//! Dependency identity on the JVM is `groupId:artifactId`.

use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

use crate::model::{Dependency, Ecosystem};

pub fn parse(manifest: Option<&Path>, lockfile: Option<&Path>) -> Result<Vec<Dependency>> {
    if let Some(lock) = lockfile {
        if lock.file_name().and_then(|s| s.to_str()) == Some("gradle.lockfile") {
            return parse_gradle(lock, manifest);
        }
    }
    if let Some(m) = manifest {
        if m.file_name().and_then(|s| s.to_str()) == Some("pom.xml") {
            return parse_maven(m);
        }
    }
    Ok(Vec::new())
}

// ---------- Maven ----------

fn dep_block_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?s)<dependency>(.*?)</dependency>").unwrap())
}
fn dep_mgmt_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?s)<dependencyManagement>.*?</dependencyManagement>").unwrap())
}

fn parse_maven(path: &Path) -> Result<Vec<Dependency>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    // `<dependencyManagement>` holds version pins, not actual dependencies; drop
    // it so we only report the real `<dependencies>` (direct) entries.
    let body = dep_mgmt_re().replace_all(&text, "");

    let mut out = Vec::new();
    for cap in dep_block_re().captures_iter(&body) {
        let block = &cap[1];
        let Some(group) = tag(block, "groupId") else { continue };
        let Some(artifact) = tag(block, "artifactId") else { continue };
        let version = tag(block, "version").unwrap_or_else(|| "managed".to_string());
        out.push(Dependency {
            name: format!("{group}:{artifact}"),
            version,
            ecosystem: Ecosystem::Java,
            direct: true, // pom.xml lists direct dependencies
            resolved_url: None,
            integrity: None,
            parents: Vec::new(),
        });
    }
    Ok(out)
}

/// Extract the trimmed text of the first `<tag>...</tag>` inside `block`.
fn tag(block: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = block.find(&open)? + open.len();
    let end = block[start..].find(&close)? + start;
    let val = block[start..end].trim();
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

// ---------- Gradle ----------

fn parse_gradle(lock: &Path, manifest: Option<&Path>) -> Result<Vec<Dependency>> {
    let text = std::fs::read_to_string(lock)
        .with_context(|| format!("reading {}", lock.display()))?;

    let direct = manifest
        .and_then(|m| std::fs::read_to_string(m).ok())
        .map(|s| gradle_direct_set(&s))
        .unwrap_or_default();

    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("empty=") {
            continue;
        }
        // group:artifact:version=configurations
        let coord = line.split('=').next().unwrap_or("");
        let mut parts = coord.splitn(3, ':');
        let (Some(group), Some(artifact), Some(version)) =
            (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let name = format!("{group}:{artifact}");
        let is_direct = direct.contains(&name);
        out.push(Dependency {
            name,
            version: version.to_string(),
            ecosystem: Ecosystem::Java,
            direct: is_direct,
            resolved_url: None,
            integrity: None,
            parents: Vec::new(),
        });
    }
    Ok(out)
}

fn gradle_coord_re() -> &'static Regex {
    // "group:artifact:version" inside a Groovy/Kotlin DSL string literal.
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"["']([A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-]+):[^"'\s]+["']"#).unwrap()
    })
}

/// Best-effort direct set from a build.gradle(.kts): every `group:artifact`
/// mentioned as a coordinate string literal.
fn gradle_direct_set(build_gradle: &str) -> HashSet<String> {
    gradle_coord_re()
        .captures_iter(build_gradle)
        .map(|c| c[1].to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(name: &str, body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("postmortem-java-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::File::create(&p).unwrap().write_all(body.as_bytes()).unwrap();
        p
    }

    const POM: &str = r#"<project>
  <groupId>com.acme</groupId>
  <artifactId>victim</artifactId>
  <version>1.0.0</version>

  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.managed</groupId>
        <artifactId>bom-only</artifactId>
        <version>9.9.9</version>
      </dependency>
    </dependencies>
  </dependencyManagement>

  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
    </dependency>
  </dependencies>
</project>"#;

    #[test]
    fn maven_reads_direct_and_skips_dependency_management() {
        let pom = tmp("pom.xml", POM);
        let deps = parse_maven(&pom).unwrap();
        assert_eq!(deps.len(), 2, "dependencyManagement must be excluded: {deps:#?}");
        let lang3 = deps.iter().find(|d| d.name == "org.apache.commons:commons-lang3").unwrap();
        assert_eq!(lang3.version, "3.12.0");
        assert!(lang3.direct);
        assert_eq!(lang3.ecosystem, Ecosystem::Java);
        // absent version falls back to "managed"
        let guava = deps.iter().find(|d| d.name == "com.google.guava:guava").unwrap();
        assert_eq!(guava.version, "managed");
        assert!(!deps.iter().any(|d| d.name == "org.managed:bom-only"));
    }

    const GRADLE_LOCK: &str = "# Gradle generated file for dependency locking.\ncom.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath\norg.apache.commons:commons-lang3:3.12.0=runtimeClasspath\nempty=annotationProcessor\n";

    #[test]
    fn gradle_reads_lockfile_and_marks_direct_from_build_gradle() {
        let lock = tmp("gradle.lockfile", GRADLE_LOCK);
        let build = tmp(
            "build.gradle",
            "dependencies {\n  implementation 'com.google.guava:guava:31.1-jre'\n}\n",
        );
        let deps = parse_gradle(&lock, Some(&build)).unwrap();
        assert_eq!(deps.len(), 2);
        let guava = deps.iter().find(|d| d.name == "com.google.guava:guava").unwrap();
        assert_eq!(guava.version, "31.1-jre");
        assert!(guava.direct, "guava is declared in build.gradle");
        let lang3 = deps.iter().find(|d| d.name == "org.apache.commons:commons-lang3").unwrap();
        assert!(!lang3.direct, "commons-lang3 is only transitive");
    }
}
