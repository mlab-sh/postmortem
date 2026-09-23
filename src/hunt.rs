//! `postmortem hunt` — an attack just dropped: were we exposed, where, and when?
//!
//! Three passes, each parallel:
//!
//! 1. **Discover** every project under the given roots with `ignore`'s parallel
//!    walker, pruning the directories that never hold a project of their own
//!    (`node_modules`, `target`, dot-dirs, …) before descending into them.
//! 2. **Parse** each project with the same parsers every other command uses,
//!    and match the targets against the resolved graph: *is it here now?* For
//!    npm, also *is it installed?*, read from `node_modules`.
//! 3. **Replay** each pinning file's git history: *was it ever here, and from
//!    when to when?* One `git log` lists the commits that touched the file and
//!    one `git cat-file --batch` streams every revision, which a single regex
//!    over all target names scans in one pass. A package that was removed last
//!    week is still an exposure — its install scripts ran on every machine that
//!    installed it in between.

use std::collections::{BTreeMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use serde::Serialize;

use crate::detect::{self, Detected};
use crate::model::Dependency;
use crate::ui;

/// The files that make a directory a project — one per ecosystem's pin.
const MARKERS: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "Pipfile.lock",
    "requirements.txt",
    "Cargo.lock",
    "Gemfile.lock",
    "composer.lock",
    "go.mod",
    "pom.xml",
    "gradle.lockfile",
];

/// Directories that never contain a project worth hunting in, and that are
/// usually the bulk of the tree: installed dependencies, build output, caches.
/// Dot-directories are pruned wholesale (`.git`, `.cache`, `.venv`, …).
const PRUNE: &[&str] = &[
    "node_modules",
    "bower_components",
    "target",
    "vendor",
    "venv",
    "__pycache__",
    "site-packages",
    "dist",
    "build",
    "Pods",
    "DerivedData",
    "Library",
];

/// One thing to hunt for: a package name, optionally pinned to a version.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Target {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl Target {
    /// `name`, `name@1.2.3`, `@scope/name@1.2.3`, `name 1.2.3` or `name,1.2.3`
    /// (the shapes advisories and IOC lists come in). `name@*` means any version.
    pub fn parse(s: &str) -> Option<Target> {
        let s = s.trim().trim_matches('"');
        if s.is_empty() || s.starts_with('#') {
            return None;
        }
        let (name, version) = if let Some((n, v)) = s.split_once([',', ' ', '\t']) {
            (n.trim(), Some(v.trim()))
        } else {
            match s.rfind('@') {
                Some(i) if i > 0 => (&s[..i], Some(&s[i + 1..])),
                _ => (s, None),
            }
        };
        let version = version
            .map(|v| v.trim_matches('"'))
            .filter(|v| !v.is_empty() && *v != "*")
            .map(String::from);
        Some(Target {
            name: name.to_string(),
            version,
        })
    }

    fn label(&self) -> String {
        match &self.version {
            Some(v) => format!("{}@{v}", self.name),
            None => self.name.clone(),
        }
    }

    fn matches(&self, name: &str, version: &str) -> bool {
        norm_name(&self.name) == norm_name(name)
            && self.version.as_deref().is_none_or(|v| norm_ver(v) == norm_ver(version))
    }
}

/// PyPI treats `-`, `_` and `.` as one character and ignores case; nothing
/// else in the supported ecosystems distinguishes names that differ only so.
fn norm_name(n: &str) -> String {
    n.to_ascii_lowercase().replace(['_', '.'], "-")
}

/// Go and Composer write `v1.2.3`; advisories usually write `1.2.3`.
fn norm_ver(v: &str) -> &str {
    v.trim().trim_start_matches(['v', '='])
}

/// Pass 1: every directory under `roots` holding a project marker.
pub fn discover(roots: &[PathBuf]) -> (Vec<PathBuf>, usize) {
    let mut b = ignore::WalkBuilder::new(&roots[0]);
    for r in &roots[1..] {
        b.add(r);
    }
    b.standard_filters(false)
        .hidden(false)
        .follow_links(false)
        .threads(workers())
        .filter_entry(|e| {
            e.depth() == 0
                || !e.file_type().is_some_and(|t| t.is_dir())
                || !prune(&e.file_name().to_string_lossy())
        });
    let found = Mutex::new(Vec::new());
    let dirs = AtomicUsize::new(0);
    b.build_parallel().run(|| {
        let (found, dirs) = (&found, &dirs);
        Box::new(move |r| {
            if let Ok(e) = r {
                match e.file_type() {
                    Some(t) if t.is_dir() => {
                        dirs.fetch_add(1, Ordering::Relaxed);
                    }
                    Some(t) if t.is_file() => {
                        let name = e.file_name().to_string_lossy();
                        if MARKERS.contains(&name.as_ref())
                            && let Some(p) = e.path().parent()
                        {
                            found.lock().unwrap().push(p.to_path_buf());
                        }
                    }
                    _ => {}
                }
            }
            ignore::WalkState::Continue
        })
    });
    let mut found = found.into_inner().unwrap();
    found.sort();
    found.dedup();
    (found, dirs.into_inner())
}

fn prune(dir: &str) -> bool {
    dir.starts_with('.') || PRUNE.contains(&dir)
}

fn workers() -> usize {
    std::thread::available_parallelism().map_or(4, |n| n.get())
}

/// A commit where a target's presence in a pinning file flipped.
#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub commit: String,
    /// Unix seconds, committer date.
    pub date: i64,
    pub author: String,
    pub subject: String,
}

/// A stretch of history during which the target was pinned.
#[derive(Debug, Clone, Serialize)]
pub struct Window {
    pub from: Change,
    /// `None` while it is still pinned at `HEAD`.
    pub to: Option<Change>,
}

#[derive(Debug, Serialize)]
pub struct Hit {
    pub target: String,
    pub project: String,
    pub file: String,
    pub ecosystem: String,
    /// Versions of the target pinned right now (empty: not any more).
    pub current: Vec<String>,
    /// npm only: the matching version is present in `node_modules`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed: Option<bool>,
    pub history: Vec<Window>,
}

pub struct Outcome {
    pub hits: Vec<Hit>,
    pub projects: usize,
    pub with_history: usize,
    pub unreadable: Vec<String>,
}

/// Passes 2 and 3 over the discovered projects, `workers()` at a time.
pub fn hunt(projects: &[PathBuf], targets: &[Target], history: bool, animate: bool) -> Outcome {
    let names = name_regex(targets);
    let quiet = ui::Ui::silent();
    let bar = crate::gochi::Loader::start(projects.len() as u64, animate);
    bar.step("hunting");
    let next = AtomicUsize::new(0);
    let hits = Mutex::new(Vec::new());
    let unreadable = Mutex::new(Vec::new());
    let with_history = AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..workers().min(projects.len()) {
            s.spawn(|| {
                while let Some(dir) = projects.get(next.fetch_add(1, Ordering::Relaxed)) {
                    bar.step(dir.display().to_string());
                    match hunt_project(dir, targets, history, &names, &quiet) {
                        Ok((mut h, replayed)) => {
                            with_history.fetch_add(usize::from(replayed), Ordering::Relaxed);
                            hits.lock().unwrap().append(&mut h);
                        }
                        Err(e) => unreadable
                            .lock()
                            .unwrap()
                            .push(format!("{}: {e:#}", dir.display())),
                    }
                    bar.inc();
                }
            });
        }
    });
    let mut hits = hits.into_inner().unwrap();
    hits.sort_by(|a, b| (&a.target, &a.project, &a.file).cmp(&(&b.target, &b.project, &b.file)));
    bar.finish(
        if hits.is_empty() { crate::gochi::Mood::Happy } else { crate::gochi::Mood::Alert },
        format!("hunted {} project(s)", projects.len()),
    );
    let mut unreadable = unreadable.into_inner().unwrap();
    unreadable.sort();
    Outcome {
        hits,
        projects: projects.len(),
        with_history: with_history.into_inner(),
        unreadable,
    }
}

/// One project: what is pinned now, and — per pinning file — what was pinned
/// over its history. Returns the hits and whether any history was replayed.
fn hunt_project(
    dir: &Path,
    targets: &[Target],
    history: bool,
    names: &regex::Regex,
    quiet: &ui::Ui,
) -> Result<(Vec<Hit>, bool)> {
    let detected = detect::detect(dir)?;
    let files: Vec<(String, PathBuf)> = detected
        .iter()
        .filter_map(|d| pin_file(d).map(|f| (d.name().to_string(), f.to_path_buf())))
        .collect();
    if detected.is_empty() {
        return Ok((Vec::new(), false));
    }
    let (_, deps, _) = crate::cmd::common::parse_detected(detected, quiet, &[])?;

    let mut out = Vec::new();
    let mut replayed = false;
    let top = if history { git_toplevel(dir) } else { None };
    for (eco, file) in &files {
        let windows = match &top {
            Some(top) => {
                let w = replay(top, file, targets, names);
                replayed |= w.is_some();
                w.unwrap_or_default()
            }
            None => Vec::new(),
        };
        for (i, t) in targets.iter().enumerate() {
            let current = current_versions(&deps, eco, t);
            let history = windows.get(i).cloned().unwrap_or_default();
            if current.is_empty() && history.is_empty() {
                continue;
            }
            let installed = (eco == "node" && !current.is_empty())
                .then(|| installed_npm(dir, &t.name, t.version.as_deref()));
            out.push(Hit {
                target: t.label(),
                project: dir.display().to_string(),
                file: file.file_name().unwrap_or_default().to_string_lossy().into(),
                ecosystem: eco.clone(),
                current,
                installed,
                history,
            });
        }
    }
    Ok((out, replayed))
}

/// The file whose history records what this ecosystem pinned.
fn pin_file(d: &Detected) -> Option<&Path> {
    match d {
        Detected::Node { lockfile, .. }
        | Detected::Rust { lockfile, .. }
        | Detected::Ruby { lockfile, .. }
        | Detected::Php { lockfile, .. } => Some(lockfile),
        Detected::Python { lockfile, manifest, .. } => Some(lockfile.as_deref().unwrap_or(manifest)),
        Detected::Go { manifest, .. } => Some(manifest),
        Detected::Java { lockfile, manifest, .. } => lockfile.as_deref().or(manifest.as_deref()),
    }
}

fn current_versions(deps: &[Dependency], eco: &str, t: &Target) -> Vec<String> {
    let mut v: Vec<String> = deps
        .iter()
        .filter(|d| d.ecosystem.as_str() == eco && t.matches(&d.name, &d.version))
        .map(|d| d.version.clone())
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Whether `node_modules` holds the package (at the target version, if one is
/// given). Top-level only: that is where npm, yarn and pnpm's links all put a
/// hoisted package, and a nested copy is already reported by the lockfile.
fn installed_npm(dir: &Path, name: &str, version: Option<&str>) -> bool {
    std::fs::read_to_string(dir.join("node_modules").join(name).join("package.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("version").and_then(|x| x.as_str()).map(String::from))
        .is_some_and(|got| version.is_none_or(|want| norm_ver(want) == norm_ver(&got)))
}

fn git_toplevel(dir: &Path) -> Option<PathBuf> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    // Canonical like the walked paths: on Windows git prints `C:/x` and the
    // roots are `\\?\C:\x`, and `strip_prefix` would silently never match.
    PathBuf::from(String::from_utf8_lossy(&out.stdout).trim())
        .canonicalize()
        .ok()
}

/// One alternation over every target name. The regex crate compiles a literal
/// alternation to a multi-pattern searcher, so a revision is scanned once
/// whatever the number of targets — a 500-line IOC feed costs what one does.
pub fn name_regex(targets: &[Target]) -> regex::Regex {
    let mut names: Vec<String> = targets.iter().map(|t| regex::escape(&t.name)).collect();
    names.sort_by_key(|n| std::cmp::Reverse(n.len())); // longest first: `foo-bar` before `foo`
    names.dedup();
    regex::RegexBuilder::new(&format!("(?i){}", names.join("|")))
        .build()
        .expect("escaped literals always compile")
}

/// Replay `file`'s first-parent history, oldest first, and return per target
/// the windows during which it was pinned. `None` when git has no history for
/// the file (untracked, or not a repository after all).
fn replay(top: &Path, file: &Path, targets: &[Target], names: &regex::Regex) -> Option<Vec<Vec<Window>>> {
    let rel = file.strip_prefix(top).ok()?.to_string_lossy().replace('\\', "/");
    let log = Command::new("git")
        .arg("-C")
        .arg(top)
        .args(["log", "--first-parent", "--reverse", "--format=%H%x1f%ct%x1f%an%x1f%s", "--"])
        .arg(&rel)
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let commits: Vec<Change> = String::from_utf8_lossy(&log.stdout)
        .lines()
        .filter_map(|l| {
            let mut f = l.splitn(4, '\x1f');
            Some(Change {
                commit: f.next()?.to_string(),
                date: f.next()?.parse().ok()?,
                author: f.next()?.to_string(),
                subject: f.next().unwrap_or("").to_string(),
            })
        })
        .collect();
    if commits.is_empty() {
        return None;
    }

    let mut windows = vec![Vec::new(); targets.len()];
    let mut open: Vec<Option<Change>> = vec![None; targets.len()];
    let mut each = |c: &Change, text: Option<&str>| {
        let present = text.map(|t| present_in(t, targets, names)).unwrap_or_default();
        for i in 0..targets.len() {
            let here = present.contains(&i);
            match (&open[i], here) {
                (None, true) => open[i] = Some(c.clone()),
                (Some(_), false) => windows[i].push(Window {
                    from: open[i].take().unwrap(),
                    to: Some(c.clone()),
                }),
                _ => {}
            }
        }
    };
    cat_file_batch(top, &rel, &commits, &mut each).ok()?;
    for (i, o) in open.into_iter().enumerate() {
        if let Some(from) = o {
            windows[i].push(Window { from, to: None });
        }
    }
    Some(windows)
}

/// Stream every revision of `rel` through one `git cat-file --batch`. A
/// deletion (the path is missing at that commit) is passed as `None`.
fn cat_file_batch(
    top: &Path,
    rel: &str,
    commits: &[Change],
    each: &mut dyn FnMut(&Change, Option<&str>),
) -> Result<()> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(top)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("git cat-file")?;
    // Feed stdin from its own thread: git answers as it reads, and a pipe
    // buffer full of unread answers would otherwise deadlock both sides.
    let mut stdin = child.stdin.take().context("stdin")?;
    let reqs: String = commits.iter().map(|c| format!("{}:{rel}\n", c.commit)).collect();
    let feeder = std::thread::spawn(move || stdin.write_all(reqs.as_bytes()));
    let mut out = BufReader::new(child.stdout.take().context("stdout")?);
    let mut header = String::new();
    let mut buf = Vec::new();
    for c in commits {
        header.clear();
        out.read_line(&mut header)?;
        // `<oid> blob <size>`, or `<request> missing`.
        let Some(size) = header
            .trim_end()
            .strip_suffix(" missing")
            .map_or_else(|| header.split(' ').nth(2)?.trim().parse::<usize>().ok(), |_| None)
        else {
            each(c, None);
            continue;
        };
        buf.resize(size + 1, 0); // content + trailing LF
        out.read_exact(&mut buf)?;
        each(c, Some(&String::from_utf8_lossy(&buf[..size])));
    }
    let _ = feeder.join();
    let _ = child.wait();
    Ok(())
}

/// Which targets a revision of a pinning file pins. Format-agnostic on
/// purpose: a past revision may predate the parser's supported formats, and
/// parsing a thousand revisions per repository would dominate the run.
///
/// A name occurrence counts when it is bounded like a package name, and — for a
/// version-pinned target — the version follows either directly (`name@1.2.3`,
/// `name (1.2.3)`, `path v1.2.3`, `/name/1.2.3`) or on the first `version` line
/// after it (`package-lock.json`, `yarn.lock`, `Cargo.lock`, `poetry.lock`,
/// `composer.lock`).
// ponytail: textual, not parsed — a version line belonging to the *next* entry
// can match when an entry has none. Re-parse the flipping revisions with the
// real parsers if that ever produces a false window.
pub fn present_in(text: &str, targets: &[Target], names: &regex::Regex) -> HashSet<usize> {
    let mut found = HashSet::new();
    for m in names.find_iter(text) {
        let before = text[..m.start()].chars().next_back();
        let after = text[m.end()..].chars().next();
        let part = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || "-_.".contains(c));
        if part(before) || part(after) {
            continue;
        }
        let name = m.as_str();
        let tail = &text[m.end()..text.len().min(m.end() + 400)];
        for (i, t) in targets.iter().enumerate() {
            if found.contains(&i) || !t.name.eq_ignore_ascii_case(name) {
                continue;
            }
            let hit = match &t.version {
                None => true,
                Some(v) => {
                    let v = norm_ver(v);
                    let adjacent = tail
                        .trim_start_matches(['@', ' ', '(', '/', '"', ':', '='])
                        .trim_start_matches("npm:");
                    let token = |s: &str| {
                        s.split(|c: char| !(c.is_ascii_alphanumeric() || "._+-".contains(c)))
                            .find(|x| !x.is_empty())
                            .map(|x| norm_ver(x) == v)
                            .unwrap_or(false)
                    };
                    token(adjacent)
                        || tail
                            .lines()
                            .find(|l| l.contains("version"))
                            .is_some_and(|l| {
                                l.split(|c: char| !(c.is_ascii_alphanumeric() || "._+-".contains(c)))
                                    .any(|x| norm_ver(x) == v)
                            })
                }
            };
            if hit {
                found.insert(i);
            }
        }
    }
    found
}

// --- output -------------------------------------------------------------------

pub fn to_json(o: &Outcome, targets: &[Target], roots: &[PathBuf], elapsed_ms: u128) -> serde_json::Value {
    serde_json::json!({
        "roots": roots,
        "targets": targets,
        "projects": o.projects,
        "projects_with_history": o.with_history,
        "elapsed_ms": elapsed_ms,
        "exposed": exposed(o),
        "hits": o.hits,
        "unreadable": o.unreadable,
    })
}

/// Projects where any target is pinned now or was at some point.
pub fn exposed(o: &Outcome) -> usize {
    o.hits.iter().map(|h| &h.project).collect::<HashSet<_>>().len()
}

fn day(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

fn short(c: &Change) -> String {
    format!("{} {}", &c.commit[..c.commit.len().min(8)], day(c.date))
}

pub fn render(o: &Outcome, targets: &[Target], discovery: (usize, u128), elapsed_ms: u128) {
    println!(
        "\n{} {} target(s) · {} project(s) found in {} dirs ({} ms) · {} with git history · {} ms total\n",
        "hunt".bold(),
        targets.len(),
        o.projects,
        discovery.0,
        discovery.1,
        o.with_history,
        elapsed_ms
    );
    let mut by_target: BTreeMap<String, Vec<&Hit>> = BTreeMap::new();
    for h in &o.hits {
        by_target.entry(h.target.clone()).or_default().push(h);
    }
    for t in targets {
        let label = t.label();
        let Some(hits) = by_target.get(&label) else {
            println!("  {} {:<32} {}", "✓".green(), label, "never pinned anywhere".dimmed());
            continue;
        };
        let now = hits.iter().filter(|h| !h.current.is_empty()).count();
        println!(
            "  {} {:<32} {}",
            "☠".red().bold(),
            label.bold(),
            format!("{} project(s), {now} still pinned now", hits.len()).red()
        );
        for h in hits {
            let state = if h.current.is_empty() {
                "gone now".dimmed().to_string()
            } else {
                let inst = match h.installed {
                    Some(true) => " · INSTALLED".red().bold().to_string(),
                    Some(false) => " · not installed".dimmed().to_string(),
                    None => String::new(),
                };
                format!("{}{inst}", format!("pinned {}", h.current.join(", ")).red())
            };
            println!("      {} {}  {state}", h.project.bold(), h.file.dimmed());
            for w in &h.history {
                let (to, days) = match &w.to {
                    Some(t) => (short(t), (t.date - w.from.date) / 86_400),
                    None => (
                        "HEAD".red().to_string(),
                        (chrono::Utc::now().timestamp() - w.from.date) / 86_400,
                    ),
                };
                println!(
                    "        {} {} → {}  {}  {}",
                    "exposed".yellow(),
                    short(&w.from),
                    to,
                    format!("({days} d)").yellow(),
                    format!("in by {}: {}", w.from.author, w.from.subject).dimmed()
                );
            }
        }
    }
    for u in &o.unreadable {
        eprintln!("  {} {}", "warn:".yellow(), u);
    }
    println!(
        "\n  {} project(s) exposed",
        if exposed(o) > 0 {
            exposed(o).to_string().red().bold().to_string()
        } else {
            "0".green().to_string()
        }
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> Target {
        Target::parse(s).unwrap()
    }

    #[test]
    fn target_shapes() {
        assert_eq!(t("event-stream@3.3.6").version.as_deref(), Some("3.3.6"));
        assert_eq!(t("@ctrl/tinycolor@4.1.1").name, "@ctrl/tinycolor");
        assert_eq!(t("@ctrl/tinycolor").version, None);
        assert_eq!(t("rest-client,1.6.13").version.as_deref(), Some("1.6.13"));
        assert_eq!(t("keyv *").version, None);
        assert!(Target::parse("# comment").is_none());
    }

    fn hits(text: &str, spec: &str) -> bool {
        let ts = vec![t(spec)];
        present_in(text, &ts, &name_regex(&ts)).contains(&0)
    }

    #[test]
    fn versions_are_read_from_every_lockfile_shape() {
        let npm = "\"node_modules/event-stream\": {\n  \"version\": \"3.3.6\",\n";
        assert!(hits(npm, "event-stream@3.3.6"));
        assert!(!hits(npm, "event-stream@3.3.5"));
        let yarn = "event-stream@^3.3.4:\n  version \"3.3.6\"\n";
        assert!(hits(yarn, "event-stream@3.3.6"));
        let pnpm = "  /event-stream@3.3.6:\n    resolution: {}\n";
        assert!(hits(pnpm, "event-stream@3.3.6"));
        let cargo = "[[package]]\nname = \"rustdecimal\"\nversion = \"1.23.1\"\n";
        assert!(hits(cargo, "rustdecimal@1.23.1"));
        let gem = "    rest-client (1.6.13)\n";
        assert!(hits(gem, "rest-client@1.6.13"));
        let gomod = "\tgithub.com/boltdb-go/bolt v1.3.1\n";
        assert!(hits(gomod, "github.com/boltdb-go/bolt@1.3.1"));
    }

    #[test]
    fn a_name_inside_a_longer_name_is_not_a_hit() {
        let npm = "\"node_modules/event-stream-extra\": {\n  \"version\": \"3.3.6\",\n";
        assert!(!hits(npm, "event-stream@3.3.6"));
        assert!(!hits("\"my-keyv\": {}", "keyv"));
    }

    #[test]
    fn many_targets_one_pass() {
        let ts: Vec<Target> = ["a-pkg@1.0.0", "b-pkg@2.0.0", "c-pkg"].iter().map(|s| t(s)).collect();
        let text = "\"node_modules/b-pkg\": {\n \"version\": \"2.0.0\"\n},\n\"node_modules/c-pkg\": {\n \"version\": \"9.9.9\"\n}";
        let got = present_in(text, &ts, &name_regex(&ts));
        assert_eq!(got, HashSet::from([1, 2]));
    }

    #[test]
    fn replay_finds_a_window_that_has_since_closed() {
        let base = std::env::temp_dir().join(format!("pm-hunt-git-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let git = |args: &[&str], date: &str| {
            let ok = Command::new("git")
                .arg("-C")
                .arg(&base)
                .args(["-c", "user.name=bob", "-c", "user.email=b@x", "-c", "commit.gpgsign=false"])
                .args(args)
                .env("GIT_COMMITTER_DATE", date)
                .env("GIT_AUTHOR_DATE", date)
                .status()
                .unwrap()
                .success();
            assert!(ok, "git {args:?}");
        };
        git(&["init", "-q"], "2018-08-01T10:00:00");
        let lock = base.join("package-lock.json");
        for (v, date, msg) in [
            ("3.3.5", "2018-08-01T10:00:00", "init"),
            ("3.3.6", "2018-09-16T10:00:00", "bump deps"),
            ("3.3.4", "2018-11-27T10:00:00", "pin back"),
        ] {
            std::fs::write(
                &lock,
                format!("{{\"packages\":{{\"node_modules/event-stream\":{{\"version\":\"{v}\"}}}}}}"),
            )
            .unwrap();
            git(&["add", "-A"], date);
            git(&["commit", "-qm", msg], date);
        }
        let ts = vec![t("event-stream@3.3.6"), t("event-stream")];
        let top = git_toplevel(&base).unwrap();
        let w = replay(&top, &top.join("package-lock.json"), &ts, &name_regex(&ts)).unwrap();
        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(w[0].len(), 1);
        assert_eq!(w[0][0].from.subject, "bump deps");
        assert_eq!(w[0][0].to.as_ref().unwrap().subject, "pin back");
        // Any version: pinned from the first commit, still pinned at HEAD.
        assert_eq!(w[1].len(), 1);
        assert!(w[1][0].to.is_none());
    }

    #[test]
    fn discovery_prunes_dependency_and_dot_dirs() {
        let base = std::env::temp_dir().join(format!("pm-hunt-{}", std::process::id()));
        for p in [
            "app/package-lock.json",
            "app/node_modules/dep/package-lock.json",
            "svc/Cargo.lock",
            ".cache/x/yarn.lock",
            "notes/readme.md",
        ] {
            let f = base.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, "").unwrap();
        }
        let (found, _) = discover(std::slice::from_ref(&base));
        let _ = std::fs::remove_dir_all(&base);
        let rel: Vec<_> = found.iter().map(|p| p.strip_prefix(&base).unwrap().to_path_buf()).collect();
        assert_eq!(rel, vec![PathBuf::from("app"), PathBuf::from("svc")]);
    }
}
