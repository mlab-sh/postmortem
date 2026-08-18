//! `postmortem timeline <pkg>` — a package's history as a narrative.
//!
//! The risk signals elsewhere in postmortem are *point-in-time*: this version
//! added an install script, this version has a new publisher. Each is a boolean
//! about one release, and a boolean is hard to weigh. The same facts laid out in
//! order tell you something a flag cannot:
//!
//! ```text
//!   2016-03-02  v0.1.0   first release
//!   2018-09-09  v3.3.6   ! publisher changed  dominictarr → right9ctrl
//!   2018-09-16  v0.1.1   ! install script added
//! ```
//!
//! That is the event-stream compromise, and read in sequence it is obviously a
//! takeover: a maintainer handover followed a week later by the first install
//! hook the package ever had. Either fact alone is unremarkable.
//!
//! ## Events are transitions, not properties
//!
//! Every entry here is a *change* between one release and the one before it —
//! a publisher that differs, a script that appeared, a repository URL that
//! moved. A property ("this version has an install script") says nothing; the
//! transition ("the install script appeared here, in a package that had none for
//! four years") is the signal.
//!
//! ## npm only
//!
//! The npm packument is the one registry document carrying per-version
//! publisher, scripts, repository and attestation together. The other registries
//! publish a current view, not a history, so there is nothing to lay out.

use owo_colors::OwoColorize;

/// One thing that changed at a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    FirstRelease,
    /// The publisher differs from the previous release's.
    PublisherChanged { from: String, to: String },
    InstallScriptAdded,
    InstallScriptRemoved,
    /// The declared source repository moved — a transfer, a rename, or a
    /// redirect to somewhere else entirely.
    RepoChanged { from: String, to: String },
    /// A published attestation appeared (a move to Trusted Publishing).
    ProvenanceAdded,
    /// One disappeared — a publish that skipped the trusted flow.
    ProvenanceRemoved,
    /// This release followed a long silence.
    Dormancy { days: i64 },
    Deprecated,
}

impl Event {
    /// Does this event, on its own, warrant attention?
    ///
    /// Used only for colour. The point of the timeline is that the *sequence*
    /// carries the meaning, so nothing is hidden on the strength of this.
    pub fn is_notable(&self) -> bool {
        matches!(
            self,
            Event::PublisherChanged { .. }
                | Event::InstallScriptAdded
                | Event::RepoChanged { .. }
                | Event::ProvenanceRemoved
        )
    }

    pub fn label(&self) -> String {
        match self {
            Event::FirstRelease => "first release".into(),
            Event::PublisherChanged { from, to } => format!("publisher changed  {from} → {to}"),
            Event::InstallScriptAdded => "install script added".into(),
            Event::InstallScriptRemoved => "install script removed".into(),
            Event::RepoChanged { from, to } => format!("repository moved  {from} → {to}"),
            Event::ProvenanceAdded => "provenance attestation added".into(),
            Event::ProvenanceRemoved => "provenance attestation removed".into(),
            Event::Dormancy { days } => format!("released after {days}d of silence"),
            Event::Deprecated => "deprecated".into(),
        }
    }

    /// A stable key for machine output.
    pub fn kind(&self) -> &'static str {
        match self {
            Event::FirstRelease => "first_release",
            Event::PublisherChanged { .. } => "publisher_changed",
            Event::InstallScriptAdded => "install_script_added",
            Event::InstallScriptRemoved => "install_script_removed",
            Event::RepoChanged { .. } => "repo_changed",
            Event::ProvenanceAdded => "provenance_added",
            Event::ProvenanceRemoved => "provenance_removed",
            Event::Dormancy { .. } => "dormancy",
            Event::Deprecated => "deprecated",
        }
    }
}

/// One release, and what changed at it.
#[derive(Debug, Clone)]
pub struct Release {
    pub version: String,
    /// Unix seconds.
    pub published: i64,
    pub publisher: Option<String>,
    pub events: Vec<Event>,
    /// This is the version the scanned project has installed.
    pub installed: bool,
}

/// A package's history.
#[derive(Debug, Default)]
pub struct Timeline {
    pub package: String,
    pub releases: Vec<Release>,
    /// Releases with no event at all, which the default view collapses.
    pub quiet: usize,
    /// The project has this version installed, but the registry no longer lists
    /// it.
    ///
    /// A finding in its own right, not a lookup failure: versions disappear
    /// because they were unpublished, and malice is the usual reason a registry
    /// removes one. `event-stream@3.3.6` — the 2018 compromise — is exactly this
    /// case today.
    pub installed_missing: Option<String>,
}

impl Timeline {
    /// Releases carrying at least one event, plus the installed one — which is
    /// always shown, since "where am I on this line" is the reason to look.
    pub fn eventful(&self) -> impl Iterator<Item = &Release> {
        self.releases.iter().filter(|r| !r.events.is_empty() || r.installed)
    }

    pub fn notable(&self) -> usize {
        self.releases.iter().filter(|r| r.events.iter().any(Event::is_notable)).count()
    }
}

/// A release gap this long is worth calling out. Matches the dormancy bar the
/// point-in-time signal uses, so the two never disagree.
const DORMANT_DAYS: i64 = 365;

/// Build the timeline from an npm packument.
///
/// `installed` marks one version as the project's. Pure and offline — the
/// caller fetches the document.
pub fn build(doc: &serde_json::Value, package: &str, installed: Option<&str>) -> Timeline {
    let (Some(times), Some(versions)) = (
        doc.get("time").and_then(|t| t.as_object()),
        doc.get("versions").and_then(|v| v.as_object()),
    ) else {
        return Timeline { package: package.into(), ..Default::default() };
    };

    // Chronological order is what makes this a narrative rather than a list;
    // the packument's maps are unordered.
    let mut ordered: Vec<(&str, i64)> = times
        .iter()
        .filter(|(k, _)| *k != "created" && *k != "modified")
        .filter_map(|(k, v)| v.as_str().and_then(parse_ts).map(|t| (k.as_str(), t)))
        .collect();
    ordered.sort_by_key(|(_, t)| *t);

    let mut releases: Vec<Release> = Vec::new();
    let mut prev: Option<&serde_json::Value> = None;
    let mut prev_ts: Option<i64> = None;

    for (version, ts) in ordered {
        let Some(manifest) = versions.get(version) else {
            // A `time` entry with no manifest is an unpublished version. It is
            // still a real event in the package's history, but there is nothing
            // to compare, so it is skipped rather than guessed at.
            continue;
        };
        let mut events = Vec::new();

        match prev {
            None => events.push(Event::FirstRelease),
            Some(p) => {
                let (was, now) = (publisher(p), publisher(manifest));
                if let (Some(a), Some(b)) = (was, now)
                    && a != b
                {
                    events.push(Event::PublisherChanged { from: a.into(), to: b.into() });
                }
                match (has_install_hook(p), has_install_hook(manifest)) {
                    (false, true) => events.push(Event::InstallScriptAdded),
                    (true, false) => events.push(Event::InstallScriptRemoved),
                    _ => {}
                }
                match (has_provenance(p), has_provenance(manifest)) {
                    (false, true) => events.push(Event::ProvenanceAdded),
                    (true, false) => events.push(Event::ProvenanceRemoved),
                    _ => {}
                }
                if let (Some(a), Some(b)) = (repo_url(p), repo_url(manifest))
                    && !same_repo(&a, &b)
                {
                    events.push(Event::RepoChanged { from: a, to: b });
                }
                if let Some(pt) = prev_ts {
                    let gap = (ts - pt) / 86_400;
                    if gap >= DORMANT_DAYS {
                        events.push(Event::Dormancy { days: gap });
                    }
                }
            }
        }
        if manifest.get("deprecated").is_some() {
            events.push(Event::Deprecated);
        }

        releases.push(Release {
            version: version.to_string(),
            published: ts,
            publisher: publisher(manifest).map(str::to_string),
            events,
            installed: installed == Some(version),
        });
        prev = Some(manifest);
        prev_ts = Some(ts);
    }

    let quiet = releases.iter().filter(|r| r.events.is_empty() && !r.installed).count();
    let installed_missing = installed
        .filter(|v| !releases.iter().any(|r| r.version == *v))
        .map(str::to_string);
    Timeline { package: package.into(), releases, quiet, installed_missing }
}

fn parse_ts(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|d| d.timestamp())
}

fn publisher(manifest: &serde_json::Value) -> Option<&str> {
    manifest.get("_npmUser").and_then(|u| u.get("name")).and_then(|n| n.as_str())
}

fn has_provenance(manifest: &serde_json::Value) -> bool {
    manifest.get("dist").and_then(|d| d.get("attestations")).is_some()
}

fn has_install_hook(manifest: &serde_json::Value) -> bool {
    manifest.get("scripts").and_then(|s| s.as_object()).is_some_and(|s| {
        ["preinstall", "install", "postinstall"].iter().any(|k| s.contains_key(*k))
    })
}

fn repo_url(manifest: &serde_json::Value) -> Option<String> {
    let r = manifest.get("repository")?;
    r.as_str()
        .map(str::to_string)
        .or_else(|| r.get("url").and_then(|u| u.as_str()).map(str::to_string))
}

/// Do two repository URLs point at the same place?
///
/// Registries record the same repo half a dozen ways — `git+https://`,
/// `git://`, a trailing `.git`, a `www.` host. Comparing raw strings would
/// report a "repository moved" every time a maintainer tidied the field, which
/// would bury the transfers that matter.
fn same_repo(a: &str, b: &str) -> bool {
    normalize_repo(a) == normalize_repo(b)
}

fn normalize_repo(u: &str) -> String {
    let u = u.trim().to_ascii_lowercase();
    let u = u
        .strip_prefix("git+")
        .unwrap_or(&u)
        .to_string();
    let u = u
        .strip_prefix("https://")
        .or_else(|| u.strip_prefix("http://"))
        .or_else(|| u.strip_prefix("git://"))
        .or_else(|| u.strip_prefix("ssh://"))
        .unwrap_or(&u)
        .to_string();
    let u = u.strip_prefix("git@").unwrap_or(&u).replacen(':', "/", 1);
    let u = u.strip_prefix("www.").unwrap_or(&u).to_string();
    u.trim_end_matches('/').trim_end_matches(".git").to_string()
}

/// Render the timeline.
pub fn render(t: &Timeline, all: bool) {
    println!("{}  {}", "timeline".bold(), t.package.cyan());

    if t.releases.is_empty() {
        println!();
        crate::gochi::say(crate::gochi::Mood::Curious, "no release history available");
        return;
    }

    if let Some(v) = &t.installed_missing {
        println!(
            "\n{}",
            format!(
                "⚠ you have {}@{v} installed, and the registry no longer lists it — \
                 versions get unpublished, and malice is the usual reason",
                t.package
            )
            .red()
            .bold()
        );
    }

    println!(
        "\n  {} release(s), {} carrying a change\n",
        t.releases.len(),
        t.releases.len() - t.quiet
    );

    let shown: Vec<&Release> =
        if all { t.releases.iter().collect() } else { t.eventful().collect() };

    for r in shown {
        let date = fmt_date(r.published);
        let here = if r.installed { "  ← installed".green().bold().to_string() } else { String::new() };
        let notable = r.events.iter().any(Event::is_notable);
        let marker = if notable { "!".red().bold().to_string() } else { " ".to_string() };

        if r.events.is_empty() {
            println!("  {} {marker} {:<12}{here}", date.dimmed(), r.version);
            continue;
        }
        for (i, e) in r.events.iter().enumerate() {
            let label = if e.is_notable() {
                e.label().red().to_string()
            } else {
                e.label().dimmed().to_string()
            };
            if i == 0 {
                println!("  {} {marker} {:<12} {label}{here}", date.dimmed(), r.version);
            } else {
                println!("  {}   {:<12} {label}", " ".repeat(10), "");
            }
        }
    }

    if !all && t.quiet > 0 {
        println!(
            "\n  {}",
            format!("… {} release(s) with no change of publisher, scripts, repository or \
                     provenance (--all to list them)", t.quiet)
                .dimmed()
        );
    }

    println!();
    let n = t.notable();
    let mood = if t.installed_missing.is_some() || n >= 2 {
        crate::gochi::Mood::Bad
    } else if n == 1 {
        crate::gochi::Mood::Alert
    } else {
        crate::gochi::Mood::Happy
    };
    crate::gochi::say(mood, summary(t, n));
}

fn summary(t: &Timeline, notable: usize) -> String {
    if let Some(v) = &t.installed_missing {
        return format!("{}@{v} is installed but no longer published", t.package);
    }
    if notable == 0 {
        return format!("{}: no handover, no new install script, no repository move", t.package);
    }
    // Two or more notable events is the shape worth naming — a handover
    // *followed by* a new install script is the takeover pattern, and neither
    // half alone would say so.
    let handover = t
        .releases
        .iter()
        .any(|r| r.events.iter().any(|e| matches!(e, Event::PublisherChanged { .. })));
    let hook = t
        .releases
        .iter()
        .any(|r| r.events.contains(&Event::InstallScriptAdded));
    if handover && hook {
        return format!(
            "{}: changed hands and gained an install script — read the order of those two",
            t.package
        );
    }
    format!("{}: {notable} release(s) changed who or how it publishes", t.package)
}

fn fmt_date(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "?".into())
}

/// The `timeline --json` document.
pub fn to_json(t: &Timeline) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "package": t.package,
        "summary": {
            "releases": t.releases.len(),
            "with_events": t.releases.len() - t.quiet,
            "notable": t.notable(),
            // Present means the installed version has been unpublished — a
            // finding, not a missing lookup.
            "installed_missing": t.installed_missing,
        },
        // Every release, including the quiet ones: the terminal view collapses
        // them for readability, but a consumer should get the whole history.
        "releases": t.releases.iter().map(|r| serde_json::json!({
            "version": r.version,
            "published": fmt_date(r.published),
            "published_ts": r.published,
            "publisher": r.publisher,
            "installed": r.installed,
            "events": r.events.iter().map(|e| serde_json::json!({
                "kind": e.kind(),
                "detail": e.label(),
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A packument from `(version, date, publisher, has_hook, repo)` rows.
    fn packument(rows: &[(&str, &str, &str, bool, &str)]) -> serde_json::Value {
        let mut time = serde_json::Map::new();
        let mut versions = serde_json::Map::new();
        for (v, date, user, hook, repo) in rows {
            time.insert((*v).into(), json!(format!("{date}T00:00:00.000Z")));
            let mut m = json!({ "_npmUser": { "name": user } });
            if *hook {
                m["scripts"] = json!({ "postinstall": "node build.js" });
            }
            if !repo.is_empty() {
                m["repository"] = json!({ "type": "git", "url": repo });
            }
            versions.insert((*v).into(), m);
        }
        json!({ "time": time, "versions": versions })
    }

    fn kinds(t: &Timeline, version: &str) -> Vec<&'static str> {
        t.releases
            .iter()
            .find(|r| r.version == version)
            .map(|r| r.events.iter().map(Event::kind).collect())
            .unwrap_or_default()
    }

    #[test]
    fn releases_come_out_in_chronological_order() {
        // The packument's maps are unordered; order is what makes this a
        // narrative rather than a list.
        let doc = packument(&[
            ("2.0.0", "2020-01-01", "a", false, ""),
            ("1.0.0", "2018-01-01", "a", false, ""),
            ("1.5.0", "2019-01-01", "a", false, ""),
        ]);
        let t = build(&doc, "p", None);
        let order: Vec<&str> = t.releases.iter().map(|r| r.version.as_str()).collect();
        assert_eq!(order, ["1.0.0", "1.5.0", "2.0.0"]);
    }

    #[test]
    fn the_event_stream_pattern_reads_as_a_takeover() {
        // A handover, then the first install script the package ever had.
        // Either alone is unremarkable; in sequence it is the 2018 compromise.
        let doc = packument(&[
            ("3.3.4", "2018-01-01", "dominictarr", false, ""),
            ("3.3.6", "2018-09-09", "right9ctrl", false, ""),
            ("3.3.7", "2018-09-16", "right9ctrl", true, ""),
        ]);
        let t = build(&doc, "event-stream", None);
        assert_eq!(kinds(&t, "3.3.6"), ["publisher_changed"]);
        assert_eq!(kinds(&t, "3.3.7"), ["install_script_added"]);
        assert!(summary(&t, t.notable()).contains("changed hands"));
    }

    #[test]
    fn the_first_release_is_an_event_and_has_nothing_to_compare() {
        let doc = packument(&[("1.0.0", "2020-01-01", "a", true, "")]);
        let t = build(&doc, "p", None);
        // The hook is present, but it did not *appear* — there is no predecessor.
        assert_eq!(kinds(&t, "1.0.0"), ["first_release"]);
    }

    #[test]
    fn a_publisher_change_needs_both_sides_known() {
        // A missing `_npmUser` is not a different publisher.
        let mut doc = packument(&[
            ("1.0.0", "2020-01-01", "a", false, ""),
            ("1.1.0", "2020-02-01", "a", false, ""),
        ]);
        doc["versions"]["1.1.0"]["_npmUser"] = json!(null);
        let t = build(&doc, "p", None);
        assert!(kinds(&t, "1.1.0").is_empty(), "unknown must not read as changed");
    }

    #[test]
    fn a_removed_install_script_is_recorded_too() {
        let doc = packument(&[
            ("1.0.0", "2020-01-01", "a", true, ""),
            ("1.1.0", "2020-02-01", "a", false, ""),
        ]);
        assert_eq!(kinds(&build(&doc, "p", None), "1.1.0"), ["install_script_removed"]);
    }

    #[test]
    fn a_repository_move_is_flagged_but_a_reformat_is_not() {
        // Registries record the same repo half a dozen ways; reporting a move
        // every time a maintainer tidied the field would bury the real ones.
        let doc = packument(&[
            ("1.0.0", "2020-01-01", "a", false, "git+https://github.com/acme/thing.git"),
            ("1.1.0", "2020-02-01", "a", false, "git://www.github.com/acme/thing"),
            ("1.2.0", "2020-03-01", "a", false, "https://github.com/evilcorp/thing"),
        ]);
        let t = build(&doc, "p", None);
        assert!(kinds(&t, "1.1.0").is_empty(), "same repo, different spelling");
        assert_eq!(kinds(&t, "1.2.0"), ["repo_changed"]);
    }

    #[test]
    fn repo_normalization_covers_the_shapes_registries_use() {
        assert!(same_repo("git+https://github.com/a/b.git", "https://github.com/a/b"));
        assert!(same_repo("git@github.com:a/b.git", "https://github.com/a/b"));
        assert!(same_repo("https://www.github.com/a/b/", "http://github.com/a/b"));
        assert!(!same_repo("https://github.com/a/b", "https://github.com/c/b"));
    }

    #[test]
    fn a_long_silence_before_a_release_is_recorded() {
        let doc = packument(&[
            ("1.0.0", "2018-01-01", "a", false, ""),
            ("1.1.0", "2021-01-01", "a", false, ""),
        ]);
        let t = build(&doc, "p", None);
        assert!(kinds(&t, "1.1.0").contains(&"dormancy"));
    }

    #[test]
    fn provenance_appearing_and_disappearing_are_different_events() {
        let mut doc = packument(&[
            ("1.0.0", "2024-01-01", "a", false, ""),
            ("1.1.0", "2024-02-01", "a", false, ""),
            ("1.2.0", "2024-03-01", "a", false, ""),
        ]);
        doc["versions"]["1.1.0"]["dist"] = json!({ "attestations": { "url": "x" } });
        let t = build(&doc, "p", None);
        assert_eq!(kinds(&t, "1.1.0"), ["provenance_added"]);
        assert_eq!(kinds(&t, "1.2.0"), ["provenance_removed"]);
    }

    #[test]
    fn the_installed_version_is_marked_and_always_shown() {
        // "Where am I on this line" is the reason to look, so a quiet installed
        // release must not be collapsed away with the rest.
        let doc = packument(&[
            ("1.0.0", "2020-01-01", "a", false, ""),
            ("1.1.0", "2020-02-01", "a", false, ""),
            ("1.2.0", "2020-03-01", "a", false, ""),
        ]);
        let t = build(&doc, "p", Some("1.1.0"));
        assert!(t.releases.iter().find(|r| r.version == "1.1.0").unwrap().installed);
        assert!(t.eventful().any(|r| r.version == "1.1.0"));
        // 1.2.0 is quiet and not installed, so it collapses.
        assert!(!t.eventful().any(|r| r.version == "1.2.0"));
    }

    #[test]
    fn quiet_releases_are_counted_not_dropped() {
        let doc = packument(&[
            ("1.0.0", "2020-01-01", "a", false, ""),
            ("1.1.0", "2020-02-01", "a", false, ""),
            ("1.2.0", "2020-03-01", "a", false, ""),
        ]);
        let t = build(&doc, "p", None);
        assert_eq!(t.releases.len(), 3);
        assert_eq!(t.quiet, 2, "only the first release carries an event");
    }

    #[test]
    fn a_time_entry_without_a_manifest_is_skipped_not_guessed_at() {
        // An unpublished version leaves a `time` entry behind; there is nothing
        // to compare it against.
        let mut doc = packument(&[("1.0.0", "2020-01-01", "a", false, "")]);
        doc["time"]["9.9.9"] = json!("2021-01-01T00:00:00.000Z");
        let t = build(&doc, "p", None);
        assert_eq!(t.releases.len(), 1);
    }

    #[test]
    fn a_malformed_packument_yields_an_empty_timeline_not_a_panic() {
        let t = build(&json!({ "nope": 1 }), "p", None);
        assert!(t.releases.is_empty());
        assert_eq!(t.notable(), 0);
    }

    #[test]
    fn json_keeps_every_release_including_the_quiet_ones() {
        // The terminal view collapses them for readability; a consumer gets all.
        let doc = packument(&[
            ("1.0.0", "2020-01-01", "a", false, ""),
            ("1.1.0", "2020-02-01", "a", false, ""),
        ]);
        let doc = to_json(&build(&doc, "p", Some("1.1.0")));
        assert_eq!(doc["summary"]["releases"], 2);
        assert_eq!(doc["releases"].as_array().unwrap().len(), 2);
        assert_eq!(doc["releases"][1]["installed"], true);
        assert_eq!(doc["releases"][0]["events"][0]["kind"], "first_release");
    }

    #[test]
    fn an_installed_version_the_registry_dropped_is_a_finding() {
        // Versions disappear because they were unpublished, and malice is the
        // usual reason — `event-stream@3.3.6` is exactly this today. Treating it
        // as a failed lookup would swallow the most interesting fact available.
        let doc = packument(&[("1.0.0", "2020-01-01", "a", false, "")]);
        let t = build(&doc, "p", Some("6.6.6"));
        assert_eq!(t.installed_missing.as_deref(), Some("6.6.6"));
        assert!(summary(&t, t.notable()).contains("no longer published"));
        let j = to_json(&t);
        assert_eq!(j["summary"]["installed_missing"], "6.6.6");
    }

    #[test]
    fn a_version_still_on_the_registry_is_not_reported_missing() {
        let doc = packument(&[("1.0.0", "2020-01-01", "a", false, "")]);
        let t = build(&doc, "p", Some("1.0.0"));
        assert_eq!(t.installed_missing, None);
        assert!(to_json(&t)["summary"]["installed_missing"].is_null());
    }
}
