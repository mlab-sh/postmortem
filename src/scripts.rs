//! `postmortem scripts` — which dependencies execute code when you install them.
//!
//! npm 11 stopped running dependency lifecycle scripts by default: it now warns
//! that *N packages have install scripts not yet covered by allowScripts* and
//! makes you approve each one with `npm approve-scripts`. That closed the
//! execution hole — an unapproved `preinstall` no longer runs — but it left the
//! decision entirely unaided. npm tells you *that* seven packages want to run
//! code. It tells you nothing about whether any of them should.
//!
//! This fills that gap. postmortem already analyzes install scripts for network
//! egress, process spawning, obfuscation and embedded IOCs; here that analysis is
//! pointed at exactly the packages you are being asked to approve.
//!
//! ## Two layers, and the difference matters
//!
//! * **Which packages run code** comes from the lockfile — npm records
//!   `hasInstallScript` per entry — so it works with nothing installed.
//! * **What the script does** needs the script, which lives in `node_modules`.
//!   Without it that column is *unknown*, never "looks fine": an unread script
//!   is not a clean one.
//!
//! ## Approvals rot
//!
//! An approval is a judgement about a script at a moment. The package publishes
//! a new version, the script changes, and the approval silently carries over —
//! `allowScripts` records a name, not a version or a hash. So approved packages
//! are still analyzed and still reported when their script looks hostile.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use owo_colors::OwoColorize;

use crate::model::{Category, Dependency, Ecosystem, Finding, Severity};

/// Where a package stands with respect to the host's approval mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    /// Listed in the project's `allowScripts` — npm will run its scripts.
    Approved,
    /// Not listed: npm withholds its scripts and warns until you decide.
    Pending,
    /// The ecosystem has no approval mechanism, so the script simply runs.
    Unmanaged,
}

/// What we could learn about the script itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Behaviour {
    /// The script was read and raised nothing.
    Quiet,
    /// The script was read and does these things.
    Flagged(Vec<String>),
    /// The script was not on disk — it could not be read.
    Unread,
}

/// One package that executes code at install time.
#[derive(Debug, Clone)]
pub struct Entry {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub approval: Approval,
    pub behaviour: Behaviour,
    /// Worst severity of the findings against its script.
    pub severity: Option<Severity>,
}

impl Entry {
    /// Does this need a human decision?
    ///
    /// Anything unapproved, and anything approved whose script now looks
    /// hostile — an approval is not a permanent pass.
    pub fn needs_attention(&self) -> bool {
        self.approval != Approval::Approved || matches!(self.behaviour, Behaviour::Flagged(_))
    }
}

/// The inventory.
#[derive(Debug, Default)]
pub struct Report {
    pub entries: Vec<Entry>,
    /// Ecosystems present that execute install code with no approval mechanism.
    pub unmanaged_ecosystems: Vec<String>,
    /// True when the dependency code was on disk, so `Behaviour` is meaningful.
    pub code_scanned: bool,
}

impl Report {
    pub fn pending(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.approval == Approval::Pending)
            .count()
    }
    pub fn flagged(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| matches!(e.behaviour, Behaviour::Flagged(_)))
            .count()
    }
    /// Approved packages whose script nonetheless looks hostile — the case an
    /// approval mechanism alone cannot catch.
    pub fn approved_but_flagged(&self) -> Vec<&Entry> {
        self.entries
            .iter()
            .filter(|e| {
                e.approval == Approval::Approved && matches!(e.behaviour, Behaviour::Flagged(_))
            })
            .collect()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Read the `allowScripts` map npm's `approve-scripts` writes into package.json.
///
/// Keys are package specs, which for a registry dependency is the bare name but
/// for a local or aliased one is the full spec — so both the spec and its last
/// path segment are accepted when matching.
pub fn read_approvals(root: &Path) -> BTreeSet<String> {
    let Ok(text) = std::fs::read_to_string(root.join("package.json")) else {
        return BTreeSet::new();
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
        return BTreeSet::new();
    };
    let Some(map) = json.get("allowScripts").and_then(|v| v.as_object()) else {
        return BTreeSet::new();
    };
    let mut out = BTreeSet::new();
    for (spec, allowed) in map {
        // A `false` value is an explicit denial, not an approval.
        if allowed.as_bool() == Some(false) {
            continue;
        }
        out.insert(spec.clone());
        if let Some(last) = spec.rsplit('/').next() {
            out.insert(last.to_string());
        }
    }
    out
}

/// Which packages the lockfile says run install scripts.
///
/// npm records `hasInstallScript` per entry, so this works with nothing
/// installed — the decision list does not require the code.
pub fn lockfile_install_scripts(lockfile: &Path) -> BTreeSet<String> {
    let Ok(text) = std::fs::read_to_string(lockfile) else {
        return BTreeSet::new();
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
        return BTreeSet::new();
    };
    let Some(pkgs) = json.get("packages").and_then(|p| p.as_object()) else {
        return BTreeSet::new();
    };
    pkgs.iter()
        .filter(|(_, v)| v.get("hasInstallScript").and_then(|h| h.as_bool()) == Some(true))
        .filter_map(|(k, _)| k.rsplit("node_modules/").next())
        .filter(|n| !n.is_empty())
        .map(str::to_string)
        .collect()
}

/// Build the inventory.
///
/// `with_scripts` is the set of package names known to run install code (from
/// the lockfile); `findings` are the analyzer results, used to describe what
/// those scripts do when the code was readable.
pub fn build(
    deps: &[Dependency],
    with_scripts: &BTreeSet<String>,
    approvals: &BTreeSet<String>,
    findings: &[Finding],
    code_scanned: bool,
) -> Report {
    // Findings about install scripts, indexed by package name.
    let mut by_pkg: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in findings
        .iter()
        .filter(|f| f.category == Category::InstallHook)
    {
        let name = f
            .dependency
            .rsplit_once('@')
            .map(|(n, _)| n)
            .filter(|n| !n.is_empty());
        by_pkg
            .entry(name.unwrap_or(&f.dependency).to_string())
            .or_default()
            .push(f);
    }

    let mut unmanaged: BTreeSet<String> = BTreeSet::new();
    let mut entries: Vec<Entry> = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for d in deps {
        let analyzed = by_pkg.get(&d.name);
        // A package counts when the lockfile flags it, or when the analyzer
        // actually found a script in it — the two sources cover each other.
        if !with_scripts.contains(&d.name) && analyzed.is_none() {
            continue;
        }
        if !seen.insert((d.name.clone(), d.version.clone())) {
            continue;
        }

        // Only npm has an approval mechanism today. Elsewhere the script runs,
        // full stop, and saying "pending" would imply a gate that is not there.
        let approval = if d.ecosystem == Ecosystem::Node {
            if approvals.contains(&d.name) {
                Approval::Approved
            } else {
                Approval::Pending
            }
        } else {
            unmanaged.insert(d.ecosystem.as_str().to_string());
            Approval::Unmanaged
        };
        let (behaviour, severity) = match analyzed {
            Some(fs) => (
                Behaviour::Flagged(fs.iter().map(|f| f.detail.clone()).collect()),
                fs.iter().map(|f| f.severity).max(),
            ),
            None if code_scanned => (Behaviour::Quiet, None),
            None => (Behaviour::Unread, None),
        };
        entries.push(Entry {
            ecosystem: d.ecosystem,
            name: d.name.clone(),
            version: d.version.clone(),
            approval,
            behaviour,
            severity,
        });
    }

    // Worst first: flagged, then pending, then the rest.
    entries.sort_by_key(|e| {
        let tier = match (&e.behaviour, e.approval) {
            (Behaviour::Flagged(_), _) => 0,
            (_, Approval::Unmanaged) => 1,
            (_, Approval::Pending) => 2,
            _ => 3,
        };
        (tier, std::cmp::Reverse(e.severity), e.name.clone())
    });

    Report {
        entries,
        unmanaged_ecosystems: unmanaged.into_iter().collect(),
        code_scanned,
    }
}

/// Render the inventory.
pub fn render(r: &Report, root_label: &str) {
    println!("{}  {}", "install scripts".bold(), root_label.dimmed());
    if r.is_empty() {
        println!();
        crate::gochi::say(
            crate::gochi::Mood::Happy,
            "no dependency runs code at install time",
        );
        return;
    }

    println!(
        "\n  {} package(s) execute code at install time — {} awaiting approval\n",
        r.entries.len(),
        r.pending()
    );
    for e in &r.entries {
        let state = match e.approval {
            Approval::Approved => "approved".green().to_string(),
            Approval::Pending => "pending".truecolor(255, 165, 0).to_string(),
            Approval::Unmanaged => "runs".red().to_string(),
        };
        let mark = match &e.behaviour {
            Behaviour::Flagged(_) => "✗".red().bold().to_string(),
            Behaviour::Unread => "?".dimmed().to_string(),
            Behaviour::Quiet if e.needs_attention() => "·".to_string(),
            Behaviour::Quiet => "·".dimmed().to_string(),
        };
        println!(
            "  {mark} {:<28} {:<10} {}",
            format!("{}@{}", e.name, e.version),
            state,
            match &e.behaviour {
                Behaviour::Quiet => "script read, nothing flagged".dimmed().to_string(),
                Behaviour::Unread => "script not on disk — not checked".dimmed().to_string(),
                Behaviour::Flagged(v) => {
                    crate::analyze::util::snippet(&v.join("; "), 70)
                        .red()
                        .to_string()
                }
            }
        );
    }

    // The case an approval mechanism cannot catch on its own.
    let rotten = r.approved_but_flagged();
    if !rotten.is_empty() {
        println!(
            "\n{}",
            format!(
                "⚠ {} approved package(s) have a script that looks hostile now — an approval \
                 records a name, not a version, so it carries across releases",
                rotten.len()
            )
            .red()
            .bold()
        );
    }

    if !r.code_scanned {
        println!(
            "{}",
            "\nnote: dependency code is not on disk, so no script was read — install the \
             project's dependencies to see what each one does"
                .dimmed()
        );
    }

    if !r.unmanaged_ecosystems.is_empty() {
        println!(
            "{}",
            format!(
                "\n⚠ {} has no approval mechanism — those scripts run on install, \
                 with nothing to withhold them",
                r.unmanaged_ecosystems.join(", ")
            )
            .truecolor(255, 165, 0)
        );
    }

    // The actionable line: what to hand npm once you have decided.
    let approve: Vec<&str> = r
        .entries
        .iter()
        .filter(|e| e.approval == Approval::Pending && e.behaviour == Behaviour::Quiet)
        .map(|e| e.name.as_str())
        .collect();
    if !approve.is_empty() {
        println!(
            "\n  {} {}",
            "to approve the quiet ones:".dimmed(),
            format!("npm approve-scripts {}", approve.join(" ")).cyan()
        );
    }

    println!();
    let mood = if r.flagged() > 0 {
        crate::gochi::Mood::Bad
    } else if r.pending() > 0 || !r.unmanaged_ecosystems.is_empty() {
        crate::gochi::Mood::Alert
    } else {
        crate::gochi::Mood::Happy
    };
    crate::gochi::say(
        mood,
        format!(
            "{} flagged, {} pending, {} approved",
            r.flagged(),
            r.pending(),
            r.entries
                .iter()
                .filter(|e| e.approval == Approval::Approved)
                .count()
        ),
    );
}

/// The `scripts --json` document.
pub fn to_json(r: &Report, root: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "root": root,
        "summary": {
            "total": r.entries.len(),
            "pending": r.pending(),
            "flagged": r.flagged(),
            "approved_but_flagged": r.approved_but_flagged().len(),
            "unmanaged_ecosystems": r.unmanaged_ecosystems,
            // False means no script was read; `behaviour: "unread"` throughout.
            "code_scanned": r.code_scanned,
        },
        "packages": r.entries.iter().map(|e| serde_json::json!({
            "ecosystem": e.ecosystem,
            "name": e.name,
            "version": e.version,
            "approval": match e.approval {
                Approval::Approved => "approved",
                Approval::Pending => "pending",
                Approval::Unmanaged => "unmanaged",
            },
            "behaviour": match &e.behaviour {
                Behaviour::Quiet => "quiet",
                Behaviour::Unread => "unread",
                Behaviour::Flagged(_) => "flagged",
            },
            "findings": match &e.behaviour {
                Behaviour::Flagged(v) => v.clone(),
                _ => Vec::new(),
            },
            "severity": e.severity,
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{LicenseSource, Scope};
    fn dep(name: &str, eco: Ecosystem) -> Dependency {
        Dependency {
            name: name.into(),
            version: "1.0.0".into(),
            ecosystem: eco,
            direct: true,
            scope: Scope::Prod,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url: None,
            integrity: None,
            parents: vec![],
        }
    }

    fn hook(dep: &str, detail: &str, sev: Severity) -> Finding {
        Finding {
            dependency: dep.into(),
            severity: sev,
            category: Category::InstallHook,
            detail: detail.into(),
            location: None,
            evidence: None,
            enrich_url: None,
        }
    }

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn only_packages_that_run_code_are_listed() {
        let deps = vec![
            dep("bcrypt", Ecosystem::Node),
            dep("lodash", Ecosystem::Node),
        ];
        let r = build(&deps, &set(&["bcrypt"]), &set(&[]), &[], true);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].name, "bcrypt");
    }

    #[test]
    fn the_lockfile_alone_answers_which_packages_run_code() {
        // No findings, no code on disk — the decision list still works, which is
        // the point of reading `hasInstallScript` rather than the scripts.
        let deps = vec![dep("bcrypt", Ecosystem::Node)];
        let r = build(&deps, &set(&["bcrypt"]), &set(&[]), &[], false);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].approval, Approval::Pending);
        assert_eq!(r.entries[0].behaviour, Behaviour::Unread);
    }

    #[test]
    fn an_unread_script_is_never_reported_as_quiet() {
        // "We could not look" must not read as "we looked and it was fine".
        let deps = vec![dep("bcrypt", Ecosystem::Node)];
        let unread = build(&deps, &set(&["bcrypt"]), &set(&[]), &[], false);
        assert_eq!(unread.entries[0].behaviour, Behaviour::Unread);
        let read = build(&deps, &set(&["bcrypt"]), &set(&[]), &[], true);
        assert_eq!(read.entries[0].behaviour, Behaviour::Quiet);
    }

    #[test]
    fn approval_comes_from_the_allow_scripts_map() {
        let deps = vec![
            dep("bcrypt", Ecosystem::Node),
            dep("esbuild", Ecosystem::Node),
        ];
        let r = build(
            &deps,
            &set(&["bcrypt", "esbuild"]),
            &set(&["bcrypt"]),
            &[],
            true,
        );
        let by = |n: &str| r.entries.iter().find(|e| e.name == n).unwrap();
        assert_eq!(by("bcrypt").approval, Approval::Approved);
        assert_eq!(by("esbuild").approval, Approval::Pending);
        assert_eq!(r.pending(), 1);
    }

    #[test]
    fn an_approved_package_with_a_hostile_script_is_still_reported() {
        // The case an approval mechanism cannot catch: `allowScripts` records a
        // name, not a version, so it carries across a release that changed the
        // script.
        let deps = vec![dep("bcrypt", Ecosystem::Node)];
        let f = vec![hook(
            "bcrypt@1.0.0",
            "references network/exec primitives",
            Severity::High,
        )];
        let r = build(&deps, &set(&["bcrypt"]), &set(&["bcrypt"]), &f, true);
        assert_eq!(r.entries[0].approval, Approval::Approved);
        assert!(matches!(r.entries[0].behaviour, Behaviour::Flagged(_)));
        assert!(
            r.entries[0].needs_attention(),
            "approval is not a permanent pass"
        );
        assert_eq!(r.approved_but_flagged().len(), 1);
    }

    #[test]
    fn a_non_npm_ecosystem_is_unmanaged_not_pending() {
        // Saying "pending" would imply a gate that does not exist: a setup.py
        // simply runs.
        let deps = vec![dep("ctx", Ecosystem::Python)];
        let f = vec![hook(
            "ctx",
            "setup.py invokes subprocess",
            Severity::Critical,
        )];
        let r = build(&deps, &set(&[]), &set(&[]), &f, true);
        assert_eq!(r.entries[0].approval, Approval::Unmanaged);
        assert_eq!(r.unmanaged_ecosystems, vec!["python"]);
        assert_eq!(
            r.pending(),
            0,
            "an unmanaged script is not awaiting a decision"
        );
    }

    #[test]
    fn an_analyzer_finding_alone_is_enough_to_list_a_package() {
        // The lockfile flag and the analyzer cover each other: a setup.py has no
        // `hasInstallScript` anywhere.
        let deps = vec![dep("ctx", Ecosystem::Python)];
        let f = vec![hook("ctx", "setup.py invokes subprocess", Severity::High)];
        let r = build(&deps, &set(&[]), &set(&[]), &f, true);
        assert_eq!(r.entries.len(), 1);
    }

    #[test]
    fn flagged_packages_sort_above_merely_pending_ones() {
        let deps = vec![
            dep("quiet-pending", Ecosystem::Node),
            dep("nasty", Ecosystem::Node),
        ];
        let f = vec![hook("nasty", "spawns a shell", Severity::Critical)];
        let r = build(
            &deps,
            &set(&["quiet-pending", "nasty"]),
            &set(&[]),
            &f,
            true,
        );
        assert_eq!(r.entries[0].name, "nasty");
    }

    #[test]
    fn approvals_are_read_from_package_json_and_a_false_is_a_denial() {
        let dir = std::env::temp_dir().join(format!("pm-approvals-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            r#"{"allowScripts":{"bcrypt":true,"esbuild":false,"file:../local-thing":true}}"#,
        )
        .unwrap();
        let a = read_approvals(&dir);
        assert!(a.contains("bcrypt"));
        assert!(
            !a.contains("esbuild"),
            "an explicit false is a denial, not an approval"
        );
        // A spec key is matchable by its last segment too.
        assert!(a.contains("local-thing"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_project_without_allow_scripts_has_no_approvals() {
        let dir = std::env::temp_dir().join(format!("pm-noappr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("package.json"), r#"{"name":"x"}"#).unwrap();
        assert!(read_approvals(&dir).is_empty());
        // A missing or unreadable file is empty too, never a panic.
        assert!(read_approvals(Path::new("/nonexistent-dir-xyz")).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_lockfile_scan_finds_nested_and_scoped_packages() {
        let dir = std::env::temp_dir().join(format!("pm-lockscan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let lock = dir.join("package-lock.json");
        std::fs::write(
            &lock,
            r#"{"packages":{
                "":{"name":"root"},
                "node_modules/bcrypt":{"version":"5.1.1","hasInstallScript":true},
                "node_modules/@scope/tool":{"version":"1.0.0","hasInstallScript":true},
                "node_modules/a/node_modules/deep":{"version":"2.0.0","hasInstallScript":true},
                "node_modules/lodash":{"version":"4.17.21"}
            }}"#,
        )
        .unwrap();
        let s = lockfile_install_scripts(&lock);
        assert!(s.contains("bcrypt"));
        assert!(s.contains("@scope/tool"), "scoped names survive the split");
        assert!(s.contains("deep"), "a nested install is still an install");
        assert!(!s.contains("lodash"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_reports_the_coverage_flag_so_unread_is_not_mistaken_for_clean() {
        let deps = vec![dep("bcrypt", Ecosystem::Node)];
        let r = build(&deps, &set(&["bcrypt"]), &set(&[]), &[], false);
        let doc = to_json(&r, "/p");
        assert_eq!(doc["summary"]["code_scanned"], false);
        assert_eq!(doc["packages"][0]["behaviour"], "unread");
        assert_eq!(doc["packages"][0]["approval"], "pending");
    }
}
