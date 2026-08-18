//! Blast radius: what a compromise of one package would reach.
//!
//! [`crate::why`] answers *how did this get here*. This answers *what happens if
//! it turns hostile tomorrow* — which is the question that decides whether you
//! act on a signal or file it.
//!
//! ## Position is the ceiling; current code is only a floor
//!
//! The distinction this module is built around, and the one it must never blur:
//!
//! * **Position** — where the package sits — determines what a compromise
//!   *could* reach. A package with an install hook executes on every machine
//!   that installs it, with that machine's environment: CI secrets, cloud
//!   credentials, the developer's SSH agent. That is true regardless of what its
//!   code does today.
//!
//! * **Current behaviour** — the sensitive APIs its published code already
//!   calls — is a *lower* bound. It tells you what the package does now, not
//!   what a hostile version could do. A package that reads no files today can
//!   read every file tomorrow.
//!
//! Reporting current behaviour as if it were the limit would be the dangerous
//! mistake, so the two are rendered as separate sections with the ceiling first.
//!
//! ## What is computed
//!
//! Reverse reachability over the resolved graph, plus the scope propagation
//! [`crate::scope`] already performed, plus whatever the offline analyzers found
//! for this package. All of it is data the scan already produced — no network.

use std::collections::{BTreeSet, HashMap, HashSet};

use owo_colors::OwoColorize;

use crate::model::{Category, DepRef, Dependency, Finding, Scope};

/// When a compromise of this package would execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// A lifecycle hook — runs on `install`, before anyone reviews anything.
    Install,
    /// No install hook found in code we actually read.
    Runtime,
    /// The dependency's code was not on disk, so this could not be determined.
    ///
    /// Distinct from [`Trigger::Runtime`] on purpose. Most ecosystems keep
    /// dependencies outside the project, and a lockfile-only scan reads none of
    /// them — reporting "runtime only" there would be a clean result nobody
    /// measured, and install-time execution is the highest-leverage position
    /// there is to be wrong about.
    Unknown,
}

/// The blast radius of one package.
#[derive(Debug, Clone)]
pub struct Blast {
    pub package: String,
    /// Every installed version of it; a package pinned twice has two.
    pub versions: Vec<String>,
    /// Packages that transitively depend on it, excluding itself.
    pub dependents: usize,
    /// Total packages in the graph, for the share.
    pub total: usize,
    /// The direct dependencies whose subtree contains it — the entries a user
    /// can actually act on.
    pub via: Vec<String>,
    /// The strongest scope of any installed copy: does it ship?
    pub scope: Scope,
    pub trigger: Trigger,
    /// Sensitive APIs the current code touches (`detail` strings from the scan).
    pub observed: Vec<String>,
    /// Non-install findings against it, worst first.
    pub findings: Vec<Finding>,
}

impl Blast {
    /// Share of the dependency graph that depends on this package.
    pub fn share(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.dependents as f64 / self.total as f64
    }

    /// Is it in the shipped artifact?
    pub fn ships(&self) -> bool {
        self.scope != Scope::Dev
    }

    /// What a compromise could reach, from position alone.
    ///
    /// Deliberately independent of the package's current code: these follow from
    /// *where it runs*, and a hostile version inherits all of them.
    pub fn exposure(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        match self.trigger {
            Trigger::Install => {
                out.push("every machine that installs — CI runners and developer laptops");
                out.push("the install-time environment: env vars, CI secrets, cloud credentials");
                out.push("the source tree it is installed into, before any review or test runs");
            }
            // Not knowing is not the same as knowing it is safe: an install hook
            // may well exist in code this run never read.
            Trigger::Unknown => {
                out.push(
                    "possibly every machine that installs — install this project's \
                     dependencies and re-run to rule an install hook in or out",
                );
            }
            Trigger::Runtime => {}
        }
        if self.ships() {
            out.push("the running application, and whatever it can reach in production");
        } else {
            out.push("the build and test process only — it is not in the shipped artifact");
        }
        if self.trigger == Trigger::Runtime && !self.ships() {
            out.push("nothing until the dev tooling that pulls it in is actually run");
        }
        out
    }
}

/// Compute the blast radius of `target` in a resolved graph.
///
/// `findings` are the offline analyzer results for the same project; pass an
/// empty slice to skip the behavioural section.
pub fn analyze(
    deps: &[Dependency],
    findings: &[Finding],
    target: &str,
    code_scanned: bool,
) -> Option<Blast> {
    let copies: Vec<&Dependency> = deps.iter().filter(|d| d.name == target).collect();
    if copies.is_empty() {
        return None;
    }

    // Children by parent, so reachability can be walked upward from the target.
    let mut parents_of: HashMap<DepRef, Vec<DepRef>> = HashMap::new();
    for d in deps {
        parents_of
            .entry((d.name.clone(), d.version.clone()))
            .or_default()
            .extend(d.parents.iter().cloned());
    }
    let index: HashMap<DepRef, &Dependency> = deps
        .iter()
        .map(|d| ((d.name.clone(), d.version.clone()), d))
        .collect();

    // Everything that transitively depends on any copy of the target.
    let mut seen: HashSet<DepRef> = HashSet::new();
    let mut via: BTreeSet<String> = BTreeSet::new();
    let mut stack: Vec<DepRef> = copies
        .iter()
        .map(|d| (d.name.clone(), d.version.clone()))
        .collect();
    let self_keys: HashSet<DepRef> = stack.iter().cloned().collect();

    while let Some(k) = stack.pop() {
        for p in parents_of.get(&k).into_iter().flatten() {
            if !seen.insert(p.clone()) {
                continue;
            }
            if let Some(d) = index.get(p) {
                if d.direct {
                    via.insert(format!("{}@{}", d.name, d.version));
                }
                stack.push(p.clone());
            }
        }
    }
    // A direct copy of the target is itself an entry point.
    for d in &copies {
        if d.direct {
            via.insert(format!("{}@{}", d.name, d.version));
        }
    }
    // Never count the target's own copies as their own dependents.
    for k in &self_keys {
        seen.remove(k);
    }

    let mine: Vec<&Finding> = findings
        .iter()
        .filter(|f| finding_is_for(f, target))
        .collect();
    let trigger = if mine.iter().any(|f| f.category == Category::InstallHook) {
        Trigger::Install
    } else if code_scanned {
        Trigger::Runtime
    } else {
        Trigger::Unknown
    };
    let observed: Vec<String> = mine
        .iter()
        .filter(|f| f.category == Category::SensitiveApi)
        .map(|f| f.detail.clone())
        .collect();
    let mut other: Vec<Finding> = mine
        .iter()
        .filter(|f| f.category != Category::SensitiveApi)
        .map(|f| (*f).clone())
        .collect();
    other.sort_by(|a, b| b.severity.cmp(&a.severity));

    Some(Blast {
        package: target.to_string(),
        versions: copies.iter().map(|d| d.version.clone()).collect(),
        dependents: seen.len(),
        total: deps.len(),
        via: via.into_iter().collect(),
        // The strongest scope across copies: one production copy means it ships.
        scope: copies.iter().map(|d| d.scope).max().unwrap_or(Scope::Prod),
        trigger,
        observed,
        findings: other,
    })
}

/// Does a finding belong to `target`? `dependency` is `name` or `name@version`.
fn finding_is_for(f: &Finding, target: &str) -> bool {
    f.dependency == target
        || f.dependency
            .rsplit_once('@')
            .is_some_and(|(n, _)| n == target && !n.is_empty())
}

/// Render the blast radius.
pub fn render(b: &Blast, root_label: &str) {
    println!(
        "{}  {}  {}",
        "blast radius".bold(),
        b.package.cyan(),
        format!("(in {root_label})").dimmed()
    );

    let versions = b.versions.join(", ");
    println!("\n  {:<12} {}", "installed".dimmed(), versions);

    let reach = format!(
        "{} of {} packages depend on it ({:.0}%)",
        b.dependents,
        b.total,
        b.share() * 100.0
    );
    let reach = if b.share() >= 0.25 {
        reach.red().bold().to_string()
    } else {
        reach
    };
    println!("  {:<12} {reach}", "reach".dimmed());

    let ships = if b.ships() {
        format!("yes — {} (it is in the shipped artifact)", b.scope.as_str())
            .red()
            .to_string()
    } else {
        "no — dev/test only".green().to_string()
    };
    println!("  {:<12} {ships}", "ships".dimmed());

    let trig = match b.trigger {
        Trigger::Install => "install hook — executes on every install, before review"
            .red()
            .bold()
            .to_string(),
        Trigger::Runtime => "runtime only — executes when the code is called".to_string(),
        Trigger::Unknown => "unknown — dependency code not on disk, so not checked"
            .truecolor(255, 165, 0)
            .to_string(),
    };
    println!("  {:<12} {trig}", "runs".dimmed());

    if !b.via.is_empty() {
        println!(
            "  {:<12} {}",
            "entered via".dimmed(),
            b.via.join(", ").yellow()
        );
    }

    // The ceiling first: this is what a hostile version could reach.
    println!("\n  {}", "if compromised, it reaches".bold());
    for e in b.exposure() {
        println!("    {} {e}", "•".red());
    }

    // Then the floor, explicitly labelled as such.
    if !b.observed.is_empty() || !b.findings.is_empty() {
        println!("\n  {}", "what its current code does".bold());
        for o in &b.observed {
            println!("    {} {o}", "·".dimmed());
        }
        for f in &b.findings {
            println!(
                "    {} [{}] {}",
                "·".dimmed(),
                f.category.as_str().dimmed(),
                crate::analyze::util::snippet(&f.detail, 80)
            );
        }
        println!(
            "    {}",
            "— a lower bound, not a limit: a hostile version is not restricted to this".dimmed()
        );
    }

    println!();
    let mood = if b.trigger == Trigger::Install || (b.ships() && b.share() >= 0.25) {
        crate::gochi::Mood::Bad
    } else if b.ships() {
        crate::gochi::Mood::Alert
    } else {
        crate::gochi::Mood::Idle
    };
    crate::gochi::say(mood, verdict(b));
}

/// One sentence a reader can act on.
fn verdict(b: &Blast) -> String {
    match (b.trigger, b.ships()) {
        (Trigger::Unknown, ships) => format!(
            "{} {} — and whether it runs an install hook is unknown, which is the \
             difference between a runtime risk and one that lands on every machine",
            b.package,
            if ships {
                "ships to production"
            } else {
                "is dev/test only"
            }
        ),
        (Trigger::Install, _) => format!(
            "highest-leverage position: {} runs on every install, so a compromise lands \
             before anyone looks at it",
            b.package
        ),
        (Trigger::Runtime, true) => format!(
            "{} ships to production and {} package(s) depend on it — a compromise reaches \
             your users",
            b.package, b.dependents
        ),
        (Trigger::Runtime, false) => format!(
            "{} is dev/test only and runs no install hook — a compromise stays on the \
             build machine",
            b.package
        ),
    }
}

/// The `why --blast --json` document.
pub fn to_json(b: &Blast, root: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "root": root,
        "package": b.package,
        "versions": b.versions,
        "reach": {
            "dependents": b.dependents,
            "total": b.total,
            "share": (b.share() * 1000.0).round() / 1000.0,
            "via": b.via,
        },
        "position": {
            "ships": b.ships(),
            "scope": b.scope.as_str(),
            "trigger": match b.trigger {
                Trigger::Install => "install",
                Trigger::Runtime => "runtime",
                // Never conflated with "runtime": a consumer must be able to
                // tell "we looked and found none" from "we could not look".
                Trigger::Unknown => "unknown",
            },
        },
        // Split deliberately: `exposure` follows from position and bounds what a
        // hostile version could do; `observed` is only what the current code
        // does, and a consumer must not read it as a limit.
        "exposure": b.exposure(),
        "observed": b.observed,
        "findings": b.findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Ecosystem, LicenseSource, Severity};

    fn dep(name: &str, direct: bool, scope: Scope, parents: &[&str]) -> Dependency {
        Dependency {
            name: name.into(),
            version: "1.0.0".into(),
            ecosystem: Ecosystem::Node,
            direct,
            scope,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url: None,
            integrity: None,
            parents: parents
                .iter()
                .map(|p| ((*p).to_string(), "1.0.0".to_string()))
                .collect(),
        }
    }

    fn finding(dep: &str, cat: Category, detail: &str) -> Finding {
        Finding {
            dependency: dep.into(),
            severity: Severity::High,
            category: cat,
            detail: detail.into(),
            location: None,
            evidence: None,
            enrich_url: None,
        }
    }

    /// app → mid → leaf, plus an unrelated package.
    fn graph() -> Vec<Dependency> {
        vec![
            dep("app", true, Scope::Prod, &[]),
            dep("mid", false, Scope::Prod, &["app"]),
            dep("leaf", false, Scope::Prod, &["mid"]),
            dep("unrelated", true, Scope::Prod, &[]),
        ]
    }

    #[test]
    fn counts_transitive_dependents_not_just_direct_parents() {
        let b = analyze(&graph(), &[], "leaf", true).unwrap();
        assert_eq!(b.dependents, 2, "mid and app, not just mid");
        assert_eq!(b.total, 4);
        assert_eq!(
            b.via,
            vec!["app@1.0.0"],
            "the entry point a user can act on"
        );
    }

    #[test]
    fn a_package_is_not_its_own_dependent() {
        let b = analyze(&graph(), &[], "app", true).unwrap();
        assert_eq!(b.dependents, 0);
        assert_eq!(
            b.via,
            vec!["app@1.0.0"],
            "a direct package is its own entry point"
        );
    }

    #[test]
    fn an_absent_package_has_no_blast_radius() {
        assert!(analyze(&graph(), &[], "ghost", true).is_none());
    }

    #[test]
    fn a_cycle_terminates() {
        let deps = vec![
            dep("root", true, Scope::Prod, &[]),
            dep("a", false, Scope::Prod, &["root", "b"]),
            dep("b", false, Scope::Prod, &["a"]),
        ];
        let b = analyze(&deps, &[], "b", true).unwrap();
        assert_eq!(b.dependents, 2);
    }

    #[test]
    fn an_install_hook_is_the_highest_leverage_position() {
        let f = vec![finding(
            "leaf",
            Category::InstallHook,
            "postinstall runs a script",
        )];
        let b = analyze(&graph(), &f, "leaf", true).unwrap();
        assert_eq!(b.trigger, Trigger::Install);
        // Position alone puts CI secrets in scope — independent of the code.
        let e = b.exposure().join(" | ");
        assert!(e.contains("CI"), "got: {e}");
        assert!(e.contains("env vars"), "got: {e}");
        assert!(verdict(&b).contains("every install"));
    }

    #[test]
    fn a_dev_only_package_without_a_hook_stays_on_the_build_machine() {
        let deps = vec![
            dep("jest", true, Scope::Dev, &[]),
            dep("helper", false, Scope::Dev, &["jest"]),
        ];
        let b = analyze(&deps, &[], "helper", true).unwrap();
        assert!(!b.ships());
        assert_eq!(b.trigger, Trigger::Runtime);
        assert!(
            b.exposure()
                .iter()
                .any(|e| e.contains("not in the shipped artifact"))
        );
        assert!(verdict(&b).contains("build machine"));
    }

    #[test]
    fn a_dev_only_package_with_a_hook_still_reaches_every_machine() {
        // The trap: "dev-only" reads as harmless, but an install hook runs on
        // every laptop and CI runner regardless of scope.
        let deps = vec![dep("tool", true, Scope::Dev, &[])];
        let f = vec![finding("tool", Category::InstallHook, "preinstall")];
        let b = analyze(&deps, &f, "tool", true).unwrap();
        assert!(!b.ships());
        let e = b.exposure().join(" | ");
        assert!(
            e.contains("developer laptops"),
            "scope must not downgrade an install hook: {e}"
        );
    }

    #[test]
    fn one_production_copy_makes_the_package_ship() {
        // Two copies, one dev one prod: the blast is the prod one.
        let deps = vec![
            dep("a", true, Scope::Prod, &[]),
            Dependency {
                version: "2.0.0".into(),
                ..dep("dup", false, Scope::Dev, &["a"])
            },
            dep("dup", false, Scope::Prod, &["a"]),
        ];
        let b = analyze(&deps, &[], "dup", true).unwrap();
        assert_eq!(b.scope, Scope::Prod);
        assert!(b.ships());
        assert_eq!(b.versions.len(), 2);
    }

    #[test]
    fn observed_behaviour_is_separated_from_positional_exposure() {
        // The distinction the whole module is built around: what the code does
        // today must never be presented as the limit.
        let f = vec![
            finding("leaf", Category::SensitiveApi, "uses net, fs"),
            finding("leaf", Category::Obfuscation, "high entropy"),
        ];
        let b = analyze(&graph(), &f, "leaf", true).unwrap();
        assert_eq!(b.observed, vec!["uses net, fs"]);
        assert_eq!(
            b.findings.len(),
            1,
            "non-sensitive-API findings listed separately"
        );
        // Exposure is derived from position, so it says nothing about net/fs.
        assert!(!b.exposure().join(" ").contains("uses net"));
    }

    #[test]
    fn findings_match_a_versioned_dependency_label() {
        let f = vec![finding("leaf@1.0.0", Category::InstallHook, "postinstall")];
        assert_eq!(
            analyze(&graph(), &f, "leaf", true).unwrap().trigger,
            Trigger::Install
        );
        // And must not match a different package sharing a prefix.
        let f = vec![finding("leafpad@1.0.0", Category::InstallHook, "x")];
        assert_eq!(
            analyze(&graph(), &f, "leaf", true).unwrap().trigger,
            Trigger::Runtime
        );
    }

    #[test]
    fn json_keeps_exposure_and_observed_apart() {
        let f = vec![finding("leaf", Category::SensitiveApi, "uses net")];
        let doc = to_json(&analyze(&graph(), &f, "leaf", true).unwrap(), "/p");
        assert!(!doc["exposure"].as_array().unwrap().is_empty());
        assert_eq!(doc["observed"][0], "uses net");
        assert_eq!(doc["reach"]["dependents"], 2);
        assert_eq!(doc["position"]["ships"], true);
    }

    #[test]
    fn share_is_zero_for_an_empty_graph_rather_than_nan() {
        let b = Blast {
            package: "x".into(),
            versions: vec![],
            dependents: 0,
            total: 0,
            via: vec![],
            scope: Scope::Prod,
            trigger: Trigger::Runtime,
            observed: vec![],
            findings: vec![],
        };
        assert_eq!(b.share(), 0.0);
    }

    #[test]
    fn unread_code_is_unknown_not_a_clean_runtime_verdict() {
        // Most ecosystems keep dependencies outside the project, so a
        // lockfile-only scan reads none of them. Reporting "runtime only" there
        // would be a clean result nobody measured — and install-time execution
        // is the highest-leverage thing to be wrong about.
        let b = analyze(&graph(), &[], "leaf", false).unwrap();
        assert_eq!(b.trigger, Trigger::Unknown);
        let e = b.exposure().join(" | ");
        assert!(e.contains("possibly every machine"), "got: {e}");
        assert!(verdict(&b).contains("unknown"));

        // With code read and no hook found, the verdict is earned.
        let b = analyze(&graph(), &[], "leaf", true).unwrap();
        assert_eq!(b.trigger, Trigger::Runtime);
        assert!(!b.exposure().join(" ").contains("possibly"));
    }

    #[test]
    fn json_never_conflates_unknown_with_runtime() {
        let unknown = to_json(&analyze(&graph(), &[], "leaf", false).unwrap(), "/p");
        let runtime = to_json(&analyze(&graph(), &[], "leaf", true).unwrap(), "/p");
        assert_eq!(unknown["position"]["trigger"], "unknown");
        assert_eq!(runtime["position"]["trigger"], "runtime");
    }
}
