//! `postmortem fix` — turn a vulnerability report into the change that clears it.
//!
//! Every other command answers *what is wrong*. This one answers *what do I
//! edit*, which is the only question that ends with the problem gone.
//!
//! ## What it can compute, and what it cannot
//!
//! The advisory databases publish the version that fixes each issue, so the
//! target is exact: `lodash@4.17.15` is cleared by `4.18.0`. Where a package
//! sits in the graph then decides the remedy, and the two cases are very
//! different in how confidently they can be stated:
//!
//! * **A direct dependency** is yours to move. Raise the constraint in your
//!   manifest and the resolver does the rest. The instruction is exact.
//!
//! * **A transitive dependency** is pinned by whatever pulls it in, and moving
//!   it means either bumping that ancestor — *if* a release of it accepts the
//!   fixed version — or forcing the version with an override.
//!
//! postmortem does **not** claim to know which ancestor release accepts the fix.
//! Answering that needs every candidate version's declared constraints, which is
//! a package-manager resolution problem and a great deal of network traffic, and
//! a wrong answer would send someone chasing an upgrade that cannot work. So the
//! ancestors are named — that is a fact, read from the resolved graph — and the
//! remedy offered is the **override**, which is exact because it does not depend
//! on anyone else's constraints.
//!
//! Overrides are a real tool with a real cost: they force a version the ancestor
//! never declared support for. That is stated in the output rather than buried,
//! because the honest sentence here is "this will clear the advisory, and you
//! should run your tests".
//!
//! ## Nothing is written
//!
//! The plan is printed, never applied. Editing a manifest is a decision, and the
//! snippets are emitted ready to paste.

use std::collections::{BTreeMap, BTreeSet};

use owo_colors::OwoColorize;

use crate::model::{Dependency, Ecosystem, Severity};
use crate::vuln::{Vuln, VulnPackage};

/// Where a vulnerable package sits, which decides the shape of the remedy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    /// Declared in the project's own manifest.
    Direct,
    /// Pulled in by something else.
    Transitive,
}

/// One vulnerable package and the change that clears it.
#[derive(Debug, Clone)]
pub struct Remedy {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub installed: String,
    /// The earliest version clearing every advisory below. `None` when at least
    /// one has no published fix — see [`Remedy::blocked_by`].
    pub target: Option<String>,
    pub position: Position,
    /// The direct dependencies this package hangs off, for a transitive one.
    /// Sorted and deduplicated; empty when it is itself direct.
    pub via: Vec<String>,
    pub vulns: Vec<Vuln>,
}

impl Remedy {
    /// The worst advisory severity — what sorts the plan.
    pub fn worst(&self) -> Severity {
        self.vulns
            .iter()
            .map(|v| v.severity)
            .max()
            .unwrap_or(Severity::Info)
    }

    /// Advisories with no published fix. A remedy carrying any of these cannot
    /// be fully resolved by upgrading, and saying so is the point: an upgrade
    /// that silently leaves one open is worse than no advice.
    pub fn blocked_by(&self) -> Vec<&Vuln> {
        self.vulns.iter().filter(|v| v.fixed.is_none()).collect()
    }

    /// Can an upgrade clear every advisory here?
    pub fn is_actionable(&self) -> bool {
        self.target.is_some() && self.blocked_by().is_empty()
    }
}

/// The whole remediation plan.
#[derive(Debug, Default)]
pub struct Plan {
    pub remedies: Vec<Remedy>,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.remedies.is_empty()
    }

    /// Remedies an upgrade can actually clear.
    pub fn actionable(&self) -> impl Iterator<Item = &Remedy> {
        self.remedies.iter().filter(|r| r.is_actionable())
    }

    /// Advisories with no published fix anywhere in the plan.
    pub fn unfixable(&self) -> usize {
        self.remedies.iter().map(|r| r.blocked_by().len()).sum()
    }

    pub fn advisories(&self) -> usize {
        self.remedies.iter().map(|r| r.vulns.len()).sum()
    }
}

/// Build the plan from a resolved graph and its advisories.
///
/// Pure: everything here is derived from data already fetched, so the plan is
/// deterministic and testable without a network.
pub fn plan(deps: &[Dependency], vulns: &[VulnPackage]) -> Plan {
    // Direct dependencies, for the reverse walk and the position check.
    let index: BTreeMap<(&str, &str), &Dependency> = deps
        .iter()
        .map(|d| ((d.name.as_str(), d.version.as_str()), d))
        .collect();

    let mut remedies = Vec::new();
    for vp in vulns {
        let Some(dep) = index.get(&(vp.name.as_str(), vp.version.as_str())) else {
            // An advisory for something not in the graph: the scan and the parse
            // disagree, so there is nothing to advise on. Skipping is right —
            // inventing a position would be a guess.
            continue;
        };

        let target = best_target(&vp.vulns, &vp.version);
        let position = if dep.direct {
            Position::Direct
        } else {
            Position::Transitive
        };
        let via = if dep.direct {
            Vec::new()
        } else {
            direct_ancestors(dep, &index)
        };

        remedies.push(Remedy {
            ecosystem: dep.ecosystem,
            name: vp.name.clone(),
            installed: vp.version.clone(),
            target,
            position,
            via,
            vulns: vp.vulns.clone(),
        });
    }

    // Worst first, then most advisories, then by name for a stable order.
    remedies.sort_by(|a, b| {
        b.worst()
            .cmp(&a.worst())
            .then(b.vulns.len().cmp(&a.vulns.len()))
            .then(a.name.cmp(&b.name))
    });
    Plan { remedies }
}

/// The single version that clears every fixable advisory: the **highest** of
/// their individual fixes.
///
/// Taking the lowest would clear one advisory and leave another open, which is
/// the failure mode that makes remediation advice worse than none.
fn best_target(vulns: &[Vuln], installed: &str) -> Option<String> {
    let mut best: Option<String> = None;
    for v in vulns {
        let Some(f) = v.fixed.as_deref() else {
            continue;
        };
        // A "fix" at or below what is installed cannot be the answer; that means
        // the ranges disagree with the installed version, so trust neither.
        if !crate::semver::lt(installed, f) {
            continue;
        }
        best = Some(match best {
            Some(b) if crate::semver::lt(&b, f) => f.to_string(),
            Some(b) => b,
            None => f.to_string(),
        });
    }
    best
}

/// The direct dependencies a transitive package hangs off.
///
/// Walks `parents` upward, stopping at each direct dependency. Cycles terminate
/// because a node is visited once.
fn direct_ancestors(dep: &Dependency, index: &BTreeMap<(&str, &str), &Dependency>) -> Vec<String> {
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut out: BTreeSet<String> = BTreeSet::new();
    let mut stack: Vec<(String, String)> = dep.parents.clone();

    while let Some(key) = stack.pop() {
        if !seen.insert(key.clone()) {
            continue;
        }
        let Some(parent) = index.get(&(key.0.as_str(), key.1.as_str())) else {
            // An edge to something the parse did not resolve. Name it anyway —
            // it is still the ancestor the user has to deal with.
            out.insert(key.0.clone());
            continue;
        };
        if parent.direct {
            out.insert(format!("{}@{}", parent.name, parent.version));
        } else {
            stack.extend(parent.parents.clone());
        }
    }
    out.into_iter().collect()
}

// --- rendering ----------------------------------------------------------------

/// The command that raises a direct dependency to `target`.
pub fn upgrade_command(eco: Ecosystem, name: &str, target: &str) -> Option<String> {
    Some(match eco {
        Ecosystem::Node => format!("npm install {name}@^{target}"),
        Ecosystem::Python => format!("pip install --upgrade '{name}>={target}'"),
        Ecosystem::Rust => format!("cargo update -p {name} --precise {target}"),
        Ecosystem::Ruby => format!("bundle update {name} --conservative"),
        Ecosystem::Php => format!("composer require {name}:^{target}"),
        Ecosystem::Go => format!("go get {name}@v{}", target.trim_start_matches('v')),
        Ecosystem::Java => return None, // no single canonical CLI; the pin is the edit
        // OS packages are the distro's to move, not a manifest edit.
        Ecosystem::Brew => format!("brew upgrade {name}"),
        Ecosystem::Pacman => format!("pacman -Syu {name}"),
        Ecosystem::Apt => format!("apt install --only-upgrade {name}"),
        Ecosystem::Dnf => format!("dnf upgrade {name}"),
        Ecosystem::Nix => return None,
        Ecosystem::Apk => format!("apk upgrade {name}"),
        // `winget list` also reports MSIX and registry-uninstall entries under
        // synthetic ids; those are not winget's to upgrade, so there is no
        // command to offer.
        Ecosystem::Winget => {
            let up = name.to_ascii_uppercase();
            if up.starts_with("MSIX\\") || up.starts_with("ARP\\") {
                return None;
            }
            format!("winget upgrade --id {name}")
        }
        // MSIX updates come from the Store or the publisher's own channel;
        // there is no per-package command to hand the user.
        Ecosystem::Msix => return None,
    })
}

/// The manifest snippet that forces `target` regardless of what an ancestor
/// declared — the exact remedy for a transitive package.
///
/// `None` where the ecosystem has no override mechanism, which is itself worth
/// reporting rather than papering over.
pub fn override_snippet(
    eco: Ecosystem,
    name: &str,
    target: &str,
) -> Option<(&'static str, String)> {
    Some(match eco {
        Ecosystem::Node => (
            "package.json (npm) — or \"resolutions\" for yarn, \"pnpm.overrides\" for pnpm",
            format!("\"overrides\": {{ \"{name}\": \"^{target}\" }}"),
        ),
        Ecosystem::Rust => (
            "Cargo.toml",
            format!("[patch.crates-io]\n{name} = \"{target}\""),
        ),
        Ecosystem::Php => (
            "composer.json",
            format!("\"require\": {{ \"{name}\": \"^{target}\" }}"),
        ),
        Ecosystem::Python => (
            "requirements.txt / constraints.txt",
            format!("{name}>={target}"),
        ),
        Ecosystem::Ruby => ("Gemfile", format!("gem \"{name}\", \">= {target}\"")),
        Ecosystem::Java => (
            "pom.xml",
            format!("<dependencyManagement> pins {name} to {target}"),
        ),
        // Go resolves to the highest required version, so requiring it directly
        // *is* the override.
        Ecosystem::Go => (
            "go.mod",
            format!("require {name} v{}", target.trim_start_matches('v')),
        ),
        _ => return None,
    })
}

/// Render the plan.
pub fn render(plan: &Plan, root_label: &str) {
    println!("{}  {}", "fix".bold(), root_label.dimmed());

    if plan.is_empty() {
        println!();
        crate::gochi::say(crate::gochi::Mood::Happy, "no known vulnerabilities to fix");
        return;
    }

    let actionable = plan.actionable().count();
    println!(
        "\n  {} advisor{} across {} package{}\n",
        plan.advisories(),
        if plan.advisories() == 1 { "y" } else { "ies" },
        plan.remedies.len(),
        if plan.remedies.len() == 1 { "" } else { "s" },
    );

    for r in &plan.remedies {
        let sev = sev_label(r.worst());
        let head = format!("{}@{}", r.name, r.installed);
        match &r.target {
            Some(t) => println!(
                "  {sev}  {}  {}  {}",
                head.bold(),
                "→".dimmed(),
                t.green().bold()
            ),
            None => println!("  {sev}  {}  {}", head.bold(), "(no published fix)".red()),
        }

        for v in &r.vulns {
            let mark = if v.fixed.is_none() {
                "✗".red().to_string()
            } else {
                "·".dimmed().to_string()
            };
            println!(
                "        {mark} {} {}",
                v.id.dimmed(),
                crate::analyze::util::snippet(&v.summary, 78).dimmed()
            );
        }

        match r.position {
            Position::Direct => {
                if let Some(t) = &r.target
                    && let Some(cmd) = upgrade_command(r.ecosystem, &r.name, t)
                {
                    println!("        {} {}", "direct —".dimmed(), cmd.cyan());
                }
            }
            Position::Transitive => {
                let via = if r.via.is_empty() {
                    "an unresolved parent".to_string()
                } else {
                    r.via.join(", ")
                };
                println!("        {} {}", "pulled in by".dimmed(), via.yellow());
                if let Some(t) = &r.target
                    && let Some((where_, snippet)) = override_snippet(r.ecosystem, &r.name, t)
                {
                    println!("        {} {}", "override in".dimmed(), where_.dimmed());
                    for line in snippet.lines() {
                        println!("          {}", line.cyan());
                    }
                }
            }
        }
        println!();
    }

    if plan.unfixable() > 0 {
        println!(
            "{}",
            format!(
                "⚠ {} advisor{} have no published fix — an upgrade cannot clear {}",
                plan.unfixable(),
                if plan.unfixable() == 1 { "y" } else { "ies" },
                if plan.unfixable() == 1 { "it" } else { "them" }
            )
            .truecolor(255, 165, 0)
        );
    }
    if plan
        .remedies
        .iter()
        .any(|r| r.position == Position::Transitive)
    {
        println!(
            "{}",
            "note: an override forces a version the parent never declared support for — \
             clear the advisory, then run your tests"
                .dimmed()
        );
    }

    let mood = if actionable == plan.remedies.len() {
        crate::gochi::Mood::Alert
    } else {
        crate::gochi::Mood::Bad
    };
    crate::gochi::say(
        mood,
        format!(
            "{actionable} of {} fixable by upgrading",
            plan.remedies.len()
        ),
    );
}

fn sev_label(s: Severity) -> String {
    match s {
        Severity::Critical => "CRIT".red().bold().to_string(),
        Severity::High => "HIGH".red().to_string(),
        Severity::Medium => "MED ".truecolor(255, 165, 0).to_string(),
        Severity::Low => "LOW ".yellow().to_string(),
        Severity::Info => "INFO".dimmed().to_string(),
    }
}

/// The `fix --json` document.
pub fn to_json(plan: &Plan, root: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "root": root,
        "summary": {
            "packages": plan.remedies.len(),
            "advisories": plan.advisories(),
            "actionable": plan.actionable().count(),
            "unfixable": plan.unfixable(),
        },
        "remedies": plan.remedies.iter().map(|r| serde_json::json!({
            "ecosystem": r.ecosystem,
            "name": r.name,
            "installed": r.installed,
            // `null` means no upgrade clears it — never an empty string, which a
            // consumer could mistake for a version.
            "target": r.target,
            "position": match r.position {
                Position::Direct => "direct",
                Position::Transitive => "transitive",
            },
            "via": r.via,
            "actionable": r.is_actionable(),
            "command": r.target.as_deref().filter(|_| r.position == Position::Direct)
                .and_then(|t| upgrade_command(r.ecosystem, &r.name, t)),
            "override": r.target.as_deref().filter(|_| r.position == Position::Transitive)
                .and_then(|t| override_snippet(r.ecosystem, &r.name, t))
                .map(|(w, s)| serde_json::json!({ "where": w, "snippet": s })),
            "vulnerabilities": r.vulns,
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{LicenseSource, Scope};

    fn dep(name: &str, version: &str, direct: bool, parents: &[(&str, &str)]) -> Dependency {
        Dependency {
            name: name.into(),
            version: version.into(),
            ecosystem: Ecosystem::Node,
            direct,
            scope: Scope::Prod,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url: None,
            integrity: None,
            parents: parents
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn vuln(id: &str, sev: Severity, fixed: Option<&str>) -> Vuln {
        Vuln {
            id: id.into(),
            severity: sev,
            summary: "s".into(),
            fixed: fixed.map(String::from),
        }
    }

    fn vp(name: &str, version: &str, vulns: Vec<Vuln>) -> VulnPackage {
        VulnPackage {
            name: name.into(),
            version: version.into(),
            ecosystem: "node".into(),
            vulns,
        }
    }

    #[test]
    fn a_direct_package_gets_an_upgrade_command() {
        let deps = vec![dep("lodash", "4.17.15", true, &[])];
        let vulns = vec![vp(
            "lodash",
            "4.17.15",
            vec![vuln("GHSA-a", Severity::High, Some("4.18.0"))],
        )];
        let p = plan(&deps, &vulns);

        assert_eq!(p.remedies.len(), 1);
        let r = &p.remedies[0];
        assert_eq!(r.position, Position::Direct);
        assert_eq!(r.target.as_deref(), Some("4.18.0"));
        assert!(r.via.is_empty());
        assert!(r.is_actionable());
        assert_eq!(
            upgrade_command(Ecosystem::Node, "lodash", "4.18.0").as_deref(),
            Some("npm install lodash@^4.18.0")
        );
    }

    #[test]
    fn a_transitive_package_names_the_direct_ancestors() {
        // The user cannot act on `ms` — they act on `express`, or override.
        let deps = vec![
            dep("express", "4.18.2", true, &[]),
            dep("send", "0.18.0", false, &[("express", "4.18.2")]),
            dep("ms", "2.0.0", false, &[("send", "0.18.0")]),
        ];
        let vulns = vec![vp(
            "ms",
            "2.0.0",
            vec![vuln("GHSA-b", Severity::Medium, Some("2.1.3"))],
        )];
        let r = &plan(&deps, &vulns).remedies[0];

        assert_eq!(r.position, Position::Transitive);
        assert_eq!(
            r.via,
            vec!["express@4.18.2"],
            "the walk stops at the direct dependency"
        );
        assert!(override_snippet(Ecosystem::Node, "ms", "2.1.3").is_some());
    }

    #[test]
    fn several_paths_to_one_package_are_deduplicated() {
        let deps = vec![
            dep("a", "1.0", true, &[]),
            dep("b", "1.0", true, &[]),
            dep(
                "shared",
                "1.0",
                false,
                &[("a", "1.0"), ("b", "1.0"), ("a", "1.0")],
            ),
        ];
        let vulns = vec![vp(
            "shared",
            "1.0",
            vec![vuln("G", Severity::Low, Some("2.0"))],
        )];
        assert_eq!(plan(&deps, &vulns).remedies[0].via, vec!["a@1.0", "b@1.0"]);
    }

    #[test]
    fn the_target_clears_every_advisory_not_just_the_first() {
        // Taking the lowest fix would clear one and leave the other open — the
        // failure mode that makes advice worse than none.
        let deps = vec![dep("x", "1.0.0", true, &[])];
        let vulns = vec![vp(
            "x",
            "1.0.0",
            vec![
                vuln("G-1", Severity::Low, Some("1.2.0")),
                vuln("G-2", Severity::High, Some("1.5.0")),
                vuln("G-3", Severity::Low, Some("1.1.0")),
            ],
        )];
        let r = &plan(&deps, &vulns).remedies[0];
        assert_eq!(r.target.as_deref(), Some("1.5.0"));
        assert!(r.is_actionable());
    }

    #[test]
    fn an_advisory_without_a_fix_blocks_the_remedy() {
        let deps = vec![dep("x", "1.0.0", true, &[])];
        let vulns = vec![vp(
            "x",
            "1.0.0",
            vec![
                vuln("G-1", Severity::High, Some("1.2.0")),
                vuln("G-2", Severity::High, None),
            ],
        )];
        let p = plan(&deps, &vulns);
        let r = &p.remedies[0];
        // A target still exists for the fixable half, but the remedy is not
        // actionable: upgrading would silently leave G-2 open.
        assert_eq!(r.target.as_deref(), Some("1.2.0"));
        assert_eq!(r.blocked_by().len(), 1);
        assert!(!r.is_actionable());
        assert_eq!(p.unfixable(), 1);
        assert_eq!(p.actionable().count(), 0);
    }

    #[test]
    fn a_fix_at_or_below_the_installed_version_is_not_a_target() {
        // The database and the lockfile disagree; recommending a downgrade would
        // be nonsense, so neither is trusted.
        let deps = vec![dep("x", "2.0.0", true, &[])];
        let vulns = vec![vp(
            "x",
            "2.0.0",
            vec![vuln("G", Severity::High, Some("1.0.0"))],
        )];
        assert_eq!(plan(&deps, &vulns).remedies[0].target, None);
    }

    #[test]
    fn an_advisory_for_a_package_outside_the_graph_is_skipped() {
        // The scan and the parse disagree; inventing a position would be a guess.
        let deps = vec![dep("x", "1.0.0", true, &[])];
        let vulns = vec![vp(
            "ghost",
            "9.9.9",
            vec![vuln("G", Severity::High, Some("10.0"))],
        )];
        assert!(plan(&deps, &vulns).is_empty());
    }

    #[test]
    fn the_plan_is_ordered_worst_first() {
        let deps = vec![dep("low", "1.0", true, &[]), dep("crit", "1.0", true, &[])];
        let vulns = vec![
            vp(
                "low",
                "1.0",
                vec![vuln("G-low", Severity::Low, Some("2.0"))],
            ),
            vp(
                "crit",
                "1.0",
                vec![vuln("G-crit", Severity::Critical, Some("2.0"))],
            ),
        ];
        let p = plan(&deps, &vulns);
        assert_eq!(p.remedies[0].name, "crit");
        assert_eq!(p.remedies[1].name, "low");
    }

    #[test]
    fn a_cycle_in_the_graph_terminates() {
        let deps = vec![
            dep("root", "1.0", true, &[]),
            dep("a", "1.0", false, &[("root", "1.0"), ("b", "1.0")]),
            dep("b", "1.0", false, &[("a", "1.0")]),
        ];
        let vulns = vec![vp("b", "1.0", vec![vuln("G", Severity::Low, Some("2.0"))])];
        assert_eq!(plan(&deps, &vulns).remedies[0].via, vec!["root@1.0"]);
    }

    #[test]
    fn json_never_emits_an_empty_string_for_a_missing_target() {
        let deps = vec![dep("x", "1.0.0", true, &[])];
        let vulns = vec![vp("x", "1.0.0", vec![vuln("G", Severity::High, None)])];
        let doc = to_json(&plan(&deps, &vulns), "/p");
        assert!(doc["remedies"][0]["target"].is_null());
        assert_eq!(doc["remedies"][0]["actionable"], false);
        assert_eq!(doc["summary"]["unfixable"], 1);
    }

    #[test]
    fn json_offers_a_command_for_direct_and_an_override_for_transitive() {
        let deps = vec![
            dep("direct", "1.0", true, &[]),
            dep("deep", "1.0", false, &[("direct", "1.0")]),
        ];
        let vulns = vec![
            vp(
                "direct",
                "1.0",
                vec![vuln("G-1", Severity::High, Some("2.0"))],
            ),
            vp(
                "deep",
                "1.0",
                vec![vuln("G-2", Severity::High, Some("3.0"))],
            ),
        ];
        let doc = to_json(&plan(&deps, &vulns), "/p");
        let by_name = |n: &str| {
            doc["remedies"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["name"] == n)
                .unwrap()
                .clone()
        };
        let d = by_name("direct");
        assert!(d["command"].is_string());
        assert!(d["override"].is_null(), "a direct dep needs no override");

        let t = by_name("deep");
        assert!(t["override"]["snippet"].is_string());
        assert!(
            t["command"].is_null(),
            "a transitive dep is not installed directly"
        );
    }
}
