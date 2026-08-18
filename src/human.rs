//! The maintainer graph: which *people* control your dependency tree.
//!
//! A dependency tree is usually read as a list of packages, but packages are not
//! the unit that gets compromised — accounts are. One phished maintainer
//! publishes to every package they own, and everything downstream of those
//! packages inherits the result. So the question worth asking is not "how many
//! dependencies do I have" but "how few people could change all of them".
//!
//! ## Reach, not package count
//!
//! An account that owns three packages sounds small. If one of those three is
//! `debug`, everything in the tree depends on it. So each account is measured by
//! **reach** — the transitive closure of everything depending on any package it
//! controls — rather than by how many packages it owns. Reach is what a
//! compromise actually touches; the owned count is trivia beside it.
//!
//! Reaches deliberately **overlap** and do not sum: two accounts on the same
//! package each reach everything below it. So "3 accounts control 41%" means the
//! union of their reach, computed as a set, never as an addition.
//!
//! ## Coverage is part of the answer
//!
//! Maintainer data is free only where the registry document postmortem already
//! fetches carries it: npm (the packument) and Packagist. crates.io, RubyGems
//! and PyPI would each need another call per package, so their packages have no
//! attribution here.
//!
//! Unattributed packages are counted and reported. A concentration figure over
//! a tree that is half unattributed means something very different from the same
//! figure over a fully-attributed one, and the reader has to be able to tell.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use owo_colors::OwoColorize;

use crate::model::{DepRef, Dependency};
use crate::resolve::Resolution;

/// One account and what it controls.
#[derive(Debug, Clone)]
pub struct Maintainer {
    pub name: String,
    /// Packages this account can publish to, as `name@version`.
    pub owns: Vec<String>,
    /// Everything that transitively depends on any of them, plus the packages
    /// themselves — what a compromise of this account would touch.
    pub reach: usize,
}

/// The whole graph.
#[derive(Debug, Default)]
pub struct Graph {
    pub maintainers: Vec<Maintainer>,
    /// Packages in the tree.
    pub total: usize,
    /// Packages with at least one known maintainer.
    pub attributed: usize,
    /// Ecosystems present whose registries we do not query for maintainers.
    pub unattributed_ecosystems: Vec<String>,
}

impl Graph {
    /// Share of the tree reachable from the `n` largest accounts, as a **union**
    /// — reaches overlap heavily, so adding them would overcount badly.
    pub fn concentration(&self, n: usize, deps: &[Dependency]) -> (usize, f64) {
        if self.total == 0 {
            return (0, 0.0);
        }
        let index = dependents_index(deps);
        let mut union: HashSet<DepRef> = HashSet::new();
        for m in self.maintainers.iter().take(n) {
            for pkg in &m.owns {
                if let Some(key) = parse_key(pkg) {
                    collect_dependents(&index, &key, &mut union);
                    union.insert(key);
                }
            }
        }
        (union.len(), union.len() as f64 / self.total as f64)
    }

    /// Fraction of the tree with no known maintainer.
    pub fn unattributed(&self) -> usize {
        self.total.saturating_sub(self.attributed)
    }
}

/// `name@version` → the graph key.
fn parse_key(s: &str) -> Option<DepRef> {
    let (n, v) = s.rsplit_once('@')?;
    (!n.is_empty()).then(|| (n.to_string(), v.to_string()))
}

/// package → the packages that depend on it.
///
/// `Dependency::parents` already *is* that relation — a parent is something that
/// requires this package — so this is a direct index of it, not an inversion.
/// Getting the direction wrong here would measure what a package depends on
/// instead of what depends on it, and report the reach of a leaf as the reach of
/// the root.
fn dependents_index(deps: &[Dependency]) -> HashMap<DepRef, Vec<DepRef>> {
    deps.iter()
        .map(|d| ((d.name.clone(), d.version.clone()), d.parents.clone()))
        .collect()
}

/// Everything that (transitively) depends on `key`, added to `out`.
///
/// Walks the direction a compromise propagates: a hostile package poisons every
/// package that requires it, and so on up to the roots.
fn collect_dependents(
    dependents: &HashMap<DepRef, Vec<DepRef>>,
    key: &DepRef,
    out: &mut HashSet<DepRef>,
) {
    let mut stack = vec![key.clone()];
    while let Some(k) = stack.pop() {
        for up in dependents.get(&k).into_iter().flatten() {
            if out.insert(up.clone()) {
                stack.push(up.clone());
            }
        }
    }
}

/// Build the maintainer graph.
pub fn graph(deps: &[Dependency], resolutions: &HashMap<DepRef, Resolution>) -> Graph {
    let dependents_of = dependents_index(deps);

    let mut owned: BTreeMap<String, BTreeSet<DepRef>> = BTreeMap::new();
    let mut attributed = 0usize;
    let mut unattributed_ecos: BTreeSet<String> = BTreeSet::new();

    for d in deps {
        let key = (d.name.clone(), d.version.clone());
        let names = resolutions
            .get(&key)
            .map(|r| r.maintainers.as_slice())
            .unwrap_or(&[]);
        if names.is_empty() {
            unattributed_ecos.insert(d.ecosystem.as_str().to_string());
            continue;
        }
        attributed += 1;
        for n in names {
            owned.entry(n.clone()).or_default().insert(key.clone());
        }
    }

    let mut maintainers: Vec<Maintainer> = owned
        .into_iter()
        .map(|(name, pkgs)| {
            // Reach = the packages themselves plus everything above them.
            let mut seen: HashSet<DepRef> = pkgs.iter().cloned().collect();
            for k in &pkgs {
                collect_dependents(&dependents_of, k, &mut seen);
            }
            Maintainer {
                name,
                owns: pkgs.iter().map(|(n, v)| format!("{n}@{v}")).collect(),
                reach: seen.len(),
            }
        })
        .collect();

    // Widest reach first, then most packages, then name for a stable order.
    maintainers.sort_by(|a, b| {
        b.reach
            .cmp(&a.reach)
            .then(b.owns.len().cmp(&a.owns.len()))
            .then(a.name.cmp(&b.name))
    });

    Graph {
        maintainers,
        total: deps.len(),
        attributed,
        unattributed_ecosystems: unattributed_ecos.into_iter().collect(),
    }
}

/// Render the maintainer graph.
pub fn render(g: &Graph, deps: &[Dependency], root_label: &str) {
    println!("{}  {}", "maintainer graph".bold(), root_label.dimmed());

    if g.maintainers.is_empty() {
        println!();
        crate::gochi::say(
            crate::gochi::Mood::Curious,
            format!(
                "no maintainer data for this tree — {} is not queried for it",
                g.unattributed_ecosystems.join(", ")
            ),
        );
        return;
    }

    println!(
        "\n  {} package(s), {} with a known maintainer, {} without\n",
        g.total,
        g.attributed,
        g.unattributed()
    );

    println!(
        "  {:>6}  {:<24} {:>8}  {}",
        "REACH".bold(),
        "MAINTAINER".bold(),
        "OWNS".bold(),
        "SHARE".bold()
    );
    for m in g.maintainers.iter().take(20) {
        let share = m.reach as f64 / g.total.max(1) as f64;
        let pct = format!("{:.0}%", share * 100.0);
        let pct = if share >= 0.20 {
            pct.red().bold().to_string()
        } else if share >= 0.05 {
            pct.truecolor(255, 165, 0).to_string()
        } else {
            pct.dimmed().to_string()
        };
        println!(
            "  {:>6}  {:<24} {:>8}  {pct}",
            m.reach,
            m.name,
            m.owns.len()
        );
    }
    if g.maintainers.len() > 20 {
        println!(
            "  {}",
            format!("… and {} more", g.maintainers.len() - 20).dimmed()
        );
    }

    // The headline. Reaches overlap, so this is a set union, not a sum.
    let (n3, share3) = g.concentration(3, deps);
    println!(
        "\n  {}",
        format!(
            "{} account(s) control {n3} of {} packages ({:.0}%)",
            3.min(g.maintainers.len()),
            g.total,
            share3 * 100.0
        )
        .bold()
    );

    if g.unattributed() > 0 {
        println!(
            "{}",
            format!(
                "\n⚠ {} package(s) have no maintainer data ({}), so the real concentration \
                 can only be higher than shown",
                g.unattributed(),
                g.unattributed_ecosystems.join(", ")
            )
            .truecolor(255, 165, 0)
        );
    }

    let mood = if share3 >= 0.30 {
        crate::gochi::Mood::Bad
    } else if share3 >= 0.10 {
        crate::gochi::Mood::Alert
    } else {
        crate::gochi::Mood::Idle
    };
    crate::gochi::say(
        mood,
        format!(
            "one compromised account at the top reaches {} package(s)",
            g.maintainers.first().map(|m| m.reach).unwrap_or(0)
        ),
    );
}

/// The `tree --human --json` document.
pub fn to_json(g: &Graph, deps: &[Dependency], root: &str) -> serde_json::Value {
    let (n3, share3) = g.concentration(3, deps);
    serde_json::json!({
        "schema_version": 1,
        "root": root,
        "summary": {
            "packages": g.total,
            "attributed": g.attributed,
            "unattributed": g.unattributed(),
            "unattributed_ecosystems": g.unattributed_ecosystems,
            "maintainers": g.maintainers.len(),
            // A union over the top three, never a sum — reaches overlap.
            "top3_reach": n3,
            "top3_share": (share3 * 1000.0).round() / 1000.0,
        },
        "maintainers": g.maintainers.iter().map(|m| serde_json::json!({
            "name": m.name,
            "reach": m.reach,
            "share": ((m.reach as f64 / g.total.max(1) as f64) * 1000.0).round() / 1000.0,
            "owns": m.owns,
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Ecosystem, LicenseSource, Scope};

    fn dep(name: &str, parents: &[&str]) -> Dependency {
        Dependency {
            name: name.into(),
            version: "1.0.0".into(),
            ecosystem: Ecosystem::Node,
            direct: parents.is_empty(),
            scope: Scope::Prod,
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

    fn res(pairs: &[(&str, &[&str])]) -> HashMap<DepRef, Resolution> {
        pairs
            .iter()
            .map(|(name, maints)| {
                (
                    ((*name).to_string(), "1.0.0".to_string()),
                    Resolution {
                        maintainers: maints.iter().map(|m| (*m).to_string()).collect(),
                        ..Default::default()
                    },
                )
            })
            .collect()
    }

    /// app → mid → leaf
    fn chain() -> Vec<Dependency> {
        vec![dep("app", &[]), dep("mid", &["app"]), dep("leaf", &["mid"])]
    }

    #[test]
    fn reach_counts_everything_above_a_package_not_just_the_package() {
        // Owning one deep package can mean reaching the whole tree — the point
        // of measuring reach rather than the owned count.
        let g = graph(&chain(), &res(&[("leaf", &["eve"])]));
        let eve = &g.maintainers[0];
        assert_eq!(eve.owns.len(), 1);
        assert_eq!(eve.reach, 3, "leaf, mid and app");
    }

    #[test]
    fn owning_a_leaf_of_the_tree_reaches_only_itself() {
        let g = graph(&chain(), &res(&[("app", &["alice"])]));
        assert_eq!(g.maintainers[0].reach, 1, "nothing depends on the root");
    }

    #[test]
    fn every_maintainer_of_a_package_gets_its_reach() {
        // Any of them can publish, so a compromise of any one is the same event.
        let g = graph(&chain(), &res(&[("leaf", &["eve", "mallory"])]));
        assert_eq!(g.maintainers.len(), 2);
        assert!(g.maintainers.iter().all(|m| m.reach == 3));
    }

    #[test]
    fn the_graph_is_ordered_by_reach_not_by_package_count() {
        let deps = vec![
            dep("app", &[]),
            dep("mid", &["app"]),
            dep("leaf", &["mid"]),
            dep("side-a", &[]),
            dep("side-b", &[]),
        ];
        // `few` owns one deep package; `many` owns two leaves of the tree.
        let g = graph(
            &deps,
            &res(&[
                ("leaf", &["few"]),
                ("side-a", &["many"]),
                ("side-b", &["many"]),
            ]),
        );
        assert_eq!(g.maintainers[0].name, "few", "3 reach beats 2 owned");
        assert_eq!(g.maintainers[0].reach, 3);
        assert_eq!(g.maintainers[1].reach, 2);
    }

    #[test]
    fn concentration_is_a_union_not_a_sum() {
        // Two accounts on the same chain each reach all three packages. Adding
        // their reaches would claim 6 of 3.
        let deps = chain();
        let g = graph(&deps, &res(&[("leaf", &["eve"]), ("mid", &["mallory"])]));
        let (n, share) = g.concentration(2, &deps);
        assert_eq!(n, 3, "the union is the whole tree, not 3 + 2");
        assert_eq!(share, 1.0);
    }

    #[test]
    fn packages_without_maintainer_data_are_counted_not_dropped() {
        // A concentration figure over a half-attributed tree means something
        // different, so the gap has to be visible.
        let deps = chain();
        let g = graph(&deps, &res(&[("leaf", &["eve"])]));
        assert_eq!(g.total, 3);
        assert_eq!(g.attributed, 1);
        assert_eq!(g.unattributed(), 2);
        assert_eq!(g.unattributed_ecosystems, vec!["node"]);
    }

    #[test]
    fn an_empty_maintainer_list_means_unknown_never_nobody() {
        let deps = chain();
        let g = graph(&deps, &res(&[("leaf", &[])]));
        assert!(g.maintainers.is_empty());
        assert_eq!(g.attributed, 0);
        assert_eq!(g.unattributed(), 3);
    }

    #[test]
    fn a_cycle_terminates() {
        let deps = vec![dep("root", &[]), dep("a", &["root", "b"]), dep("b", &["a"])];
        let g = graph(&deps, &res(&[("b", &["eve"])]));
        assert_eq!(g.maintainers[0].reach, 3);
    }

    #[test]
    fn concentration_of_an_empty_graph_is_zero_not_nan() {
        let g = Graph::default();
        assert_eq!(g.concentration(3, &[]), (0, 0.0));
    }

    #[test]
    fn json_reports_the_union_and_the_coverage_gap() {
        let deps = chain();
        let g = graph(&deps, &res(&[("leaf", &["eve"])]));
        let doc = to_json(&g, &deps, "/p");
        assert_eq!(doc["summary"]["packages"], 3);
        assert_eq!(doc["summary"]["unattributed"], 2);
        assert_eq!(doc["summary"]["top3_reach"], 3);
        assert_eq!(doc["maintainers"][0]["name"], "eve");
        assert_eq!(doc["maintainers"][0]["reach"], 3);
    }
}
