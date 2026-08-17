//! Dependency-scope propagation and the `--omit` filter.
//!
//! Parsers can only classify what a manifest states directly: npm's root
//! `devDependencies`, Cargo's `[dev-dependencies]`, composer's `require-dev`,
//! and so on. That is a statement about *direct* dependencies — it says nothing
//! about the hundreds of transitive packages underneath them.
//!
//! Getting this wrong in either direction is bad:
//!
//! * Treating "listed under devDependencies" as the whole answer under-reports —
//!   the transitive tree below a dev dependency stays marked production, so
//!   `--omit dev` barely removes anything.
//! * Treating "reachable from a dev dependency" as the whole answer over-reports
//!   — a package pulled in by *both* a dev tool and the application itself would
//!   be dropped, hiding a package that genuinely ships.
//!
//! So scope is a **reachability** property, resolved here in one place for every
//! ecosystem: seed each direct dependency with the scope its manifest declared,
//! then walk the graph and give every package the *most production-ish* scope
//! that reaches it ([`Scope`] is ordered `Dev < Optional < Prod`, so merging is
//! [`Ord::max`]). A package is `Dev` only when every path to it is a dev path.
//!
//! Packages that no root reaches — a detached lockfile entry, or an ecosystem
//! with no edges at all (Go, Java) — keep whatever the parser gave them, which
//! defaults to [`Scope::Prod`]. Unknown therefore means *kept*, never *hidden*.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::model::{DepRef, Dependency, Scope};

/// Resolve every dependency's scope from the direct seeds plus the graph edges.
///
/// Idempotent, and a no-op for a graph whose parsers never seeded anything (all
/// `Prod` in, all `Prod` out).
pub fn propagate(deps: &mut [Dependency]) {
    // Children by parent: `parents` points up, and we need to walk down.
    let mut children: HashMap<DepRef, Vec<DepRef>> = HashMap::new();
    for d in deps.iter() {
        let me = (d.name.clone(), d.version.clone());
        for p in &d.parents {
            children.entry(p.clone()).or_default().push(me.clone());
        }
    }

    // Seed from the direct dependencies — the only ones a manifest classified.
    // A non-direct package starts unassigned so it can inherit purely from above.
    let mut best: HashMap<DepRef, Scope> = HashMap::new();
    let mut queue: VecDeque<DepRef> = VecDeque::new();
    for d in deps.iter().filter(|d| d.direct) {
        let me = (d.name.clone(), d.version.clone());
        let entry = best.entry(me.clone()).or_insert(d.scope);
        *entry = (*entry).max(d.scope);
        queue.push_back(me);
    }

    // Relax downward until nothing improves. A node is re-queued only when its
    // scope actually rises, so each node is processed at most three times (once
    // per scope level) — cycles in the graph terminate on their own.
    while let Some(node) = queue.pop_front() {
        let Some(scope) = best.get(&node).copied() else { continue };
        let Some(kids) = children.get(&node) else { continue };
        for kid in kids.clone() {
            let improved = match best.get(&kid) {
                Some(cur) if *cur >= scope => false,
                _ => {
                    best.insert(kid.clone(), scope);
                    true
                }
            };
            if improved {
                queue.push_back(kid);
            }
        }
    }

    for d in deps.iter_mut() {
        if let Some(s) = best.get(&(d.name.clone(), d.version.clone())) {
            d.scope = *s;
        }
    }
}

/// Drop every dependency whose scope is in `omit`, then repair the survivors'
/// `parents` so no edge points at a package that is no longer in the set (a
/// dangling parent would otherwise orphan a subtree when the tree is built).
///
/// An empty `omit` is a no-op.
pub fn apply_omit(deps: Vec<Dependency>, omit: &[Scope]) -> Vec<Dependency> {
    if omit.is_empty() {
        return deps;
    }
    let mut kept: Vec<Dependency> = deps.into_iter().filter(|d| !omit.contains(&d.scope)).collect();
    let alive: HashSet<DepRef> =
        kept.iter().map(|d| (d.name.clone(), d.version.clone())).collect();
    for d in &mut kept {
        d.parents.retain(|p| alive.contains(p));
    }
    kept
}

/// How many of each scope are present — used to tell the user what `--omit`
/// actually removed, so a shrunken dependency count is never mysterious.
pub fn count(deps: &[Dependency], scope: Scope) -> usize {
    deps.iter().filter(|d| d.scope == scope).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Ecosystem;

    fn dep(name: &str, direct: bool, scope: Scope, parents: &[&str]) -> Dependency {
        Dependency {
            name: name.into(),
            version: "1.0.0".into(),
            ecosystem: Ecosystem::Node,
            direct,
            scope,
            licenses: Vec::new(),
            license_source: crate::model::LicenseSource::Unknown,
            resolved_url: None,
            integrity: None,
            parents: parents.iter().map(|p| ((*p).to_string(), "1.0.0".to_string())).collect(),
        }
    }

    fn scope_of(deps: &[Dependency], name: &str) -> Scope {
        deps.iter().find(|d| d.name == name).unwrap().scope
    }

    #[test]
    fn dev_root_taints_its_whole_subtree() {
        let mut deps = vec![
            dep("jest", true, Scope::Dev, &[]),
            dep("jest-worker", false, Scope::Prod, &["jest"]),
            dep("supports-color", false, Scope::Prod, &["jest-worker"]),
        ];
        propagate(&mut deps);
        assert_eq!(scope_of(&deps, "jest-worker"), Scope::Dev, "one hop below a dev root");
        assert_eq!(scope_of(&deps, "supports-color"), Scope::Dev, "two hops below");
    }

    #[test]
    fn prod_wins_over_dev_on_a_shared_package() {
        // `ms` is pulled by both a dev tool and the shipped app — it ships.
        let mut deps = vec![
            dep("jest", true, Scope::Dev, &[]),
            dep("express", true, Scope::Prod, &[]),
            dep("ms", false, Scope::Prod, &["jest", "express"]),
        ];
        propagate(&mut deps);
        assert_eq!(scope_of(&deps, "ms"), Scope::Prod, "a dev path must not hide a prod package");
        let kept = apply_omit(deps, &[Scope::Dev]);
        assert!(kept.iter().any(|d| d.name == "ms"), "--omit dev must keep it");
    }

    #[test]
    fn prod_wins_regardless_of_seed_order() {
        // Same graph as above with the roots declared the other way round: the
        // result must not depend on iteration order.
        let mut deps = vec![
            dep("express", true, Scope::Prod, &[]),
            dep("jest", true, Scope::Dev, &[]),
            dep("ms", false, Scope::Prod, &["express", "jest"]),
        ];
        propagate(&mut deps);
        assert_eq!(scope_of(&deps, "ms"), Scope::Prod);
    }

    #[test]
    fn optional_outranks_dev_but_loses_to_prod() {
        let mut deps = vec![
            dep("fsevents-user", true, Scope::Optional, &[]),
            dep("jest", true, Scope::Dev, &[]),
            dep("shared", false, Scope::Prod, &["fsevents-user", "jest"]),
        ];
        propagate(&mut deps);
        assert_eq!(scope_of(&deps, "shared"), Scope::Optional);

        let mut deps2 = vec![
            dep("app", true, Scope::Prod, &[]),
            dep("opt", true, Scope::Optional, &[]),
            dep("shared", false, Scope::Prod, &["app", "opt"]),
        ];
        propagate(&mut deps2);
        assert_eq!(scope_of(&deps2, "shared"), Scope::Prod);
    }

    #[test]
    fn cycles_terminate() {
        let mut deps = vec![
            dep("jest", true, Scope::Dev, &[]),
            dep("a", false, Scope::Prod, &["jest", "b"]),
            dep("b", false, Scope::Prod, &["a"]),
        ];
        propagate(&mut deps);
        assert_eq!(scope_of(&deps, "a"), Scope::Dev);
        assert_eq!(scope_of(&deps, "b"), Scope::Dev);
    }

    #[test]
    fn unreachable_packages_keep_their_parser_scope() {
        // Nothing reaches `orphan`: it must survive `--omit dev` rather than be
        // guessed away. This is the "unknown means kept" guarantee.
        let mut deps = vec![dep("orphan", false, Scope::Prod, &["ghost"])];
        propagate(&mut deps);
        assert_eq!(scope_of(&deps, "orphan"), Scope::Prod);
        assert_eq!(apply_omit(deps, &[Scope::Dev]).len(), 1);
    }

    #[test]
    fn omit_repairs_dangling_parent_edges() {
        let mut deps = vec![
            dep("jest", true, Scope::Dev, &[]),
            dep("express", true, Scope::Prod, &[]),
            dep("ms", false, Scope::Prod, &["jest", "express"]),
        ];
        propagate(&mut deps);
        let kept = apply_omit(deps, &[Scope::Dev]);
        let ms = kept.iter().find(|d| d.name == "ms").unwrap();
        assert_eq!(
            ms.parents,
            vec![("express".to_string(), "1.0.0".to_string())],
            "the dropped dev parent must not linger as a dangling edge"
        );
    }

    #[test]
    fn omit_is_a_no_op_when_empty() {
        let deps = vec![dep("jest", true, Scope::Dev, &[])];
        assert_eq!(apply_omit(deps, &[]).len(), 1);
    }

    #[test]
    fn propagate_is_idempotent() {
        let mut deps = vec![
            dep("jest", true, Scope::Dev, &[]),
            dep("jest-worker", false, Scope::Prod, &["jest"]),
        ];
        propagate(&mut deps);
        let once: Vec<Scope> = deps.iter().map(|d| d.scope).collect();
        propagate(&mut deps);
        let twice: Vec<Scope> = deps.iter().map(|d| d.scope).collect();
        assert_eq!(once, twice);
    }

    #[test]
    fn counts_report_what_omit_would_remove() {
        let mut deps = vec![
            dep("jest", true, Scope::Dev, &[]),
            dep("jest-worker", false, Scope::Prod, &["jest"]),
            dep("express", true, Scope::Prod, &[]),
        ];
        propagate(&mut deps);
        assert_eq!(count(&deps, Scope::Dev), 2);
        assert_eq!(count(&deps, Scope::Prod), 1);
    }
}
