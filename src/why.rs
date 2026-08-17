//! `postmortem why <package>` — explain why a package is in the tree by showing
//! the dependency paths from it back up to the direct (root) dependencies, like
//! `npm why` / `cargo tree -i`. Pure graph walk over the `parents` edges the
//! parsers already record.

use owo_colors::OwoColorize;

use crate::model::Dependency;

type Key = (String, String);

/// Every dependency path from an installed `target` version up to a root: each
/// path is `[target, …, direct-dependency]`. A package installed at several
/// versions yields a path set per version; cycles are broken (a node is not
/// revisited within one path).
pub fn paths(deps: &[Dependency], target: &str) -> Vec<Vec<Key>> {
    let index: std::collections::HashMap<Key, &Dependency> =
        deps.iter().map(|d| ((d.name.clone(), d.version.clone()), d)).collect();

    let mut out = Vec::new();
    for d in deps.iter().filter(|d| d.name == target) {
        let mut trail = vec![(d.name.clone(), d.version.clone())];
        walk(d, &index, &mut trail, &mut out);
    }
    out
}

fn walk(
    node: &Dependency,
    index: &std::collections::HashMap<Key, &Dependency>,
    trail: &mut Vec<Key>,
    out: &mut Vec<Vec<Key>>,
) {
    // A root of a path: a direct dependency, or one with no known parent.
    if node.direct || node.parents.is_empty() {
        out.push(trail.clone());
        return;
    }
    for parent in &node.parents {
        if trail.contains(parent) {
            continue; // cycle — stop this branch
        }
        let Some(pd) = index.get(parent) else {
            // Parent isn't a resolved node; end the path at it anyway.
            let mut t = trail.clone();
            t.push(parent.clone());
            out.push(t);
            continue;
        };
        trail.push(parent.clone());
        walk(pd, index, trail, out);
        trail.pop();
    }
}

/// Render the reverse-dependency paths for `target` to stdout.
pub fn render(deps: &[Dependency], target: &str, root_label: &str) {
    println!("{}  {}  {}", "why".bold(), target.cyan(), format!("(in {root_label})").dimmed());

    let installed: Vec<&Dependency> = deps.iter().filter(|d| d.name == target).collect();
    if installed.is_empty() {
        println!();
        crate::gochi::say(
            crate::gochi::Mood::Curious,
            format!("{target} is not in the dependency graph"),
        );
        return;
    }

    let paths = paths(deps, target);
    let direct = installed.iter().any(|d| d.direct);
    for d in &installed {
        let v = &d.version;
        let paths_for: Vec<&Vec<Key>> =
            paths.iter().filter(|p| p.first().is_some_and(|(_, pv)| pv == v)).collect();
        println!("\n{}{}", format!("{target}@{v}").bold(), if d.direct { "  [direct]".green().to_string() } else { String::new() });
        // Each path is target → … → root; print the chain after the target.
        for path in paths_for {
            for (depth, (name, ver)) in path.iter().enumerate().skip(1) {
                let is_root = depth == path.len() - 1;
                let tag = if is_root { "  [direct]".green().to_string() } else { String::new() };
                println!("{}{} required by {}{}", "  ".repeat(depth), "└─".dimmed(), format!("{name}@{ver}").yellow(), tag);
            }
        }
    }

    if direct && installed.len() == 1 {
        // A pure direct dep with no upward chain — make that explicit.
        if paths.iter().all(|p| p.len() == 1) {
            println!("  {}", "it is a direct dependency".dimmed());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Ecosystem;

    fn dep(name: &str, ver: &str, direct: bool, parents: &[(&str, &str)]) -> Dependency {
        Dependency {
            name: name.into(),
            version: ver.into(),
            ecosystem: Ecosystem::Node,
            scope: crate::model::Scope::Prod,
            licenses: Vec::new(),
            license_source: crate::model::LicenseSource::Unknown,
            direct,
            resolved_url: None,
            integrity: None,
            parents: parents.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect(),
        }
    }

    #[test]
    fn paths_walk_up_to_roots() {
        // app (direct) → mid → leaf; also app → leaf directly (two paths to leaf).
        let deps = vec![
            dep("app", "1.0", true, &[]),
            dep("mid", "2.0", false, &[("app", "1.0")]),
            dep("leaf", "3.0", false, &[("mid", "2.0"), ("app", "1.0")]),
        ];
        let mut ps = paths(&deps, "leaf");
        ps.sort();
        assert_eq!(ps.len(), 2);
        // Both paths end at the direct root `app`.
        assert!(ps.iter().all(|p| p.last() == Some(&("app".to_string(), "1.0".to_string()))));
        assert!(ps.contains(&vec![
            ("leaf".into(), "3.0".into()),
            ("mid".into(), "2.0".into()),
            ("app".into(), "1.0".into()),
        ]));
    }

    #[test]
    fn direct_package_is_its_own_path() {
        let deps = vec![dep("app", "1.0", true, &[])];
        assert_eq!(paths(&deps, "app"), vec![vec![("app".into(), "1.0".into())]]);
        assert!(paths(&deps, "missing").is_empty());
    }

    #[test]
    fn cycle_does_not_loop() {
        // a ↔ b mutual edge, with b a direct root. The walk must terminate and
        // still find the path to the root (the cycle edge b→a is not re-entered).
        let deps = vec![
            dep("a", "1", false, &[("b", "1")]),
            dep("b", "1", true, &[("a", "1")]),
        ];
        let ps = paths(&deps, "a");
        assert_eq!(ps, vec![vec![("a".into(), "1".into()), ("b".into(), "1".into())]]);
    }
}
