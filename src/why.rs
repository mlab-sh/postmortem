//! `postmortem why <package>` — explain why a package is in the tree by showing
//! the dependency paths from it back up to the direct (root) dependencies, like
//! `npm why` / `cargo tree -i`. Pure graph walk over the `parents` edges the
//! parsers already record.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;

use owo_colors::OwoColorize;

use crate::model::Dependency;

type Key = (String, String);
/// A `(name, version)` borrowed from the dependency list — the walk's working
/// key, so stepping onto a node clones nothing.
type Ref<'a> = (&'a str, &'a str);

/// Paths listed per installed version before the walk stops.
///
/// Simple paths multiply at every diamond, so their number is exponential in
/// the depth of a shared-dependency graph (pnpm and Cargo graphs are full of
/// them): uncapped, one package could run for as long as the count grows. Real
/// graphs stay far below this — the most measured was 2 535 paths
/// (`call-bound` in a Next.js app) and 1 024 (`proc-macro2` in this repo) — so
/// their answer is unchanged; past it the listing is not something one reads.
pub const MAX_PATHS: usize = 10_000;

/// How far a capped version keeps *counting* (not listing) to report its
/// total. Counting is the same walk without storing paths, so this bounds its
/// time as well; beyond it the total is reported as unknown, not guessed.
const MAX_COUNTED: usize = 100_000;

/// The paths of [`paths_capped`], plus each installed version whose listing
/// hit the cap, mapped to its total path count — `None` when even the count
/// passed [`MAX_COUNTED`].
pub struct Paths {
    pub paths: Vec<Vec<Key>>,
    pub truncated: BTreeMap<String, Option<u64>>,
}

/// Every dependency path from an installed `target` version up to a root: each
/// path is `[target, …, direct-dependency]`. A package installed at several
/// versions yields a path set per version; cycles are broken (a node is not
/// revisited within one path). At most [`MAX_PATHS`] per version.
#[cfg(test)]
pub fn paths(deps: &[Dependency], target: &str) -> Vec<Vec<Key>> {
    paths_capped(deps, target, MAX_PATHS).paths
}

/// [`paths`] with an explicit per-version cap, and a record of which versions
/// it cut short.
pub fn paths_capped(deps: &[Dependency], target: &str, cap: usize) -> Paths {
    let index: HashMap<Ref, &Dependency> = deps
        .iter()
        .map(|d| ((d.name.as_str(), d.version.as_str()), d))
        .collect();

    let mut out = Paths {
        paths: Vec::new(),
        truncated: BTreeMap::new(),
    };
    for d in deps.iter().filter(|d| d.name == target) {
        if Walk::new(&index, d, Some(&mut out.paths), cap).walk(d) {
            continue;
        }
        let mut count = Walk::new(&index, d, None, MAX_COUNTED);
        let total = count.walk(d).then(|| (MAX_COUNTED - count.left) as u64);
        // The same version listed twice (two ecosystems) sums its totals.
        let e = out.truncated.entry(d.version.clone()).or_insert(Some(0));
        *e = e.zip(total).map(|(a, b)| a + b);
    }
    out
}

struct Walk<'a, 'o> {
    index: &'o HashMap<Ref<'a>, &'a Dependency>,
    trail: Vec<Ref<'a>>,
    /// The trail as a set: the cycle check was an O(depth) `contains` per edge.
    on_trail: HashSet<Ref<'a>>,
    /// Where paths are listed; `None` only counts them.
    out: Option<&'o mut Vec<Vec<Key>>>,
    /// Paths still allowed for this version.
    left: usize,
}

impl<'a, 'o> Walk<'a, 'o> {
    fn new(
        index: &'o HashMap<Ref<'a>, &'a Dependency>,
        from: &'a Dependency,
        out: Option<&'o mut Vec<Vec<Key>>>,
        left: usize,
    ) -> Self {
        let me = (from.name.as_str(), from.version.as_str());
        Walk {
            index,
            trail: vec![me],
            on_trail: HashSet::from([me]),
            out,
            left,
        }
    }

    /// Record the current trail (plus `extra`), or report `false` when the cap
    /// is already spent — the path that does not fit is what makes it truncated.
    fn emit(&mut self, extra: Option<Ref<'a>>) -> bool {
        if self.left == 0 {
            return false;
        }
        self.left -= 1;
        if let Some(out) = self.out.as_mut() {
            out.push(
                self.trail
                    .iter()
                    .chain(extra.as_ref())
                    .map(|(n, v)| (n.to_string(), v.to_string()))
                    .collect(),
            );
        }
        true
    }

    /// `false` once the cap is hit; the walk then unwinds without exploring more.
    fn walk(&mut self, node: &'a Dependency) -> bool {
        // A root of a path: a direct dependency, or one with no known parent.
        if node.direct || node.parents.is_empty() {
            return self.emit(None);
        }
        for (pn, pv) in &node.parents {
            let parent = (pn.as_str(), pv.as_str());
            if self.on_trail.contains(&parent) {
                continue; // cycle — stop this branch
            }
            let Some(pd) = self.index.get(&parent).copied() else {
                // Parent isn't a resolved node; end the path at it anyway.
                if !self.emit(Some(parent)) {
                    return false;
                }
                continue;
            };
            self.trail.push(parent);
            self.on_trail.insert(parent);
            let go = self.walk(pd);
            self.trail.pop();
            self.on_trail.remove(&parent);
            if !go {
                return false;
            }
        }
        true
    }
}

/// The `why --json` document.
///
/// Each installed version gets its own entry with the paths leading to it,
/// because "why is this here" has a different answer per version — which is
/// exactly the case a human reads this command for, and the one a script most
/// needs to branch on.
///
/// A package absent from the graph yields `installed: []` rather than an error:
/// "it is not there" is a legitimate answer, and a consumer should not have to
/// distinguish it from a failed run.
///
/// A version whose listing hit [`MAX_PATHS`] also carries `"truncated": true`
/// and, when it could be counted, `"total_paths"`; the fields are absent
/// otherwise, so an uncapped answer is the same document it always was.
pub fn to_json(deps: &[Dependency], target: &str, root: &str) -> serde_json::Value {
    let capped = paths_capped(deps, target, MAX_PATHS);
    let all = &capped.paths;
    let installed: Vec<serde_json::Value> = deps
        .iter()
        .filter(|d| d.name == target)
        .map(|d| {
            let for_version: Vec<Vec<serde_json::Value>> = all
                .iter()
                .filter(|p| p.first().is_some_and(|(_, pv)| pv == &d.version))
                .map(|p| {
                    // Skip the target itself: the path is what lies *above* it.
                    p.iter()
                        .skip(1)
                        .map(|(n, v)| serde_json::json!({ "name": n, "version": v }))
                        .collect::<Vec<_>>()
                })
                .collect();
            let mut entry = serde_json::json!({
                "name": d.name,
                "version": d.version,
                "direct": d.direct,
                "ecosystem": d.ecosystem,
                "paths": for_version,
            });
            if let Some(total) = capped.truncated.get(&d.version) {
                entry["truncated"] = true.into();
                if let Some(n) = total {
                    entry["total_paths"] = (*n).into();
                }
            }
            entry
        })
        .collect();

    serde_json::json!({
        "schema_version": 1,
        "root": root,
        "package": target,
        "installed": installed,
    })
}

/// Render the reverse-dependency paths for `target` to stdout.
pub fn render(deps: &[Dependency], target: &str, root_label: &str) {
    // Buffered and locked once: a path listing is up to [`MAX_PATHS`] × depth
    // lines, and `println!` pays a lock and a `write` syscall for each.
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    let _ = writeln!(
        out,
        "{}  {}  {}",
        "why".bold(),
        target.cyan(),
        format!("(in {root_label})").dimmed()
    );

    let installed: Vec<&Dependency> = deps.iter().filter(|d| d.name == target).collect();
    if installed.is_empty() {
        let _ = writeln!(out);
        // gochi prints on its own: flush what is buffered ahead of it.
        drop(out);
        crate::gochi::say(
            crate::gochi::Mood::Curious,
            format!("{target} is not in the dependency graph"),
        );
        return;
    }

    let capped = paths_capped(deps, target, MAX_PATHS);
    let paths = &capped.paths;
    let direct = installed.iter().any(|d| d.direct);
    for d in &installed {
        let v = &d.version;
        let paths_for: Vec<&Vec<Key>> = paths
            .iter()
            .filter(|p| p.first().is_some_and(|(_, pv)| pv == v))
            .collect();
        let shown = paths_for.len();
        let _ = writeln!(
            out,
            "\n{}{}",
            format!("{target}@{v}").bold(),
            if d.direct {
                "  [direct]".green().to_string()
            } else {
                String::new()
            }
        );
        // Each path is target → … → root; print the chain after the target.
        for path in paths_for {
            for (depth, (name, ver)) in path.iter().enumerate().skip(1) {
                let is_root = depth == path.len() - 1;
                let tag = if is_root {
                    "  [direct]".green().to_string()
                } else {
                    String::new()
                };
                let _ = writeln!(
                    out,
                    "{}{} required by {}{}",
                    "  ".repeat(depth),
                    "└─".dimmed(),
                    format!("{name}@{ver}").yellow(),
                    tag
                );
            }
        }
        if let Some(total) = capped.truncated.get(v) {
            let more = match total {
                Some(n) => format!("{} more path(s)", n.saturating_sub(shown as u64)),
                None => format!("more than {MAX_COUNTED} path(s) in all"),
            };
            let _ = writeln!(
                out,
                "  {}",
                format!("… {more} not shown — listing stops at {MAX_PATHS}").dimmed()
            );
        }
    }

    if direct && installed.len() == 1 {
        // A pure direct dep with no upward chain — make that explicit.
        if paths.iter().all(|p| p.len() == 1) {
            let _ = writeln!(out, "  {}", "it is a direct dependency".dimmed());
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
            parents: parents
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
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
        assert!(
            ps.iter()
                .all(|p| p.last() == Some(&("app".to_string(), "1.0".to_string())))
        );
        assert!(ps.contains(&vec![
            ("leaf".into(), "3.0".into()),
            ("mid".into(), "2.0".into()),
            ("app".into(), "1.0".into()),
        ]));
    }

    #[test]
    fn direct_package_is_its_own_path() {
        let deps = vec![dep("app", "1.0", true, &[])];
        assert_eq!(
            paths(&deps, "app"),
            vec![vec![("app".into(), "1.0".into())]]
        );
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
        assert_eq!(
            ps,
            vec![vec![("a".into(), "1".into()), ("b".into(), "1".into())]]
        );
    }

    /// `n` stacked diamonds under one root: 2^n paths from the bottom rung.
    fn ladder(rungs: usize) -> (Vec<Dependency>, String) {
        let mut deps = vec![dep("root", "1", true, &[])];
        let mut below = ("root".to_string(), "1".to_string());
        for i in 0..rungs {
            let (l, r, j) = (format!("l{i}"), format!("r{i}"), format!("j{i}"));
            deps.push(dep(&l, "1", false, &[(&below.0, &below.1)]));
            deps.push(dep(&r, "1", false, &[(&below.0, &below.1)]));
            deps.push(dep(&j, "1", false, &[(&l, "1"), (&r, "1")]));
            below = (j, "1".to_string());
        }
        (deps, below.0)
    }

    #[test]
    fn a_diamond_ladder_is_capped_and_counted() {
        let (deps, bottom) = ladder(12);
        let p = paths_capped(&deps, &bottom, 100);
        assert_eq!(p.paths.len(), 100);
        assert_eq!(p.truncated.get("1"), Some(&Some(4096)));

        // Exactly at the cap is not truncated.
        let p = paths_capped(&deps, "j1", 4);
        assert_eq!(p.paths.len(), 4);
        assert!(p.truncated.is_empty());

        // The JSON carries the flag only when it applies.
        let doc = to_json(&deps, "j0", ".");
        assert!(doc["installed"][0].get("truncated").is_none());
    }

    #[test]
    fn an_exponential_answer_terminates_without_a_guessed_total() {
        // 2^40 paths: uncapped this never finishes. Capped, it lists the first
        // few, gives up counting past MAX_COUNTED, and says the total is unknown.
        let (deps, bottom) = ladder(40);
        let p = paths_capped(&deps, &bottom, 10);
        assert_eq!(p.paths.len(), 10);
        assert_eq!(p.truncated.get("1"), Some(&None));
    }
}
