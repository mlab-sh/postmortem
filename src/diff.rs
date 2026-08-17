//! `postmortem diff` — compare the resolved dependency sets of two project states
//! (e.g. two branches / commits checked out side by side) and report what changed:
//! packages **added**, **removed**, or **version-changed**. This is the signal a
//! reviewer actually wants on a lockfile change ("what did this PR pull in?"), and
//! the natural companion to the CI `gate`'s `--baseline` mode.
//!
//! v1 is an offline set-diff. Layering `--online` risk/vuln deltas on top (does
//! this change *raise* the risk score) is the intended next step.

use owo_colors::OwoColorize;

use crate::model::{Dependency, Ecosystem};

/// One package identity across the two sides: its ecosystem + name.
type Key = (Ecosystem, String);

/// The result of comparing two dependency sets.
#[derive(Debug, Default, PartialEq)]
pub struct DiffReport {
    /// In `new`, absent from `old`.
    pub added: Vec<(Key, String)>,
    /// In `old`, absent from `new`.
    pub removed: Vec<(Key, String)>,
    /// Present in both at a different version: `(key, old_version, new_version)`.
    pub changed: Vec<(Key, String, String)>,
    /// Count of packages present at the same version on both sides.
    pub unchanged: usize,
}

impl DiffReport {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

/// The `diff --json` document.
///
/// The three lists carry the ecosystem alongside the name, because the same
/// package name can legitimately exist in two ecosystems of one project and a
/// consumer must not conflate them.
pub fn to_json(r: &DiffReport, old: &str, new: &str) -> serde_json::Value {
    let entry = |(eco, name): &Key, version: &String| {
        serde_json::json!({ "ecosystem": eco, "name": name, "version": version })
    };
    serde_json::json!({
        "schema_version": 1,
        "old": old,
        "new": new,
        "summary": {
            "added": r.added.len(),
            "removed": r.removed.len(),
            "changed": r.changed.len(),
            "unchanged": r.unchanged,
        },
        "added": r.added.iter().map(|(k, v)| entry(k, v)).collect::<Vec<_>>(),
        "removed": r.removed.iter().map(|(k, v)| entry(k, v)).collect::<Vec<_>>(),
        "changed": r
            .changed
            .iter()
            .map(|((eco, name), ov, nv)| serde_json::json!({
                "ecosystem": eco,
                "name": name,
                "from": ov,
                "to": nv,
            }))
            .collect::<Vec<_>>(),
    })
}

/// Index a dependency list by `(ecosystem, name)` → version. Duplicate keys (the
/// same package pinned twice) keep the first version seen.
fn index(deps: &[Dependency]) -> std::collections::BTreeMap<Key, String> {
    let mut map = std::collections::BTreeMap::new();
    for d in deps {
        map.entry((d.ecosystem, d.name.clone())).or_insert_with(|| d.version.clone());
    }
    map
}

/// Compare two resolved dependency sets.
pub fn diff(old: &[Dependency], new: &[Dependency]) -> DiffReport {
    let (old, new) = (index(old), index(new));
    let mut report = DiffReport::default();
    for (key, nv) in &new {
        match old.get(key) {
            None => report.added.push((key.clone(), nv.clone())),
            Some(ov) if ov == nv => report.unchanged += 1,
            Some(ov) => report.changed.push((key.clone(), ov.clone(), nv.clone())),
        }
    }
    for (key, ov) in &old {
        if !new.contains_key(key) {
            report.removed.push((key.clone(), ov.clone()));
        }
    }
    report
}

/// Render the diff to stdout (color-coded: `+` added, `-` removed, `~` changed).
pub fn render(report: &DiffReport, old_label: &str, new_label: &str) {
    println!("{}  {}  →  {}", "dependency diff".bold(), old_label.dimmed(), new_label.dimmed());

    if report.is_empty() {
        println!();
        crate::gochi::say(crate::gochi::Mood::Happy, "no dependency changes");
        return;
    }

    if !report.added.is_empty() {
        println!("\n{}", format!("+ {} added", report.added.len()).green().bold());
        for ((eco, name), v) in &report.added {
            println!("  {}", format!("+ {name}@{v} ({})", eco.as_str()).green());
        }
    }
    if !report.removed.is_empty() {
        println!("\n{}", format!("- {} removed", report.removed.len()).red().bold());
        for ((eco, name), v) in &report.removed {
            println!("  {}", format!("- {name}@{v} ({})", eco.as_str()).red());
        }
    }
    if !report.changed.is_empty() {
        println!("\n{}", format!("~ {} changed", report.changed.len()).yellow().bold());
        for ((eco, name), ov, nv) in &report.changed {
            println!(
                "  {} {} {} {} {}",
                "~".yellow(),
                name.yellow(),
                ov.dimmed(),
                "→".dimmed(),
                format!("{nv} ({})", eco.as_str()).yellow(),
            );
        }
    }

    // New dependencies are new attack surface, so additions make gochi look up.
    let mood =
        if report.added.is_empty() { crate::gochi::Mood::Idle } else { crate::gochi::Mood::Alert };
    println!();
    crate::gochi::say(
        mood,
        format!(
            "+{} -{} ~{}  ({} unchanged)",
            report.added.len(),
            report.removed.len(),
            report.changed.len(),
            report.unchanged,
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(name: &str, ver: &str) -> Dependency {
        Dependency {
            name: name.into(),
            version: ver.into(),
            ecosystem: Ecosystem::Node,
            scope: crate::model::Scope::Prod,
            licenses: Vec::new(),
            license_source: crate::model::LicenseSource::Unknown,
            direct: true,
            resolved_url: None,
            integrity: None,
            parents: vec![],
        }
    }

    #[test]
    fn diff_classifies_added_removed_changed() {
        let old = vec![dep("keep", "1.0"), dep("gone", "2.0"), dep("bump", "1.0")];
        let new = vec![dep("keep", "1.0"), dep("new", "0.1"), dep("bump", "2.0")];
        let r = diff(&old, &new);
        assert_eq!(r.added, vec![((Ecosystem::Node, "new".into()), "0.1".into())]);
        assert_eq!(r.removed, vec![((Ecosystem::Node, "gone".into()), "2.0".into())]);
        assert_eq!(
            r.changed,
            vec![((Ecosystem::Node, "bump".into()), "1.0".into(), "2.0".into())]
        );
        assert_eq!(r.unchanged, 1); // keep
        assert!(!r.is_empty());
    }

    #[test]
    fn diff_identical_is_empty() {
        let a = vec![dep("x", "1.0"), dep("y", "2.0")];
        let r = diff(&a, &a);
        assert!(r.is_empty());
        assert_eq!(r.unchanged, 2);
    }
}
