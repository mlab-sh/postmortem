//! `postmortem sbom` — export the resolved dependency graph as a **CycloneDX
//! 1.5** SBOM (JSON). postmortem already reconstructs the full forest for every
//! ecosystem, so emitting a standard, portable bill of materials is a thin
//! projection: one `component` per dependency (with a package URL), plus the
//! `dependencies` graph rebuilt from the parent edges.

use serde_json::{Value, json};

use crate::model::{Dependency, Ecosystem};

/// The [package-URL](https://github.com/package-url/purl-spec) type for an
/// ecosystem, e.g. `pkg:npm/...`, `pkg:cargo/...`, `pkg:deb/...`.
fn purl_type(eco: Ecosystem) -> &'static str {
    match eco {
        Ecosystem::Node => "npm",
        Ecosystem::Python => "pypi",
        Ecosystem::Rust => "cargo",
        Ecosystem::Ruby => "gem",
        Ecosystem::Php => "composer",
        Ecosystem::Go => "golang",
        Ecosystem::Java => "maven",
        Ecosystem::Brew => "brew",
        Ecosystem::Pacman => "alpm",
        Ecosystem::Apt => "deb",
        Ecosystem::Dnf => "rpm",
        Ecosystem::Nix => "nix",
        Ecosystem::Apk => "apk",
    }
}

/// A dependency's package URL, e.g. `pkg:npm/left-pad@1.3.0`. Doubles as the
/// component's stable `bom-ref`.
pub fn purl(dep: &Dependency) -> String {
    let base = format!("pkg:{}/{}", purl_type(dep.ecosystem), dep.name);
    if dep.version.is_empty() {
        base
    } else {
        format!("{base}@{}", dep.version)
    }
}

/// Build a CycloneDX 1.5 document for `deps`, rooted at an application component
/// named `root`. `timestamp` is an RFC-3339 string (passed in so this stays a
/// pure, testable function).
pub fn cyclonedx(root: &str, deps: &[Dependency], timestamp: &str) -> Value {
    // Stable purl per (name, version) so edges reference the same ref as components.
    let ref_of = |d: &Dependency| purl(d);

    // components: one per unique purl.
    let mut seen = std::collections::HashSet::new();
    let mut components = Vec::new();
    for d in deps {
        let r = ref_of(d);
        if !seen.insert(r.clone()) {
            continue;
        }
        components.push(json!({
            "type": "library",
            "bom-ref": r,
            "name": d.name,
            "version": d.version,
            "purl": r,
        }));
    }

    // dependency edges: rebuild parent → child adjacency from the `parents` field.
    let purl_by_key: std::collections::HashMap<(&str, &str), String> =
        deps.iter().map(|d| ((d.name.as_str(), d.version.as_str()), ref_of(d))).collect();
    let mut depends_on: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
        std::collections::BTreeMap::new();
    let mut direct: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for d in deps {
        let child = ref_of(d);
        if d.direct {
            direct.insert(child.clone());
        }
        for (pn, pv) in &d.parents {
            if let Some(parent) = purl_by_key.get(&(pn.as_str(), pv.as_str())) {
                depends_on.entry(parent.clone()).or_default().insert(child.clone());
            }
        }
    }

    // The root application depends on every direct dependency.
    let mut dependencies = vec![json!({
        "ref": "postmortem:root",
        "dependsOn": direct.into_iter().collect::<Vec<_>>(),
    })];
    for comp_ref in seen.iter() {
        let kids: Vec<String> =
            depends_on.get(comp_ref).map(|s| s.iter().cloned().collect()).unwrap_or_default();
        dependencies.push(json!({ "ref": comp_ref, "dependsOn": kids }));
    }
    // Stable order for reproducible output.
    dependencies.sort_by(|a, b| a["ref"].as_str().cmp(&b["ref"].as_str()));

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{
                "vendor": "mlab",
                "name": "postmortem",
                "version": env!("CARGO_PKG_VERSION"),
            }],
            "component": {
                "type": "application",
                "bom-ref": "postmortem:root",
                "name": root,
            },
        },
        "components": components,
        "dependencies": dependencies,
    })
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
            direct,
            resolved_url: None,
            integrity: None,
            parents: parents.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect(),
        }
    }

    #[test]
    fn purl_encodes_type_and_version() {
        assert_eq!(purl(&dep("left-pad", "1.3.0", true, &[])), "pkg:npm/left-pad@1.3.0");
        let mut d = dep("hello", "", true, &[]);
        d.ecosystem = Ecosystem::Nix;
        assert_eq!(purl(&d), "pkg:nix/hello"); // empty version → no @
    }

    #[test]
    fn cyclonedx_has_components_and_edges() {
        // app (direct) → lib; lib is transitive.
        let deps = vec![
            dep("app", "1.0.0", true, &[]),
            dep("lib", "2.0.0", false, &[("app", "1.0.0")]),
        ];
        let bom = cyclonedx("myproject", &deps, "2026-01-01T00:00:00Z");
        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert_eq!(bom["components"].as_array().unwrap().len(), 2);
        // The root depends on the direct package `app`.
        let root_edge = bom["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["ref"] == "postmortem:root")
            .unwrap();
        assert_eq!(root_edge["dependsOn"][0], "pkg:npm/app@1.0.0");
        // `app` depends on `lib`.
        let app_edge = bom["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["ref"] == "pkg:npm/app@1.0.0")
            .unwrap();
        assert_eq!(app_edge["dependsOn"][0], "pkg:npm/lib@2.0.0");
    }
}
