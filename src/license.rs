//! License normalization, SPDX validation, and policy evaluation.
//!
//! Registries do not agree on what a "license" is. npm mostly emits valid SPDX
//! (`MIT`, `MIT OR Apache-2.0`) but has legacy shapes (`{"type":"MIT"}`, a
//! `licenses` array). PyPI's `license` field is free text authored by hand
//! (`Apache 2.0`, `BSD`, `see LICENSE`), with a parallel signal in the trove
//! classifiers (`License :: OSI Approved :: MIT License`). crates.io and
//! Packagist are usually clean. So every value passes through [`normalize`]
//! before it is trusted.
//!
//! The rule that matters for output: **an identifier we cannot verify is never
//! emitted as an SPDX id.** CycloneDX consumers validate `license.id` against
//! the SPDX list and reject the whole document on a miss, so a wrong guess costs
//! more than an honest [`License::Name`]. When in doubt we degrade, never invent.
//!
//! Coverage is deliberately partial: the SPDX list has ~600 entries, most of
//! which never appear in a dependency tree. [`SPDX_IDS`] carries the identifiers
//! that actually show up, plus the aliases people really write. Anything else
//! survives as a `Name` — visible, flagged as non-SPDX, never silently dropped.

use std::collections::BTreeMap;

use crate::model::{Dependency, License};

/// SPDX identifiers postmortem recognises, **in their official casing**.
///
/// Stored canonically and matched case-insensitively, rather than lowercased and
/// re-capitalized on the way out: SPDX casing has no derivable rule
/// (`BSD-3-Clause` but `GPL-3.0-only`, `ODbL-1.0` but `OFL-1.1`), so any
/// reconstruction heuristic eventually emits an id that fails validation.
///
/// Not the full SPDX list — the subset that occurs in real dependency graphs.
/// Adding an entry only ever *improves* output (a `Name` becomes an `Id`); a
/// missing one is reported honestly rather than guessed.
const SPDX_IDS: &[&str] = &[
    "0BSD",
    "AFL-2.1",
    "AGPL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "Apache-1.1",
    "Apache-2.0",
    "Artistic-2.0",
    "BlueOak-1.0.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSD-3-Clause-Clear",
    "BSD-4-Clause",
    "BSL-1.0",
    "CC-BY-3.0",
    "CC-BY-4.0",
    "CC-BY-SA-4.0",
    "CC0-1.0",
    "CDLA-Permissive-2.0",
    "CDDL-1.0",
    "CDDL-1.1",
    "EPL-1.0",
    "EPL-2.0",
    "EUPL-1.2",
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "ISC",
    "LGPL-2.1",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MIT",
    "MIT-0",
    "MPL-1.1",
    "MPL-2.0",
    "MS-PL",
    "NCSA",
    "ODbL-1.0",
    "OFL-1.1",
    "OpenSSL",
    "PostgreSQL",
    "Python-2.0",
    "Ruby",
    "SSPL-1.0",
    "Unlicense",
    "Unicode-3.0",
    "Unicode-DFS-2016",
    "UPL-1.0",
    "Vim",
    "W3C",
    "WTFPL",
    "X11",
    "Zlib",
    "ZPL-2.1",
];

/// Free-text spellings mapped to their SPDX identifier.
///
/// Every entry here is a spelling seen in the wild — chiefly from PyPI, whose
/// `license` field is prose. Compared after [`squash`], so spacing, punctuation
/// and case are already gone: `Apache 2.0`, `apache-2.0` and `APACHE  2.0` all
/// arrive as `apache20`.
const ALIASES: &[(&str, &str)] = &[
    ("apache", "Apache-2.0"),
    ("apache2", "Apache-2.0"),
    ("apache20", "Apache-2.0"),
    ("apachelicense20", "Apache-2.0"),
    ("apachesoftwarelicense", "Apache-2.0"),
    ("apachev2", "Apache-2.0"),
    ("bsd2", "BSD-2-Clause"),
    ("bsd2clause", "BSD-2-Clause"),
    ("bsd3", "BSD-3-Clause"),
    ("bsd3clause", "BSD-3-Clause"),
    ("bsdlicense", "BSD-3-Clause"),
    ("gnugplv2", "GPL-2.0-only"),
    ("gnugplv3", "GPL-3.0-only"),
    ("gnulgplv3", "LGPL-3.0-only"),
    ("gpl2", "GPL-2.0-only"),
    ("gpl3", "GPL-3.0-only"),
    ("gplv2", "GPL-2.0-only"),
    ("gplv3", "GPL-3.0-only"),
    ("iscliense", "ISC"),
    ("isclicense", "ISC"),
    ("lgpl21", "LGPL-2.1-only"),
    ("lgpl3", "LGPL-3.0-only"),
    ("lgplv3", "LGPL-3.0-only"),
    ("mitlicense", "MIT"),
    ("mozillapubliclicense20", "MPL-2.0"),
    ("mpl2", "MPL-2.0"),
    ("mpl20", "MPL-2.0"),
    ("newbsd", "BSD-3-Clause"),
    ("publicdomain", "CC0-1.0"),
    ("simplifiedbsd", "BSD-2-Clause"),
    ("theunlicense", "Unlicense"),
    ("unlicense", "Unlicense"),
    ("zlibpng", "Zlib"),
];

/// Values that carry no information — treated as *absent*, not as a license.
/// Reporting `UNKNOWN` as a license name would make an unlicensed package look
/// documented.
const NULL_VALUES: &[&str] = &["", "unknown", "none", "null", "nolicense", "unlicensed", "seelicense", "other", "proprietary1", "todo"];

/// Strip everything that varies between spellings: case, spaces, punctuation.
/// `Apache License 2.0` → `apachelicense20`.
fn squash(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase()
}

/// The canonical SPDX identifier for a single token, preserving official casing
/// (`mit` → `MIT`, `apache-2.0` → `Apache-2.0`).
fn canonical_id(token: &str) -> Option<String> {
    let t = token.trim().trim_matches(|c| c == '(' || c == ')').trim();
    if t.is_empty() {
        return None;
    }
    // An exact SPDX id (case-insensitive) — the common, clean path. The table
    // already holds the official casing, so the hit is returned verbatim.
    let lower = t.to_ascii_lowercase();
    if let Some(hit) = SPDX_IDS.iter().find(|id| id.to_ascii_lowercase() == lower) {
        return Some((*hit).to_string());
    }
    // A `+` suffix is SPDX's deprecated "or later" (`GPL-2.0+`), valid on a known
    // id. `GPL-2.0` is itself deprecated in favour of the explicit forms, so map
    // straight to the `-or-later` spelling when it exists.
    if let Some(base) = lower.strip_suffix('+')
        && let Some(hit) = SPDX_IDS.iter().find(|id| id.to_ascii_lowercase() == base)
    {
        let or_later = format!("{hit}-or-later");
        if SPDX_IDS.contains(&or_later.as_str()) {
            return Some(or_later);
        }
        return Some((*hit).to_string());
    }
    // Otherwise try the free-text aliases.
    let sq = squash(t);
    ALIASES.iter().find(|(k, _)| *k == sq).map(|(_, v)| (*v).to_string())
}

/// Turn a raw registry/lockfile value into a [`License`], or `None` when it says
/// nothing at all.
///
/// Handles three cases in order: a compound SPDX expression (`MIT OR
/// Apache-2.0`), a single identifier or known alias, and finally unrecognised
/// free text — which is preserved verbatim as a [`License::Name`] so the user can
/// see what the package actually claims.
pub fn normalize(raw: &str) -> Option<License> {
    let raw = raw.trim();
    if NULL_VALUES.contains(&squash(raw).as_str()) {
        return None;
    }
    // A long value is prose (a pasted license text or a sentence), not an id.
    if raw.len() > 200 {
        return Some(License::Name { value: crate::analyze::util::snippet(raw, 80) });
    }

    // The pre-SPDX slash form (`MIT/Apache-2.0`) meant "or" in both Cargo and
    // npm manifests, and is still all over crates.io. Rewrite it to `OR` before
    // parsing, but only when every side is a license we recognise — otherwise a
    // path-looking value would be mangled into a bogus expression.
    let raw_owned;
    let raw = if !is_expression(raw) && raw.contains('/') {
        let parts: Vec<&str> = raw.split('/').map(str::trim).collect();
        if parts.len() > 1 && parts.iter().all(|p| canonical_id(p).is_some()) {
            raw_owned = parts.join(" OR ");
            raw_owned.as_str()
        } else {
            raw
        }
    } else {
        raw
    };

    // Compound expression? Split on the SPDX operators, keeping them.
    if is_expression(raw) {
        if let Some(expr) = normalize_expression(raw) {
            return Some(License::Expression { value: expr });
        }
        return Some(License::Name { value: raw.to_string() });
    }

    match canonical_id(raw) {
        Some(id) => Some(License::Id { value: id }),
        None => Some(License::Name { value: raw.to_string() }),
    }
}

/// Does this look like an SPDX compound expression rather than a bare id?
fn is_expression(raw: &str) -> bool {
    raw.split_whitespace().any(|w| matches!(w.to_ascii_uppercase().as_str(), "OR" | "AND" | "WITH"))
}

/// Normalize every operand of an expression, keeping the operators. Returns
/// `None` if any operand is unrecognisable — a partially-normalized expression
/// would be an SPDX expression that isn't valid SPDX.
fn normalize_expression(raw: &str) -> Option<String> {
    let mut out: Vec<String> = Vec::new();
    for tok in raw.split_whitespace() {
        let upper = tok.to_ascii_uppercase();
        if matches!(upper.as_str(), "OR" | "AND" | "WITH") {
            out.push(upper);
            continue;
        }
        // `WITH` introduces a license *exception* (`GPL-3.0 WITH
        // Classpath-exception-2.0`), which is a separate SPDX list we do not
        // carry — keep the operand verbatim rather than fail the whole value.
        if out.last().map(String::as_str) == Some("WITH") {
            out.push(tok.trim_matches(|c| c == '(' || c == ')').to_string());
            continue;
        }
        let lead = tok.chars().take_while(|c| *c == '(').count();
        let trail = tok.chars().rev().take_while(|c| *c == ')').count();
        let id = canonical_id(tok)?;
        out.push(format!("{}{}{}", "(".repeat(lead), id, ")".repeat(trail)));
    }
    (!out.is_empty()).then(|| out.join(" "))
}

/// Normalize a list of raw values (npm's legacy `licenses` array, composer's
/// `license`, RubyGems' `licenses`), deduplicating and dropping empties.
///
/// Several entries mean "any of these" in every ecosystem that uses an array, so
/// two or more collapse into a single `OR` expression — which is what an SBOM
/// consumer expects, rather than a list of unrelated licenses.
pub fn normalize_list(raws: &[String]) -> Vec<License> {
    let mut seen: Vec<License> = Vec::new();
    for r in raws {
        if let Some(l) = normalize(r)
            && !seen.contains(&l)
        {
            seen.push(l);
        }
    }
    if seen.len() > 1 && seen.iter().all(License::is_spdx) {
        let expr =
            seen.iter().map(|l| l.label().to_string()).collect::<Vec<_>>().join(" OR ");
        return vec![License::Expression { value: expr }];
    }
    seen
}

/// Resolve the raw license candidates a registry document offered.
///
/// Called on *every* read, including cache hits — the cache stores what the
/// registry said, never what we made of it. That separation matters because
/// entries are cached forever: an improvement to [`SPDX_IDS`] or [`ALIASES`]
/// then benefits every already-cached package, instead of being frozen out
/// until someone invalidates the cache.
///
/// Candidates that map to SPDX win over ones that do not, which is what makes a
/// PyPI package with `license = "see LICENSE"` and a
/// `License :: OSI Approved :: MIT License` classifier resolve to `MIT` rather
/// than to prose. When several SPDX candidates survive they are alternatives, so
/// they collapse into one `OR` expression.
pub fn resolve_raw(raws: &[String]) -> Vec<License> {
    let spdx: Vec<String> =
        raws.iter().filter(|r| normalize(r).is_some_and(|l| l.is_spdx())).cloned().collect();
    if !spdx.is_empty() {
        return normalize_list(&spdx);
    }
    // Nothing structured: keep the first thing that says anything at all.
    raws.iter().find_map(|r| normalize(r)).into_iter().collect()
}

// --- policy -------------------------------------------------------------------

/// A license policy: which identifiers are forbidden, and whether an
/// unidentifiable license is itself a failure.
#[derive(Debug, Default, Clone)]
pub struct Policy {
    /// SPDX ids that fail the build. Matched case-insensitively.
    pub deny: Vec<String>,
    /// When non-empty, *only* these are permitted — anything else fails.
    pub allow: Vec<String>,
    /// Treat a package with no resolvable license as a failure.
    pub fail_on_unknown: bool,
}

impl Policy {
    pub fn is_empty(&self) -> bool {
        self.deny.is_empty() && self.allow.is_empty() && !self.fail_on_unknown
    }
}

/// One package that violates the policy.
#[derive(Debug, Clone, PartialEq)]
pub struct Violation {
    pub package: String,
    pub version: String,
    /// The offending license, or `None` when the package declared none.
    pub license: Option<String>,
    pub reason: Reason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Explicitly listed in `deny`.
    Denied,
    /// An allowlist is in force and this is not on it.
    NotAllowed,
    /// No license could be resolved at all.
    Unknown,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Denied => "denied",
            Reason::NotAllowed => "not-allowed",
            Reason::Unknown => "unknown",
        }
    }
}

/// Evaluate `policy` over `deps`.
///
/// A package with several licenses (an `OR` expression) satisfies an allowlist
/// if *any* operand is permitted — that is what a choice of license means — and
/// trips the denylist only if *every* operand is denied, since you may simply
/// take the other one.
pub fn evaluate(deps: &[Dependency], policy: &Policy) -> Vec<Violation> {
    if policy.is_empty() {
        return Vec::new();
    }
    let norm = |s: &str| s.trim().to_ascii_lowercase();
    let deny: Vec<String> = policy.deny.iter().map(|s| norm(s)).collect();
    let allow: Vec<String> = policy.allow.iter().map(|s| norm(s)).collect();

    let mut out = Vec::new();
    for d in deps {
        if d.licenses.is_empty() {
            if policy.fail_on_unknown {
                out.push(Violation {
                    package: d.name.clone(),
                    version: d.version.clone(),
                    license: None,
                    reason: Reason::Unknown,
                });
            }
            continue;
        }
        // The set of alternatives this package offers.
        let options: Vec<String> = d
            .licenses
            .iter()
            .flat_map(|l| operands(l.label()))
            .map(|s| norm(&s))
            .collect();
        let label = d.licenses.iter().map(License::label).collect::<Vec<_>>().join(", ");

        if !deny.is_empty() && options.iter().all(|o| deny.contains(o)) {
            out.push(Violation {
                package: d.name.clone(),
                version: d.version.clone(),
                license: Some(label.clone()),
                reason: Reason::Denied,
            });
            continue;
        }
        if !allow.is_empty() && !options.iter().any(|o| allow.contains(o)) {
            out.push(Violation {
                package: d.name.clone(),
                version: d.version.clone(),
                license: Some(label),
                reason: Reason::NotAllowed,
            });
        }
    }
    out
}

/// The individual license ids inside a value, so `MIT OR Apache-2.0` is treated
/// as the two choices it is. `AND` operands are also split: a policy naming
/// either half should see it.
fn operands(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .filter(|t| !matches!(t.to_ascii_uppercase().as_str(), "OR" | "AND" | "WITH"))
        .map(|t| t.trim_matches(|c| c == '(' || c == ')').to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

// --- inventory ----------------------------------------------------------------

/// A license and the packages carrying it, for the `licenses` view.
#[derive(Debug, Clone)]
pub struct Bucket {
    pub label: String,
    pub spdx: bool,
    pub packages: Vec<String>,
}

/// Group `deps` by license, biggest bucket first. Packages with no resolvable
/// license land in a single `(unknown)` bucket, which is reported last and is
/// the number worth acting on.
pub fn inventory(deps: &[Dependency]) -> Vec<Bucket> {
    let mut by_label: BTreeMap<String, (bool, Vec<String>)> = BTreeMap::new();
    let mut unknown: Vec<String> = Vec::new();

    for d in deps {
        let id = format!("{}@{}", d.name, d.version);
        if d.licenses.is_empty() {
            unknown.push(id);
            continue;
        }
        let label = d.licenses.iter().map(License::label).collect::<Vec<_>>().join(", ");
        let spdx = d.licenses.iter().all(License::is_spdx);
        by_label.entry(label).or_insert((spdx, Vec::new())).1.push(id);
    }

    let mut out: Vec<Bucket> = by_label
        .into_iter()
        .map(|(label, (spdx, mut packages))| {
            packages.sort();
            packages.dedup();
            Bucket { label, spdx, packages }
        })
        .collect();
    // Biggest first, then alphabetically for a stable, diffable order.
    out.sort_by(|a, b| b.packages.len().cmp(&a.packages.len()).then(a.label.cmp(&b.label)));

    if !unknown.is_empty() {
        unknown.sort();
        unknown.dedup();
        out.push(Bucket { label: "(unknown)".into(), spdx: false, packages: unknown });
    }
    out
}

/// The `licenses --json` document.
///
/// Shaped for a CI consumer rather than for reading: totals first, then the
/// buckets, then the violations. `spdx: false` marks a bucket that resolved to
/// something we could not tie to an SPDX identifier, which a policy cannot
/// meaningfully match on.
pub fn inventory_json(
    inventory: &[Bucket],
    violations: &[Violation],
    deps: &[Dependency],
) -> serde_json::Value {
    let unknown = inventory.iter().find(|b| b.label == "(unknown)").map_or(0, |b| b.packages.len());
    serde_json::json!({
        "schema_version": 1,
        "total": deps.len(),
        "unresolved": unknown,
        "licenses": inventory
            .iter()
            .map(|b| serde_json::json!({
                "license": b.label,
                "spdx": b.spdx,
                "count": b.packages.len(),
                "packages": b.packages,
            }))
            .collect::<Vec<_>>(),
        "violations": violations
            .iter()
            .map(|v| serde_json::json!({
                "package": v.package,
                "version": v.version,
                "license": v.license,
                "reason": v.reason.as_str(),
            }))
            .collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Ecosystem, Scope};

    fn lic(s: &str) -> Option<License> {
        normalize(s)
    }

    #[test]
    fn exact_spdx_ids_round_trip_with_official_casing() {
        assert_eq!(lic("MIT"), Some(License::Id { value: "MIT".into() }));
        assert_eq!(lic("mit"), Some(License::Id { value: "MIT".into() }));
        assert_eq!(lic("Apache-2.0"), Some(License::Id { value: "Apache-2.0".into() }));
        assert_eq!(lic("apache-2.0"), Some(License::Id { value: "Apache-2.0".into() }));
        assert_eq!(lic("ISC"), Some(License::Id { value: "ISC".into() }));
        assert_eq!(lic("BSD-3-Clause"), Some(License::Id { value: "BSD-3-Clause".into() }));
        assert_eq!(lic("GPL-3.0-only"), Some(License::Id { value: "GPL-3.0-only".into() }));
        assert_eq!(lic("MPL-2.0"), Some(License::Id { value: "MPL-2.0".into() }));
    }

    #[test]
    fn pypi_free_text_maps_to_spdx() {
        // These are real PyPI `license` values — the field is prose.
        assert_eq!(lic("Apache 2.0"), Some(License::Id { value: "Apache-2.0".into() }));
        assert_eq!(lic("MIT License"), Some(License::Id { value: "MIT".into() }));
        assert_eq!(lic("BSD License"), Some(License::Id { value: "BSD-3-Clause".into() }));
        assert_eq!(lic("GPLv3"), Some(License::Id { value: "GPL-3.0-only".into() }));
        assert_eq!(lic("Mozilla Public License 2.0"), Some(License::Id { value: "MPL-2.0".into() }));
    }

    #[test]
    fn unrecognised_text_degrades_to_a_name_never_an_id() {
        // The critical rule: an invalid `license.id` fails CycloneDX schema
        // validation, so we must not guess.
        let l = lic("see the LICENSE file in the repo").unwrap();
        assert!(matches!(l, License::Name { .. }), "got {l:?}");
        assert!(!l.is_spdx());
        assert_eq!(l.label(), "see the LICENSE file in the repo");
    }

    #[test]
    fn empty_and_placeholder_values_are_absent_not_named() {
        for v in ["", "  ", "UNKNOWN", "unknown", "NONE", "unlicensed"] {
            assert_eq!(lic(v), None, "{v:?} should carry no license at all");
        }
    }

    #[test]
    fn compound_expressions_are_normalized_as_expressions() {
        assert_eq!(
            lic("MIT OR Apache-2.0"),
            Some(License::Expression { value: "MIT OR Apache-2.0".into() })
        );
        // Operands are normalized individually, operators upper-cased.
        assert_eq!(
            lic("mit or apache-2.0"),
            Some(License::Expression { value: "MIT OR Apache-2.0".into() })
        );
        assert_eq!(
            lic("(MIT AND Zlib)"),
            Some(License::Expression { value: "(MIT AND Zlib)".into() })
        );
    }

    #[test]
    fn the_legacy_slash_form_is_read_as_or() {
        // Pre-SPDX Cargo and npm manifests wrote `MIT/Apache-2.0`, and crates.io
        // still serves plenty of them.
        assert_eq!(
            lic("MIT/Apache-2.0"),
            Some(License::Expression { value: "MIT OR Apache-2.0".into() })
        );
        assert_eq!(
            lic("Unlicense/MIT"),
            Some(License::Expression { value: "Unlicense OR MIT".into() })
        );
    }

    #[test]
    fn a_slash_value_that_is_not_licenses_is_left_alone() {
        // A path or URL must not be mangled into a bogus expression.
        let l = lic("see licenses/COPYING").unwrap();
        assert!(matches!(l, License::Name { .. }), "got {l:?}");
        assert_eq!(l.label(), "see licenses/COPYING");
    }

    #[test]
    fn an_expression_with_an_unknown_operand_degrades_whole() {
        // Half-normalized would be an SPDX expression that isn't valid SPDX.
        let l = lic("MIT OR SomethingBespoke").unwrap();
        assert!(matches!(l, License::Name { .. }), "got {l:?}");
    }

    #[test]
    fn with_exception_keeps_the_exception_verbatim() {
        // Exceptions are a separate SPDX list we don't carry; keeping the
        // operand beats failing the whole value.
        assert_eq!(
            lic("GPL-2.0 WITH Classpath-exception-2.0"),
            Some(License::Expression {
                value: "GPL-2.0 WITH Classpath-exception-2.0".into()
            })
        );
    }

    #[test]
    fn or_later_plus_suffix_is_expanded() {
        assert_eq!(lic("GPL-2.0+"), Some(License::Id { value: "GPL-2.0-or-later".into() }));
    }

    #[test]
    fn prose_is_truncated_rather_than_stored_whole() {
        let long = "a".repeat(500);
        let l = lic(&long).unwrap();
        assert!(matches!(l, License::Name { .. }));
        assert!(l.label().len() < 120, "a pasted license body must not bloat the report");
    }

    #[test]
    fn a_list_of_alternatives_collapses_to_one_or_expression() {
        // composer / rubygems emit arrays meaning "any of these".
        let v = normalize_list(&["MIT".into(), "Apache-2.0".into()]);
        assert_eq!(v, vec![License::Expression { value: "MIT OR Apache-2.0".into() }]);
    }

    #[test]
    fn a_single_element_list_stays_an_id() {
        assert_eq!(normalize_list(&["MIT".into()]), vec![License::Id { value: "MIT".into() }]);
        assert!(normalize_list(&[]).is_empty());
        assert!(normalize_list(&["UNKNOWN".into()]).is_empty());
    }

    #[test]
    fn a_list_mixing_known_and_unknown_keeps_both_separately() {
        // Collapsing into an expression would produce invalid SPDX.
        let v = normalize_list(&["MIT".into(), "custom-thing".into()]);
        assert_eq!(v.len(), 2);
        assert!(v.iter().any(|l| matches!(l, License::Name { .. })));
    }

    // --- policy ---

    fn dep(name: &str, licenses: Vec<License>) -> Dependency {
        Dependency {
            name: name.into(),
            version: "1.0.0".into(),
            ecosystem: Ecosystem::Node,
            direct: true,
            scope: Scope::Prod,
            licenses,
            license_source: crate::model::LicenseSource::Registry,
            resolved_url: None,
            integrity: None,
            parents: vec![],
        }
    }

    #[test]
    fn an_empty_policy_flags_nothing() {
        let deps = vec![dep("a", vec![]), dep("b", vec![License::Id { value: "AGPL-3.0".into() }])];
        assert!(evaluate(&deps, &Policy::default()).is_empty());
    }

    #[test]
    fn deny_matches_case_insensitively() {
        let deps = vec![dep("a", vec![License::Id { value: "AGPL-3.0".into() }])];
        let p = Policy { deny: vec!["agpl-3.0".into()], ..Default::default() };
        let v = evaluate(&deps, &p);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].reason, Reason::Denied);
        assert_eq!(v[0].package, "a");
    }

    #[test]
    fn a_dual_licensed_package_escapes_a_denylist_via_its_other_option() {
        // `MIT OR AGPL-3.0` means you may take MIT. Denying AGPL must not flag it.
        let deps = vec![dep("a", vec![License::Expression { value: "MIT OR AGPL-3.0".into() }])];
        let p = Policy { deny: vec!["AGPL-3.0".into()], ..Default::default() };
        assert!(evaluate(&deps, &p).is_empty(), "a permitted alternative exists");

        // Denying both leaves no way out.
        let p = Policy { deny: vec!["AGPL-3.0".into(), "MIT".into()], ..Default::default() };
        assert_eq!(evaluate(&deps, &p).len(), 1);
    }

    #[test]
    fn an_allowlist_is_satisfied_by_any_one_option() {
        let deps = vec![
            dep("ok", vec![License::Expression { value: "MIT OR AGPL-3.0".into() }]),
            dep("bad", vec![License::Id { value: "AGPL-3.0".into() }]),
        ];
        let p = Policy { allow: vec!["MIT".into()], ..Default::default() };
        let v = evaluate(&deps, &p);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].package, "bad");
        assert_eq!(v[0].reason, Reason::NotAllowed);
    }

    #[test]
    fn unknown_licenses_are_only_flagged_when_asked() {
        let deps = vec![dep("a", vec![])];
        let p = Policy { deny: vec!["AGPL-3.0".into()], ..Default::default() };
        assert!(evaluate(&deps, &p).is_empty(), "no license is not a denied license");

        let p = Policy { fail_on_unknown: true, ..Default::default() };
        let v = evaluate(&deps, &p);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].reason, Reason::Unknown);
        assert_eq!(v[0].license, None);
    }

    // --- inventory ---

    #[test]
    fn inventory_groups_by_license_biggest_first_with_unknown_last() {
        let deps = vec![
            dep("a", vec![License::Id { value: "MIT".into() }]),
            dep("b", vec![License::Id { value: "MIT".into() }]),
            dep("c", vec![License::Id { value: "Apache-2.0".into() }]),
            dep("d", vec![]),
        ];
        let inv = inventory(&deps);
        assert_eq!(inv[0].label, "MIT");
        assert_eq!(inv[0].packages.len(), 2);
        assert_eq!(inv[1].label, "Apache-2.0");
        assert_eq!(inv.last().unwrap().label, "(unknown)");
        assert!(!inv.last().unwrap().spdx);
    }

    #[test]
    fn inventory_dedupes_identical_package_versions() {
        let deps = vec![
            dep("a", vec![License::Id { value: "MIT".into() }]),
            dep("a", vec![License::Id { value: "MIT".into() }]),
        ];
        assert_eq!(inventory(&deps)[0].packages.len(), 1);
    }
}
