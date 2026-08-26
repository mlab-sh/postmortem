//! Typosquatting proximity check against bundled corpora of popular package
//! names, one per ecosystem.
//!
//! Fully offline and deterministic. We flag a dependency only on **high-
//! confidence** proximity to a popular package it is *not* — one edit away, an
//! adjacent transposition, a punctuation variant (`cross-env` vs `crossenv` —
//! the real crossenv attack), or a digit/letter homoglyph — so false positives
//! stay rare. Distance-2 and looser matches are deliberately excluded.
//!
//! Each corpus is compared against **its own ecosystem only**. Cross-checking
//! would be actively wrong: `requests` is a top PyPI package and a perfectly
//! ordinary npm name, so a shared corpus would flag half of one registry as
//! squatting the other.
//!
//! Three name shapes exist. Most registries are flat (`lodash`, `requests`).
//! Packagist and Go are `vendor/name`, where the vendor half carries the
//! impersonation (`evil/monolog` squats `monolog/monolog`), so those are matched
//! whole, with an extra rule for a near-miss vendor under an identical name.
//! Maven is `group:artifact`, the same shape with another separator — but *not*
//! the same rule: an artifactId is only unique within its group, so `core`,
//! `annotations` and `commons-io` each appear under several unrelated groups in
//! the corpus alone. "Same artifact, different group" is therefore ordinary on
//! Maven where it is impersonation on Packagist, and only the shape-based
//! matches (one edit, transposition, punctuation, homoglyph) apply there.
//!
//! The corpora are a few thousand names each, and the check runs once per
//! dependency, so every derived form (separator-stripped, homoglyph-folded) is
//! computed **once** when a corpus is first touched rather than per comparison.

use std::collections::HashSet;
use std::sync::OnceLock;

use crate::model::Ecosystem;

const NPM: &str = include_str!("data/npm-popular.txt");
const PYPI: &str = include_str!("data/pypi-popular.txt");
const CRATES: &str = include_str!("data/crates-popular.txt");
const RUBYGEMS: &str = include_str!("data/rubygems-popular.txt");
const PACKAGIST: &str = include_str!("data/packagist-popular.txt");
const GO: &str = include_str!("data/go-popular.txt");
const MAVEN: &str = include_str!("data/maven-popular.txt");

/// A corpus with its comparison forms precomputed.
///
/// Without this, every dependency would re-derive `strip_sep` and `homoglyph`
/// for all few-thousand entries — two allocations per entry per dependency, so
/// millions on a real lockfile. Precomputing makes the scan linear in corpus
/// size with no allocation in the hot loop.
struct Corpus {
    names: Vec<&'static str>,
    /// `strip_sep(name)`, index-aligned with `names`.
    stripped: Vec<String>,
    /// `homoglyph(name)`, index-aligned with `names`.
    folded: Vec<String>,
    /// Lowercased, index-aligned with `names`. Go module paths are
    /// case-sensitive as *paths* but 67 of the popular ones carry a capital
    /// (`github.com/BurntSushi/toml`, `Azure`, `Microsoft`), and a dependency
    /// on one must not read as a one-edit near-miss of itself.
    lowered: Vec<String>,
    /// Membership test for "this *is* the popular package".
    set: HashSet<&'static str>,
}

impl Corpus {
    fn build(raw: &'static str) -> Self {
        let names: Vec<&'static str> = raw
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        let stripped = names.iter().map(|n| strip_sep(n)).collect();
        let folded = names.iter().map(|n| homoglyph(n)).collect();
        let lowered = names.iter().map(|n| n.to_lowercase()).collect();
        let set = names.iter().copied().collect();
        Corpus {
            names,
            stripped,
            folded,
            lowered,
            set,
        }
    }
}

macro_rules! corpus {
    ($fn_name:ident, $raw:ident) => {
        fn $fn_name() -> &'static Corpus {
            static C: OnceLock<Corpus> = OnceLock::new();
            C.get_or_init(|| Corpus::build($raw))
        }
    };
}
corpus!(npm, NPM);
corpus!(pypi, PYPI);
corpus!(crates, CRATES);
corpus!(rubygems, RUBYGEMS);
corpus!(packagist, PACKAGIST);
corpus!(go, GO);
corpus!(maven, MAVEN);

/// The corpus for an ecosystem, or `None` where we have no list — the OS
/// package managers, whose names are distribution-specific.
fn corpus_for(eco: Ecosystem) -> Option<&'static Corpus> {
    Some(match eco {
        Ecosystem::Node => npm(),
        Ecosystem::Python => pypi(),
        Ecosystem::Rust => crates(),
        Ecosystem::Ruby => rubygems(),
        Ecosystem::Php => packagist(),
        Ecosystem::Go => go(),
        Ecosystem::Java => maven(),
        _ => return None,
    })
}

/// A near-miss against a popular package.
#[derive(Debug, Clone, PartialEq)]
pub struct Match {
    pub target: String,
    pub kind: &'static str,
}

/// Return a typosquat match if `name` is a high-confidence near-miss of a
/// popular package in **its own ecosystem** (and isn't itself popular).
///
/// Ecosystems with no corpus return `None` — an absent list must never turn into
/// a comparison against someone else's registry.
pub fn check(name: &str, eco: Ecosystem) -> Option<Match> {
    let c = corpus_for(eco)?;
    // Two-part coordinates (`vendor/name`) carry the impersonation in the vendor
    // half, so they are matched whole rather than by last segment.
    if matches!(eco, Ecosystem::Php) {
        // Packagist is case-insensitive, and a fork there takes a new vendor
        // under the same name — so the vendor-variant rule applies.
        return check_two_part(&name.to_lowercase(), c, PACKAGIST_SHAPE);
    }
    if matches!(eco, Ecosystem::Java) {
        // Maven coordinates are case-sensitive (`org.antlr:ST4`), so no folding.
        return check_two_part(name, c, MAVEN_SHAPE);
    }
    if matches!(eco, Ecosystem::Go) {
        return check_module_path(name);
    }
    check_flat(name, c)
}

/// Flat registry names (npm, PyPI, crates.io, RubyGems).
fn check_flat(name: &str, c: &Corpus) -> Option<Match> {
    // The full name first: `@babel/core` is itself a popular package, and
    // testing only its last segment would compare `core` against the corpus and
    // report it as a near-miss of `cors`.
    if c.set.contains(name) {
        return None;
    }

    // A scoped name is namespaced by its scope, which an attacker cannot take.
    // The real attack there is reusing a popular name *verbatim* under a foreign
    // scope (`@evil/lodash`), so that is all we flag: running edit-distance on
    // the bare segment would call every `@vendor/core` a squat of `cors`.
    if let Some((_, bare)) = name.split_once('/')
        && name.starts_with('@')
    {
        return (bare.len() >= 4 && c.set.contains(bare))
            .then(|| hit(bare, "popular name under a foreign scope"));
    }

    let n = name;
    if n.len() < 4 {
        return None;
    }

    // A Unicode look-alike (Cyrillic/Greek homograph) in the name is almost
    // never legitimate; flag it, naming the popular package it mimics when the
    // ASCII skeleton matches one.
    if let Some(skel) = confusable_of(n) {
        let target = c
            .set
            .get(skel.as_str())
            .map(|s| s.to_string())
            .unwrap_or(skel);
        return Some(hit(&target, "unicode confusable"));
    }

    let n_sep = strip_sep(n);
    let n_homo = homoglyph(n);
    let nlen = n.chars().count();
    for (i, &t) in c.names.iter().enumerate() {
        if t == n {
            return None;
        }
        // Punctuation variant: same letters, different separators/none.
        if n_sep == c.stripped[i] {
            return Some(hit(t, "punctuation variant"));
        }
        // Digit/letter homoglyph (`l0dash` vs `lodash`).
        if n_homo == c.folded[i] {
            return Some(hit(t, "homoglyph"));
        }
        // The edit-distance rules can only fire on near-equal lengths; the check
        // is far cheaper than the walk, so it gates both.
        let tlen = t.chars().count();
        if nlen.abs_diff(tlen) > 1 {
            continue;
        }
        // One character off (insert/delete/substitute).
        if tlen >= 4 && lev1(n, t) {
            return Some(hit(t, "1 edit away"));
        }
        // Adjacent transposition (`recat` vs `react`).
        if transposition(n, t) {
            return Some(hit(t, "transposed"));
        }
    }
    None
}

/// `vendor/name` coordinates (Packagist).
///
/// The vendor half is what an attacker forges — `evil/monolog` ships whatever it
/// likes under a name a reader skims as `monolog`. So an identical package name
/// under a *different* vendor is the signal, alongside the ordinary whole-string
/// near-misses.
/// What a two-part coordinate means in a given registry.
struct TwoPart {
    /// `vendor/name` or `group:artifact`.
    sep: char,
    /// Does "same name, other vendor" read as impersonation? On Packagist yes:
    /// one flat namespace, a name is claimed once, so a second vendor
    /// publishing `monolog` is impersonating the first. On Maven no: an
    /// artifactId is unique only within its group, and `core`, `annotations`
    /// and `commons-io` each sit under several unrelated groups in the corpus
    /// alone — the rule would fire on every one of them.
    vendor_variant: bool,
    /// Do names carry their version? See `version_skeleton`.
    versioned_names: bool,
    /// Is the vendor half an *owned* namespace? Maven Central verifies a
    /// groupId against a domain or repository the publisher controls, so an
    /// impostor cannot publish into its victim's group — two coordinates
    /// sharing a group are siblings of one project (`aether-api` and
    /// `aether-spi`), never an impersonation.
    verified_vendor: bool,
}

const PACKAGIST_SHAPE: TwoPart = TwoPart {
    sep: '/',
    vendor_variant: true,
    versioned_names: false,
    verified_vendor: false,
};
const MAVEN_SHAPE: TwoPart = TwoPart {
    sep: ':',
    vendor_variant: false,
    versioned_names: true,
    verified_vendor: true,
};

fn check_two_part(p: &str, c: &Corpus, shape: TwoPart) -> Option<Match> {
    if c.set.contains(p) {
        return None;
    }
    let (pv, pn) = p.split_once(shape.sep)?;
    if pn.len() < 4 {
        return None;
    }
    if let Some(skel) = confusable_of(p) {
        let target = c
            .set
            .get(skel.as_str())
            .map(|s| s.to_string())
            .unwrap_or(skel);
        return Some(hit(&target, "unicode confusable"));
    }

    let p_sep = strip_sep(p);
    let p_homo = homoglyph(p);
    let p_skel = shape.versioned_names.then(|| version_skeleton(p));
    let plen = p.chars().count();
    for (i, &t) in c.names.iter().enumerate() {
        if t == p {
            return None;
        }
        // Same project, another version — see `version_skeleton`.
        if p_skel.as_deref() == Some(version_skeleton(t).as_str()) {
            continue;
        }
        // Siblings under one owned namespace — see `TwoPart::verified_vendor`.
        if shape.verified_vendor && t.split_once(shape.sep).is_some_and(|(tv, _)| tv == pv) {
            continue;
        }
        if p_sep == c.stripped[i] {
            return Some(hit(t, "punctuation variant"));
        }
        if p_homo == c.folded[i] {
            return Some(hit(t, "homoglyph"));
        }
        if shape.vendor_variant
            && let Some((tv, tn)) = t.split_once(shape.sep)
            // Same package name, impostor vendor — the squat that matters here.
            && tn == pn
            && tv != pv
        {
            return Some(hit(t, "vendor variant"));
        }
        if plen.abs_diff(t.chars().count()) > 1 {
            continue;
        }
        if lev1(p, t) {
            return Some(hit(t, "1 edit away"));
        }
        if transposition(p, t) {
            return Some(hit(t, "transposed"));
        }
    }
    None
}

fn hit(target: &str, kind: &'static str) -> Match {
    Match {
        target: target.to_string(),
        kind,
    }
}

/// Remove `-`, `_`, `.` so `cross-env`, `cross_env`, `crossenv` collapse.
/// A name with every digit removed.
///
/// Package names on Maven and Go carry the version *in the name*: Scala's
/// `_2.12` / `_2.13` cross-build suffix, a major bump baked into the artifact
/// (`retrofit` → `retrofit2`, `okhttp3`, `antlr4`), a gopkg.in `.v1` / `.v3`, a
/// `/v2` element, a JDK target (`kotlin-stdlib-jre7` vs `-jre8`). Two releases
/// of one project are then exactly one edit apart, which is the signature this
/// module looks for — so before calling anything a squat, check whether the two
/// names are the same modulo their digits. If they are, it is a version, and a
/// version is not an impostor.
fn version_skeleton(s: &str) -> String {
    s.chars().filter(|c| !c.is_ascii_digit()).collect()
}

fn strip_sep(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '-' | '_' | '.'))
        .collect()
}

/// Map common digit/letter look-alikes to a canonical letter.
fn homoglyph(s: &str) -> String {
    s.chars().map(fold_glyph).collect()
}

/// Fold a character to its ASCII look-alike: digit/letter substitutions
/// (`0`→`o`) **and** Unicode confusables (Cyrillic `е`, Greek `ο` → `e`/`o`).
fn fold_glyph(c: char) -> char {
    match c {
        // ASCII digit / letter look-alikes.
        '0' => 'o',
        '1' | 'l' => 'i',
        '3' => 'e',
        '5' => 's',
        '7' => 't',
        _ => deconfuse(c),
    }
}

/// Map a Unicode confusable (Cyrillic / Greek homograph) to its Latin ASCII
/// look-alike; other chars pass through. Registry names are conventionally
/// ASCII, so any of these in a name is a strong impersonation tell.
fn deconfuse(c: char) -> char {
    match c {
        // Cyrillic → Latin.
        'а' => 'a',
        'е' => 'e',
        'о' => 'o',
        'р' => 'p',
        'с' => 'c',
        'у' => 'y',
        'х' => 'x',
        'ѕ' => 's',
        'і' | 'ї' => 'i',
        'ј' => 'j',
        'ԁ' => 'd',
        'һ' => 'h',
        'ӏ' => 'l',
        'ո' => 'n',
        'ԛ' => 'q',
        'ѡ' => 'w',
        'ъ' => 'b',
        'м' => 'm',
        'т' => 't',
        // Greek → Latin.
        'ο' => 'o',
        'α' => 'a',
        'ν' => 'v',
        'ρ' => 'p',
        'τ' => 't',
        'ι' => 'i',
        'κ' => 'k',
        'μ' => 'u',
        'χ' => 'x',
        'ε' => 'e',
        other => other,
    }
}

/// If `name` uses a Unicode confusable (a non-ASCII char that maps to an ASCII
/// look-alike), return its all-ASCII skeleton — otherwise `None`. Used to flag
/// mixed-script impersonation regardless of the corpus (`Strіpe.net`, `Nеthereum`).
fn confusable_of(name: &str) -> Option<String> {
    let mut hit = false;
    let skeleton: String = name
        .chars()
        .map(|c| {
            let d = deconfuse(c);
            if d != c && !c.is_ascii() {
                hit = true;
            }
            d
        })
        .collect();
    (hit && skeleton.is_ascii()).then_some(skeleton)
}

/// True if `a` and `b` differ by exactly one insertion, deletion, or
/// substitution — cheaper and tighter than a full Levenshtein.
fn lev1(a: &str, b: &str) -> bool {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let (la, lb) = (a.len(), b.len());
    if la.abs_diff(lb) > 1 {
        return false;
    }
    if la == lb {
        // exactly one substitution
        return a.iter().zip(&b).filter(|(x, y)| x != y).count() == 1;
    }
    // one insertion/deletion: walk the shorter against the longer
    let (short, long) = if la < lb { (&a, &b) } else { (&b, &a) };
    let (mut i, mut j, mut skipped) = (0, 0, false);
    while i < short.len() && j < long.len() {
        if short[i] == long[j] {
            i += 1;
            j += 1;
        } else if skipped {
            return false;
        } else {
            skipped = true;
            j += 1;
        }
    }
    true
}

/// Typosquat check for a **Go module path** (`github.com/boltdb-go/bolt` squats
/// `github.com/boltdb/bolt`). Beyond a whole-path near-miss, it catches the
/// common owner-suffix trick: same host + same repo, but the owner is a
/// popular owner with a plausible suffix (`boltdb` → `boltdb-go`).
pub fn check_module_path(path: &str) -> Option<Match> {
    let normalized = path.trim_end_matches('/').to_lowercase();
    // Drop a trailing major-version element (`/v2`) for comparison.
    let p = normalized
        .rsplit_once('/')
        .filter(|(_, v)| is_major(v))
        .map(|(base, _)| base)
        .unwrap_or(normalized.as_str());
    let c = go();
    // Compared lowercased throughout — see `Corpus::lowered`.
    if c.lowered.iter().any(|t| t == p) {
        return None;
    }
    let (ph, po, pr) = split_path(p);
    let p_skel = version_skeleton(p);
    for (i, t) in c.lowered.iter().map(String::as_str).enumerate() {
        // Same module, another version — `gopkg.in/yaml.v1` vs `.v3`,
        // `hashicorp/hcl2` vs `hcl`. See `version_skeleton`.
        if p_skel == version_skeleton(t) {
            continue;
        }
        // Siblings under one owned namespace. Nobody but `github.com/aws` can
        // publish under `github.com/aws`, so its `service/sqs` and
        // `service/sts` are two modules of one project, not an impersonation —
        // the same reasoning as a verified Maven groupId.
        let (th_, to_, _) = split_path(t);
        if (ph, po) == (th_, to_) && !po.is_empty() {
            continue;
        }
        // Whole-path near-miss. The corpus entry keeps its own spelling in
        // the report — it is what the user would go and look up.
        let shown = c.names[i];
        if strip_sep(p) == strip_sep(t) {
            return Some(hit(shown, "punctuation variant"));
        }
        if lev1(p, t) {
            return Some(hit(shown, "1 edit away"));
        }
        if homoglyph(p) == homoglyph(t) {
            return Some(hit(shown, "homoglyph"));
        }
        // Owner-squat: same host + repo, an impostor owner near/suffixed.
        // `owner_squat(popular_owner, candidate_owner)`.
        let (th, to, tr) = split_path(t);
        if ph == th && pr == tr && !pr.is_empty() && po != to && owner_squat(to, po) {
            return Some(hit(shown, "owner variant"));
        }
    }
    None
}

/// A trailing path element that's a Go major-version marker (`v2`, `v10`).
fn is_major(seg: &str) -> bool {
    seg.strip_prefix('v')
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Split a module path into `(host, owner, repo)` (repo empty when the path has
/// only two segments, e.g. `k8s.io/client-go`).
fn split_path(p: &str) -> (&str, &str, &str) {
    let mut it = p.splitn(3, '/');
    (
        it.next().unwrap_or(""),
        it.next().unwrap_or(""),
        it.next().unwrap_or(""),
    )
}

/// Is `candidate` a squat of popular owner `pop`? A short added suffix
/// (`boltdb`→`boltdb-go`), a punctuation variant, or a single edit.
fn owner_squat(pop: &str, candidate: &str) -> bool {
    if pop.is_empty() || candidate.is_empty() {
        return false;
    }
    if let Some(rest) = candidate.strip_prefix(pop) {
        // e.g. "-go", "go", "-official", "-dev", "2", "-lib" (≤6 extra chars).
        if !rest.is_empty() && rest.len() <= 6 {
            return true;
        }
    }
    strip_sep(pop) == strip_sep(candidate) || lev1(pop, candidate)
}

/// True if `a` is `b` with one pair of adjacent characters swapped.
fn transposition(a: &str, b: &str) -> bool {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    if a.len() != b.len() || a == b {
        return false;
    }
    let diffs: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
    matches!(diffs.as_slice(), &[i, j] if j == i + 1 && a[i] == b[j] && a[j] == b[i])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn java(n: &str) -> Option<Match> {
        check(n, Ecosystem::Java)
    }

    fn go_path(n: &str) -> Option<Match> {
        check(n, Ecosystem::Go)
    }

    #[test]
    fn flags_a_maven_group_impostor() {
        // The Maven squat shape: the artifact is kept, the *group* is the lie.
        assert_eq!(
            java("com.gogle.guava:guava").unwrap().target,
            "com.google.guava:guava"
        );
        assert_eq!(
            java("com.g00gle.guava:guava").unwrap().target,
            "com.google.guava:guava",
            "digit homoglyph in the group"
        );
        assert!(java("com.google.guava:guava").is_none(), "the real one");
        // A near-miss *inside* the victim's own group is not reachable by an
        // attacker: Maven Central verifies a groupId against a domain or
        // repository its publisher controls.
        assert!(java("org.slf4j:slf4j-ap").is_none());
    }

    /// Every one of these is a real, legitimate coordinate that an earlier cut
    /// of this matcher flagged. They are the reason the Maven rules differ from
    /// the Packagist ones.
    #[test]
    fn maven_version_and_sibling_shapes_are_not_squats() {
        for n in [
            // Scala cross-build suffixes: one edit apart, by construction.
            "com.beachape:enumeratum_2.13",
            "org.typelevel:cats-effect_2.11",
            // A major version baked into the group or the artifact.
            "com.squareup.retrofit:retrofit",
            "org.antlr:antlr",
            "org.jetbrains.kotlin:kotlin-stdlib-jre7",
            // Siblings under one verified groupId.
            "org.mongodb:mongodb-driver-async",
            "org.eclipse.aether:aether-spi",
            // A generic artifactId under an unrelated group — ordinary on Maven,
            // which is why the vendor-variant rule is off there.
            "com.acme.internal:core",
            "com.acme.internal:annotations",
        ] {
            assert!(
                java(n).is_none(),
                "{n} should not be flagged: {:?}",
                java(n)
            );
        }
    }

    #[test]
    fn go_version_and_namespace_shapes_are_not_squats() {
        for n in [
            // gopkg.in carries the major version in the name.
            "gopkg.in/yaml.v1",
            "gopkg.in/tomb.v2",
            "github.com/hashicorp/hcl2",
            // Sub-modules of one project, under an owner nobody else can use.
            "github.com/aws/aws-sdk-go-v2/service/sqs",
            "github.com/aws/aws-sdk-go-v2/service/sns",
            "github.com/gobuffalo/packd",
            // A capitalised owner must not read as a near-miss of itself.
            "github.com/BurntSushi/toml",
            "github.com/Microsoft/go-winio",
        ] {
            assert!(
                go_path(n).is_none(),
                "{n} should not be flagged: {:?}",
                go_path(n)
            );
        }
    }

    /// npm is the historical corpus, so most shape tests live here.
    fn npm_check(n: &str) -> Option<Match> {
        check(n, Ecosystem::Node)
    }

    #[test]
    fn flags_classic_squats() {
        assert_eq!(npm_check("crossenv").unwrap().target, "cross-env"); // real 2017 attack
        assert_eq!(npm_check("expres").unwrap().target, "express"); // deletion
        assert_eq!(npm_check("recat").unwrap().target, "react"); // transposition
        assert_eq!(npm_check("l0dash").unwrap().target, "lodash"); // homoglyph
        assert_eq!(npm_check("momentt").unwrap().target, "moment"); // insertion
    }

    #[test]
    fn ignores_legit_and_distant() {
        assert!(npm_check("lodash").is_none()); // is popular
        assert!(npm_check("react").is_none());
        assert!(npm_check("my-bespoke-internal-thing").is_none());
        assert!(npm_check("abc").is_none()); // too short
    }

    #[test]
    fn a_popular_name_under_a_foreign_scope_is_flagged() {
        // The scope squat that happens: the reader skims `lodash` and misses the
        // scope entirely.
        let m = npm_check("@evil/lodash").unwrap();
        assert_eq!(m.target, "lodash");
        assert_eq!(m.kind, "popular name under a foreign scope");
    }

    #[test]
    fn a_scope_owned_package_is_not_judged_by_its_bare_segment() {
        // `@babel/core` is itself popular; comparing only `core` reported it as a
        // near-miss of `cors`. Six such false positives appeared on one real
        // 466-package tree.
        for n in ["@babel/core", "@jest/core", "@babel/parser", "@types/node"] {
            assert!(npm_check(n).is_none(), "{n} should not be flagged");
        }
        // Nor is an unknown vendor's own package: a scope cannot be forged, so a
        // merely *similar* bare name under one carries no impersonation. This is
        // a deliberate trade — edit-distance here cost far more in noise than it
        // caught.
        assert!(npm_check("@acme/coro").is_none());
    }

    #[test]
    fn flags_unicode_confusable() {
        // Cyrillic 'е' (U+0435) in "rеact" → skeleton "react" (a popular pkg).
        assert_eq!(
            npm_check("r\u{0435}act").unwrap().kind,
            "unicode confusable"
        );
        // A confusable name not in the corpus still flags (mixed-script).
        assert!(npm_check("n\u{0435}thereum").is_some());
        // Pure-ASCII legitimate names are untouched.
        assert!(npm_check("react").is_none());
        assert!(npm_check("mocha").is_none());
    }

    #[test]
    fn flags_go_owner_and_path_squats() {
        // boltdb-go/bolt borrows boltdb/bolt via an owner suffix.
        assert_eq!(
            check_module_path("github.com/boltdb-go/bolt")
                .unwrap()
                .target,
            "github.com/boltdb/bolt"
        );
        assert!(check_module_path("github.com/boltdb/bolt").is_none()); // the real one
        assert!(check_module_path("github.com/boltdb/bolt/v2").is_none()); // major suffix ok
        assert!(check_module_path("github.com/acme/internal-widget").is_none()); // unrelated
    }

    // --- the newly covered registries ---

    #[test]
    fn pypi_squats_are_flagged() {
        // PyPI is the most typosquatted registry; these are its classic shapes.
        assert_eq!(
            check("requsts", Ecosystem::Python).unwrap().target,
            "requests"
        );
        assert_eq!(
            check("urllib", Ecosystem::Python).unwrap().target,
            "urllib3"
        );
        assert!(
            check("requests", Ecosystem::Python).is_none(),
            "the real one"
        );
        assert!(check("numpy", Ecosystem::Python).is_none());
    }

    #[test]
    fn crates_squats_are_flagged() {
        // rustdecimal, the real May 2022 attack on rust_decimal, is a
        // punctuation variant.
        let m = check("rustdecimal", Ecosystem::Rust).unwrap();
        assert_eq!(m.target, "rust_decimal");
        assert_eq!(m.kind, "punctuation variant");
        assert!(check("rust_decimal", Ecosystem::Rust).is_none());
        assert!(check("serde", Ecosystem::Rust).is_none());
    }

    #[test]
    fn rubygems_squats_are_flagged() {
        assert!(check("nokogiri", Ecosystem::Ruby).is_none(), "the real gem");
        assert_eq!(
            check("nokogri", Ecosystem::Ruby).unwrap().target,
            "nokogiri"
        );
        assert!(check("rails", Ecosystem::Ruby).is_none());
    }

    #[test]
    fn packagist_vendor_squats_are_flagged() {
        // The shape that matters on Packagist: the package name is untouched and
        // the *vendor* is forged, so a reader skims it as the real thing.
        let m = check("evilcorp/monolog", Ecosystem::Php).unwrap();
        assert_eq!(m.kind, "vendor variant");
        assert!(m.target.ends_with("/monolog"), "got {}", m.target);
        assert!(
            check("monolog/monolog", Ecosystem::Php).is_none(),
            "the real one"
        );
    }

    #[test]
    fn packagist_keeps_the_vendor_in_view() {
        // A flat comparison would strip the vendor and see `monolog` == `monolog`,
        // missing the squat entirely — the reason PHP is matched whole.
        assert!(check("evilcorp/monolog", Ecosystem::Php).is_some());
        // And an unrelated internal package is left alone.
        assert!(check("acme/internal-billing-client", Ecosystem::Php).is_none());
    }

    #[test]
    fn corpora_do_not_bleed_across_ecosystems() {
        // The same string means different things per registry, which is exactly
        // why each corpus is consulted alone.
        //
        // `requests` IS the canonical PyPI package, so PyPI must stay silent —
        // while on npm it is one edit from npm's own `request`, so npm flags it
        // and names *npm's* package, never PyPI's.
        assert!(
            check("requests", Ecosystem::Python).is_none(),
            "requests is genuine on PyPI"
        );
        assert_eq!(
            check("requests", Ecosystem::Node).unwrap().target,
            "request"
        );

        // And a crate name is not judged against Python's list.
        assert!(
            check("serde", Ecosystem::Rust).is_none(),
            "serde is genuine on crates.io"
        );
        let py = check("serde", Ecosystem::Python);
        assert!(
            py.is_none_or(|m| !crates().set.contains(m.target.as_str())
                || pypi().set.contains(m.target.as_str())),
            "a PyPI verdict must cite a PyPI package"
        );
    }

    #[test]
    fn ecosystems_without_a_corpus_never_match() {
        // OS packages and Java have no list; they must return None rather than
        // borrow another registry's.
        for eco in [
            Ecosystem::Java,
            Ecosystem::Brew,
            Ecosystem::Apt,
            Ecosystem::Nix,
        ] {
            assert!(check("lodahs", eco).is_none(), "{eco:?} has no corpus");
        }
    }

    #[test]
    fn corpora_are_non_trivial_and_well_formed() {
        // A corpus that silently failed to parse would disable detection without
        // any error, so assert the shape rather than trust the include.
        for (name, c) in [
            ("npm", npm()),
            ("pypi", pypi()),
            ("crates", crates()),
            ("rubygems", rubygems()),
            ("packagist", packagist()),
        ] {
            assert!(
                c.names.len() > 500,
                "{name} corpus is too small: {}",
                c.names.len()
            );
            assert_eq!(
                c.names.len(),
                c.stripped.len(),
                "{name} derived forms misaligned"
            );
            assert_eq!(
                c.names.len(),
                c.folded.len(),
                "{name} derived forms misaligned"
            );
            assert!(
                !c.names.iter().any(|n| n.is_empty()),
                "{name} has an empty entry"
            );
            assert!(
                !c.names.iter().any(|n| n.starts_with('#')),
                "{name} leaked a comment line into the corpus"
            );
        }
        // Packagist entries are `vendor/name`; a flat one would never match.
        assert!(
            packagist().names.iter().filter(|n| n.contains('/')).count() > 1000,
            "packagist corpus should be vendor/name coordinates"
        );
    }
}
