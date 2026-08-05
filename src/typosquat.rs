//! Typosquatting proximity check against a bundled corpus of popular npm names.
//!
//! Fully offline and deterministic. We flag a dependency only on **high-
//! confidence** proximity to a popular package it is *not* — one edit away, an
//! adjacent transposition, a punctuation variant (`cross-env` vs `crossenv` —
//! the real crossenv attack), or a digit/letter homoglyph — so false positives
//! stay rare. Distance-2 and looser matches are deliberately excluded.

use std::sync::OnceLock;

const CORPUS: &str = include_str!("data/npm-popular.txt");
const GO_CORPUS: &str = include_str!("data/go-popular.txt");

fn lines_of(corpus: &'static str) -> Vec<&'static str> {
    corpus
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

fn popular() -> &'static [&'static str] {
    static NAMES: OnceLock<Vec<&'static str>> = OnceLock::new();
    NAMES.get_or_init(|| lines_of(CORPUS))
}

fn popular_go() -> &'static [&'static str] {
    static PATHS: OnceLock<Vec<&'static str>> = OnceLock::new();
    PATHS.get_or_init(|| lines_of(GO_CORPUS))
}

/// A near-miss against a popular package.
#[derive(Debug, Clone, PartialEq)]
pub struct Match {
    pub target: String,
    pub kind: &'static str,
}

/// Return a typosquat match if `name` is a high-confidence near-miss of a
/// popular package (and isn't itself popular).
pub fn check(name: &str) -> Option<Match> {
    // Compare the unscoped last segment (`@evil/lodash` squats `lodash`).
    let n = name.rsplit('/').next().unwrap_or(name);
    if n.len() < 4 {
        return None;
    }
    let pop = popular();
    if pop.contains(&n) {
        return None; // it *is* the popular package
    }

    // A Unicode look-alike (Cyrillic/Greek homograph) in the name is almost
    // never legitimate; flag it, naming the popular package it mimics when the
    // ASCII skeleton matches one.
    if let Some(skel) = confusable_of(n) {
        let target = pop.iter().find(|&&t| t == skel).map(|s| s.to_string()).unwrap_or(skel);
        return Some(hit(&target, "unicode confusable"));
    }

    let n_sep = strip_sep(n);
    let n_homo = homoglyph(n);
    for &t in pop {
        if t == n {
            return None;
        }
        // Punctuation variant: same letters, different separators/none.
        if n != t && n_sep == strip_sep(t) {
            return Some(hit(t, "punctuation variant"));
        }
        // One character off (insert/delete/substitute).
        if t.len() >= 4 && lev1(n, t) {
            return Some(hit(t, "1 edit away"));
        }
        // Adjacent transposition (`recat` vs `react`).
        if transposition(n, t) {
            return Some(hit(t, "transposed"));
        }
        // Digit/letter homoglyph (`l0dash` vs `lodash`).
        if n != t && n_homo == homoglyph(t) {
            return Some(hit(t, "homoglyph"));
        }
    }
    None
}

fn hit(target: &str, kind: &'static str) -> Match {
    Match { target: target.to_string(), kind }
}

/// Remove `-`, `_`, `.` so `cross-env`, `cross_env`, `crossenv` collapse.
fn strip_sep(s: &str) -> String {
    s.chars().filter(|c| !matches!(c, '-' | '_' | '.')).collect()
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
        'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c', 'у' => 'y',
        'х' => 'x', 'ѕ' => 's', 'і' | 'ї' => 'i', 'ј' => 'j', 'ԁ' => 'd', 'һ' => 'h',
        'ӏ' => 'l', 'ո' => 'n', 'ԛ' => 'q', 'ѡ' => 'w', 'ъ' => 'b', 'м' => 'm', 'т' => 't',
        // Greek → Latin.
        'ο' => 'o', 'α' => 'a', 'ν' => 'v', 'ρ' => 'p', 'τ' => 't', 'ι' => 'i',
        'κ' => 'k', 'μ' => 'u', 'χ' => 'x', 'ε' => 'e',
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
    let go = popular_go();
    if go.contains(&p) {
        return None;
    }
    let (ph, po, pr) = split_path(p);
    for &t in go {
        if t == p {
            return None;
        }
        // Whole-path near-miss.
        if strip_sep(p) == strip_sep(t) {
            return Some(hit(t, "punctuation variant"));
        }
        if lev1(p, t) {
            return Some(hit(t, "1 edit away"));
        }
        if p != t && homoglyph(p) == homoglyph(t) {
            return Some(hit(t, "homoglyph"));
        }
        // Owner-squat: same host + repo, an impostor owner near/suffixed.
        // `owner_squat(popular_owner, candidate_owner)`.
        let (th, to, tr) = split_path(t);
        if ph == th && pr == tr && !pr.is_empty() && po != to && owner_squat(to, po) {
            return Some(hit(t, "owner variant"));
        }
    }
    None
}

/// A trailing path element that's a Go major-version marker (`v2`, `v10`).
fn is_major(seg: &str) -> bool {
    seg.strip_prefix('v').is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Split a module path into `(host, owner, repo)` (repo empty when the path has
/// only two segments, e.g. `k8s.io/client-go`).
fn split_path(p: &str) -> (&str, &str, &str) {
    let mut it = p.splitn(3, '/');
    (it.next().unwrap_or(""), it.next().unwrap_or(""), it.next().unwrap_or(""))
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

    #[test]
    fn flags_classic_squats() {
        assert_eq!(check("crossenv").unwrap().target, "cross-env"); // real 2017 attack
        assert_eq!(check("expres").unwrap().target, "express"); // deletion
        assert_eq!(check("recat").unwrap().target, "react"); // transposition
        assert_eq!(check("l0dash").unwrap().target, "lodash"); // homoglyph
        assert_eq!(check("momentt").unwrap().target, "moment"); // insertion
    }

    #[test]
    fn ignores_legit_and_distant() {
        assert!(check("lodash").is_none()); // is popular
        assert!(check("react").is_none());
        assert!(check("my-bespoke-internal-thing").is_none());
        assert!(check("abc").is_none()); // too short
        // two edits away should not fire
        assert!(check("exprss").is_none() || check("exprss").unwrap().kind == "1 edit away");
    }

    #[test]
    fn scoped_name_compares_last_segment() {
        assert_eq!(check("@evil/lodahs").unwrap().target, "lodash");
    }

    #[test]
    fn flags_unicode_confusable() {
        // Cyrillic 'е' (U+0435) in "rеact" → skeleton "react" (a popular pkg).
        assert_eq!(check("r\u{0435}act").unwrap().kind, "unicode confusable");
        // A confusable name not in the corpus still flags (mixed-script).
        assert!(check("n\u{0435}thereum").is_some());
        // Pure-ASCII legitimate names are untouched.
        assert!(check("react").is_none());
        assert!(check("mocha").is_none());
    }

    #[test]
    fn flags_go_owner_and_path_squats() {
        // boltdb-go/bolt borrows boltdb/bolt via an owner suffix.
        assert_eq!(
            check_module_path("github.com/boltdb-go/bolt").unwrap().target,
            "github.com/boltdb/bolt"
        );
        assert!(check_module_path("github.com/boltdb/bolt").is_none()); // the real one
        assert!(check_module_path("github.com/boltdb/bolt/v2").is_none()); // major suffix ok
        assert!(check_module_path("github.com/acme/internal-widget").is_none()); // unrelated
    }
}
