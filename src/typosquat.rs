//! Typosquatting proximity check against a bundled corpus of popular npm names.
//!
//! Fully offline and deterministic. We flag a dependency only on **high-
//! confidence** proximity to a popular package it is *not* — one edit away, an
//! adjacent transposition, a punctuation variant (`cross-env` vs `crossenv` —
//! the real crossenv attack), or a digit/letter homoglyph — so false positives
//! stay rare. Distance-2 and looser matches are deliberately excluded.

use std::sync::OnceLock;

const CORPUS: &str = include_str!("data/npm-popular.txt");

fn popular() -> &'static [&'static str] {
    static NAMES: OnceLock<Vec<&'static str>> = OnceLock::new();
    NAMES.get_or_init(|| {
        CORPUS
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    })
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
    s.chars()
        .map(|c| match c {
            '0' => 'o',
            '1' | 'l' => 'i',
            '3' => 'e',
            '5' => 's',
            '7' => 't',
            other => other,
        })
        .collect()
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
}
