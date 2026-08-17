//! Version ordering, good enough for every registry we read.
//!
//! Deliberately *not* a SemVer implementation, and deliberately not a new
//! dependency. postmortem compares versions across npm, PyPI, crates.io,
//! RubyGems, Packagist, Go, Maven and half a dozen OS package managers, and no
//! single specification covers that set — a strict SemVer parser would reject
//! `1.2.3.4` (Maven), `1.0.0b2` (PEP 440) and `1:2.3-1` (dpkg) outright.
//!
//! So versions are compared the way OSV's own `ECOSYSTEM` ordering approximates
//! it: split into numeric and non-numeric runs, compare numbers numerically and
//! text lexically. That gets the cases this crate needs right —
//! `4.17.15 < 4.17.19 < 4.18.0`, `1.9 < 1.10` — without pretending to a
//! precision it cannot deliver.
//!
//! The one rule it borrows from SemVer is pre-release ordering: a version
//! carrying a `-suffix` sorts *below* the same version without one, so
//! `2.0.0-rc1 < 2.0.0`. Getting that backwards would tell someone a release
//! candidate already contains a fix that only landed in the final.
//!
//! Where this is imprecise it is imprecise *conservatively*: [`compare`] returns
//! `None` when it cannot order two versions, and callers then decline to claim a
//! fix rather than guess one.

use std::cmp::Ordering;

/// One component of a version: a number, or a text run.
#[derive(Debug, PartialEq, Eq)]
enum Part {
    Num(u64),
    Text(String),
}

/// Split a version into comparable parts, dropping the separators.
///
/// Build metadata (`+sha`) is discarded: SemVer says it carries no ordering, and
/// two builds of one version are the same release for our purposes.
fn parts(v: &str) -> (Vec<Part>, Option<String>) {
    let v = v.trim().trim_start_matches(['v', 'V']);
    let v = v.split('+').next().unwrap_or(v);
    // An epoch (`1:2.3`, dpkg/rpm) outranks everything after it; keep it as the
    // leading number so `2:1.0` > `1:9.9`.
    let v = v.replace(':', ".");
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) => (c.to_string(), Some(p.to_string())),
        None => (v.clone(), None),
    };

    let mut out = Vec::new();
    let mut cur = String::new();
    let mut cur_numeric = false;
    for c in core.chars() {
        if c == '.' || c == '_' {
            flush(&mut out, &mut cur, cur_numeric);
            continue;
        }
        let is_digit = c.is_ascii_digit();
        if !cur.is_empty() && is_digit != cur_numeric {
            flush(&mut out, &mut cur, cur_numeric);
        }
        cur_numeric = is_digit;
        cur.push(c);
    }
    flush(&mut out, &mut cur, cur_numeric);
    (out, pre)
}

fn flush(out: &mut Vec<Part>, cur: &mut String, numeric: bool) {
    if cur.is_empty() {
        return;
    }
    let taken = std::mem::take(cur);
    out.push(if numeric {
        match taken.parse::<u64>() {
            Ok(n) => Part::Num(n),
            // A number too large for u64 is pathological; keep it as text so it
            // still orders deterministically instead of panicking.
            Err(_) => Part::Text(taken),
        }
    } else {
        Part::Text(taken.to_ascii_lowercase())
    });
}

/// Order two versions, or `None` when they cannot be meaningfully compared.
///
/// `None` is returned for an empty or non-version string (`"unknown"`,
/// `"managed"`, `"unspecified"` — all of which our parsers legitimately produce
/// when a lockfile pins nothing). Callers must treat that as "cannot tell",
/// never as equal.
pub fn compare(a: &str, b: &str) -> Option<Ordering> {
    if !is_versionish(a) || !is_versionish(b) {
        return None;
    }
    let (pa, prea) = parts(a);
    let (pb, preb) = parts(b);

    for i in 0..pa.len().max(pb.len()) {
        match (pa.get(i), pb.get(i)) {
            (Some(Part::Num(x)), Some(Part::Num(y))) if x != y => return Some(x.cmp(y)),
            (Some(Part::Text(x)), Some(Part::Text(y))) if x != y => return Some(x.cmp(y)),
            // A number outranks text at the same position (`1.1` > `1.rc`).
            (Some(Part::Num(_)), Some(Part::Text(_))) => return Some(Ordering::Greater),
            (Some(Part::Text(_)), Some(Part::Num(_))) => return Some(Ordering::Less),
            // A missing component is lower: `1.2` < `1.2.1`.
            (None, Some(_)) => return Some(Ordering::Less),
            (Some(_), None) => return Some(Ordering::Greater),
            _ => {}
        }
    }

    // Equal cores: a pre-release sorts below the plain release.
    Some(match (prea, preb) {
        (None, None) => Ordering::Equal,
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (Some(x), Some(y)) => x.cmp(&y),
    })
}

/// Does this look like a version at all? Our parsers emit placeholders when a
/// manifest pins nothing, and comparing those would invent an ordering.
fn is_versionish(v: &str) -> bool {
    let v = v.trim();
    !v.is_empty() && v.chars().any(|c| c.is_ascii_digit())
}

/// `a < b`, false when they cannot be compared.
pub fn lt(a: &str, b: &str) -> bool {
    compare(a, b) == Some(Ordering::Less)
}

/// `a >= b`, false when they cannot be compared.
pub fn gte(a: &str, b: &str) -> bool {
    matches!(compare(a, b), Some(Ordering::Greater | Ordering::Equal))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_ordinary_releases() {
        assert!(lt("4.17.15", "4.17.19"));
        assert!(lt("4.17.19", "4.18.0"));
        assert!(lt("1.9.0", "1.10.0"), "numeric, not lexical");
        assert!(lt("1.2", "1.2.1"), "a missing component is lower");
        assert_eq!(compare("1.2.3", "1.2.3"), Some(Ordering::Equal));
    }

    #[test]
    fn a_leading_v_is_ignored() {
        // Go tags and many changelogs carry it.
        assert_eq!(compare("v1.2.3", "1.2.3"), Some(Ordering::Equal));
        assert!(lt("v1.2.3", "v1.2.4"));
    }

    #[test]
    fn build_metadata_carries_no_ordering() {
        assert_eq!(compare("1.2.3+build9", "1.2.3+build1"), Some(Ordering::Equal));
    }

    #[test]
    fn a_prerelease_sorts_below_its_release() {
        // Getting this backwards would claim a release candidate already
        // contains a fix that only landed in the final.
        assert!(lt("2.0.0-rc1", "2.0.0"));
        assert!(lt("2.0.0-alpha", "2.0.0-beta"));
        assert!(lt("1.9.9", "2.0.0-rc1"));
    }

    #[test]
    fn handles_the_shapes_a_strict_semver_parser_would_reject() {
        assert!(lt("1.2.3.4", "1.2.3.5"), "Maven four-part");
        assert!(lt("1.0.0b1", "1.0.0b2"), "PEP 440");
        assert!(lt("1:1.0", "2:1.0"), "dpkg epoch");
        assert!(lt("2.3-1", "2.3-2"), "distro revision");
    }

    #[test]
    fn a_number_outranks_text_at_the_same_position() {
        assert!(lt("1.rc", "1.1"));
    }

    #[test]
    fn non_versions_are_incomparable_not_equal() {
        // Our parsers emit these when a manifest pins nothing; inventing an
        // ordering for them would fabricate a fix.
        for v in ["", "  ", "unknown", "managed", "unspecified"] {
            assert_eq!(compare(v, "1.0.0"), None, "{v:?} should be incomparable");
            assert_eq!(compare("1.0.0", v), None);
            assert!(!lt(v, "1.0.0"));
            assert!(!gte(v, "1.0.0"), "incomparable must not read as satisfied");
        }
    }

    #[test]
    fn gte_covers_equal_and_greater_only() {
        assert!(gte("1.2.3", "1.2.3"));
        assert!(gte("1.2.4", "1.2.3"));
        assert!(!gte("1.2.2", "1.2.3"));
    }
}
