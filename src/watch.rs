//! `postmortem watch` — re-scan whenever a lockfile changes.
//!
//! ## This is a feedback loop, not a gate
//!
//! It reacts *after* an install: by the time a lockfile's mtime moves, the
//! install that wrote it has finished and any script it ran has run. Nothing
//! here withholds execution — that is npm's `allowScripts` (see
//! [`crate::scripts`]), and blocking a build is the [CI gate](crate::gate).
//!
//! What it is good for is the loop it closes: add a dependency, see within
//! seconds what came with it, without remembering to run anything.
//!
//! ## Polling, deliberately
//!
//! Watching a handful of files by `stat` needs no dependency. Pulling in a
//! filesystem-notification crate — and its transitive tree — so that a
//! supply-chain scanner can watch three files would be exactly what this tool
//! flags in other people's projects. A poll costs one `stat` per lockfile per
//! interval; at the default that is a few syscalls a second.
//!
//! Size **and** mtime are compared, because an editor or a package manager can
//! rewrite a file within a filesystem's mtime granularity, and a change that
//! kept both is a change nothing could have observed anyway.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// The lockfiles and manifests worth reacting to. A manifest change without a
/// lockfile change is still worth a scan: it is usually the moment before one.
const WATCHED: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "package.json",
    "Cargo.lock",
    "Gemfile.lock",
    "composer.lock",
    "poetry.lock",
    "Pipfile.lock",
    "go.sum",
    "gradle.lockfile",
    "requirements.txt",
];

/// A file's observable state. `None` for a file that does not exist, so that a
/// lockfile appearing or being deleted both register as changes.
type Fingerprint = BTreeMap<PathBuf, Option<(u64, SystemTime)>>;

/// Fingerprint the watched files under `root`.
///
/// Only the project root is scanned, not the whole tree: a recursive walk would
/// pick up every vendored manifest under `node_modules` and fire on installs
/// that changed nothing about the project itself.
pub fn fingerprint(root: &Path) -> Fingerprint {
    WATCHED
        .iter()
        .map(|name| {
            let p = root.join(name);
            let meta = std::fs::metadata(&p)
                .ok()
                .and_then(|m| m.modified().ok().map(|t| (m.len(), t)));
            (p, meta)
        })
        .collect()
}

/// The files that differ between two fingerprints.
pub fn changed(before: &Fingerprint, after: &Fingerprint) -> Vec<PathBuf> {
    after
        .iter()
        .filter(|(p, now)| before.get(*p).map(|was| was != *now).unwrap_or(true))
        .map(|(p, _)| p.clone())
        .collect()
}

/// Which of the watched files currently exist — reported at startup so a watch
/// over a directory with no lockfile is obviously doing nothing.
pub fn present(root: &Path) -> Vec<String> {
    fingerprint(root)
        .into_iter()
        .filter(|(_, m)| m.is_some())
        .filter_map(|(p, _)| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pm-watch-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn an_unchanged_directory_reports_nothing() {
        let d = dir("stable");
        std::fs::write(d.join("package-lock.json"), "{}").unwrap();
        let a = fingerprint(&d);
        let b = fingerprint(&d);
        assert!(changed(&a, &b).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_content_change_is_detected_even_within_mtime_granularity() {
        // Two writes in the same instant can share an mtime; the size catches it.
        let d = dir("size");
        let f = d.join("package-lock.json");
        std::fs::write(&f, "{}").unwrap();
        let a = fingerprint(&d);
        std::fs::write(&f, r#"{"lockfileVersion":3}"#).unwrap();
        assert_eq!(changed(&a, &fingerprint(&d)), vec![f]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_lockfile_appearing_or_vanishing_both_register() {
        let d = dir("appear");
        let a = fingerprint(&d);
        let f = d.join("Cargo.lock");
        std::fs::write(&f, "x").unwrap();
        assert_eq!(changed(&a, &fingerprint(&d)), vec![f.clone()]);
        let b = fingerprint(&d);
        std::fs::remove_file(&f).unwrap();
        assert_eq!(
            changed(&b, &fingerprint(&d)),
            vec![f],
            "a deletion is a change too"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_unrelated_file_is_ignored() {
        let d = dir("noise");
        let a = fingerprint(&d);
        std::fs::write(d.join("README.md"), "hello").unwrap();
        assert!(changed(&a, &fingerprint(&d)).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn only_the_root_is_watched_not_vendored_manifests() {
        // A recursive watch would fire on every install that touched
        // node_modules without changing the project at all.
        let d = dir("vendored");
        std::fs::create_dir_all(d.join("node_modules").join("x")).unwrap();
        let a = fingerprint(&d);
        std::fs::write(d.join("node_modules").join("x").join("package.json"), "{}").unwrap();
        assert!(changed(&a, &fingerprint(&d)).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn present_lists_only_what_exists() {
        let d = dir("present");
        assert!(present(&d).is_empty());
        std::fs::write(d.join("yarn.lock"), "").unwrap();
        assert_eq!(present(&d), vec!["yarn.lock"]);
        let _ = std::fs::remove_dir_all(&d);
    }
}
