//! Immutable on-disk cache under `$HOME/.postmortem/cache/<namespace>/<key>.json`.
//!
//! A published npm version's manifest never changes, so its repository
//! resolution is cached **forever**. GitHub repo stats do drift over time, but
//! we still cache them (keyed by repo) and rely on a future `postmortem cache`
//! command to inspect/clear entries rather than a TTL — matching the "keep it
//! for a given version for life" model. Each entry records `fetched_at` so that
//! command (or a later TTL policy) has something to work with.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::Serialize;
use serde::de::DeserializeOwned;

pub struct Cache {
    root: Option<PathBuf>,
}

/// Outcome of a [`Cache::prune`] pass.
#[derive(Debug, Default, Clone, Copy)]
pub struct PruneReport {
    pub removed: usize,
    pub kept: usize,
    /// Bytes freed (or that would be freed, for a dry run).
    pub freed: u64,
}

impl Cache {
    /// The real cache at `$HOME/.postmortem/cache/`. A `None` root (no `$HOME`)
    /// degrades to a no-op cache: every `get` misses and every `put` is dropped.
    pub fn open() -> Self {
        Cache { root: crate::settings::base_dir().map(|d| d.join("cache")) }
    }

    /// A cache rooted at an explicit directory (used in tests).
    #[cfg(test)]
    pub fn at(root: PathBuf) -> Self {
        Cache { root: Some(root) }
    }

    fn path(&self, namespace: &str, key: &str) -> Option<PathBuf> {
        self.root
            .as_ref()
            .map(|r| r.join(namespace).join(format!("{}.json", sanitize(key))))
    }

    pub fn get<T: DeserializeOwned>(&self, namespace: &str, key: &str) -> Option<T> {
        let raw = std::fs::read_to_string(self.path(namespace, key)?).ok()?;
        serde_json::from_str(&raw).ok()
    }

    pub fn put<T: Serialize>(&self, namespace: &str, key: &str, value: &T) {
        let Some(p) = self.path(namespace, key) else {
            return;
        };
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string(value) {
            let _ = std::fs::write(p, json);
        }
    }

    /// The cache root directory, if `$HOME` is known.
    pub fn root(&self) -> Option<&Path> {
        self.root.as_deref()
    }

    /// Remove cached entries. `older_than_days = None` prunes everything;
    /// `Some(d)` keeps entries modified within the last `d` days. With
    /// `dry_run`, nothing is deleted — the report says what *would* go.
    pub fn prune(&self, older_than_days: Option<u64>, dry_run: bool) -> PruneReport {
        let mut report = PruneReport::default();
        let Some(root) = self.root.as_ref().filter(|r| r.is_dir()) else {
            return report;
        };
        let cutoff = older_than_days
            .map(|d| SystemTime::now() - Duration::from_secs(d.saturating_mul(86_400)));

        for entry in walkdir::WalkDir::new(root).into_iter().flatten() {
            let meta = match entry.metadata() {
                Ok(m) if m.is_file() => m,
                _ => continue,
            };
            let stale = match cutoff {
                None => true, // no threshold → prune all
                Some(cut) => meta.modified().map(|m| m < cut).unwrap_or(false),
            };
            if stale {
                report.removed += 1;
                report.freed += meta.len();
                if !dry_run {
                    let _ = std::fs::remove_file(entry.path());
                }
            } else {
                report.kept += 1;
            }
        }
        report
    }
}

/// Collapse an arbitrary key into one filesystem-safe path segment. npm scoped
/// names (`@scope/pkg`) and versions are common keys; `/` and other separators
/// become `_`.
fn sanitize(key: &str) -> String {
    key.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Blob {
        a: u32,
        b: String,
    }

    #[test]
    fn round_trips_through_disk() {
        let dir = std::env::temp_dir().join(format!("pm-cache-test-{}", std::process::id()));
        let cache = Cache::at(dir.clone());
        assert!(cache.get::<Blob>("npm", "left-pad@1.0.0").is_none());

        let v = Blob { a: 7, b: "hi".into() };
        cache.put("npm", "left-pad@1.0.0", &v);
        assert_eq!(cache.get::<Blob>("npm", "left-pad@1.0.0"), Some(v));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn scoped_names_are_safe_segments() {
        assert_eq!(sanitize("@babel/core@7.0.0"), "@babel_core@7.0.0");
        assert_eq!(sanitize("a/b/../c"), "a_b_.._c");
    }

    #[test]
    fn prune_all_respects_dry_run() {
        let dir = std::env::temp_dir().join(format!("pm-prune-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = Cache::at(dir.clone());
        cache.put("npm", "a@1.0.0", &Blob { a: 1, b: "x".into() });
        cache.put("github", "o/r", &Blob { a: 2, b: "y".into() });

        // Dry run: reports 2 but deletes nothing.
        let r = cache.prune(None, true);
        assert_eq!(r.removed, 2);
        assert!(r.freed > 0);
        assert!(cache.get::<Blob>("npm", "a@1.0.0").is_some());

        // Real prune: removes both.
        let r = cache.prune(None, false);
        assert_eq!(r.removed, 2);
        assert!(cache.get::<Blob>("npm", "a@1.0.0").is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn prune_older_than_keeps_fresh_entries() {
        let dir = std::env::temp_dir().join(format!("pm-prune-age-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = Cache::at(dir.clone());
        cache.put("npm", "fresh@1.0.0", &Blob { a: 1, b: "x".into() });

        // Just-written entry is younger than 30 days → kept.
        let r = cache.prune(Some(30), false);
        assert_eq!(r.removed, 0);
        assert_eq!(r.kept, 1);
        assert!(cache.get::<Blob>("npm", "fresh@1.0.0").is_some());

        let _ = std::fs::remove_dir_all(dir);
    }
}
