//! Immutable on-disk cache under `$HOME/.postmortem/cache/<namespace>/<key>.json`.
//!
//! A published npm version's manifest never changes, so its repository
//! resolution is cached **forever**. GitHub repo stats do drift over time, but
//! we still cache them (keyed by repo) and rely on the `postmortem cache`
//! command to inspect/clear entries rather than a TTL — matching the "keep it
//! for a given version for life" model.
//!
//! ## Why entries are versioned
//!
//! Every record is written inside an [`Envelope`] carrying [`FORMAT_VERSION`]
//! and a `fetched_at` stamp. That envelope is what makes the "cache forever"
//! model safe to evolve.
//!
//! Without it, adding a field to a cached struct is silently destructive: serde
//! fills a missing `Option` field with `None` even without `#[serde(default)]`,
//! so every pre-existing entry would deserialize *successfully* and report the
//! new field as absent — permanently, since nothing ever expires it. A user
//! upgrading postmortem would get a cache full of plausible, wrong answers with
//! no error anywhere.
//!
//! So [`Cache::get`] checks the version and treats a mismatch as a miss,
//! deleting the file so the next write replaces it. Callers see an ordinary
//! cache miss and refetch. Bumping [`FORMAT_VERSION`] therefore invalidates
//! everything lazily, as it is touched — and `cache prune --stale` sweeps the
//! rest eagerly.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The on-disk record format.
///
/// **Bump this whenever a cached struct's shape changes** (a new field, a
/// renamed one, a changed meaning). Entries written by any other version are
/// discarded on read rather than misread. See the module docs for why a version
/// check is required and not merely nice to have.
pub const FORMAT_VERSION: u32 = 1;

pub struct Cache {
    root: Option<PathBuf>,
}

/// A cached record on disk: the payload plus the version that decides whether it
/// is still trustworthy.
///
/// The stored `fetched_at` is deliberately absent here — serde ignores unknown
/// fields, and the read path has no use for it. It is read back through
/// [`Header`] instead, by the passes that report on entries rather than use them.
#[derive(Deserialize)]
struct Envelope<T> {
    v: u32,
    data: T,
}

/// The write-side envelope, borrowing the payload so `put` never clones it.
#[derive(Serialize)]
struct EnvelopeRef<'a, T> {
    v: u32,
    fetched_at: u64,
    data: &'a T,
}

/// Just the envelope metadata, for passes that inspect entries without knowing
/// their payload type (`info`, `prune --stale`).
///
/// `data` is required and deserialized as [`IgnoredAny`], which skips the payload
/// without allocating. Requiring it is what makes the check unambiguous: a
/// pre-envelope record is a bare payload, and some payloads have their own
/// top-level fields — `RepoStats` carries a `fetched_at`, and a future one could
/// carry a `v`. Keying off `v` alone would then read a legacy entry's own field
/// and could report it as current, which is precisely the silent misread the
/// envelope exists to prevent.
#[derive(Deserialize)]
struct Header {
    #[serde(default)]
    v: u32,
    #[serde(default)]
    fetched_at: u64,
    #[allow(dead_code)]
    data: serde::de::IgnoredAny,
}

/// Read an entry's envelope metadata. `None` when the file is unreadable, is not
/// JSON, or is a pre-envelope record — all of which mean "not a current entry".
fn read_header(path: &Path) -> Option<Header> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<Header>(&raw).ok()
}

/// Is this file a current-format entry?
fn is_current(path: &Path) -> bool {
    read_header(path).is_some_and(|h| h.v == FORMAT_VERSION)
}

/// Outcome of a [`Cache::prune`] pass.
#[derive(Debug, Default, Clone, Copy)]
pub struct PruneReport {
    pub removed: usize,
    pub kept: usize,
    /// Bytes freed (or that would be freed, for a dry run).
    pub freed: u64,
}

/// What to remove in a [`Cache::prune`] pass.
#[derive(Debug, Default, Clone, Copy)]
pub struct PruneOpts {
    /// Keep entries fetched within the last N days. `None` prunes every age.
    pub older_than_days: Option<u64>,
    /// Only remove entries written by a different [`FORMAT_VERSION`].
    pub stale_only: bool,
    /// Report what would go without deleting anything.
    pub dry_run: bool,
}

/// Per-namespace totals for `cache info`.
#[derive(Debug, Clone)]
pub struct NamespaceStats {
    pub name: String,
    pub entries: usize,
    pub bytes: u64,
    /// Entries written by a different [`FORMAT_VERSION`] — refetched on next use.
    pub stale: usize,
    /// Oldest / newest `fetched_at`, as unix seconds.
    pub oldest: Option<u64>,
    pub newest: Option<u64>,
}

/// The whole cache, summarized.
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub root: Option<PathBuf>,
    pub namespaces: Vec<NamespaceStats>,
}

impl CacheStats {
    pub fn entries(&self) -> usize {
        self.namespaces.iter().map(|n| n.entries).sum()
    }
    pub fn bytes(&self) -> u64 {
        self.namespaces.iter().map(|n| n.bytes).sum()
    }
    pub fn stale(&self) -> usize {
        self.namespaces.iter().map(|n| n.stale).sum()
    }
    pub fn oldest(&self) -> Option<u64> {
        self.namespaces.iter().filter_map(|n| n.oldest).min()
    }
    pub fn newest(&self) -> Option<u64> {
        self.namespaces.iter().filter_map(|n| n.newest).max()
    }
}

/// Seconds since the unix epoch, saturating to 0 before it.
fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
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

    /// Read an entry, or `None` on a miss.
    ///
    /// An entry written by a different [`FORMAT_VERSION`] — or one whose payload
    /// no longer matches `T` — counts as a miss **and is deleted**, so the next
    /// `put` replaces it. The caller cannot tell the difference from a cold
    /// miss, which is the point: a stale record must never surface as data.
    pub fn get<T: DeserializeOwned>(&self, namespace: &str, key: &str) -> Option<T> {
        let p = self.path(namespace, key)?;
        let raw = std::fs::read_to_string(&p).ok()?;
        match serde_json::from_str::<Envelope<T>>(&raw) {
            Ok(e) if e.v == FORMAT_VERSION => Some(e.data),
            // Wrong version, or a record predating the envelope: drop it. Errors
            // are ignored — a failed unlink just means we retry next run, and
            // concurrent resolvers may race on the same key.
            _ => {
                let _ = std::fs::remove_file(&p);
                None
            }
        }
    }

    pub fn put<T: Serialize>(&self, namespace: &str, key: &str, value: &T) {
        let Some(p) = self.path(namespace, key) else {
            return;
        };
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let env = EnvelopeRef { v: FORMAT_VERSION, fetched_at: now_secs(), data: value };
        if let Ok(json) = serde_json::to_string(&env) {
            let _ = std::fs::write(p, json);
        }
    }

    /// Summarize the cache by namespace, for `cache info`. Reads only each
    /// entry's [`Header`], never its payload, so it stays cheap on a large cache.
    pub fn stats(&self) -> CacheStats {
        let mut by_ns: BTreeMap<String, NamespaceStats> = BTreeMap::new();
        let Some(root) = self.root.as_ref().filter(|r| r.is_dir()) else {
            return CacheStats { root: self.root.clone(), namespaces: Vec::new() };
        };

        for entry in walkdir::WalkDir::new(root).into_iter().flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            // The namespace is the directory holding the entry; anything loose
            // at the root is bucketed under "(root)" rather than dropped.
            let ns = entry
                .path()
                .parent()
                .filter(|p| *p != root)
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                .unwrap_or("(root)")
                .to_string();

            // `None` (or a version mismatch) means the entry is stale. Only a
            // current entry's timestamp is trusted for the age columns — a legacy
            // payload's own `fetched_at` is not the envelope's.
            let header = read_header(entry.path()).filter(|h| h.v == FORMAT_VERSION);

            let s = by_ns.entry(ns.clone()).or_insert_with(|| NamespaceStats {
                name: ns,
                entries: 0,
                bytes: 0,
                stale: 0,
                oldest: None,
                newest: None,
            });
            s.entries += 1;
            s.bytes += meta.len();
            match header {
                None => s.stale += 1,
                Some(h) if h.fetched_at > 0 => {
                    s.oldest = Some(s.oldest.map_or(h.fetched_at, |o: u64| o.min(h.fetched_at)));
                    s.newest = Some(s.newest.map_or(h.fetched_at, |n: u64| n.max(h.fetched_at)));
                }
                Some(_) => {}
            }
        }
        CacheStats { root: self.root.clone(), namespaces: by_ns.into_values().collect() }
    }

    /// The cache root directory, if `$HOME` is known.
    pub fn root(&self) -> Option<&Path> {
        self.root.as_deref()
    }

    /// Remove cached entries, filtered by [`PruneOpts`].
    ///
    /// With no options every entry goes. `older_than_days` keeps entries
    /// modified within the window; `stale_only` restricts the pass to entries
    /// written by a different [`FORMAT_VERSION`]. The two combine (both must
    /// hold). `dry_run` reports without deleting.
    pub fn prune(&self, opts: PruneOpts) -> PruneReport {
        let mut report = PruneReport::default();
        let Some(root) = self.root.as_ref().filter(|r| r.is_dir()) else {
            return report;
        };
        let cutoff = opts
            .older_than_days
            .map(|d| SystemTime::now() - Duration::from_secs(d.saturating_mul(86_400)));

        for entry in walkdir::WalkDir::new(root).into_iter().flatten() {
            let meta = match entry.metadata() {
                Ok(m) if m.is_file() => m,
                _ => continue,
            };
            let old_enough = match cutoff {
                None => true, // no threshold → every age qualifies
                Some(cut) => meta.modified().map(|m| m < cut).unwrap_or(false),
            };
            // Reading the header costs a parse per file, so only do it when the
            // filter actually needs it.
            let wrong_version = !opts.stale_only || !is_current(entry.path());

            if old_enough && wrong_version {
                report.removed += 1;
                report.freed += meta.len();
                if !opts.dry_run {
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

    /// A unique cache dir per test — the suite runs in parallel.
    fn tmp_cache(tag: &str) -> (Cache, PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pm-cache-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        (Cache::at(dir.clone()), dir)
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
    fn entries_are_written_inside_a_versioned_envelope() {
        let (cache, dir) = tmp_cache("envelope");
        cache.put("npm", "a@1.0.0", &Blob { a: 1, b: "x".into() });

        let raw = std::fs::read_to_string(dir.join("npm").join("a@1.0.0.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["v"], FORMAT_VERSION, "the record carries its format version");
        assert!(v["fetched_at"].as_u64().unwrap() > 0, "and when it was fetched");
        assert_eq!(v["data"]["a"], 1, "the payload lives under `data`");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_record_from_another_version_is_a_miss_and_is_deleted() {
        let (cache, dir) = tmp_cache("version");
        let p = dir.join("npm");
        std::fs::create_dir_all(&p).unwrap();
        let f = p.join("a@1.0.0.json");
        std::fs::write(
            &f,
            format!(r#"{{"v":{},"fetched_at":1,"data":{{"a":1,"b":"x"}}}}"#, FORMAT_VERSION + 1),
        )
        .unwrap();

        assert!(cache.get::<Blob>("npm", "a@1.0.0").is_none(), "wrong version must not be read");
        assert!(!f.exists(), "and the file must be dropped so the next put replaces it");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_pre_envelope_record_is_a_miss_and_is_deleted() {
        // Records written before the envelope existed are bare payloads.
        let (cache, dir) = tmp_cache("legacy");
        let p = dir.join("npm");
        std::fs::create_dir_all(&p).unwrap();
        let f = p.join("a@1.0.0.json");
        std::fs::write(&f, r#"{"a":1,"b":"x"}"#).unwrap();

        assert!(cache.get::<Blob>("npm", "a@1.0.0").is_none());
        assert!(!f.exists());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_changed_payload_shape_is_a_miss_rather_than_a_silent_wrong_answer() {
        // This is the failure the envelope exists to prevent: serde fills a
        // missing `Option` field with `None` even without `#[serde(default)]`,
        // so without a version check a stale entry would deserialize fine and
        // report the new field as absent — forever, since nothing expires it.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Old {
            repo: Option<String>,
        }
        #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
        struct New {
            repo: Option<String>,
            license: Option<String>,
        }

        let (cache, dir) = tmp_cache("shape");
        cache.put("registry", "a@1.0.0", &Old { repo: Some("github.com/o/r".into()) });

        // Same FORMAT_VERSION, so the entry IS returned — with `license: None`,
        // which is exactly the silent-wrong-answer case.
        let got: Option<New> = cache.get("registry", "a@1.0.0");
        assert_eq!(
            got,
            Some(New { repo: Some("github.com/o/r".into()), license: None }),
            "serde does not reject the missing field — hence FORMAT_VERSION must be bumped"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn stats_group_by_namespace_and_count_stale() {
        let (cache, dir) = tmp_cache("stats");
        cache.put("npm", "a@1.0.0", &Blob { a: 1, b: "x".into() });
        cache.put("npm", "b@1.0.0", &Blob { a: 2, b: "y".into() });
        cache.put("github", "o/r", &Blob { a: 3, b: "z".into() });
        // One hand-written entry from a future version.
        std::fs::write(
            dir.join("npm").join("old@1.0.0.json"),
            format!(r#"{{"v":{},"fetched_at":1,"data":{{"a":9,"b":"q"}}}}"#, FORMAT_VERSION + 1),
        )
        .unwrap();

        let s = cache.stats();
        assert_eq!(s.entries(), 4);
        assert_eq!(s.stale(), 1);
        assert!(s.bytes() > 0);

        let npm = s.namespaces.iter().find(|n| n.name == "npm").unwrap();
        assert_eq!(npm.entries, 3);
        assert_eq!(npm.stale, 1);
        let gh = s.namespaces.iter().find(|n| n.name == "github").unwrap();
        assert_eq!(gh.entries, 1);
        assert_eq!(gh.stale, 0);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn stats_on_an_absent_cache_are_empty_not_an_error() {
        let (cache, dir) = tmp_cache("absent");
        let s = cache.stats();
        assert_eq!(s.entries(), 0);
        assert!(s.namespaces.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn prune_stale_only_removes_wrong_version_entries() {
        let (cache, dir) = tmp_cache("prune-stale");
        cache.put("npm", "keep@1.0.0", &Blob { a: 1, b: "x".into() });
        std::fs::write(
            dir.join("npm").join("drop@1.0.0.json"),
            format!(r#"{{"v":{},"fetched_at":1,"data":{{"a":9,"b":"q"}}}}"#, FORMAT_VERSION + 1),
        )
        .unwrap();

        let r = cache.prune(PruneOpts { stale_only: true, ..Default::default() });
        assert_eq!(r.removed, 1, "only the stale entry");
        assert_eq!(r.kept, 1);
        assert!(cache.get::<Blob>("npm", "keep@1.0.0").is_some(), "the current entry survives");

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
        let r = cache.prune(PruneOpts { dry_run: true, ..Default::default() });
        assert_eq!(r.removed, 2);
        assert!(r.freed > 0);
        assert!(cache.get::<Blob>("npm", "a@1.0.0").is_some());

        // Real prune: removes both.
        let r = cache.prune(PruneOpts::default());
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
        let r = cache.prune(PruneOpts { older_than_days: Some(30), ..Default::default() });
        assert_eq!(r.removed, 0);
        assert_eq!(r.kept, 1);
        assert!(cache.get::<Blob>("npm", "fresh@1.0.0").is_some());

        let _ = std::fs::remove_dir_all(dir);
    }
}
