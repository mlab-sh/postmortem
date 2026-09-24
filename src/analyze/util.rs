use aho_corasick::AhoCorasick;
use ignore::{DirEntry, WalkBuilder, WalkState};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The source languages the content analyzers cover.
///
/// One enum, shared by IOC / obfuscation / sensitive-API detection. It used to
/// be declared three times, identically, which is what made three separate
/// walks of the same tree look natural — they are now one pass (see
/// [`super::scan_content`]).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Lang {
    JavaScript,
    Python,
    Rust,
    Ruby,
    Php,
    Go,
    Java,
    /// C and C++ (shared headers, overlapping surface).
    Cpp,
    Perl,
    /// Shell (sh/bash/zsh) - covers OS-package install hooks.
    Shell,
    /// PowerShell (`ps1`/`psm1`) - Chocolatey packages ARE PowerShell scripts,
    /// and Windows install hooks live here.
    PowerShell,
    Lua,
}

impl Lang {
    /// Every language, for a full-tree source scan (`system inspect --deep`).
    pub const ALL: &'static [Lang] = &[
        Lang::JavaScript,
        Lang::Python,
        Lang::Rust,
        Lang::Ruby,
        Lang::Php,
        Lang::Go,
        Lang::Java,
        Lang::Cpp,
        Lang::Perl,
        Lang::Shell,
        Lang::PowerShell,
        Lang::Lua,
    ];

    /// Whether `path`'s extension is one of this language's, compared the way
    /// [`Listing::files`] compares it.
    pub fn matches(self, path: &Path) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| self.exts().iter().any(|x| x.eq_ignore_ascii_case(e)))
    }

    pub fn exts(self) -> &'static [&'static str] {
        match self {
            Lang::JavaScript => &["js", "mjs", "cjs", "ts"],
            Lang::Python => &["py"],
            Lang::Rust => &["rs"],
            Lang::Ruby => &["rb"],
            Lang::Php => &["php"],
            Lang::Go => &["go"],
            Lang::Java => &["java", "kt"],
            Lang::Cpp => &["c", "h", "cpp", "cc", "cxx", "hpp", "hh", "hxx"],
            Lang::Perl => &["pl", "pm", "t"],
            Lang::Shell => &["sh", "bash", "zsh", "ksh"],
            Lang::PowerShell => &["ps1", "psm1", "psd1"],
            Lang::Lua => &["lua"],
        }
    }
}

/// Cap each file we read at 1 MiB — minified bundles and source-maps blow past this
/// and would dominate runtime without adding signal.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Try to extract the package name from a path inside `node_modules/`. Handles scoped
/// packages (`@scope/name`). Returns `None` if the path is not under a `node_modules` segment.
pub fn node_pkg_from_path(path: &Path) -> Option<String> {
    let mut comps = path.components().peekable();
    let mut last_pkg: Option<String> = None;
    while let Some(c) = comps.next() {
        if c.as_os_str() == "node_modules" {
            let first = comps.next()?.as_os_str().to_str()?.to_string();
            let pkg = if first.starts_with('@') {
                let second = comps.next()?.as_os_str().to_str()?.to_string();
                format!("{first}/{second}")
            } else {
                first
            };
            last_pkg = Some(pkg);
        }
    }
    last_pkg
}

/// Try to extract a Python package name from a path inside `site-packages/`.
pub fn python_pkg_from_path(path: &Path) -> Option<String> {
    let mut comps = path.components().peekable();
    while let Some(c) = comps.next() {
        if c.as_os_str() == "site-packages" {
            let next = comps.next()?.as_os_str().to_str()?.to_string();
            // strip *.dist-info / *.egg-info suffixes
            let cleaned = next
                .trim_end_matches(".dist-info")
                .trim_end_matches(".egg-info");
            return Some(cleaned.to_string());
        }
    }
    None
}

/// Every readable file under one root, listed once and shared by every analyzer
/// that looks at that root.
///
/// Each analyzer used to walk the tree itself: five full walks of the same
/// `node_modules` per scan (IDE hooks, behaviour, workflows, Dockerfiles,
/// install hooks) on top of the content pass, each a single-threaded chain of
/// `opendir`/`getdirentries` — they were the critical path once the analyzers
/// ran concurrently. One parallel walk replaces them.
///
/// Files are sorted by path, so what an analyzer emits in walk order is the
/// same on every machine (readdir order is filesystem-dependent), and the files
/// below any directory are one contiguous run (`Path`'s order is
/// component-wise), which is how [`Listing::select`] serves a subdirectory
/// without walking it again.
pub struct Listing {
    root: PathBuf,
    files: Vec<PathBuf>,
    /// Set by [`Listing::owned_by`]: the package this listing is narrowed to,
    /// kept so a directory walked on its own is narrowed the same way.
    only: Option<String>,
}

impl Listing {
    /// Walk `root` without respecting `.gitignore` or hidden-file conventions —
    /// vendored and dot-directory code is exactly what we want. Files over
    /// [`MAX_FILE_BYTES`] are left out.
    pub fn walk(root: &Path) -> Listing {
        /// A worker's finds, handed over when the walker drops its visitor.
        struct Local<'s> {
            found: Vec<PathBuf>,
            sink: &'s Mutex<Vec<PathBuf>>,
        }
        impl Drop for Local<'_> {
            fn drop(&mut self) {
                self.sink.lock().unwrap().append(&mut self.found);
            }
        }

        let sink = Mutex::new(Vec::new());
        WalkBuilder::new(root)
            .hidden(false)
            .follow_links(false)
            .standard_filters(false) // include node_modules, ignore .gitignore — we WANT vendored code
            .threads(std::thread::available_parallelism().map_or(4, |n| n.get()))
            .build_parallel()
            .run(|| {
                let mut local = Local {
                    found: Vec::new(),
                    sink: &sink,
                };
                Box::new(move |entry| {
                    if let Some(p) = entry.ok().as_ref().and_then(readable_file) {
                        local.found.push(p);
                    }
                    WalkState::Continue
                })
            });
        let mut files = sink.into_inner().unwrap();
        files.sort_unstable();
        Listing {
            root: root.to_path_buf(),
            files,
            only: None,
        }
    }

    /// Only the files [`owner`] attributes to `pkg`: every copy of
    /// `node_modules/<pkg>` (nested ones included, but not the packages nested
    /// inside it) or `site-packages/<pkg>`. Every analyzer names its findings
    /// after the owner of the file they come from, so this is all of `pkg`'s.
    pub fn owned_by(mut self, pkg: &str) -> Listing {
        self.files.retain(|p| is_owned_by(p, pkg));
        self.only = Some(pkg.to_string());
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The files under `dir` that `keep` selects. `dir` is normally the root
    /// or inside it; anything else — or a subdirectory that is itself a link,
    /// which the root walk did not descend — is walked on its own, as the
    /// per-analyzer walk used to.
    pub fn select(&self, dir: &Path, keep: impl Fn(&Path) -> bool) -> Vec<PathBuf> {
        let covered = dir == self.root
            || (dir.starts_with(&self.root)
                && std::fs::symlink_metadata(dir).is_ok_and(|m| !m.file_type().is_symlink()));
        if !covered {
            let sub = Listing::walk(dir);
            let sub = match &self.only {
                Some(pkg) => sub.owned_by(pkg),
                None => sub,
            };
            return sub.select(dir, keep);
        }
        let start = self.files.partition_point(|p| p.as_path() < dir);
        self.files[start..]
            .iter()
            .take_while(|p| p.starts_with(dir))
            .filter(|p| keep(p))
            .cloned()
            .collect()
    }

    /// The files under `dir` with one of `exts` (ASCII case-insensitive).
    pub fn files(&self, dir: &Path, exts: &[&str]) -> Vec<PathBuf> {
        self.select(dir, |p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| exts.iter().any(|x| x.eq_ignore_ascii_case(e)))
        })
    }
}

/// The path of a walk entry worth reading: a regular file within the size cap.
///
/// A symlink is resolved explicitly: `follow_links(false)` stops the walk
/// descending through linked *directories*, but a linked file is ordinary
/// source that must still be read — pnpm's `node_modules` is built almost
/// entirely out of them, and skipping them would blind the scan to a whole
/// package manager. `DirEntry::metadata` does not follow, so ask the filesystem.
fn readable_file(e: &DirEntry) -> Option<PathBuf> {
    let ft = e.file_type()?;
    if ft.is_dir() {
        return None;
    }
    let md = if ft.is_symlink() {
        std::fs::metadata(e.path()).ok()?
    } else {
        e.metadata().ok()?
    };
    (md.is_file() && md.len() <= MAX_FILE_BYTES).then(|| e.path().to_path_buf())
}

/// Shannon entropy in bits/byte over the given text. Uses byte frequencies — good
/// enough to distinguish English/source from base64/hex/encrypted blobs.
pub fn shannon_entropy(s: &[u8]) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in s {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Most needles one automaton may carry in [`needle_counts`].
pub const MAX_NEEDLES: usize = 32;

/// How often each of `ac`'s patterns occurs in `text`, by pattern id — one pass
/// for a whole needle list instead of one `contains` per needle. Overlapping,
/// so a needle inside another (`exec(` within `.exec(`) is counted as a
/// `contains` of each would have found it.
pub fn needle_counts(ac: &AhoCorasick, text: &str) -> [u32; MAX_NEEDLES] {
    let mut counts = [0u32; MAX_NEEDLES];
    for m in ac.find_overlapping_iter(text) {
        counts[m.pattern().as_usize()] += 1;
    }
    counts
}

/// An automaton for [`needle_counts`]. The default `MatchKind::Standard` is
/// the one overlapping search needs.
pub fn automaton(needles: &[&str]) -> AhoCorasick {
    assert!(needles.len() <= MAX_NEEDLES, "raise MAX_NEEDLES");
    AhoCorasick::new(needles).expect("static needle list")
}

/// Truncate an evidence snippet for safe display.
pub fn snippet(s: &str, max: usize) -> String {
    let trimmed = s.trim();
    if trimmed.len() <= max {
        trimmed.to_string()
    } else {
        let cut = trimmed
            .char_indices()
            .nth(max)
            .map(|(i, _)| i)
            .unwrap_or(max);
        format!("{}…", &trimmed[..cut])
    }
}

/// True when a path lives under a test/fixture directory. Test trees routinely
/// embed fake IPs / URLs / domains that are pure IOC noise, so IOC detection
/// skips them by default (override with `--allow-test-files`).
pub fn is_test_path(path: &str) -> bool {
    path.split(['/', '\\']).any(|c| {
        matches!(
            c,
            "test"
                | "tests"
                | "testdata"
                | "__tests__"
                | "spec"
                | "specs"
                | "fixtures"
                | "__mocks__"
        )
    })
}

/// Owning-dependency derivation: pick the most specific source.
pub fn owner(path: &Path, project_label: &str) -> String {
    if let Some(p) = node_pkg_from_path(path) {
        return p;
    }
    if let Some(p) = python_pkg_from_path(path) {
        return p;
    }
    project_label.to_string()
}

/// `owner(path, _) == pkg`, for a real package name (never the project label).
fn is_owned_by(path: &Path, pkg: &str) -> bool {
    node_pkg_from_path(path)
        .or_else(|| python_pkg_from_path(path))
        .is_some_and(|p| p == pkg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn node_pkg_unscoped() {
        let p = PathBuf::from("/x/node_modules/foo/index.js");
        assert_eq!(node_pkg_from_path(&p), Some("foo".into()));
    }

    #[test]
    fn node_pkg_scoped() {
        let p = PathBuf::from("/x/node_modules/@scope/bar/lib/a.js");
        assert_eq!(node_pkg_from_path(&p), Some("@scope/bar".into()));
    }

    #[test]
    fn node_pkg_nested_picks_innermost() {
        let p = PathBuf::from("/x/node_modules/a/node_modules/b/index.js");
        assert_eq!(node_pkg_from_path(&p), Some("b".into()));
    }

    #[test]
    fn entropy_low_for_english() {
        let e = shannon_entropy(b"hello world this is a normal sentence");
        assert!(e < 5.0, "got {e}");
    }

    #[test]
    fn entropy_high_for_base64ish() {
        // 64-character alphabet uniform over a long buffer → entropy near 6 bits/byte.
        let mut s = Vec::new();
        for _ in 0..50 {
            s.extend_from_slice(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            );
        }
        let e = shannon_entropy(&s);
        assert!(e > 5.9, "got {e}");
    }
}

/// Unix-only: creating a symlink on Windows needs `SeCreateSymbolicLinkPrivilege`,
/// which a CI runner does not reliably have, so the fixture cannot be built
/// there. The walk's symlink handling itself is platform-independent — the
/// `is_symlink` branch resolves through `std::fs::metadata` on every target.
#[cfg(all(test, unix))]
mod walk_tests {
    use super::*;

    /// pnpm builds `node_modules` out of symlinks into a content-addressed
    /// store. The walk does not *descend* through links (`follow_links(false)`,
    /// so a link loop cannot hang it), but a linked file is ordinary source and
    /// must still be read — skipping it would blind the scan to pnpm entirely.
    #[test]
    fn symlinked_files_are_walked() {
        let base = std::env::temp_dir().join(format!("pm-walk-{}", std::process::id()));
        let store = base.join("store");
        let pkg = base.join("node_modules/p");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(store.join("real.js"), "console.log(1)").unwrap();
        std::os::unix::fs::symlink(store.join("real.js"), pkg.join("index.js")).unwrap();

        let found = Listing::walk(&base).files(&base, &["js"]);
        std::fs::remove_dir_all(&base).ok();

        assert!(
            found.iter().any(|p| p.ends_with("node_modules/p/index.js")),
            "symlinked source must be walked, got {found:?}"
        );
    }
}

#[cfg(test)]
mod listing_tests {
    use super::*;

    /// A subdirectory is served from the root listing as one contiguous run:
    /// its own files, and not a sibling that merely shares its name as a prefix
    /// (`a.b`, `ab` sort right next to `a/…`).
    #[test]
    fn select_serves_a_subdirectory_without_its_siblings() {
        let base = std::env::temp_dir().join(format!("pm-listing-{}", std::process::id()));
        for f in ["a/x.js", "a/deep/y.js", "a.b/z.js", "ab/w.js", "top.js"] {
            let p = base.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "x").unwrap();
        }
        let list = Listing::walk(&base);
        let under_a = list.files(&base.join("a"), &["js"]);
        let all = list.files(&base, &["JS"]);
        std::fs::remove_dir_all(&base).ok();

        assert_eq!(under_a, vec![base.join("a/deep/y.js"), base.join("a/x.js")]);
        assert_eq!(all.len(), 5, "extension match is case-insensitive: {all:?}");
    }

    /// Narrowed to a package: each copy of it, nested ones too, but neither
    /// the packages nested inside it nor a sibling sharing its name's prefix.
    #[test]
    fn owned_by_keeps_every_copy_of_one_package() {
        let base = std::env::temp_dir().join(format!("pm-owned-{}", std::process::id()));
        for f in [
            "node_modules/t/a.js",
            "node_modules/x/node_modules/t/b.js",
            "node_modules/t/node_modules/u/c.js",
            "node_modules/tt/d.js",
            "src/e.js",
        ] {
            let p = base.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "x").unwrap();
        }
        let got = Listing::walk(&base).owned_by("t").files(&base, &["js"]);
        std::fs::remove_dir_all(&base).ok();

        assert_eq!(
            got,
            vec![
                base.join("node_modules/t/a.js"),
                base.join("node_modules/x/node_modules/t/b.js"),
            ]
        );
    }
}
