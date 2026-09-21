use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

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

/// Best-effort: walk a directory, respect `.gitignore` and hidden-file conventions,
/// yield files matching any extension in `exts`. File-size capped.
pub fn walk_files(root: &Path, exts: &[&str]) -> impl Iterator<Item = PathBuf> {
    let exts: Vec<String> = exts.iter().map(|s| s.to_ascii_lowercase()).collect();
    walk(root, move |p| {
        if exts.is_empty() {
            return true;
        }
        let ext = p
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        exts.iter().any(|e| e == &ext)
    })
}

/// Walk a directory, yielding the files `keep` selects. Callers that match on
/// an extension want [`walk_files`]; this is for the ones that match on the
/// whole name, because their targets have no extension of their own
/// (`Dockerfile`). Passing `|_| true` would walk the tree and pay a `metadata`
/// syscall per file to hand every path back — which is what the Dockerfile scan
/// used to do through `walk_files(root, &[])`.
pub fn walk(root: &Path, keep: impl Fn(&Path) -> bool) -> impl Iterator<Item = PathBuf> {
    WalkBuilder::new(root)
        .hidden(false)
        .follow_links(false)
        .standard_filters(false) // include node_modules, ignore .gitignore — we WANT vendored code
        .build()
        .filter_map(Result::ok)
        .filter_map(move |e| {
            // `file_type` rides along with the readdir entry, and `keep` is a
            // name test — both free. They gate the one syscall we still pay,
            // the `metadata` behind the size cap.
            let ft = e.file_type()?;
            if ft.is_dir() {
                return None;
            }
            let p = e.path();
            if !keep(p) {
                return None;
            }
            // A symlink is resolved explicitly: `follow_links(false)` stops the
            // walk descending through linked *directories*, but a linked file
            // is ordinary source that must still be read — pnpm's
            // `node_modules` is built almost entirely out of them, and skipping
            // them would blind the scan to a whole package manager.
            // `DirEntry::metadata` does not follow, so ask the filesystem.
            let md = if ft.is_symlink() {
                std::fs::metadata(p).ok()?
            } else {
                e.metadata().ok()?
            };
            if !md.is_file() || md.len() > MAX_FILE_BYTES {
                return None;
            }
            Some(p.to_path_buf())
        })
        .collect::<Vec<_>>()
        .into_iter()
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

/// Find the line number of the first occurrence of `needle` in `text` (1-indexed).
pub fn line_of(text: &str, needle: &str) -> Option<u32> {
    let idx = text.find(needle)?;
    Some(text[..idx].bytes().filter(|&b| b == b'\n').count() as u32 + 1)
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

        let found: Vec<PathBuf> = walk_files(&base, &["js"]).collect();
        std::fs::remove_dir_all(&base).ok();

        assert!(
            found.iter().any(|p| p.ends_with("node_modules/p/index.js")),
            "symlinked source must be walked, got {found:?}"
        );
    }
}
