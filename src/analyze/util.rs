use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

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
    WalkBuilder::new(root)
        .hidden(false)
        .follow_links(false)
        .standard_filters(false) // include node_modules, ignore .gitignore — we WANT vendored code
        .build()
        .filter_map(Result::ok)
        .filter_map(move |e| {
            let p = e.path();
            if !p.is_file() {
                return None;
            }
            let md = std::fs::metadata(p).ok()?;
            if md.len() > MAX_FILE_BYTES {
                return None;
            }
            let ext = p
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();
            if exts.is_empty() || exts.iter().any(|e| e == &ext) {
                Some(p.to_path_buf())
            } else {
                None
            }
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
            s.extend_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
        }
        let e = shannon_entropy(&s);
        assert!(e > 5.9, "got {e}");
    }
}
