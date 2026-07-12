//! Obfuscation heuristics.
//!
//! Single signals fire constantly in legit code (minified bundles, embedded data,
//! crypto libs). We score multiple signals per file and emit one Finding per file
//! with severity scaled by how many independent signals hit.
//!
//! Signals:
//!   * High Shannon entropy (>= 5.5 bits/byte) — base64/hex/encrypted blobs
//!   * `eval(` or `new Function(` / Python `exec(` / `compile(`
//!   * Long hex escape runs (`\xNN\xNN\xNN...`) or `\uNNNN` runs
//!   * Long base64 string literals (>200 chars)
//!   * `String.fromCharCode` / `.charCodeAt` chains (Node)
//!   * `__import__("...")` with reversed/encoded module name (Python)
//!
//! Crude minified-vs-obfuscated guard: if the longest line is enormous AND the file
//! looks like a known minifier output (`/*! ... */` banner, sourceMappingURL footer),
//! we downgrade severity by one level.

use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

use crate::analyze::util;
use crate::model::{Category, Finding, Severity};

#[derive(Copy, Clone)]
pub enum Lang {
    JavaScript,
    Python,
    Ruby,
    Php,
}

impl Lang {
    fn exts(self) -> &'static [&'static str] {
        match self {
            Lang::JavaScript => &["js", "mjs", "cjs"],
            Lang::Python => &["py"],
            Lang::Ruby => &["rb"],
            Lang::Php => &["php"],
        }
    }
}

fn hex_run_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?:\\x[0-9a-fA-F]{2}){8,}").unwrap())
}
fn unicode_run_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?:\\u[0-9a-fA-F]{4}){6,}").unwrap())
}
fn base64_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"["'][A-Za-z0-9+/]{200,}={0,2}["']"#).unwrap())
}

pub fn scan_dir(root: &Path, out: &mut Vec<Finding>, lang: Lang) {
    for path in util::walk_files(root, lang.exts()) {
        // Skip source maps and declaration files outright
        let s = path.to_string_lossy();
        if s.ends_with(".min.js.map") || s.ends_with(".d.ts") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        scan_file(&path, &text, out, lang);
    }
}

fn scan_file(path: &Path, text: &str, out: &mut Vec<Finding>, lang: Lang) {
    if text.len() < 64 {
        return; // tiny stub files: no point
    }
    let mut signals: Vec<&'static str> = Vec::new();

    let entropy = util::shannon_entropy(text.as_bytes());
    if entropy >= 5.5 {
        signals.push("high-entropy");
    }

    let lower = text; // keep case for now; markers are case-sensitive
    match lang {
        Lang::JavaScript => {
            if lower.contains("eval(") {
                signals.push("eval()");
            }
            if lower.contains("new Function(") || lower.contains("Function(\"return") {
                signals.push("Function() constructor");
            }
            if lower.contains("String.fromCharCode") {
                signals.push("String.fromCharCode");
            }
            if lower.matches(".charCodeAt").count() >= 3 {
                signals.push("charCodeAt chain");
            }
            if lower.contains("atob(") {
                signals.push("atob() base64 decode");
            }
        }
        Lang::Python => {
            if lower.contains("exec(") {
                signals.push("exec()");
            }
            if lower.contains("compile(") {
                signals.push("compile()");
            }
            if lower.contains("marshal.loads") {
                signals.push("marshal.loads");
            }
            if lower.contains("base64.b64decode") || lower.contains("codecs.decode") {
                signals.push("base64/codecs decode");
            }
            if lower.contains("__import__(") {
                signals.push("__import__()");
            }
        }
        Lang::Ruby => {
            if lower.contains("eval(")
                || lower.contains("instance_eval")
                || lower.contains("class_eval")
            {
                signals.push("eval()");
            }
            if lower.contains("Marshal.load") {
                signals.push("marshal.loads");
            }
            if lower.contains("Base64.decode64") || lower.contains(".unpack(") {
                signals.push("base64/codecs decode");
            }
            if lower.contains("Zlib::Inflate") {
                signals.push("zlib inflate");
            }
        }
        Lang::Php => {
            if lower.contains("eval(") {
                signals.push("eval()");
            }
            if lower.contains("base64_decode(") {
                signals.push("base64/codecs decode");
            }
            if lower.contains("gzinflate(") || lower.contains("gzuncompress(") {
                signals.push("gzinflate");
            }
            if lower.contains("str_rot13(") {
                signals.push("str_rot13");
            }
            if lower.contains("create_function(") {
                signals.push("create_function");
            }
        }
    }

    if hex_run_re().is_match(text) {
        signals.push(r"long \xNN run");
    }
    if unicode_run_re().is_match(text) {
        signals.push(r"long \uNNNN run");
    }
    if base64_re().is_match(text) {
        signals.push("base64 blob");
    }

    if signals.is_empty() {
        return;
    }
    // A single "weak" signal (`compile(`, `__import__(`, `eval(`, ...) fires
    // constantly in legit metaprogramming, so it only counts when corroborated:
    // require at least one strong signal, or two signals of any kind.
    let has_strong = signals.iter().any(|s| !is_weak_signal(s));
    if !has_strong && signals.len() < 2 {
        return;
    }

    let mut severity = match signals.len() {
        1 => Severity::Low,
        2 => Severity::Medium,
        3 => Severity::High,
        _ => Severity::Critical,
    };

    // Minified-bundle dampener
    if looks_minified(text) {
        severity = match severity {
            Severity::Critical => Severity::High,
            Severity::High => Severity::Medium,
            Severity::Medium => Severity::Low,
            Severity::Low => Severity::Info,
            s => s,
        };
    }

    let dep = util::owner(path, "<project>");
    out.push(Finding {
        dependency: dep,
        severity,
        category: Category::Obfuscation,
        detail: format!(
            "{} obfuscation signal(s): {} (entropy {:.2})",
            signals.len(),
            signals.join(", "),
            entropy
        ),
        location: Some(path.display().to_string()),
        evidence: None,
        enrich_url: None,
    });
}

/// Signals common enough in benign code that alone they mean nothing; they add
/// weight only alongside another signal.
fn is_weak_signal(s: &str) -> bool {
    matches!(
        s,
        "eval()"
            | "Function() constructor"
            | "atob() base64 decode"
            | "exec()"
            | "compile()"
            | "__import__()"
            | "base64/codecs decode"
    )
}

fn looks_minified(text: &str) -> bool {
    let max_line = text.lines().map(|l| l.len()).max().unwrap_or(0);
    let banner = text.starts_with("/*!") || text.contains("//# sourceMappingURL=");
    max_line > 2000 && banner
}
