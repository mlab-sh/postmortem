//! IOC extraction: URLs, IPv4 + IPv6 addresses, bare domain names, and crypto
//! wallets (BTC, ETH).
//!
//! Regex-based on raw text (AST extraction is a v2 upgrade). We deliberately
//! suppress common false positives — example.com, registry hosts, RFC1918,
//! loopback, file-extension lookalikes — to keep the signal-to-noise ratio
//! high. We also dedupe: if a URL already covers the host, we don't emit a
//! second domain finding for the same byte range.

use regex::Regex;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;
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
            Lang::Lua => &["lua"],
        }
    }
}

fn url_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"https?://[A-Za-z0-9.\-_~:/?#@!$&'()*+,;=%]+"#).unwrap())
}
fn ipv4_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap())
}
fn ipv6_re() -> &'static Regex {
    // Verbose pattern covering full + every well-formed `::` compression position,
    // plus the all-zero shortcut and IPv4-mapped form (`::ffff:1.2.3.4`).
    // Final validation happens via Ipv6Addr::from_str.
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // Ordered longest-tail first so leftmost-first alternation lands on the
        // most-complete form of compressed addresses (e.g. `2001:db8::dead:beef`
        // must not be cut short to `2001:db8::dead`).
        Regex::new(
            r"(?x)
            (?:
                (?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}
              | [0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})
              | (?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}
              | (?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}
              | (?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}
              | (?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}
              | (?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}
              | (?:[0-9a-fA-F]{1,4}:){1,7}:
              | ::(?:[fF]{4}:)?(?:\d{1,3}\.){3}\d{1,3}
            )
            ",
        )
        .unwrap()
    })
}
fn domain_re() -> &'static Regex {
    // host.label(.label)+ — purely structural; validity is enforced by the
    // TLD allowlist below.
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?\.){1,}[A-Za-z]{2,24}\b")
            .unwrap()
    })
}
fn btc_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b").unwrap())
}
fn eth_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\b0x[a-fA-F0-9]{40}\b").unwrap())
}

const URL_NOISE_HOSTS: &[&str] = &[
    "example.com",
    "example.org",
    "example.net",
    "example.invalid",
    "localhost",
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "raw.githubusercontent.com",
    "www.w3.org",
    "schema.org",
    "nodejs.org",
    "rust-lang.org",
    "python.org",
    "developer.mozilla.org",
    "tools.ietf.org",
    "creativecommons.org",
    "fonts.googleapis.com",
    // Knowledge / reference sites — ubiquitous in doc comments and docstrings,
    // never an exfil endpoint.
    "wikipedia.org",
    "stackoverflow.com",
    "stackexchange.com",
    "projecteuler.net",
    "geeksforgeeks.org",
    "geeksquiz.com",
    "leetcode.com",
    "youtube.com",
    "youtu.be",
    "medium.com",
    "arxiv.org",
    "doi.org",
    "wolfram.com",
    "mathworld.wolfram.com",
    "investopedia.com",
    "tutorialspoint.com",
    "rapidtables.com",
    "worldometers.info",
    "cp-algorithms.com",
    "byjus.com",
    "brilliant.org",
    "khanacademy.org",
    "researchgate.net",
    "sciencedirect.com",
    "springer.com",
    "jstor.org",
    "ietf.org",
    "rfc-editor.org",
    "docs.python.org",
    "pytorch.org",
    "tensorflow.org",
    "numpy.org",
    "scipy.org",
    "pydata.org",
    "reddit.com",
    // Go module hosts — appear constantly in import paths, never an exfil target.
    "golang.org",
    "go.dev",
    "pkg.go.dev",
    "gopkg.in",
    "go.uber.org",
    "go.mongodb.org",
    "k8s.io",
];

// Public resolvers that show up constantly in examples/tests and are never the
// actual IOC. Non-routable ranges (RFC1918, loopback, doc, ...) are handled
// structurally by `is_noteworthy_ipv4`.
const IP_NOISE: &[&str] = &["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"];

/// gTLDs/ccTLDs that double as ordinary code identifiers (`self.name`,
/// `logging.info`, `vertex.id`, `stack.top`). A bare token ending in one of
/// these is almost always attribute access, so we require string/URL context
/// before treating it as a hostname.
const AMBIGUOUS_TLDS: &[&str] = &[
    "info", "name", "top", "id", "host", "link", "click", "services", "solutions",
    "systems", "page", "app", "dev", "cloud", "digital", "media", "news", "press",
    "blog", "world", "today", "guru", "ninja", "live", "store", "shop", "site",
    "online", "tech", "fun", "best", "wtf", "lol", "buzz", "monster", "rest", "uno",
    "cam", "skin", "design", "global", "studio", "pro", "biz", "mobi", "club", "icu",
    // ccTLDs that double as ordinary words / struct-field names (`tc.in`, `x.at`,
    // `this.ch` where `ch` is a char).
    "in", "it", "at", "be", "no", "me", "us", "ch",
];

/// TLDs that, as the *leading* label, mark a reverse-DNS package path
/// (`com.google.gson`, `org.apache.commons`) rather than a hostname. Real
/// hostnames never start with one of these.
const REVERSE_DNS_HEADS: &[&str] = &["com", "org", "net", "edu", "gov", "mil", "int"];

/// Embedded TLD allowlist — popular gTLDs/ccTLDs plus a handful of TLDs that
/// frequently host throwaway exfil infrastructure (`tk`, `xyz`, `top`, ...).
/// Anything outside this list is dropped; the goal is high signal, not a
/// faithful public-suffix-list implementation.
const KNOWN_TLDS: &[&str] = &[
    // Generic
    "com", "org", "net", "info", "biz", "pro", "name", "io", "dev", "app", "ai", "sh",
    "co", "tv", "cc", "me", "mobi", "tech", "cloud", "online", "site", "store", "shop",
    "live", "studio", "host", "page", "ninja", "guru", "today", "world", "press", "blog",
    "news", "media", "design", "digital", "global", "systems", "solutions", "services",
    // Governments / academia
    "gov", "edu", "mil", "int",
    // Country-codes (top 30 by registrations + a few useful)
    "uk", "de", "fr", "jp", "cn", "ru", "br", "in", "au", "ca", "us", "eu", "it", "es",
    "nl", "pl", "se", "no", "fi", "dk", "be", "ch", "at", "ie", "pt", "gr", "cz", "kr",
    "tw", "hk", "sg", "id", "th", "vn", "ph", "my", "mx", "ar", "cl", "za", "il", "tr",
    // Free-TLD / throwaway-prone — often abused for C2
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "pw", "club", "icu", "link", "click",
    "lol", "fun", "wtf", "best", "buzz", "monster", "rest", "uno", "cam", "skin",
];

/// File extensions that would otherwise look like 2-label domains
/// (`config.json` parsed as `config.json`).
const FILE_EXTENSIONS: &[&str] = &[
    "json", "js", "mjs", "cjs", "ts", "tsx", "jsx", "py", "pyc", "pyi", "rs", "toml",
    "lock", "yml", "yaml", "md", "html", "htm", "css", "scss", "sass", "less", "map",
    "txt", "xml", "svg", "png", "jpg", "jpeg", "gif", "webp", "ico", "woff", "woff2",
    "ttf", "eot", "rb", "go", "java", "class", "kt", "swift", "c", "cpp", "h", "hpp",
    "sh", "bat", "ps1", "gradle", "jar", "war", "deb", "rpm", "tar", "gz", "zip",
    "min", "node", "wasm", "log", "csv", "tsv", "sql", "db", "sqlite",
];

pub fn scan_dir(root: &Path, out: &mut Vec<Finding>, lang: Lang) {
    for path in util::walk_files(root, lang.exts()) {
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        scan_text(&path, &text, out);
    }
}

fn scan_text(path: &Path, text: &str, out: &mut Vec<Finding>) {
    let dep = util::owner(path, "<project>");

    // First pass: collect URL match ranges so we can suppress redundant
    // domain/ipv4/ipv6 findings that already live inside a URL we've reported.
    let mut url_ranges: Vec<(usize, usize)> = Vec::new();
    for m in url_re().find_iter(text) {
        let url = m.as_str();
        // A URL in a comment or docstring is a documentation reference, not an
        // exfil endpoint. Record the range so inner domains stay suppressed too.
        if in_comment(text, m.start()) {
            url_ranges.push((m.start(), m.end()));
            continue;
        }
        if !url_has_host(url)
            || URL_NOISE_HOSTS.iter().any(|h| url.contains(h))
            || url_host_is_private_ip(url)
        {
            // Still record the range so domain matches inside don't fire.
            url_ranges.push((m.start(), m.end()));
            continue;
        }
        if url.contains("/2000/svg") || url.contains("/1999/xhtml") {
            url_ranges.push((m.start(), m.end()));
            continue;
        }
        url_ranges.push((m.start(), m.end()));
        out.push(Finding {
            dependency: dep.clone(),
            severity: Severity::Medium,
            category: Category::Ioc,
            detail: "embedded URL".to_string(),
            location: line_loc(path, text, url),
            evidence: Some(util::snippet(url, 120)),
            enrich_url: None,
        });
    }

    let in_url = |start: usize| url_ranges.iter().any(|(s, e)| start >= *s && start < *e);

    for m in ipv4_re().find_iter(text) {
        if in_url(m.start()) || in_comment(text, m.start()) {
            continue;
        }
        let ip = m.as_str();
        if IP_NOISE.contains(&ip) {
            continue;
        }
        let Ok(addr) = Ipv4Addr::from_str(ip) else { continue };
        if !is_noteworthy_ipv4(&addr) {
            continue;
        }
        out.push(Finding {
            dependency: dep.clone(),
            severity: Severity::Medium,
            category: Category::Ioc,
            detail: "embedded IPv4 address".to_string(),
            location: line_loc(path, text, ip),
            evidence: Some(util::snippet(ip, 60)),
            enrich_url: None,
        });
    }

    for m in ipv6_re().find_iter(text) {
        if in_url(m.start()) || in_comment(text, m.start()) {
            continue;
        }
        // Scope-resolution paths (`web::get`, `std::vector`) whose trailing hex
        // chars + `::` parse as a valid compressed IPv6 are the dominant false
        // positive. A real address literal is always delimited; if the match is
        // welded to an identifier char on either side, it's code, not data.
        if touches_identifier(text, m.start(), m.end()) {
            continue;
        }
        let candidate = m.as_str();
        // A `::` scope operator with a hex-ish left side (`E::<T>`, `eb::`) is a
        // valid *compressed* IPv6 with a single explicit hextet. Real address
        // literals have at least two; requiring that kills the whole class
        // without dropping anything routable.
        if explicit_hextets(candidate) < 2 {
            continue;
        }
        // RFC-valid?
        let Ok(addr) = Ipv6Addr::from_str(candidate) else { continue };
        if !is_noteworthy_ipv6(&addr) {
            continue;
        }
        out.push(Finding {
            dependency: dep.clone(),
            severity: Severity::Medium,
            category: Category::Ioc,
            detail: "embedded IPv6 address".to_string(),
            location: line_loc(path, text, candidate),
            evidence: Some(util::snippet(candidate, 60)),
            enrich_url: None,
        });
    }

    // Domains — heavily filtered to keep noise down.
    for m in domain_re().find_iter(text) {
        if in_url(m.start()) || in_comment(text, m.start()) {
            continue;
        }
        let candidate = m.as_str();
        if domain_is_code_access(text, m.start(), m.end(), candidate) {
            continue;
        }
        let lower = candidate.to_ascii_lowercase();
        if !is_interesting_domain(&lower) {
            continue;
        }
        out.push(Finding {
            dependency: dep.clone(),
            severity: Severity::Medium,
            category: Category::Ioc,
            detail: "embedded domain name".to_string(),
            location: line_loc(path, text, candidate),
            evidence: Some(util::snippet(candidate, 80)),
            enrich_url: None,
        });
    }

    for m in btc_re().find_iter(text) {
        let addr = m.as_str();
        if !looks_like_btc(addr) {
            continue;
        }
        out.push(Finding {
            dependency: dep.clone(),
            severity: Severity::High,
            category: Category::Ioc,
            detail: "Bitcoin address, extremely unusual in dependency code".to_string(),
            location: line_loc(path, text, addr),
            evidence: Some(addr.to_string()),
            enrich_url: None,
        });
    }

    for m in eth_re().find_iter(text) {
        let addr = m.as_str();
        out.push(Finding {
            dependency: dep.clone(),
            severity: Severity::High,
            category: Category::Ioc,
            detail: "Ethereum address, extremely unusual in dependency code".to_string(),
            location: line_loc(path, text, addr),
            evidence: Some(addr.to_string()),
            enrich_url: None,
        });
    }
}

fn is_interesting_domain(d: &str) -> bool {
    // Direct noise allowlist (exact or subdomain match).
    if URL_NOISE_HOSTS.iter().any(|h| d == *h || d.ends_with(&format!(".{h}"))) {
        return false;
    }
    let labels: Vec<&str> = d.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let tld = *labels.last().unwrap();
    // 2-label "foo.json" → reject (file extension)
    if labels.len() == 2 && FILE_EXTENSIONS.contains(&tld) {
        return false;
    }
    // TLD must be in our allowlist
    if !KNOWN_TLDS.contains(&tld) {
        return false;
    }
    // No purely-numeric labels (catches "1.2.3.4" already matched by ipv4, plus
    // odd version strings).
    if labels.iter().any(|l| l.chars().all(|c| c.is_ascii_digit())) {
        return false;
    }
    // At least one label other than the TLD must be non-trivially long, to weed
    // out things like "a.io" that are usually method chains or single chars.
    if labels[..labels.len() - 1].iter().all(|l| l.len() <= 1) {
        return false;
    }
    true
}

fn line_loc(path: &Path, text: &str, needle: &str) -> Option<String> {
    let line = util::line_of(text, needle)?;
    Some(format!("{}:{}", path.display(), line))
}

/// True when the byte just before `start` or just after `end` is an ASCII
/// identifier character (alnum or `_`) — i.e. the match is embedded in a larger
/// token rather than standing alone as a literal.
fn touches_identifier(text: &str, start: usize, end: usize) -> bool {
    let b = text.as_bytes();
    let left = start.checked_sub(1).is_some_and(|i| is_ident_byte(b[i]));
    let right = b.get(end).copied().is_some_and(is_ident_byte);
    left || right
}

fn is_ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Count textual hextet groups in an IPv6 candidate, ignoring the zero-run
/// implied by `::`. An embedded IPv4 tail (`::ffff:1.2.3.4`) counts as two.
fn explicit_hextets(s: &str) -> usize {
    s.split(':')
        .filter(|p| !p.is_empty())
        .map(|p| if p.contains('.') { 2 } else { 1 })
        .sum()
}

/// True only for addresses that could plausibly be a real exfil/C2 target.
/// Everything non-routable — RFC1918, loopback, link-local, CGNAT, documentation
/// (TEST-NET), benchmarking, multicast, reserved, broadcast, unspecified — is
/// config/example data, never an IOC.
fn is_noteworthy_ipv4(a: &Ipv4Addr) -> bool {
    let o = a.octets();
    !(a.is_private()
        || a.is_loopback()
        || a.is_link_local()
        || a.is_documentation()
        || a.is_multicast()
        || a.is_broadcast()
        || a.is_unspecified()
        || o[0] == 0                                // 0.0.0.0/8 "this network"
        || (o[0] == 100 && (64..=127).contains(&o[1])) // 100.64.0.0/10 CGNAT
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // 198.18.0.0/15 benchmarking
        || o[0] >= 240)                            // 240.0.0.0/4 reserved
}

/// IPv6 analogue of `is_noteworthy_ipv4`: drop the non-routable ranges that
/// turn up in dual-stack stubs and IP-matching test fixtures — unspecified,
/// loopback, multicast, the `2001:db8::/32` documentation prefix (RFC 3849),
/// link-local (`fe80::/10`), and unique-local (`fc00::/7`).
fn is_noteworthy_ipv6(a: &Ipv6Addr) -> bool {
    if a.is_unspecified() || a.is_loopback() || a.is_multicast() {
        return false;
    }
    let s = a.segments();
    let documentation = s[0] == 0x2001 && s[1] == 0x0db8;
    let link_local = (s[0] & 0xffc0) == 0xfe80;
    let unique_local = (s[0] & 0xfe00) == 0xfc00;
    !(documentation || link_local || unique_local)
}

/// True when a domain-shaped match is really source code — a member access or
/// method call whose attribute happens to be a valid TLD (`self.name`,
/// `logging.info`, `stack.top`, `vertex.id`), an uppercase constant path
/// (`Other.Host`), or an ambiguous-TLD token with no surrounding string/URL
/// context to mark it as data.
fn domain_is_code_access(text: &str, start: usize, end: usize, candidate: &str) -> bool {
    let b = text.as_bytes();
    // Continuation of a dotted path, or an immediate call: `x.y.info`, `logger.info(`.
    if start.checked_sub(1).is_some_and(|i| b[i] == b'.') {
        return true;
    }
    if b.get(end).copied() == Some(b'(') {
        return true;
    }
    // Reverse-DNS package path (`com.google.gson`, `org.apache.commons`).
    let head = candidate.split('.').next().unwrap_or("");
    if REVERSE_DNS_HEADS.contains(&head.to_ascii_lowercase().as_str()) {
        return true;
    }
    let tld = candidate.rsplit('.').next().unwrap_or("");
    // Real hostnames are written lowercase; an uppercase TLD is a type/constant.
    if tld.chars().any(|c| c.is_ascii_uppercase()) {
        return true;
    }
    // Identifier-ish TLD (`.name`, `.id`, `.top`): treat as data only when the
    // token is quote/URL-delimited, which member access never is.
    if AMBIGUOUS_TLDS.contains(&tld.to_ascii_lowercase().as_str())
        && !quote_adjacent(b, start, end)
    {
        return true;
    }
    false
}

/// Whether the URL has a real host after `://`. String-interpolation fragments
/// (`http://#{root_url}` in Ruby, `http://${host}` in JS) match the URL regex
/// but resolve to an empty host and are pure noise.
fn url_has_host(url: &str) -> bool {
    url.split_once("://")
        .and_then(|(_, rest)| rest.bytes().next())
        .is_some_and(|c| c.is_ascii_alphanumeric())
}

/// True when a URL's host is a non-routable IPv4 (`http://172.16.1.1:5000`) —
/// a local/test endpoint, never real exfil infrastructure.
fn url_host_is_private_ip(url: &str) -> bool {
    let Some(rest) = url.split_once("://").map(|(_, r)| r) else { return false };
    let host = rest.split(['/', ':', '?', '#', '@']).next().unwrap_or("");
    Ipv4Addr::from_str(host).is_ok_and(|a| !is_noteworthy_ipv4(&a))
}

/// Whether the match at `start` sits on a comment or docstring-bullet line.
/// Language-agnostic across the scanned set: `#` (Python), `//` `///` `//!`
/// (Rust/JS line + doc comments), and `*` / `/*` (block-comment bodies). Also
/// catches a trailing `//` line comment that isn't the `//` in `scheme://`.
fn in_comment(text: &str, start: usize) -> bool {
    let ls = text[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let prefix = &text[ls..start];
    let t = prefix.trim_start();
    if t.starts_with('#') || t.starts_with("//") || t.starts_with('*') || t.starts_with("/*") {
        return true;
    }
    let b = prefix.as_bytes();
    (1..b.len()).any(|i| b[i] == b'/' && b[i - 1] == b'/' && (i < 2 || b[i - 2] != b':'))
}

/// Whether the byte just before `start` or just after `end` is a string quote —
/// a cheap proxy for "this token sits inside a string literal".
fn quote_adjacent(b: &[u8], start: usize, end: usize) -> bool {
    let is_q = |c: u8| matches!(c, b'"' | b'\'' | b'`');
    start.checked_sub(1).is_some_and(|i| is_q(b[i])) || b.get(end).copied().is_some_and(is_q)
}

fn looks_like_btc(addr: &str) -> bool {
    let has_digit = addr.chars().any(|c| c.is_ascii_digit());
    let has_lower = addr.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = addr.chars().any(|c| c.is_ascii_uppercase());
    has_digit && has_lower && has_upper
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scan(input: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        scan_text(&PathBuf::from("test.js"), input, &mut out);
        out
    }

    fn details(fs: &[Finding]) -> Vec<&str> {
        fs.iter().map(|f| f.detail.as_str()).collect()
    }

    #[test]
    fn finds_bare_domain_with_known_tld() {
        let fs = scan(r#"const c2 = "track.evil.tk";"#);
        assert!(details(&fs).contains(&"embedded domain name"), "{fs:#?}");
    }

    #[test]
    fn rejects_file_extension_lookalikes() {
        let fs = scan(r#"require("./package.json"); read("config.yaml");"#);
        assert!(fs.is_empty(), "should not flag filenames: {fs:#?}");
    }

    #[test]
    fn rejects_unknown_tld() {
        let fs = scan(r#"host = "exfil.malicious.foobar";"#);
        assert!(fs.is_empty(), "unknown TLD should be silent: {fs:#?}");
    }

    #[test]
    fn rejects_noise_host_subdomain() {
        let fs = scan(r#"const u = "raw.githubusercontent.com/x/y/z";"#);
        assert!(
            !details(&fs).contains(&"embedded domain name"),
            "github subdomain should be noise: {fs:#?}"
        );
    }

    #[test]
    fn dedupes_domain_inside_url() {
        // The URL fires; the bare domain inside the URL should not fire a 2nd time.
        let fs = scan(r#"fetch("http://evil.tk/path");"#);
        let domains: Vec<&Finding> = fs.iter().filter(|f| f.detail == "embedded domain name").collect();
        assert!(domains.is_empty(), "domain should not double-fire inside URL: {fs:#?}");
        assert!(fs.iter().any(|f| f.detail == "embedded URL"));
    }

    #[test]
    fn finds_ipv6_compressed() {
        let fs = scan(r#"const host = "2606:4700::1";"#);
        assert!(
            details(&fs).contains(&"embedded IPv6 address"),
            "{fs:#?}"
        );
    }

    #[test]
    fn finds_ipv6_full() {
        let fs = scan(r#"connect("2606:4700:4700:1111:2222:8a2e:0370:7334", 80);"#);
        assert!(details(&fs).contains(&"embedded IPv6 address"), "{fs:#?}");
    }

    #[test]
    fn rejects_ipv6_loopback_and_unspecified() {
        let fs = scan(r#"const a = "::1"; const b = "::";"#);
        assert!(
            !details(&fs).contains(&"embedded IPv6 address"),
            "loopback/unspecified should be noise: {fs:#?}"
        );
    }

    #[test]
    fn rejects_rust_scope_paths_as_ipv6() {
        // `web::get`, `crate::api`, `Interface::new` etc. have hex-tailed idents
        // before `::` that parse as valid compressed IPv6 (`eb::`, `e::a`, ...).
        let fs = scan(
            r#"use actix_web::web; let r = web::get(); crate::api::init(); Interface::new();"#,
        );
        assert!(
            !details(&fs).contains(&"embedded IPv6 address"),
            "scope-resolution paths must not be flagged as IPv6: {fs:#?}"
        );
    }

    #[test]
    fn rejects_rust_turbofish_as_ipv6() {
        // `E::<PrimeField>` — a single hex-ish hextet + `::` is a valid
        // compressed IPv6 but is really a turbofish / generic path.
        let fs = scan(r#"let p = E::<PrimeField<7>>::new(); let q = E::coeff();"#);
        assert!(
            !details(&fs).contains(&"embedded IPv6 address"),
            "turbofish must not be flagged as IPv6: {fs:#?}"
        );
    }

    #[test]
    fn rejects_documentation_and_local_ipv6() {
        let fs = scan(
            r#"a="2001:db8::52:0:3"; b="fe80::1ff:fe23:4567:890a"; c="fc00::abcd";"#,
        );
        assert!(
            !details(&fs).contains(&"embedded IPv6 address"),
            "doc/link-local/unique-local IPv6 must be suppressed: {fs:#?}"
        );
    }

    #[test]
    fn still_finds_ipv4_mapped_ipv6() {
        let fs = scan(r#"const m = "::ffff:203.0.113.5";"#);
        assert!(details(&fs).contains(&"embedded IPv6 address"), "{fs:#?}");
    }

    #[test]
    fn rejects_private_and_doc_ipv4() {
        let fs = scan(
            r#"a="192.168.0.1"; b="10.0.0.255"; c="172.16.5.4"; d="127.0.0.1"; e="203.0.113.5"; f="169.254.1.1";"#,
        );
        assert!(
            !details(&fs).contains(&"embedded IPv4 address"),
            "non-routable/doc IPv4 must be suppressed: {fs:#?}"
        );
    }

    #[test]
    fn finds_public_ipv4() {
        let fs = scan(r#"const c2 = "45.77.12.34";"#);
        assert!(details(&fs).contains(&"embedded IPv4 address"), "{fs:#?}");
    }

    #[test]
    fn rejects_member_access_as_domain() {
        let fs = scan(
            r#"self.name; logging.info(x); stack.top; vertex.id; obj.services; logging.INFO; Other.Host;"#,
        );
        assert!(
            !details(&fs).contains(&"embedded domain name"),
            "attribute access must not be flagged as a domain: {fs:#?}"
        );
    }

    #[test]
    fn rejects_go_field_access_and_module_hosts() {
        // `tc.in` is struct-field access (`.in` = India ccTLD); import paths like
        // golang.org / gopkg.in are module hosts, not exfil targets.
        let fs = scan(
            "for _, tc := range cases { got := run(tc.in) }\nimport \"golang.org/x/net\"\nimport \"gopkg.in/yaml.v3\"",
        );
        assert!(
            !details(&fs).contains(&"embedded domain name"),
            "Go field access / module hosts must not be flagged: {fs:#?}"
        );
    }

    #[test]
    fn rejects_java_packages_and_char_field() {
        // Reverse-DNS package paths and `.ch` (a char field) are code, not hosts.
        let fs = scan("package com.google.gson; import org.apache.commons.Lang; c = this.ch;");
        assert!(
            !details(&fs).contains(&"embedded domain name"),
            "Java packages / char field must not be flagged: {fs:#?}"
        );
    }

    #[test]
    fn still_finds_real_domains() {
        // Classic TLD bare, and an ambiguous TLD only when quoted as data.
        let fs = scan(r#"host="evil.tk"; url2="steal.top"; ref=gmail.com;"#);
        let n = details(&fs).iter().filter(|d| **d == "embedded domain name").count();
        assert!(n >= 3, "expected evil.tk, steal.top, gmail.com: {fs:#?}");
    }

    #[test]
    fn rejects_interpolation_url_fragments() {
        let fs = scan("u = \"http://#{root_url}/x\"; v = `http://${host}:3000`;");
        assert!(
            !details(&fs).contains(&"embedded URL"),
            "interpolation fragments must not be flagged: {fs:#?}"
        );
    }

    #[test]
    fn suppresses_iocs_in_comments() {
        let fs = scan(
            "// see https://en.wikipedia.org/wiki/Foo and 45.77.12.34\n# ref https://evil.tk/x\n/// doc 203.0.113.9 https://bar.io\n",
        );
        assert!(fs.is_empty(), "comment/doc lines must be suppressed: {fs:#?}");
    }

    #[test]
    fn still_finds_url_in_code() {
        let fs = scan(r#"fetch("https://exfil.tk/steal");"#);
        assert!(details(&fs).contains(&"embedded URL"), "{fs:#?}");
    }

    #[test]
    fn rejects_random_colons() {
        let fs = scan(r#"const m = {time: 10:20:30, key: "value"};"#);
        assert!(
            !details(&fs).contains(&"embedded IPv6 address"),
            "should not flag non-IPv6 colon sequences: {fs:#?}"
        );
    }
}
