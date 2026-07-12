//! IOC extraction: URLs, IPv4 + IPv6 addresses, bare domain names, and crypto
//! wallets (BTC, ETH).
//!
//! Regex-based on raw text (AST extraction is a v2 upgrade). We deliberately
//! suppress common false positives — example.com, registry hosts, RFC1918,
//! loopback, file-extension lookalikes — to keep the signal-to-noise ratio
//! high. We also dedupe: if a URL already covers the host, we don't emit a
//! second domain finding for the same byte range.

use regex::Regex;
use std::net::Ipv6Addr;
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
}

impl Lang {
    fn exts(self) -> &'static [&'static str] {
        match self {
            Lang::JavaScript => &["js", "mjs", "cjs", "ts"],
            Lang::Python => &["py"],
            Lang::Rust => &["rs"],
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
];

const IP_NOISE: &[&str] = &["0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8", "8.8.4.4"];

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
        if URL_NOISE_HOSTS.iter().any(|h| url.contains(h)) {
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
        if in_url(m.start()) {
            continue;
        }
        let ip = m.as_str();
        if IP_NOISE.contains(&ip) || !is_plausible_ip(ip) {
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
        if in_url(m.start()) {
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
        // RFC-valid?
        let Ok(addr) = Ipv6Addr::from_str(candidate) else { continue };
        // Drop unspecified / loopback — they show up in dual-stack server stubs.
        if addr.is_unspecified() || addr.is_loopback() {
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
        if in_url(m.start()) {
            continue;
        }
        let candidate = m.as_str();
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
            detail: "Bitcoin address — extremely unusual in dependency code".to_string(),
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
            detail: "Ethereum address — extremely unusual in dependency code".to_string(),
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

fn is_plausible_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
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
        let fs = scan(r#"const host = "2001:db8::1";"#);
        assert!(
            details(&fs).contains(&"embedded IPv6 address"),
            "{fs:#?}"
        );
    }

    #[test]
    fn finds_ipv6_full() {
        let fs = scan(r#"connect("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 80);"#);
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
    fn rejects_random_colons() {
        let fs = scan(r#"const m = {time: 10:20:30, key: "value"};"#);
        assert!(
            !details(&fs).contains(&"embedded IPv6 address"),
            "should not flag non-IPv6 colon sequences: {fs:#?}"
        );
    }
}
