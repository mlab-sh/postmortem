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

fn url_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"https?://[A-Za-z0-9.\-_~:/?#@!$&'()*+,;=%]+"#).unwrap())
}
// The patterns below use ASCII `(?-u:\b)` and `[0-9]` rather than `\b` / `\d`.
// A Unicode word boundary makes the regex crate's lazy DFA quit at the first
// non-ASCII byte and hand the rest of the haystack to the PikeVM, so one `é`
// early in a bundle made every later match far dearer. The patterns are ASCII
// anyway. The one place they differ — an ASCII token directly against a
// non-ASCII letter (`ller.de` out of `müller.de`) — is put back per match by
// `welded_to_non_ascii`, which only ever sees the few matches, not the text.
fn ipv4_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?-u:\b)(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?-u:\b)").unwrap())
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
        Regex::new(
            r"(?-u:\b)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?\.){1,}[A-Za-z]{2,24}(?-u:\b)",
        )
        .unwrap()
    })
}
fn btc_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?-u:\b)[13][a-km-zA-HJ-NP-Z1-9]{25,34}(?-u:\b)").unwrap())
}
fn eth_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?-u:\b)0x[a-fA-F0-9]{40}(?-u:\b)").unwrap())
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
    // JSON Schema `$schema` / `$id` identifiers — in every validator and
    // generated schema. Was only ever suppressed as a substring of the URL
    // matching `schema.org`; the host check needs it by name.
    "json-schema.org",
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
    "info",
    "name",
    "top",
    "id",
    "host",
    "link",
    "click",
    "services",
    "solutions",
    "systems",
    "page",
    "app",
    "dev",
    "cloud",
    "digital",
    "media",
    "news",
    "press",
    "blog",
    "world",
    "today",
    "guru",
    "ninja",
    "live",
    "store",
    "shop",
    "site",
    "online",
    "tech",
    "fun",
    "best",
    "wtf",
    "lol",
    "buzz",
    "monster",
    "rest",
    "uno",
    "cam",
    "skin",
    "design",
    "global",
    "studio",
    "pro",
    "biz",
    "mobi",
    "club",
    "icu",
    // ccTLDs that double as ordinary words / struct-field names (`tc.in`, `x.at`,
    // `this.ch` where `ch` is a char).
    "in",
    "it",
    "at",
    "be",
    "no",
    "me",
    "us",
    "ch",
];

/// TLDs that, as the *leading* label, mark a reverse-DNS package path
/// (`com.google.gson`, `org.apache.commons`) rather than a hostname. Real
/// hostnames never start with one of these.
const REVERSE_DNS_HEADS: &[&str] = &["com", "org", "net", "edu", "gov", "mil", "int"];

/// Embedded TLD allowlist — popular gTLDs/ccTLDs plus a handful of TLDs that
/// frequently host throwaway exfil infrastructure (`tk`, `xyz`, `top`, ...).
/// Anything outside this list is dropped; the goal is high signal, not a
/// faithful public-suffix-list implementation. ASCII case-insensitive.
///
/// A `match` rather than a slice `contains`: it is asked once per domain-shaped
/// token, and a bundle has one at every property access.
fn is_known_tld(tld: &str) -> bool {
    // The domain pattern caps a TLD at 24 letters; lowercase it on the stack.
    let mut buf = [0u8; 24];
    let Some(dst) = buf.get_mut(..tld.len()) else {
        return false;
    };
    dst.copy_from_slice(tld.as_bytes());
    dst.make_ascii_lowercase();
    matches!(
        &*dst,
        // Generic
        b"com" | b"org" | b"net" | b"info" | b"biz" | b"pro" | b"name" | b"io" | b"dev"
            | b"app" | b"ai" | b"sh" | b"co" | b"tv" | b"cc" | b"me" | b"mobi" | b"tech"
            | b"cloud" | b"online" | b"site" | b"store" | b"shop" | b"live" | b"studio"
            | b"host" | b"page" | b"ninja" | b"guru" | b"today" | b"world" | b"press"
            | b"blog" | b"news" | b"media" | b"design" | b"digital" | b"global" | b"systems"
            | b"solutions" | b"services"
            // Governments / academia
            | b"gov" | b"edu" | b"mil" | b"int"
            // Country-codes (top 30 by registrations + a few useful)
            | b"uk" | b"de" | b"fr" | b"jp" | b"cn" | b"ru" | b"br" | b"in" | b"au" | b"ca"
            | b"us" | b"eu" | b"it" | b"es" | b"nl" | b"pl" | b"se" | b"no" | b"fi" | b"dk"
            | b"be" | b"ch" | b"at" | b"ie" | b"pt" | b"gr" | b"cz" | b"kr" | b"tw" | b"hk"
            | b"sg" | b"id" | b"th" | b"vn" | b"ph" | b"my" | b"mx" | b"ar" | b"cl" | b"za"
            | b"il" | b"tr"
            // Free-TLD / throwaway-prone — often abused for C2
            | b"tk" | b"ml" | b"ga" | b"cf" | b"gq" | b"xyz" | b"top" | b"pw" | b"club"
            | b"icu" | b"link" | b"click" | b"lol" | b"fun" | b"wtf" | b"best" | b"buzz"
            | b"monster" | b"rest" | b"uno" | b"cam" | b"skin"
    )
}

/// File extensions that would otherwise look like 2-label domains
/// (`config.json` parsed as `config.json`).
const FILE_EXTENSIONS: &[&str] = &[
    "json", "js", "mjs", "cjs", "ts", "tsx", "jsx", "py", "pyc", "pyi", "rs", "toml", "lock",
    "yml", "yaml", "md", "html", "htm", "css", "scss", "sass", "less", "map", "txt", "xml", "svg",
    "png", "jpg", "jpeg", "gif", "webp", "ico", "woff", "woff2", "ttf", "eot", "rb", "go", "java",
    "class", "kt", "swift", "c", "cpp", "h", "hpp", "sh", "bat", "ps1", "gradle", "jar", "war",
    "deb", "rpm", "tar", "gz", "zip", "min", "node", "wasm", "log", "csv", "tsv", "sql", "db",
    "sqlite",
];

pub fn scan_text(path: &Path, text: &str, out: &mut Vec<Finding>) {
    // Most files yield no IOC at all, so the owner is only worked out for one
    // that does.
    let owner = std::cell::OnceCell::new();
    let dep = || owner.get_or_init(|| util::owner(path, "<project>")).clone();

    // First pass: collect URL match ranges so we can suppress redundant
    // domain/ipv4/ipv6 findings that already live inside a URL we've reported.
    let mut url_ranges: Vec<(usize, usize)> = Vec::new();
    let (mut lines, mut comments) = (Lines::new(text), Comments::new(text));
    for m in url_re().find_iter(text) {
        let url = m.as_str();
        // A URL in a comment or docstring is a documentation reference, not an
        // exfil endpoint. Record the range so inner domains stay suppressed too.
        if comments.at(m.start()) {
            url_ranges.push((m.start(), m.end()));
            continue;
        }
        if !url_has_host(url) || is_noise_host(url_host(url)) || url_host_is_private_ip(url) {
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
            dependency: dep(),
            severity: Severity::Medium,
            category: Category::Ioc,
            detail: "embedded URL".to_string(),
            location: line_loc(path, lines.at(m.start())),
            evidence: Some(util::snippet(url, 120)),
            enrich_url: None,
        });
    }

    // The ranges are sorted and disjoint (they come from one `find_iter`), so
    // the enclosing range is the last one starting at or before `start`. A
    // linear `any` here was O(URLs) for every candidate in the file.
    let in_url = |start: usize| {
        let i = url_ranges.partition_point(|&(s, _)| s <= start);
        i > 0 && start < url_ranges[i - 1].1
    };

    let (mut lines, mut comments) = (Lines::new(text), Comments::new(text));
    for m in ipv4_re().find_iter(text) {
        if in_url(m.start())
            || comments.at(m.start())
            || welded_to_non_ascii(text, m.start(), m.end())
        {
            continue;
        }
        let ip = m.as_str();
        if IP_NOISE.contains(&ip) {
            continue;
        }
        let Ok(addr) = Ipv4Addr::from_str(ip) else {
            continue;
        };
        if !is_noteworthy_ipv4(&addr) {
            continue;
        }
        out.push(Finding {
            dependency: dep(),
            severity: Severity::Medium,
            category: Category::Ioc,
            detail: "embedded IPv4 address".to_string(),
            location: line_loc(path, lines.at(m.start())),
            evidence: Some(util::snippet(ip, 60)),
            enrich_url: None,
        });
    }

    let (mut lines, mut comments) = (Lines::new(text), Comments::new(text));
    for m in ipv6_re().find_iter(text) {
        if in_url(m.start()) || comments.at(m.start()) {
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
        let Ok(addr) = Ipv6Addr::from_str(candidate) else {
            continue;
        };
        if !is_noteworthy_ipv6(&addr) {
            continue;
        }
        out.push(Finding {
            dependency: dep(),
            severity: Severity::Medium,
            category: Category::Ioc,
            detail: "embedded IPv6 address".to_string(),
            location: line_loc(path, lines.at(m.start())),
            evidence: Some(util::snippet(candidate, 60)),
            enrich_url: None,
        });
    }

    // Domains — heavily filtered to keep noise down. Every `a.b` property
    // access in a bundle is a candidate, so the filters (a pure AND) run
    // cheapest first: the O(1) code-shape and TLD checks reject nearly all of
    // them before the URL-range and comment lookups.
    let (mut lines, mut comments) = (Lines::new(text), Comments::new(text));
    for m in domain_re().find_iter(text) {
        let candidate = m.as_str();
        if domain_is_code_access(text, m.start(), m.end(), candidate)
            || welded_to_non_ascii(text, m.start(), m.end())
            || !is_interesting_domain(candidate)
            || in_url(m.start())
            || comments.at(m.start())
        {
            continue;
        }
        out.push(Finding {
            dependency: dep(),
            severity: Severity::Medium,
            category: Category::Ioc,
            detail: "embedded domain name".to_string(),
            location: line_loc(path, lines.at(m.start())),
            evidence: Some(util::snippet(candidate, 80)),
            enrich_url: None,
        });
    }

    let mut lines = Lines::new(text);
    for m in btc_re().find_iter(text) {
        let addr = m.as_str();
        if !looks_like_btc(addr) || welded_to_non_ascii(text, m.start(), m.end()) {
            continue;
        }
        out.push(Finding {
            dependency: dep(),
            severity: Severity::High,
            category: Category::Ioc,
            detail: "Bitcoin address, extremely unusual in dependency code".to_string(),
            location: line_loc(path, lines.at(m.start())),
            evidence: Some(addr.to_string()),
            enrich_url: None,
        });
    }

    let mut lines = Lines::new(text);
    for m in eth_re().find_iter(text) {
        let addr = m.as_str();
        if welded_to_non_ascii(text, m.start(), m.end()) {
            continue;
        }
        out.push(Finding {
            dependency: dep(),
            severity: Severity::High,
            category: Category::Ioc,
            detail: "Ethereum address, extremely unusual in dependency code".to_string(),
            location: line_loc(path, lines.at(m.start())),
            evidence: Some(addr.to_string()),
            enrich_url: None,
        });
    }
}

/// `d` is a domain-regex match, so plain ASCII. No allocation: this runs for
/// every domain-shaped token in the file.
fn is_interesting_domain(d: &str) -> bool {
    let tld = d.rsplit('.').next().unwrap_or(d);
    // TLD must be in our allowlist — checked first, it rejects most candidates.
    if !is_known_tld(tld) {
        return false;
    }
    // Direct noise allowlist (exact or subdomain match).
    if is_noise_host(d) {
        return false;
    }
    let labels = d.split('.').count();
    if labels < 2 {
        return false;
    }
    // 2-label "foo.json" → reject (file extension)
    if labels == 2 && FILE_EXTENSIONS.iter().any(|x| x.eq_ignore_ascii_case(tld)) {
        return false;
    }
    // No purely-numeric labels (catches "1.2.3.4" already matched by ipv4, plus
    // odd version strings).
    if d.split('.').any(|l| l.bytes().all(|c| c.is_ascii_digit())) {
        return false;
    }
    // At least one label other than the TLD must be non-trivially long, to weed
    // out things like "a.io" that are usually method chains or single chars.
    if d.split('.').take(labels - 1).all(|l| l.len() <= 1) {
        return false;
    }
    true
}

/// Is `host` (any case) one of [`URL_NOISE_HOSTS`] or a subdomain of one?
fn is_noise_host(host: &str) -> bool {
    let h = host.as_bytes();
    URL_NOISE_HOSTS.iter().any(|n| {
        h.len() >= n.len()
            && h[h.len() - n.len()..].eq_ignore_ascii_case(n.as_bytes())
            && (h.len() == n.len() || h[h.len() - n.len() - 1] == b'.')
    })
}

/// The host of a URL: after the scheme and any userinfo, up to the first byte
/// a hostname cannot hold — which drops the port and path, and the quote or
/// paren the URL pattern's wide class drags along (`https://x.org',`). The
/// noise check used to be `url.contains(host)`, which let
/// `https://evil.tk/?r=github.com` hide behind a query parameter.
fn url_host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    let end = host
        .bytes()
        .position(|c| !(c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_')))
        .unwrap_or(host.len());
    &host[..end]
}

fn line_loc(path: &Path, line: u32) -> Option<String> {
    Some(format!("{}:{}", path.display(), line))
}

/// The 1-based line of successive match offsets. A regex's matches come in
/// order, so each lookup counts only the newlines since the previous one. The
/// line used to be found by searching the file from byte 0 for the matched
/// text — O(findings × file size), and wrong whenever the same text appeared
/// earlier (it reported the first occurrence, not the match).
struct Lines<'t> {
    text: &'t [u8],
    pos: usize,
    line: u32,
}

impl<'t> Lines<'t> {
    fn new(text: &'t str) -> Self {
        Lines {
            text: text.as_bytes(),
            pos: 0,
            line: 1,
        }
    }

    fn at(&mut self, offset: usize) -> u32 {
        if offset < self.pos {
            (self.pos, self.line) = (0, 1);
        }
        self.line += memchr::memchr_iter(b'\n', &self.text[self.pos..offset]).count() as u32;
        self.pos = offset;
        self.line
    }
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

/// Whether the match is glued to a non-ASCII letter or digit on either side —
/// where a Unicode `\b` saw no boundary, so the match is a fragment of a
/// longer word (`müller.de`), not a token.
fn welded_to_non_ascii(text: &str, start: usize, end: usize) -> bool {
    let word = |c: char| !c.is_ascii() && c.is_alphanumeric();
    text[..start].chars().next_back().is_some_and(word)
        || text[end..].chars().next().is_some_and(word)
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
        || o[0] >= 240) // 240.0.0.0/4 reserved
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
    if REVERSE_DNS_HEADS
        .iter()
        .any(|h| h.eq_ignore_ascii_case(head))
    {
        return true;
    }
    let tld = candidate.rsplit('.').next().unwrap_or("");
    // Real hostnames are written lowercase; an uppercase TLD is a type/constant.
    if tld.chars().any(|c| c.is_ascii_uppercase()) {
        return true;
    }
    // Identifier-ish TLD (`.name`, `.id`, `.top`): treat as data only when the
    // token is quote/URL-delimited, which member access never is.
    if AMBIGUOUS_TLDS.iter().any(|t| t.eq_ignore_ascii_case(tld)) && !quote_adjacent(b, start, end)
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
    let Some(rest) = url.split_once("://").map(|(_, r)| r) else {
        return false;
    };
    let host = rest.split(['/', ':', '?', '#', '@']).next().unwrap_or("");
    Ipv4Addr::from_str(host).is_ok_and(|a| !is_noteworthy_ipv4(&a))
}

/// Longest line we still read as source. A minified bundle is one 200 KB
/// "line"; scanning back to its start cost O(line) *per match*, and a bundle
/// yields thousands of matches (every `a.b` property access matches the domain
/// pattern), so the pass went quadratic — one 1 MiB bundle took 0.59s of a 2.7s
/// scan. Past this width the line cannot be a comment anyway: a `//` that far
/// back is a protocol separator or a regex literal, and a real line comment
/// would have swallowed the rest of the file.
const MAX_COMMENT_LINE: usize = 4096;

/// Whether matches sit on a comment or docstring-bullet line. Language-agnostic
/// across the scanned set: `#` (Python), `//` `///` `//!` (Rust/JS line + doc
/// comments), and `*` / `/*` (block-comment bodies). Also catches a trailing
/// `//` line comment that isn't the `//` in `scheme://`.
///
/// Whether the prefix up to a match is a comment only grows along a line (a
/// marker, once in the prefix, stays there), so each line is examined once for
/// the offset its comment starts at, and every match on it is then a compare.
/// It used to re-scan the prefix byte by byte for each match.
///
/// A match more than [`MAX_COMMENT_LINE`] bytes into its line is never in a
/// comment; up to that width the answer is the one the per-match scan gave.
struct Comments<'t> {
    text: &'t str,
    /// The cached line, `[start, end)`; empty until the first lookup.
    start: usize,
    end: usize,
    /// Offset from which a match on this line is in a comment.
    from: usize,
}

impl<'t> Comments<'t> {
    fn new(text: &'t str) -> Self {
        Comments {
            text,
            start: 1,
            end: 0,
            from: usize::MAX,
        }
    }

    fn at(&mut self, pos: usize) -> bool {
        if !(self.start <= pos && pos <= self.end) {
            let b = self.text.as_bytes();
            self.start = memchr::memrchr(b'\n', &b[..pos]).map_or(0, |i| i + 1);
            self.end = memchr::memchr(b'\n', &b[pos..]).map_or(b.len(), |i| pos + i);
            self.from = comment_from(&self.text[self.start..self.end])
                .map_or(usize::MAX, |i| self.start + i);
        }
        // The old backward scan stopped `MAX_COMMENT_LINE` bytes before the
        // match: it saw the line's opening newline only up to `MAX - 1` bytes
        // in, while on the first line (no newline) it reached byte 0 at `MAX`.
        let reach = if self.start == 0 {
            MAX_COMMENT_LINE
        } else {
            MAX_COMMENT_LINE - 1
        };
        pos >= self.from && pos - self.start <= reach
    }
}

/// The shortest prefix of `line` that puts what follows it in a comment: a
/// leading marker, or a `//` that is not the one in `scheme://`.
fn comment_from(line: &str) -> Option<usize> {
    let b = line.as_bytes();
    // Nothing past the reach is ever asked about.
    let cap = b.len().min(MAX_COMMENT_LINE + 1);
    let lead = line
        .char_indices()
        .take_while(|&(i, _)| i < cap)
        .find(|&(_, c)| !c.is_whitespace())
        .and_then(|(i, c)| match (c, b.get(i + 1)) {
            ('#' | '*', _) => Some(i + 1),
            ('/', Some(b'/' | b'*')) => Some(i + 2),
            _ => None,
        });
    let trailing =
        (1..cap).find(|&i| b[i] == b'/' && b[i - 1] == b'/' && (i < 2 || b[i - 2] != b':'));
    match (lead, trailing.map(|i| i + 1)) {
        (Some(a), Some(t)) => Some(a.min(t)),
        (a, t) => a.or(t),
    }
}

#[cfg(test)]
fn in_comment(text: &str, start: usize) -> bool {
    Comments::new(text).at(start)
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

    /// Lines up to the cap keep the exact pre-cap behaviour: a marker at the
    /// line start, or a `//` earlier on the line that isn't `scheme://`.
    #[test]
    fn comment_detection_unchanged_within_the_cap() {
        assert!(in_comment("// see http://x.tk", 8));
        assert!(in_comment("# see http://x.tk", 7));
        assert!(in_comment(" * see http://x.tk", 8));
        assert!(in_comment("code(); // http://x.tk", 11));
        assert!(!in_comment("fetch(\"http://x.tk\")", 7));
        // A line just under the cap still resolves to its real start.
        let long = format!("// {}http://x.tk", "a".repeat(MAX_COMMENT_LINE - 20));
        let at = long.find("http").unwrap();
        assert!(in_comment(&long, at));
    }

    /// A minified bundle is one line hundreds of KB wide. Scanning back to its
    /// start cost O(line) per match and the pass went quadratic; past the cap we
    /// answer `false`, which is also the right answer — the bundle's `//` are
    /// protocol separators and regex literals, not comment openers.
    #[test]
    fn minified_single_line_is_not_a_comment_and_stays_cheap() {
        let filler = "a".repeat(MAX_COMMENT_LINE * 4);
        let text = format!("//x;{filler}http://evil.tk");
        let at = text.find("http://evil.tk").unwrap();
        assert!(!in_comment(&text, at), "a `//` 16 KB back is not a comment");

        // And the IOC is now actually reported, where it used to be swallowed.
        let found = scan(&text);
        assert!(
            found.iter().any(|f| f.detail == "embedded URL"),
            "expected the URL in the minified line to surface: {found:#?}"
        );
    }

    /// The cap slices `text` by byte offset; a multi-byte character straddling
    /// it must not panic.
    #[test]
    fn cap_lands_on_a_char_boundary() {
        let text = format!("{}http://evil.tk", "é".repeat(MAX_COMMENT_LINE));
        let at = text.find("http://evil.tk").unwrap();
        assert!(!in_comment(&text, at));
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
        let domains: Vec<&Finding> = fs
            .iter()
            .filter(|f| f.detail == "embedded domain name")
            .collect();
        assert!(
            domains.is_empty(),
            "domain should not double-fire inside URL: {fs:#?}"
        );
        assert!(fs.iter().any(|f| f.detail == "embedded URL"));
    }

    #[test]
    fn finds_ipv6_compressed() {
        let fs = scan(r#"const host = "2606:4700::1";"#);
        assert!(details(&fs).contains(&"embedded IPv6 address"), "{fs:#?}");
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
        let fs = scan(r#"a="2001:db8::52:0:3"; b="fe80::1ff:fe23:4567:890a"; c="fc00::abcd";"#);
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
        let n = details(&fs)
            .iter()
            .filter(|d| **d == "embedded domain name")
            .count();
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
        assert!(
            fs.is_empty(),
            "comment/doc lines must be suppressed: {fs:#?}"
        );
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

    /// The line is the match's own, not that of the first place the same text
    /// appears (which is what searching the file for it reported).
    #[test]
    fn reports_the_line_of_each_match() {
        let fs = scan("a = 1\nfetch(\"http://evil.tk/x\")\n\nfetch(\"http://evil.tk/x\")\n");
        let locs: Vec<_> = fs.iter().filter_map(|f| f.location.as_deref()).collect();
        assert_eq!(locs, ["test.js:2", "test.js:4"], "{fs:#?}");
    }

    /// A noise host only counts as the URL's host: in a query string it must
    /// not hide the real destination.
    #[test]
    fn noise_host_in_the_query_does_not_hide_the_url() {
        let fs = scan(r#"fetch("https://evil.tk/?r=github.com");"#);
        assert!(details(&fs).contains(&"embedded URL"), "{fs:#?}");
        // The host itself, or a subdomain of it, is still noise.
        let quiet = scan(r#"a("https://github.com/x"); b("https://api.GitHub.com/y");"#);
        assert!(!details(&quiet).contains(&"embedded URL"), "{quiet:#?}");
        assert_eq!(url_host("https://u:p@Evil.tk:8080/p?q#f"), "Evil.tk");
        // The URL pattern drags trailing punctuation along; it is not the host.
        assert_eq!(url_host("https://example.com',"), "example.com");
        assert_eq!(url_host("http://localhost$"), "localhost");
    }

    /// ASCII word boundaries in the patterns, but a token glued to a non-ASCII
    /// letter is still a word fragment, as it was under Unicode `\b`.
    #[test]
    fn a_fragment_of_a_non_ascii_word_is_not_a_domain() {
        let fs = scan(r#"name = "müller.de"; host = "é45.77.12.34"; c2 = "évil.tk é evil.tk";"#);
        let ev: Vec<_> = fs.iter().filter_map(|f| f.evidence.as_deref()).collect();
        assert_eq!(ev, ["evil.tk"], "{fs:#?}");
    }

    /// The per-line comment cache answers exactly what the per-match backward
    /// scan it replaced did, at every offset of every line shape — markers,
    /// `scheme://`, Unicode whitespace, and lines either side of the cap.
    #[test]
    fn comment_cache_matches_the_per_match_scan() {
        fn reference(text: &str, start: usize) -> bool {
            let mut floor = start.saturating_sub(MAX_COMMENT_LINE);
            while floor < start && !text.is_char_boundary(floor) {
                floor += 1;
            }
            let window = &text[floor..start];
            let is_comment = |prefix: &str| {
                let t = prefix.trim_start();
                if t.starts_with('#')
                    || t.starts_with("//")
                    || t.starts_with('*')
                    || t.starts_with("/*")
                {
                    return true;
                }
                let b = prefix.as_bytes();
                (1..b.len())
                    .any(|i| b[i] == b'/' && b[i - 1] == b'/' && (i < 2 || b[i - 2] != b':'))
            };
            match window.rfind('\n') {
                Some(nl) => is_comment(&window[nl + 1..]),
                None => floor == 0 && is_comment(window),
            }
        }
        let pieces: Vec<&str> = "a| |\u{a0}|é|#|*|/|/*|//|:|://|http://x.tk|\n"
            .split('|')
            .collect();
        let mut texts: Vec<String> = Vec::new();
        let mut seed = 0x2545_f491_u32;
        for _ in 0..400 {
            let mut t = String::new();
            for _ in 0..(seed % 14) {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                t.push_str(pieces[(seed >> 16) as usize % pieces.len()]);
            }
            texts.push(t);
        }
        for pad in [MAX_COMMENT_LINE - 3, MAX_COMMENT_LINE, MAX_COMMENT_LINE + 2] {
            let fill = "a".repeat(pad);
            texts.push(format!("//{fill}x.tk\n// {fill}x.tk"));
            texts.push(format!("x\n{fill}// y.tk z.tk"));
            texts.push(format!("{fill}é// y.tk"));
        }
        for t in &texts {
            let mut cache = Comments::new(t);
            for pos in (0..=t.len()).filter(|&p| t.is_char_boundary(p)) {
                assert_eq!(cache.at(pos), reference(t, pos), "{t:?} @ {pos}");
            }
        }
    }
}
