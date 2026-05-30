//! IOC enrichment — generates deep-links into external lookup tooling so a
//! human can pivot from a finding to context (WHOIS, passive DNS, abuse
//! history, blocklists) in one click.
//!
//! v1 only emits **links**, no HTTP. The goal is "make me copy/paste this
//! into the browser less". Future versions may resolve some of these inline
//! when the user opts into a network-allowed mode.
//!
//! Provider: [mlab.sh](https://mlab.sh). Templates:
//!
//! ```text
//! https://mlab.sh/ip/<ipv4-or-ipv6>
//! https://mlab.sh/domain/<host>
//! https://mlab.sh/crypto/<address>   # chain auto-detected (BTC/ETH/…)
//! ```
//!
//! For findings whose evidence is a URL we extract the host first, then
//! produce a `/domain/<host>` link — the same lookup as if the domain were
//! written bare.

use crate::model::{Category, Finding};

const MLAB: &str = "https://mlab.sh";

pub fn annotate(findings: &mut [Finding]) {
    for f in findings.iter_mut() {
        if f.category != Category::Ioc {
            continue;
        }
        let Some(ev) = f.evidence.as_deref() else { continue };
        let url = match f.detail.as_str() {
            "embedded URL" => host_of(ev).map(|h| format!("{MLAB}/domain/{h}")),
            "embedded IPv4 address" => Some(format!("{MLAB}/ip/{ev}")),
            "embedded IPv6 address" => Some(format!("{MLAB}/ip/{ev}")),
            "embedded domain name" => Some(format!("{MLAB}/domain/{ev}")),
            // Crypto wallets — single route, chain auto-detected by mlab.sh.
            d if d.starts_with("Bitcoin address") || d.starts_with("Ethereum address") => {
                Some(format!("{MLAB}/crypto/{ev}"))
            }
            _ => None,
        };
        if let Some(u) = url {
            f.enrich_url = Some(u);
        }
    }
}

/// Extract the host portion of a URL like `https://drop.example.tld/x?y=1`.
/// Strips scheme, then takes everything up to the first `/`, `?`, `#`, or
/// `:` (port separator). Returns `None` if no scheme is present.
fn host_of(url: &str) -> Option<String> {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let end = after_scheme
        .find(|c: char| c == '/' || c == '?' || c == '#' || c == ':')
        .unwrap_or(after_scheme.len());
    let host = &after_scheme[..end];
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    fn ioc(detail: &str, evidence: &str) -> Finding {
        Finding {
            dependency: "x".into(),
            severity: Severity::Medium,
            category: Category::Ioc,
            detail: detail.into(),
            location: None,
            evidence: Some(evidence.into()),
            enrich_url: None,
        }
    }

    #[test]
    fn ipv4_link() {
        let mut fs = vec![ioc("embedded IPv4 address", "172.226.148.47")];
        annotate(&mut fs);
        assert_eq!(fs[0].enrich_url.as_deref(), Some("https://mlab.sh/ip/172.226.148.47"));
    }

    #[test]
    fn ipv6_link_keeps_colons() {
        let mut fs = vec![ioc("embedded IPv6 address", "2001:db8::dead:beef")];
        annotate(&mut fs);
        assert_eq!(
            fs[0].enrich_url.as_deref(),
            Some("https://mlab.sh/ip/2001:db8::dead:beef")
        );
    }

    #[test]
    fn domain_link() {
        let mut fs = vec![ioc("embedded domain name", "lessentiel.lu")];
        annotate(&mut fs);
        assert_eq!(fs[0].enrich_url.as_deref(), Some("https://mlab.sh/domain/lessentiel.lu"));
    }

    #[test]
    fn url_becomes_domain_link() {
        let mut fs = vec![ioc("embedded URL", "https://drop.malicious.invalid/upload?x=1")];
        annotate(&mut fs);
        assert_eq!(
            fs[0].enrich_url.as_deref(),
            Some("https://mlab.sh/domain/drop.malicious.invalid")
        );
    }

    #[test]
    fn url_with_port_strips_port() {
        let mut fs = vec![ioc("embedded URL", "http://evil.tk:8080/path")];
        annotate(&mut fs);
        assert_eq!(fs[0].enrich_url.as_deref(), Some("https://mlab.sh/domain/evil.tk"));
    }

    #[test]
    fn non_ioc_findings_untouched() {
        let mut f = ioc("embedded URL", "https://x.tk/");
        f.category = Category::Obfuscation;
        let mut fs = vec![f];
        annotate(&mut fs);
        assert!(fs[0].enrich_url.is_none());
    }

    #[test]
    fn wallet_link_uses_unified_crypto_route() {
        let mut fs = vec![
            ioc("Bitcoin address — extremely unusual in dependency code", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),
            ioc("Ethereum address — extremely unusual in dependency code", "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b"),
        ];
        annotate(&mut fs);
        assert_eq!(
            fs[0].enrich_url.as_deref(),
            Some("https://mlab.sh/crypto/1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
        );
        assert_eq!(
            fs[1].enrich_url.as_deref(),
            Some("https://mlab.sh/crypto/0xd90e2f925da726b50c4ed8d0fb90ad053324f31b")
        );
    }
}
