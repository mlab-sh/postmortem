//! `--webhook`: deliver a machine-readable report to an HTTP endpoint.
//!
//! The same JSON `--json` prints, POSTed instead of (or as well as) written to
//! stdout — so a scheduled run can push its result somewhere that watches it
//! rather than relying on somebody reading a log.
//!
//! Delivery failure is an **error**, not a warning. A webhook that silently
//! stopped arriving is worse than one that never worked: the whole point is
//! that something downstream is waiting for it, so a run that could not deliver
//! must not report success.

use anyhow::{Context, Result};

use crate::settings::NetworkSettings;

/// How long to wait on the endpoint before giving up.
const TIMEOUT_SECS: u64 = 30;

/// Emit a report: print it when asked, deliver it when a webhook is configured.
///
/// `--webhook` implies producing the JSON, so a caller passing only the webhook
/// still builds the report; `--json` alongside it also prints.
pub fn deliver_opt(url: Option<&str>, body: &str) -> Result<()> {
    match url {
        // The proxy configuration is read here rather than threaded through
        // every call site: a corporate runner has one, and a webhook that
        // ignores it fails for a reason nobody can see.
        Some(u) => deliver(u, body, &crate::settings::Settings::load_or_warn().network),
        None => Ok(()),
    }
}

/// POST `body` to `url` as `application/json`.
pub fn deliver(url: &str, body: &str, net: &NetworkSettings) -> Result<()> {
    warn_if_cleartext(url);

    let agent = net
        .apply(
            ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(TIMEOUT_SECS)),
        )
        .build();

    let response = agent
        .post(url)
        .set("content-type", "application/json")
        .set("user-agent", concat!("postmortem/", env!("CARGO_PKG_VERSION")))
        .send_string(body);

    match response {
        Ok(r) => {
            eprintln!(
                "webhook: delivered {} bytes to {url} ({})",
                body.len(),
                r.status()
            );
            Ok(())
        }
        // A status response is the endpoint refusing the report, which is a
        // different problem from not reaching it — say which.
        Err(ureq::Error::Status(code, r)) => {
            let detail = r
                .into_string()
                .ok()
                .map(|s| crate::analyze::util::snippet(&s, 200))
                .unwrap_or_default();
            anyhow::bail!("webhook rejected the report: HTTP {code} {detail}")
        }
        Err(e) => Err(e).with_context(|| format!("webhook could not be reached at {url}")),
    }
}

/// A report carries an inventory of the machine or the project. Sending that in
/// clear text is the caller's call to make, but not one to make unknowingly.
fn warn_if_cleartext(url: &str) {
    if !url.starts_with("http://") {
        return;
    }
    if is_loopback(url) {
        return;
    }
    eprintln!(
        "warning: {url} is plain HTTP — the report travels in clear text. Use https:// unless \
         the collector is on this machine."
    );
}

/// Is this URL pointed at the local machine?
pub(crate) fn is_loopback(url: &str) -> bool {
    let host = url
        .split("//")
        .nth(1)
        .unwrap_or("")
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    // Strip the port, taking care of a bracketed IPv6 literal.
    let host = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(""),
        None => host.split(':').next().unwrap_or(""),
    };
    if matches!(host, "localhost" | "::1") {
        return true;
    }
    // 127.0.0.0/8, but only as an address: `127.evil.test` is a hostname that
    // resolves wherever its owner points it.
    let mut parts = host.split('.');
    parts.next() == Some("127")
        && host.split('.').count() == 4
        && parts.all(|p| !p.is_empty() && p.parse::<u8>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A report is an inventory of the machine; sending it in clear text should
    /// be a choice, not an accident — but a collector on this machine is not
    /// the same risk.
    #[test]
    fn loopback_is_recognised_so_a_local_collector_is_not_scolded() {
        for url in [
            "http://localhost:8080/hook",
            "http://127.0.0.1/hook",
            "http://127.0.0.53:9000/",
            "http://[::1]:8080/hook",
            "http://user:pass@localhost:8080/hook",
        ] {
            assert!(is_loopback(url), "{url}");
        }
        for url in [
            "http://collector.corp/hook",
            "http://10.0.0.5/hook",
            "https://hooks.example.test/x",
            "http://127.evil.test/hook",
        ] {
            assert!(!is_loopback(url), "{url}");
        }
    }

    /// Without a webhook nothing is delivered and the network is never touched.
    #[test]
    fn no_webhook_means_no_delivery() {
        assert!(deliver_opt(None, "{}").is_ok());
    }
}
