//! High-signal malicious-behaviour patterns in dependency code.
//!
//! Where [`sensitive_api`](crate::analyze::sensitive_api) flags *generic*
//! dangerous primitives at Low severity, this pass targets the specific
//! objectives of the 2022–2026 supply-chain wave with tight, rarely-legitimate
//! markers, so it can speak at Medium/High:
//!
//! - **credential/secret harvesting** — cloud-metadata endpoints, `~/.aws`/`.ssh`
//!   /`.npmrc` reads, secret-scanners (Shai-Hulud, ctx, torchtriton, LiteLLM);
//! - **self-propagation / worm** — writing `.github/workflows`, minting npm
//!   tokens, creating repos (Shai-Hulud, Nx);
//! - **persistence** — LaunchAgent/systemd/cron/autostart/Run-key drops;
//! - **paste/webhook exfil** — `webhook.site`, paste-site raw endpoints.
//!
//! Substring-only (no AST), so it stays cheap; the markers are chosen to be
//! things ordinary library code does not contain.

use aho_corasick::AhoCorasick;
use std::path::Path;
use std::sync::OnceLock;

use crate::analyze::{Lang, util};
use crate::model::{Category, Finding, Severity};

/// Source extensions worth scanning — the behaviours span languages.
const SRC_EXTS: &[&str] = &[
    "js", "mjs", "cjs", "ts", "py", "rb", "php", "go", "sh", "bash", "pl", "pm", "lua",
];

struct Group {
    label: &'static str,
    severity: Severity,
    needles: &'static [&'static str],
}

const GROUPS: &[Group] = &[
    Group {
        label: "credential/secret harvesting",
        severity: Severity::High,
        needles: &[
            "169.254.169.254", // AWS/GCP/Azure instance metadata
            "169.254.170.2",   // ECS task metadata
            "metadata.google.internal",
            "/.aws/credentials",
            ".aws/credentials",
            "/.ssh/id_",
            ".git-credentials",
            ".docker/config.json",
            ".kube/config",
            "/etc/shadow",
            "trufflehog",
        ],
    },
    Group {
        label: "npm-token / registry credential access",
        severity: Severity::High,
        needles: &["/-/npm/v1/tokens", "_authToken", "registry.npmjs.org/-/"],
    },
    Group {
        label: "self-propagation / worm behaviour",
        severity: Severity::High,
        needles: &[
            ".github/workflows/",
            "api.github.com/user/repos",
            "npm publish",
        ],
    },
    Group {
        label: "persistence mechanism",
        severity: Severity::Medium,
        needles: &[
            "LaunchAgents",
            "/etc/systemd/system",
            ".config/systemd/user",
            "/etc/cron",
            "crontab -",
            "/.config/autostart",
            "CurrentVersion\\Run",
        ],
    },
    Group {
        label: "exfil to paste/webhook site",
        severity: Severity::Medium,
        needles: &["webhook.site", "pastebin.com/raw", "hastebin.com/raw"],
    },
];

/// Across the shared read pool: this pass walks the whole project root,
/// `node_modules` included, and was the single largest serial cost of a scan.
/// JavaScript under `skip_js` is left out: the content pass over that
/// directory already ran [`scan_text`] on it.
pub fn scan_dir(list: &util::Listing, skip_js: Option<&Path>, out: &mut Vec<Finding>) {
    let files = list.select(list.root(), |p| {
        covers(p) && !(skip_js.is_some_and(|d| p.starts_with(d)) && Lang::JavaScript.matches(p))
    });
    out.extend(super::par_scan(&files, scan_text));
}

/// Whether this pass reads `path` (by extension).
pub fn covers(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| SRC_EXTS.iter().any(|x| x.eq_ignore_ascii_case(e)))
}

/// Every group's needles in one automaton, pattern ids in `GROUPS` order.
fn automaton() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        let all: Vec<&str> = GROUPS.iter().flat_map(|g| g.needles).copied().collect();
        util::automaton(&all)
    })
}

/// One pass over `text` for all groups' needles (it was one `contains` each).
pub fn scan_text(path: &Path, text: &str, out: &mut Vec<Finding>) {
    let counts = util::needle_counts(automaton(), text);
    let mut ids = counts.iter();
    let mut dep = None;
    for g in GROUPS {
        // This group's slice of the pattern ids, in its needle order.
        let hits: Vec<&str> = g
            .needles
            .iter()
            .zip(ids.by_ref())
            .filter(|&(_, &n)| n > 0)
            .map(|(&needle, _)| needle)
            .collect();
        if hits.is_empty() {
            continue;
        }
        let dep = dep.get_or_insert_with(|| util::owner(path, "<project>"));
        out.push(Finding {
            dependency: dep.clone(),
            severity: g.severity,
            category: Category::SensitiveApi,
            detail: format!("{}: {}", g.label, hits.join(", ")),
            location: Some(path.display().to_string()),
            evidence: None,
            enrich_url: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn flags_credential_harvest_and_worm_but_not_clean_code() {
        let tmp = std::env::temp_dir().join(format!("pm-behav-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        fs::write(
            tmp.join("stealer.js"),
            "fetch('http://169.254.169.254/latest/meta-data/')",
        )
        .unwrap();
        fs::write(
            tmp.join("worm.js"),
            "fs.writeFileSync('.github/workflows/x.yml', payload)",
        )
        .unwrap();
        fs::write(tmp.join("clean.js"), "export const add = (a,b) => a+b;").unwrap();

        let mut out = Vec::new();
        scan_dir(&util::Listing::walk(&tmp), None, &mut out);
        assert!(
            out.iter()
                .any(|f| f.detail.contains("credential/secret") && f.severity == Severity::High)
        );
        assert!(out.iter().any(|f| f.detail.contains("self-propagation")));
        assert!(!out.iter().any(|f| {
            f.location
                .as_deref()
                .is_some_and(|l| l.ends_with("clean.js"))
        }));
        let _ = fs::remove_dir_all(&tmp);
    }
}
