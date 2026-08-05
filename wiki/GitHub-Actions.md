# GitHub Actions workflow analysis

`scan` statically inspects your `.github/workflows/*.yml` files for the risky
patterns behind the CI supply-chain incidents (tj-actions, Codecov, the
poisoned-pipeline class). It's a pure text/line analysis — no YAML parse — so
templated or unusual workflows don't break it, and it needs nothing but the
files already in your repo.

This runs automatically as part of [`scan`](Scan) (and `system inspect --deep`);
there is no separate flag.

## What it flags

| Check | Severity | Why it matters |
| --- | --- | --- |
| Action pinned to a **mutable branch** (`uses: x@main`) | Medium | a branch is trivially repointed — the tj-actions vector (CVE-2025-30066) |
| **Third-party action** not pinned to a commit SHA (tag) | Low | tags are repointable; pin a full SHA |
| `pull_request_target` / `workflow_run` trigger | Medium | runs in a privileged context with repo secrets |
| …the same trigger **+ a checkout of the PR head** | High | runs untrusted PR code with secrets — poisoned-pipeline execution |
| Untrusted `${{ github.event.* }}` in a `run:` step | High | expression injection into a shell step |
| `permissions: write-all` | Medium | the `GITHUB_TOKEN` is over-scoped |
| `runs-on: self-hosted` | Medium | untrusted workflow code runs inside your network |
| `curl … \| sh` in a step | High | pipes a remote script straight to a shell (the Codecov pattern) |

An official action on a version tag (`actions/checkout@v4`), a local action
(`./…`), a `docker://` image, or a **commit-SHA-pinned** action is not flagged.

## Safer workflows

- **Pin actions by commit SHA**, not a tag or branch:
  `uses: actions/checkout@11bd719…` (a comment can note the version).
- Avoid `pull_request_target` unless you understand the risk; never check out and
  execute the PR head in that context.
- Never interpolate `${{ github.event.<user-controlled> }}` into `run:`; pass it
  through an `env:` variable and reference `"$VAR"` instead.
- Set least-privilege `permissions:` per job.
- Prefer GitHub-hosted runners; isolate self-hosted ones and make them ephemeral.

Findings appear in the [`scan`](Scan) report under the `sensitive_api` category
and feed the same [CI gate](CI-Gate) as every other finding.
