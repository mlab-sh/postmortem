# CI gate

[`tree`](Tree), [`audit`](Audit) and [`system`](System) share one gate: the same
thresholds, the same `[gate]` table, the same fail-closed rules. Pick `tree` for
the precise view, `audit` when you also want a graded verdict in the same step.

`tree` can turn its scores and vuln scan into a **pass/fail exit code**, so a
build fails when supply-chain risk crosses a threshold. Every threshold is a
**ceiling**: the gate trips (exit `1`) when the measured value is strictly
greater.

The gate summary is printed to **stderr**, so it never corrupts `--json` on
stdout.

## Thresholds

Pass them as flags, or as a `[gate]` block in `postmortem.conf` (flags win).

| Flag / key | Trips when | Requires |
| --- | --- | --- |
| `--max-risk <N>` | worst own-risk score > N | `--online` |
| `--max-dep <N>` | any subtree `dep` score > N | `--online` |
| `--max-high <N>` | more than N high-risk deps | `--online` |
| `--max-sus <N>` | more than N suspicious deps | `--online` |
| `--max-vulns <N>` | more than N known vulnerabilities | `--vulns` |
| `--fail-on-vuln <SEV>` | any vuln at least this severe | `--vulns` |

Score/count gates need `--online`; vuln gates need `--vulns`. Requesting a gate
without the data it needs is a configuration error (non-zero exit, clear message).

## Allowlist

Exempt a package from every gate count - by name or `name@version`:

```bash
postmortem tree . --online --max-high 0 --allow left-pad --allow foo@1.2.3
```

For a reason and an expiry, use `postmortem.conf`:

```toml
[gate]
max_high = 0
max_dep = 60
fail_on_vuln = "high"

[[gate.allow]]
package = "foo@1.2.3"
reason  = "vendored fork, tracked in JIRA-123"
expires = "2026-12-31"      # after this date the allow lapses
```

## Diff mode (baseline)

Fail only on **newly-introduced** risk by diffing against a prior
`tree --json` snapshot:

```bash
postmortem tree . --json -o baseline.json          # record a clean baseline
postmortem tree . --online --max-high 0 --baseline baseline.json
```

Risk already present in the baseline is not counted - only risk absent from it.

## Example

```bash
postmortem tree . --online --vulns \
  --max-high 0 --max-dep 60 --fail-on-vuln high
```

Exit `1` if there is any high-risk dependency, any subtree `dep` score above 60,
or any vulnerability of `high` severity or worse.

## Monorepos - several targets, one job

The gate takes any number of targets and trips if **any** of them trips, so a
monorepo does not need a build matrix:

```bash
postmortem tree packages/api packages/web services/worker/go.mod \
  --online --max-high 0 --fail-on-vuln high
```

A target is a project directory, or an explicit manifest/lockfile that pins one
ecosystem and one lockfile flavor - see [Targets](Tree#targets-directories-and-pinned-lockfiles).
An unreadable target exits `2`; it is never skipped silently.

In the GitHub Action, use the newline-separated `paths` input (it replaces
`path`); `--allow-multiple` is added for you when a machine format needs it:

```yaml
- uses: mlab-sh/postmortem@v2
  with:
    paths: |
      packages/api/yarn.lock     # pin yarn, ignore a stale package-lock.json
      packages/web
      services/worker/go.mod
    online: true
    vulns: true
    fail-on-vuln: high
    sarif: true
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

The uploaded SARIF carries one `runs[]` entry per target, each with its own
`SRCROOT`, so Code Scanning attributes every alert to the right package.

## Opening an issue when the gate trips

The GitHub Action can turn a tripped gate into an issue that explains it: which
thresholds were exceeded and what each one measures, the vulnerable and risky
packages (top 20 of each, read from the SARIF), how to fix or allowlist them,
and the raw gate output.

```yaml
on:
  push:
    branches: [main]
  schedule:
    - cron: "0 6 * * 1"

permissions:
  contents: read
  issues: write            # required by create-issue
  security-events: write   # SARIF upload

jobs:
  supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mlab-sh/postmortem@v2
        with:
          max-high: 0
          fail-on-vuln: high
          create-issue: true
          issue-assignees: alice,bob   # optional
```

- **One issue per branch.** A later failing run refreshes the description and
  adds a comment instead of opening a duplicate; the issue is found again by its
  label (`issue-label`, default `postmortem`) and a hidden marker.
- **Closes itself** with a comment once the gate passes again
  (`close-issue-on-pass: false` to keep it open).
- **Pull requests are skipped**: a fork's token is read-only, and a failing PR
  already shows up as a failed check.
- A misconfiguration (exit `2`) never opens an issue — it is a setup problem,
  not a supply-chain one.
- It never fails the job by itself: a missing `issues: write` permission or an
  API error is reported as a warning.
- Package names and advisory text come from third parties, so they are
  rendered inert: code spans, no `@mentions`, no HTML.
- The `issue-url` output holds the issue opened, updated or closed.
