# CI gate

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

Exempt a package from every gate count — by name or `name@version`:

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

Risk already present in the baseline is not counted — only risk absent from it.

## Example

```bash
postmortem tree . --online --vulns \
  --max-high 0 --max-dep 60 --fail-on-vuln high
```

Exit `1` if there is any high-risk dependency, any subtree `dep` score above 60,
or any vulnerability of `high` severity or worse.
