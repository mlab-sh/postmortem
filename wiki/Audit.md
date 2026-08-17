# `postmortem audit`

One command, one graded verdict. `audit` unifies the signals the other commands
surface separately: the static malware [`scan`](Scan), the dependency inventory
and graph health from [`tree`](Tree), and (opt-in) online reputation and
known-vulnerability intelligence.

```bash
postmortem audit <path>                    # offline: malware scan + inventory
postmortem audit <path> --online           # + source-repo reputation risk
postmortem audit <path> --online --vulns   # + known CVE / GHSA / OSV advisories
```

## Output

```
audit  ./myproject

  ecosystems  node, python
  packages    313 (14 direct · 299 transitive)
  malware     2 finding(s)  (1 critical · 1 high · 0 medium · 0 low)
  reputation  risk 85/100 · 1 high-risk · 3 suspicious
  vulns       4 known (worst: high)

  verdict  CRITICAL  malicious code detected
```

Each row is a self-contained check; the **verdict** at the bottom is the overall
grade, with a one-line reason.

## The grade

| Grade | When |
| --- | --- |
| **CRITICAL** | Malicious code detected (a Critical/High static finding), a High+ known vulnerability, or a high risk score (>= 70). |
| **WARN** | Softer signals: Medium/Low static findings, graph diagnostics, any known vulnerability, high-risk / suspicious dependencies, or an elevated risk score (>= 40). |
| **CLEAN** | None of the above. |

## Exit codes and the gate

| Exit | When |
| --- | --- |
| `0` | Verdict is CLEAN or WARN, and no gate threshold tripped. |
| `1` | Verdict is **CRITICAL**, *or* a [gate](CI-Gate) threshold tripped. |
| `2` | No supported ecosystem found, or the gate is misconfigured (see below). |

The grade is the **built-in floor**: malicious code fails the build whether or not
you configure anything. On top of it, `audit` accepts the same
[CI gate](CI-Gate) as [`tree`](Tree) — the `--max-*` thresholds, `--allow`,
`--baseline` and `--config`, plus the `[gate]` table of a `postmortem.conf`
auto-loaded from the project. Either the grade or the gate failing fails the run.

```bash
postmortem audit . --online --vulns --max-high 0 --fail-on-vuln high
```

Thresholds are **fail-closed**: `--max-risk` / `--max-dep` / `--max-high` /
`--max-sus` need `--online`, and `--max-vulns` / `--fail-on-vuln` need `--vulns`.
Asking for a threshold over data the run never collected exits **2**, because an
unmeasured check is not a passing one.

## Options

| Flag | Description |
| --- | --- |
| `--online` | Add source-repo reputation risk scoring (network). |
| `--languages` | With `--online`, also fetch each repo's language breakdown. |
| `--vulns` | Add known-vulnerability intelligence (vuln.mlab.sh). |
| `--allow-test-files` | Report IOC findings inside test/fixture directories too. |
| `--omit <dev\|optional>` | Drop a dependency set. Repeatable. A package reachable from production is always kept — see [Dependency scopes](Dependency-Scopes). |
| `--no-progress` | Disable the animated progress UI. |
| **Gate flags** | `--max-risk` `--max-dep` `--max-high` `--max-sus` `--max-vulns` `--fail-on-vuln` `--allow` `--baseline` `--config` — see [CI gate](CI-Gate). |
