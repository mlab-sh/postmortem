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

`audit` exits **1** on a CRITICAL verdict and **2** when no supported ecosystem is
found, so it is usable as a CI guard on its own. (For fine-grained thresholds, the
[`tree`](Tree) gate stays the precise tool.)

## Options

| Flag | Description |
| --- | --- |
| `--online` | Add source-repo reputation risk scoring (network). |
| `--languages` | With `--online`, also fetch each repo's language breakdown. |
| `--vulns` | Add known-vulnerability intelligence (vuln.mlab.sh). |
| `--allow-test-files` | Report IOC findings inside test/fixture directories too. |
| `--no-progress` | Disable the animated progress UI. |
