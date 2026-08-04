# `postmortem tree`

Reconstruct and render the **dependency forest** from your lockfiles. Offline by
default; `--online` and `--vulns` are opt-in network steps.

```bash
postmortem tree <paths>... [options]
```

## Offline (default)

Builds the recursive dependency graph straight from the lockfiles — the same
parsers `scan` uses — with diamond/cycle dedup (`(*)`) and depth control. See
[Ecosystems & Hosts](Ecosystems-and-Hosts) for supported lockfiles.

```bash
postmortem tree . --depth 2
```

```
my-project (node)
├── express@4.18.2
│   ├── accepts@1.3.8
│   └── ...
└── ...

312 nodes · 24 direct · 288 transitive · depth 6 · 41 deduped
```

## `--online` — source-repo reputation

Resolves each dependency to its source repository and pulls reputation stats
(stars, age, last activity, archived), producing a **`(risk:dep)`** score per
node. Full details in [Online resolution](Online-Resolution).

```bash
postmortem tree . --online              # (risk:dep) + flags + gochi recap
postmortem tree . --online --languages  # + repo language / breakdown
```

## `--vulns` — known vulnerabilities

Scans the lockfile against the mlab SBOM API (`vuln.mlab.sh`, OSV/GHSA/CVE) and
lists advisories per package, worst-severity first. Independent of `--online`.

```bash
postmortem tree . --vulns
postmortem tree . --online --vulns      # reputation + CVEs together
```

## Options

| Flag | Description |
| --- | --- |
| `--depth <N>` | Limit the tree to N levels below each root. |
| `--online` | Resolve source repos + reputation/provenance signals (network). |
| `--languages` | With `--online`, add each repo's language breakdown (one extra cached call/repo). |
| `--vulns` | Query known vulnerabilities via `vuln.mlab.sh` (network). |
| `--json` / `--sarif` | Emit the resolved forest as JSON, or SARIF for Code Scanning. Single path only. |
| `-o, --output <FILE>` | Output file (`-` = stdout). |
| `--no-progress` | Disable the animated progress UI. |
| **Gate flags** | `--max-risk` `--max-dep` `--max-high` `--max-sus` `--max-vulns` `--fail-on-vuln` `--allow` `--baseline` `--config` — see [CI gate](CI-Gate). |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Resolved; no active gate tripped. |
| `1` | A [CI gate](CI-Gate) threshold was exceeded. |
| `2` | No supported ecosystem was found. |

## JSON output

`--json` emits the serializable `Tree`/`Node` model (repo, stars, signals,
severity, `risk`/`dep`, language) — the foundation for feeding the graph into
downstream tooling, or as a `--baseline` for the diff gate.
