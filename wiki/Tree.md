# `postmortem tree`

Reconstruct and render the **dependency forest** from your lockfiles. Offline by
default; `--online` and `--vulns` are opt-in network steps.

```bash
postmortem tree <paths>... [options]
```

## Offline (default)

Builds the recursive dependency graph straight from the lockfiles - the same
parsers `scan` uses - with diamond/cycle dedup (`(*)`) and depth control. See
[Ecosystems & Hosts](Ecosystems-and-Hosts) for the supported lockfiles, and each
ecosystem's page for its quirks: [Node](Node) · [Python](Python) · [Rust](Rust) ·
[Ruby](Ruby) · [PHP](PHP) · [Go](Go) · [Java](Java).

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

## `--online` - source-repo reputation

Resolves each dependency to its source repository and pulls reputation stats
(stars, age, last activity, archived), producing a **`(risk:dep)`** score per
node. Full details in [Online resolution](Online-Resolution).

```bash
postmortem tree . --online              # (risk:dep) + flags + gochi recap
postmortem tree . --online --languages  # + repo language / breakdown
```

## `--vulns` - known vulnerabilities

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
| `--json` / `--sarif` | Emit the resolved forest as JSON, or SARIF for Code Scanning. One target only, unless `--allow-multiple`. |
| `--allow-multiple` | Allow `--json`/`--sarif` with several targets - **the output shape changes**, see [Several targets](#several-targets). |
| `-o, --output <FILE>` | Output file (`-` = stdout). |
| `--omit <dev\|optional>` | Drop a dependency set. Repeatable. A package reachable from production is always kept — see [Dependency scopes](Dependency-Scopes). |
| `--no-progress` | Disable the animated progress UI. |
| **Gate flags** | `--max-risk` `--max-dep` `--max-high` `--max-sus` `--max-vulns` `--fail-on-vuln` `--allow` `--baseline` `--config` - see [CI gate](CI-Gate). |

## Targets: directories and pinned lockfiles

A target is either a **project directory** - only that directory is inspected,
there is no recursion into subprojects - or an explicit **manifest/lockfile**:

```bash
postmortem tree packages/api/yarn.lock
```

Pinning a file selects one ecosystem, and one **lockfile flavor** when several
coexist. This matters because a directory picks a single lockfile per ecosystem
by a fixed priority (`package-lock.json` › `npm-shrinkwrap.json` ›
`pnpm-lock.yaml` › `yarn.lock`; `poetry.lock` › `Pipfile.lock` ›
`requirements.txt`; `pom.xml` › `gradle.lockfile`) - so a stale
`package-lock.json` left next to your real `yarn.lock` silently wins. Pinning the
file settles it.

The parent directory still supplies the manifest (`package.json`, `Cargo.toml`,
…), so direct-vs-transitive classification is unaffected, and it stays the tree
`root` and the place `postmortem.conf` is looked up.

## Several targets

`tree` takes any number of targets and resolves them in sequence; the
[gate](CI-Gate) trips if **any** of them trips. This replaces a CI build matrix
for a monorepo:

```bash
postmortem tree packages/api packages/web services/worker/go.mod \
  --online --max-high 0
```

The terminal view renders each target as it goes. Machine formats stay
**single-target by default** - `--json` keeps emitting one bare tree object, the
shape every existing consumer expects. Passing several targets with
`--json`/`--sarif` is an error until you opt in with `--allow-multiple`, which
**changes the output shape**:

| Format | Without the flag | With `--allow-multiple` |
| --- | --- | --- |
| `--json` | one `Tree` object | an **array** of `Tree` objects (always, even for one target) |
| `--sarif` | one `runs[]` entry | one `runs[]` entry **per target**, each with its own `SRCROOT` |

Multi-run SARIF is valid 2.1.0 and GitHub Code Scanning ingests it as a single
upload, so a monorepo needs one gate job, not one per package.

A target that cannot be read - a typo, a lockfile with no manifest beside it, a
file that isn't a manifest at all - is a **configuration error (exit 2)**, never
a silently skipped one. A green build must mean everything was checked.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Resolved; no active gate tripped. |
| `1` | A [CI gate](CI-Gate) threshold was exceeded. |
| `2` | No supported ecosystem was found, or a target was unusable / the gate was misconfigured. |

## JSON output

`--json` emits the serializable `Tree`/`Node` model (repo, stars, signals,
severity, `risk`/`dep`, language) - the foundation for feeding the graph into
downstream tooling, or as a `--baseline` for the diff gate.
