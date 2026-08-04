# `postmortem scan`

Static analysis of your dependency graph for **malicious code patterns**. Reads
lockfiles + on-disk package sources; makes **no network calls**.

```bash
postmortem scan <paths>... [options]
```

Multiple paths are scanned in sequence. Machine formats (`--json` / `--html` /
`--sarif`) require a single path.

## What it looks for

Each finding has a **severity** (`info` → `critical`) and a **category**:

| Category | Detects |
| --- | --- |
| `ioc` | Indicators of compromise - hard-coded IPs, bare/suspicious domains, exfil URLs. |
| `obfuscation` | Encoded/packed payloads, eval chains, and other obfuscation tells. |
| `install_hook` | `preinstall`/`install`/`postinstall` lifecycle scripts that run on install. |
| `sensitive_api` | Calls to sensitive APIs (process spawning, filesystem, network). |

Findings can carry an `--enrich` deep-link into mlab.sh (WHOIS / passive DNS /
abuse) - **links only, no HTTP is made**.

See [Source-code scanning](Source-Code-Scanning) for the full analyzer ×
language coverage matrix.

## Options

| Flag | Description |
| --- | --- |
| `--json` / `--html` / `--sarif` | Emit a machine format instead of the terminal view. SARIF feeds GitHub Code Scanning. |
| `-o, --output <FILE>` | Write to a file (`-` forces stdout). Defaults to `postmortem-report-[date].<ext>`. |
| `--severity <SEV>` | Minimum severity that trips a non-zero exit (CI gate). Default: `high`. |
| `--min-severity <SEV>` | Hide findings below this severity from the report. |
| `--skip-category <C,...>` | Hide whole categories (`ioc`, `obfuscation`, `install_hook`, `sensitive_api`). |
| `--skip-analyze` | Emit only the SBOM (dependency inventory), no analysis. |
| `--no-deps` | Terminal only: omit the dependency table, show findings only. |
| `--enrich` | Attach mlab.sh investigation links to IOC findings. |
| `--config <FILE>` / `--no-config` | Point at a `postmortem.conf`, or disable its auto-loading. See [Configuration](Configuration). |
| `--no-progress` | Disable the animated progress UI. |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scanned; nothing at or above `--severity`. |
| `1` | A finding met or exceeded `--severity` (gate tripped). |
| `2` | No supported ecosystem was found at any path. |

## Suppressing findings

Drop a `postmortem.conf` (TOML) in the project to suppress known-accepted
findings; it is auto-loaded unless `--no-config` is set. See
[Configuration](Configuration).
