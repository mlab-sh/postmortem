<p align="center">
  <img src=".github/banner.png" alt="postmortem" width="640">
</p>

# postmortem

A static dependency scanner for **Node.js, Python, Rust, and Ruby** projects. Resolves
the lockfile graph, walks the vendored sources, and flags the patterns that
typically show up in supply-chain compromises — install hooks, obfuscation,
embedded IOCs (URLs, IPs, crypto wallets), and dangerous API surface.

Offline by default. No network calls, no telemetry, no daemon. One binary,
~2.7 MB.

```
postmortem ./my-project
postmortem ./my-project --json -o report.json
postmortem ./my-project --html -o report.html
postmortem ./my-project --skip-category ioc
```

---

## Features

- **Multi-ecosystem SBOM** — npm `package-lock.json` v2/v3 (with full hoisting
  resolution for parent edges), Python `poetry.lock` / `Pipfile.lock` /
  `requirements*.txt`, Rust `Cargo.lock`, Ruby `Gemfile.lock` (Bundler).
- **Four static analyzers** that run against vendored source on disk:
  - `install_hook` — npm `pre/post-install` scripts; Python `setup.py` invoking
    `subprocess` / `os.system` / `exec` / network primitives.
  - `obfuscation` — Shannon entropy + `eval` / `Function` / `charCodeAt` chains /
    long `\xNN` runs / base64 blobs. Multi-signal scoring; minified-bundle
    dampener to avoid false alarms on legit bundles.
  - `ioc` — embedded URLs, IPv4 and IPv6 addresses, bare domain names (with
    an embedded TLD allowlist that includes commonly-abused throwaway TLDs),
    Bitcoin (Base58-validated) and Ethereum addresses. Hosts already covered
    by a URL match aren't double-reported; registry/docs hosts are allow-listed.
  - `sensitive_api` — `child_process` / `fs` / `net` / `https` (Node);
    `subprocess` / `socket` / `urllib` / `os.system` (Python); `std::process`
    / `std::net` / `Command::new` (Rust).
- **Four output formats** — colored terminal, stable versioned JSON, a
  self-contained HTML report, and **SARIF 2.1.0** for GitHub Code Scanning and
  other SARIF-aware tools.
- **CI-friendly exit codes** — `0` clean, `1` findings ≥ `--severity`,
  `2` execution error.
- **Suppression** via CLI flags and / or a `postmortem.conf` file in the
  scanned directory.

---

## Install

### From a prebuilt release (recommended)

Each release is built by [`.github/workflows/release.yml`](.github/workflows/release.yml)
for four targets:

| Target triple | Platform |
|---|---|
| `aarch64-apple-darwin`        | macOS, Apple Silicon |
| `x86_64-apple-darwin`         | macOS, Intel |
| `x86_64-unknown-linux-gnu`    | Linux, x86_64 |
| `aarch64-unknown-linux-gnu`   | Linux, arm64 |

#### Homebrew

```bash
brew tap mlab-sh/postmortem https://github.com/mlab-sh/postmortem.git
brew install postmortem
```

The formula at [`Formula/postmortem.rb`](Formula/postmortem.rb) is auto-regenerated
by the release workflow with live sha256 hashes — never edit it by hand.

#### Direct tarball

URL template: `https://github.com/mlab-sh/postmortem/releases/download/v<VERSION>/postmortem-<VERSION>-<TARGET>.tar.gz`

```bash
VERSION=1.0.1
TARGET=aarch64-apple-darwin   # pick your target from the table above
curl -L "https://github.com/mlab-sh/postmortem/releases/download/v${VERSION}/postmortem-${VERSION}-${TARGET}.tar.gz" \
  | tar xz
sudo mv "postmortem-${VERSION}-${TARGET}/postmortem" /usr/local/bin/
```

#### Ad-hoc CI build (no tagged release needed)

The release workflow is `workflow_dispatch`-only — no automatic builds on push or
tag. To grab a binary from an untagged commit, trigger the workflow manually:

1. Open the [Release workflow](https://github.com/mlab-sh/postmortem/actions/workflows/release.yml).
2. Click **Run workflow**, pick the branch or commit, run it.
3. Either download the per-platform `*.tar.gz` from the run-summary **Artifacts**
   panel (kept 90 days), or grab it from the `v<version>` Release the run
   publishes when it finishes.

### Local build

```bash
git clone https://github.com/mlab-sh/postmortem.git
cd postmortem
cargo build --release
./target/release/postmortem --help
```

Requires a recent stable Rust toolchain (1.80+). For an editable, install-on-path
build, `cargo install --path .` puts the binary in `~/.cargo/bin/`.

---

## Usage

```text
postmortem [OPTIONS] <PATH>

Arguments:
  <PATH>  Path to the project to scan

Options:
      --json                     Emit JSON
      --html                     Emit a self-contained HTML report
      --sarif                    Emit SARIF 2.1.0 (GitHub Code Scanning)
  -o, --output <OUTPUT>          Write output to this path. Pass `-` to force
                                 stdout. When omitted for --json/--html/--sarif,
                                 a file is auto-created in the cwd named
                                 `postmortem-report-[MM.DD.YYYY::HH:MM].<ext>`
      --severity <SEVERITY>      Min severity that causes a non-zero exit code
                                 [default: high]  [info|low|medium|high|critical]
      --min-severity <SEV>       Hide findings below this severity from the report
      --skip-analyze             Skip every analyzer — only emit the SBOM
      --enrich                   Attach mlab.sh deep-links to every IOC finding
                                 so you can click straight through to enrichment
                                 (WHOIS / passive DNS / abuse). Link emission
                                 only — no HTTP is made.
      --skip-category <CAT>...   Hide entire finding categories. Repeatable, or
                                 comma-separated. [ioc|obfuscation|install_hook
                                 |sensitive_api]
      --config <PATH>            Path to a postmortem.conf
      --no-config                Disable auto-loading of postmortem.conf
      --no-deps                  Skip the dependency table in terminal output
  -h, --help                     Print help
  -V, --version                  Print version
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No findings at or above `--severity` (default: `high`). |
| `1`  | At least one finding at or above the threshold — block the build. |
| `2`  | Execution error (no ecosystem detected, lockfile unreadable, etc.). |

---

## `postmortem.conf`

Drop a `postmortem.conf` at the root of the project you scan to suppress noise
without typing flags every time. It's auto-loaded when present; the CLI flags
take precedence and are unioned with the file's settings.

Full schema (all fields optional):

```toml
# Drop entire finding categories.
skip_categories = ["ioc"]

# Drop everything attributed to these dependencies. Bare name matches every
# version of that dep; "name@version" pins to a specific version.
skip_dependencies = ["lodash", "left-pad@1.3.0"]

# Raise the noise floor — findings below this severity are dropped before
# rendering and never count toward the CI exit code.
min_severity = "medium"

# Fine-grained ignore rules. A finding is suppressed when ALL specified fields
# match. An empty rule (no fields) is ignored on purpose so a typo can't
# accidentally mute everything.
[[ignore]]
category = "obfuscation"
dependency = "uglify-js"
reason = "known minifier, expected high-entropy output"

[[ignore]]
path = "**/test/**"
reason = "test fixtures legitimately contain weird strings"

[[ignore]]
path = "**/*.min.js"
reason = "minified bundles"
```

Path matching uses globs: `*` matches anything except `/`, `**` matches anything
including `/`, `?` matches one non-slash char. Matching is substring (no
implicit anchoring), so `**/test/**` works regardless of the absolute prefix.

Use `--no-config` to scan without auto-loading, or `--config <path>` to point
at a file outside the project root.

---

## Output

### Terminal

```
postmortem scan of ./tests/fixtures/malicious-node
ecosystems: node
dependencies: 2 total, 1 direct, 1 transitive
findings: 1 critical, 3 high, 1 medium, 1 low, 0 info
┌──────────────┬─────────┬────────────┬────────────────────┐
│ name         ┆ version ┆ kind       ┆ parents            │
├──────────────┼─────────┼────────────┼────────────────────┤
│ event-stream ┆ 3.3.6   ┆ direct     ┆ -                  │
│ flatmap-…    ┆ 0.1.1   ┆ transitive ┆ event-stream@3.3.6 │
└──────────────┴─────────┴────────────┴────────────────────┘
… findings table follows …
```

### JSON

Stable schema versioned via `schema_version` (currently `1`). Safe for CI
pipelines:

```json
{
  "schema_version": 1,
  "root": "/path/to/project",
  "ecosystems": ["node"],
  "dependencies": [ /* ... */ ],
  "findings": [
    {
      "dependency": "flatmap-stream",
      "severity": "critical",
      "category": "obfuscation",
      "detail": "6 obfuscation signal(s): high-entropy, eval(), …",
      "location": "…/flatmap-stream/index.js"
    }
  ]
}
```

### HTML

`--html -o report.html` produces a self-contained single-file report — no
external CSS, JS, fonts or images. Safe to attach to a ticket or upload to
artifact storage.

### SARIF (GitHub Code Scanning)

`--sarif -o report.sarif` produces a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/)
document — one rule per analyzer category (`postmortem.ioc`, `.obfuscation`,
`.install_hook`, `.sensitive_api`), one result per finding. Severity maps to
SARIF levels: `critical/high → error`, `medium → warning`, `low → note`,
`info → none`. Each result carries a stable `partialFingerprints` entry so
re-runs don't re-open the same alert, and paths are made relative to a
`SRCROOT` URI base so the same SARIF file makes sense on any reviewer's
machine. When combined with `--enrich`, the mlab.sh deep-link is surfaced as
`properties.enrichUrl` on each IOC result.

Wire into GitHub Code Scanning:

```yaml
- name: Run postmortem
  run: postmortem . --sarif -o postmortem.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: postmortem.sarif
```

---

## What is scanned (and what isn't)

| | scanned | not scanned |
|---|---|---|
| **Node** | `node_modules/` on disk, with full hoist resolution | tarballs on the registry; never downloaded |
| **Python** | project root (`setup.py`, etc.) and `.venv/lib/.../site-packages/` if present | system-wide site-packages |
| **Rust** | the project's own `src/` for sensitive APIs | `~/.cargo/registry/` (not walked by default) |
| **Ruby** | the project's own source (`lib/`, `app/`, …) for sensitive APIs, IOCs, obfuscation | gems in the Bundler path (not walked by default) |

The scanner never makes network calls. The optional `--enrich` flag emits
clickable [mlab.sh](https://mlab.sh) deep-links per IOC finding so a human can
pivot to enrichment in one click — it does **not** call any network itself.

| IOC kind | mlab.sh link template |
|---|---|
| URL | `https://mlab.sh/domain/<host>` (host extracted from the URL) |
| IPv4 | `https://mlab.sh/ip/<addr>` |
| IPv6 | `https://mlab.sh/ip/<addr>` |
| Domain | `https://mlab.sh/domain/<name>` |
| BTC / ETH wallet | `https://mlab.sh/crypto/<address>` (chain auto-detected) |

---

## Fixtures

The test corpus emulates **real public supply-chain incidents** with inert
payloads (see [tests/fixtures/README.md](tests/fixtures/README.md) for
references). Each fixture is a reproduction of patterns from the incident, not
the original malicious code:

| Fixture | Models incident | Year | Trigger |
|---|---|---|---|
| [`tests/fixtures/malicious-node/`](tests/fixtures/malicious-node) | `event-stream@3.3.6` → `flatmap-stream@0.1.1` Copay wallet stealer | 2018 | `install_hook` HIGH, `obfuscation` CRITICAL, `ioc` HIGH (BTC + ETH wallets), `sensitive_api` |
| [`tests/fixtures/malicious-python/`](tests/fixtures/malicious-python) | `ctx@0.2.6` PyPI hijack — AWS-key exfil via `setup.py` | 2022 | `install_hook` CRITICAL (6 primitives), `ioc` HIGH (wallet), `sensitive_api` |
| [`tests/fixtures/malicious-rust/`](tests/fixtures/malicious-rust) | `rustdecimal` typosquat of `rust_decimal` | 2022 | SBOM resolves typosquat, `sensitive_api` MEDIUM on local `src/` |
| [`tests/fixtures/clean-node/`](tests/fixtures/clean-node) | benign baseline | — | no findings, exit `0` |

Run the live demo:

```bash
postmortem ./tests/fixtures/malicious-node
postmortem ./tests/fixtures/malicious-python
postmortem ./tests/fixtures/malicious-rust
```

---

## Development

```bash
cargo build              # debug build
cargo build --release    # stripped, LTO, ~2.7 MB
cargo test               # 16 unit + 16 integration tests
```

### Architecture

```
src/
  main.rs                # orchestration, exit codes
  cli.rs                 # clap definitions
  config.rs              # postmortem.conf loader + filter engine
  detect.rs              # detect ecosystems + locate manifests/lockfiles
  model.rs               # Dependency, Finding, Severity, Category, Report
  parsers/
    node.rs              # package-lock.json v2/v3 + npm hoist resolution
    python.rs            # poetry.lock / Pipfile.lock / requirements*.txt
    rust.rs              # Cargo.lock
    ruby.rs              # Gemfile.lock (Bundler)
  analyze/
    install_hooks.rs     # npm pre/post-install + Python setup.py
    obfuscation.rs       # entropy + eval + hex/base64 heuristics
    ioc.rs               # URL / IPv4 / BTC / ETH extraction
    sensitive_api.rs     # dangerous primitives by language
    util.rs              # walkers, entropy, path → package mapping
  report/
    terminal.rs          # colored TUI table
    json.rs              # schema-stable JSON
    html.rs              # self-contained HTML
tests/
  integration.rs         # end-to-end against fixtures
  fixtures/              # reproductions of real public incidents
```

---

## License

See [LICENSE](LICENSE).

---

> "Don't dig up the corpse to find the cause of death after the breach — do it
> before you ship the dependency."
