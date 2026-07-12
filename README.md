<p align="center">
  <img src=".github/banner.png" alt="postmortem" width="640">
</p>

# postmortem

A static dependency scanner for **Node.js, Python, Rust, Ruby, PHP, Go, and
JVM (Java/Kotlin)** projects. It resolves the lockfile graph, walks the vendored
sources, and flags the patterns that typically show up in supply-chain
compromises: install hooks, obfuscation, embedded IOCs (URLs, IPs, crypto
wallets), and dangerous API surface.

Offline by default: no network calls, no telemetry, no daemon. One binary,
about 2.7 MB.

```
postmortem ./my-project
postmortem ./my-project --json -o report.json
postmortem ./my-project --html -o report.html
postmortem ./my-project --skip-category ioc
```

## Supported ecosystems

| Ecosystem | Lockfiles parsed | Source scanned for findings |
|---|---|---|
| Node.js | `package-lock.json` v2/v3, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` | `node_modules/` on disk |
| Python | `poetry.lock`, `Pipfile.lock`, `requirements*.txt` | project root, `.venv/.../site-packages/` |
| Rust | `Cargo.lock` | the project's own `src/` |
| Ruby | `Gemfile.lock` (Bundler) | the project's own source (`lib/`, `app/`, ...) |
| PHP | `composer.lock` (Composer) | project root, including a committed `vendor/` tree |
| Go | `go.mod` (with `go.sum` for checksums) | the project's own source and a committed `vendor/` tree |
| JVM | Maven `pom.xml` (direct deps), Gradle `gradle.lockfile` (full resolved set) | the project's own `.java` / `.kt` source |

## Features

- **Multi-ecosystem SBOM.** Resolves the full dependency graph from each
  lockfile, including parent edges (npm hoisting is fully resolved) and a
  direct-vs-transitive classification per package.
- **Four static analyzers** that run against vendored source on disk:
  - `install_hook`: npm `pre/post-install` scripts, and Python `setup.py`
    invoking `subprocess`, `os.system`, `exec`, or network primitives.
  - `obfuscation`: Shannon entropy plus language-specific signals (`eval`,
    `Function`, `charCodeAt` chains, long `\xNN` runs, base64 blobs, PHP
    `gzinflate`/`str_rot13`, Ruby `Marshal.load`). Multi-signal scoring, with a
    minified-bundle dampener so legit bundles do not raise alarms. A lone weak
    signal (a bare `eval(` or `compile(`) is never reported on its own.
  - `ioc`: embedded URLs, IPv4 and IPv6 addresses, bare domain names, and
    Bitcoin (Base58-validated) and Ethereum addresses. Heavily filtered to stay
    high-signal (see [False-positive controls](#false-positive-controls)).
  - `sensitive_api`: dangerous primitives per language, such as
    `child_process`/`net`/`https` (Node), `subprocess`/`socket`/`os.system`
    (Python), `std::process`/`std::net`/`Command::new` (Rust),
    `system`/`Net::HTTP`/`Open3` (Ruby), `shell_exec`/`proc_open`/`fsockopen`
    (PHP), `exec.Command`/`net.Dial`/`plugin.Open` (Go), and
    `Runtime.exec`/`ProcessBuilder`/`Class.forName` (JVM).
- **Four output formats:** colored terminal, stable versioned JSON, a
  self-contained HTML report, and SARIF 2.1.0 for GitHub Code Scanning and other
  SARIF-aware tools.
- **CI-friendly exit codes:** `0` clean, `1` findings at or above `--severity`,
  `2` execution error.
- **Suppression** via CLI flags and/or a `postmortem.conf` file in the scanned
  directory.

## False-positive controls

The `ioc` analyzer is tuned for a high signal-to-noise ratio on real codebases:

- **Scope operators are not addresses.** `web::get`, `Foo::<T>`, and other
  `::` paths in Rust, PHP, and Ruby are never mistaken for compressed IPv6.
- **Comments and docstrings are skipped.** A URL or IP in a `#`, `//`, `///`, or
  `/* */` line is documentation, not an exfil endpoint.
- **Non-routable ranges are dropped.** RFC1918, loopback, link-local, CGNAT, and
  TEST-NET IPv4, plus documentation (`2001:db8::/32`), link-local, and
  unique-local IPv6, are treated as config/test data.
- **Member access is not a domain.** `self.name`, `logging.info`, `tc.in`,
  `this.ch`, and other attribute accesses whose trailing label happens to be a
  TLD (including short ccTLDs like `.in` or `.ch`) are filtered out, as are
  reverse-DNS package paths (`com.google.gson`, `org.apache.commons`).
- **Reference hosts are allow-listed.** Registry, docs, knowledge, and
  module-host sites (npm, PyPI, crates.io, `golang.org`, `gopkg.in`, Wikipedia,
  Stack Overflow, and more) are treated as noise, and hosts already covered by a
  URL match are not double-reported.

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

The formula at [`Formula/postmortem.rb`](Formula/postmortem.rb) is
auto-regenerated by the release workflow with live sha256 hashes. Never edit it
by hand.

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

The release workflow is `workflow_dispatch`-only, with no automatic builds on
push or tag. To grab a binary from an untagged commit, trigger it manually:

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
      --skip-analyze             Skip every analyzer and only emit the SBOM
      --enrich                   Attach mlab.sh deep-links to every IOC finding
                                 so you can click straight through to enrichment
                                 (WHOIS / passive DNS / abuse). Link emission
                                 only, no HTTP is made.
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
| `1`  | At least one finding at or above the threshold. Block the build. |
| `2`  | Execution error (no ecosystem detected, lockfile unreadable, etc.). |

## `postmortem.conf`

Drop a `postmortem.conf` at the root of the project you scan to suppress noise
without typing flags every time. It is auto-loaded when present; CLI flags take
precedence and are unioned with the file's settings.

Full schema (all fields optional):

```toml
# Drop entire finding categories.
skip_categories = ["ioc"]

# Drop everything attributed to these dependencies. A bare name matches every
# version of that dep; "name@version" pins to a specific version.
skip_dependencies = ["lodash", "left-pad@1.3.0"]

# Raise the noise floor: findings below this severity are dropped before
# rendering and never count toward the CI exit code.
min_severity = "medium"

# Fine-grained ignore rules. A finding is suppressed when ALL specified fields
# match. An empty rule (no fields) is ignored on purpose so a typo cannot
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
including `/`, `?` matches one non-slash char. Matching is substring (no implicit
anchoring), so `**/test/**` works regardless of the absolute prefix.

Use `--no-config` to scan without auto-loading, or `--config <path>` to point at
a file outside the project root.

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

`--html -o report.html` produces a self-contained single-file report, with no
external CSS, JS, fonts, or images. Safe to attach to a ticket or upload to
artifact storage.

### SARIF (GitHub Code Scanning)

`--sarif -o report.sarif` produces a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/)
document: one rule per analyzer category (`postmortem.ioc`, `.obfuscation`,
`.install_hook`, `.sensitive_api`), one result per finding. Severity maps to
SARIF levels as `critical/high` to `error`, `medium` to `warning`, `low` to
`note`, and `info` to `none`. Each result carries a stable `partialFingerprints`
entry so re-runs do not re-open the same alert, and paths are made relative to a
`SRCROOT` URI base so the same SARIF file makes sense on any reviewer's machine.
When combined with `--enrich`, the mlab.sh deep-link is surfaced as
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

## Enrichment links

The scanner never makes network calls. The optional `--enrich` flag emits
clickable [mlab.sh](https://mlab.sh) deep-links per IOC finding so a human can
pivot to enrichment in one click. It does **not** call any network itself.

| IOC kind | mlab.sh link template |
|---|---|
| URL | `https://mlab.sh/domain/<host>` (host extracted from the URL) |
| IPv4 | `https://mlab.sh/ip/<addr>` |
| IPv6 | `https://mlab.sh/ip/<addr>` |
| Domain | `https://mlab.sh/domain/<name>` |
| BTC / ETH wallet | `https://mlab.sh/crypto/<address>` (chain auto-detected) |

## Fixtures

The test corpus emulates **real public supply-chain incidents** with inert
payloads (see [tests/fixtures/README.md](tests/fixtures/README.md) for
references). Each fixture reproduces patterns from the incident, not the original
malicious code:

| Fixture | Models incident | Year | Triggers |
|---|---|---|---|
| [`malicious-node/`](tests/fixtures/malicious-node) | `event-stream@3.3.6` to `flatmap-stream@0.1.1` Copay wallet stealer | 2018 | `install_hook` HIGH, `obfuscation` CRITICAL, `ioc` HIGH (BTC + ETH wallets), `sensitive_api` |
| [`malicious-python/`](tests/fixtures/malicious-python) | `ctx@0.2.6` PyPI hijack, AWS-key exfil via `setup.py` | 2022 | `install_hook` CRITICAL (6 primitives), `ioc` HIGH (wallet), `sensitive_api` |
| [`malicious-rust/`](tests/fixtures/malicious-rust) | `rustdecimal` typosquat of `rust_decimal` | 2022 | SBOM resolves typosquat, `sensitive_api` MEDIUM on local `src/` |
| [`malicious-ruby/`](tests/fixtures/malicious-ruby) | `rest-client 1.6.13` / `strong_password` hijack shape | 2019 | SBOM resolves typosquat, `obfuscation` (eval + base64), `sensitive_api`, `ioc` |
| [`malicious-php/`](tests/fixtures/malicious-php) | Composer package-hijack webshell shape | n/a | SBOM resolves typosquat, `obfuscation` HIGH (eval + gzinflate + base64), `sensitive_api`, `ioc` |
| [`malicious-go/`](tests/fixtures/malicious-go) | Go module-typosquat payload shape | n/a | SBOM resolves typosquat and `// indirect` split, `obfuscation` (base64 blob), `sensitive_api`, `ioc` |
| [`malicious-java/`](tests/fixtures/malicious-java) | Maven artifact-typosquat payload shape | n/a | SBOM reads pom direct deps and skips the BOM, `obfuscation` (base64 blob), `sensitive_api`, `ioc` |
| [`clean-node/`](tests/fixtures/clean-node) | benign baseline | n/a | no findings, exit `0` |

Run the live demo:

```bash
postmortem ./tests/fixtures/malicious-node
postmortem ./tests/fixtures/malicious-python
postmortem ./tests/fixtures/malicious-rust
postmortem ./tests/fixtures/malicious-ruby
postmortem ./tests/fixtures/malicious-php
postmortem ./tests/fixtures/malicious-go
postmortem ./tests/fixtures/malicious-java
```

## Development

```bash
cargo build              # debug build
cargo build --release    # stripped, LTO, about 2.7 MB
cargo test               # 61 unit + 36 integration tests
```

### False-positive harness

[`scripts/fp-harness.sh`](scripts/fp-harness.sh) clones a set of well-known,
legitimate repositories (algorithm collections and popular libraries) across all
supported ecosystems, runs postmortem on each, and summarizes the findings.
Because the repos are trusted, essentially every finding is a candidate false
positive, so the breakdown doubles as a regression harness for the IOC and
obfuscation heuristics. It also runs a few per-repo sanity checks (determinism,
SARIF validity, `--skip-category`, and the CI gate).

```bash
scripts/fp-harness.sh              # all ecosystems
scripts/fp-harness.sh rust ruby    # a subset
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
    php.rs               # composer.lock (Composer)
    go.rs                # go.mod / go.sum (Go modules)
    java.rs              # Maven pom.xml / Gradle gradle.lockfile
  analyze/
    install_hooks.rs     # npm pre/post-install + Python setup.py
    obfuscation.rs       # entropy + eval + hex/base64 heuristics
    ioc.rs               # URL / IPv4 / IPv6 / domain / BTC / ETH extraction
    sensitive_api.rs     # dangerous primitives by language
    util.rs              # walkers, entropy, path to package mapping
  report/
    terminal.rs          # colored TUI table
    json.rs              # schema-stable JSON
    html.rs              # self-contained HTML
    sarif.rs             # SARIF 2.1.0
scripts/
  fp-harness.sh          # false-positive harness over real repos
  fp_summarize.py        # JSON report summarizer used by the harness
tests/
  integration.rs         # end-to-end against fixtures
  fixtures/              # reproductions of real public incidents
```

## License

See [LICENSE](LICENSE).

> "Don't dig up the corpse to find the cause of death after the breach. Do it
> before you ship the dependency."
