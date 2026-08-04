# Source-code scanning

The **content analyzers** read package/dependency source files and flag malicious
or suspicious code. They power [`scan`](Scan) and the deep audit of
[`system inspect --deep`](Homebrew#inspect-a-single-package).

## What each analyzer detects

| Analyzer | Looks for |
| --- | --- |
| **IOC** | Indicators of compromise in source - hard-coded IPs, suspicious/bare domains, exfil URLs. Language-agnostic (text + allowlists). |
| **Obfuscation** | High-entropy blobs, long `\xNN`/`\uNNNN` runs, base64 blobs, and per-language markers (`eval()`, base64 decode, `include_bytes!`, inline asm, `pack/unpack`, …). |
| **Sensitive-API** | Dangerous primitives per language - process spawning, raw sockets, dynamic loading, HTTP clients. |
| **Install-hooks** | Install-time code execution (see below) - ecosystem-specific, not language-generic. |

## Language coverage

| Language | Extensions | IOC | Obfuscation | Sensitive-API |
| --- | --- | --- | --- | --- |
| JavaScript / TypeScript | `js mjs cjs ts` | yes | yes | yes |
| Python | `py` | yes | yes | yes |
| Rust | `rs` | yes | yes | yes |
| Ruby | `rb` | yes | yes | yes |
| PHP | `php` | yes | yes | yes |
| Go | `go` | yes | yes | yes |
| Java / Kotlin | `java kt` | yes | yes | yes |
| C / C++ | `c h cpp cc cxx hpp hh hxx` | yes | yes | yes |
| Perl | `pl pm t` | yes | yes | yes |

Adding a language: extend that analyzer's `Lang` enum (extensions), plus the
per-language patterns for Obfuscation and Sensitive-API. IOC needs only the
extensions. Next candidates: C#, Shell, Swift.

## Install-hooks (ecosystem-specific)

| Ecosystem | Detects |
| --- | --- |
| **Node** | Lifecycle scripts in `package.json` (`preinstall` / `install` / `postinstall`). |
| **Python** | Payload in `setup.py`. |

## Where each scan runs

The analyzers execute in two different contexts:

**1. `scan` / `tree`** - runs only for the **detected ecosystem** (i.e. a package
manager was found), over specific directories:

| Ecosystem | Scanned |
| --- | --- |
| Node (with `node_modules`) | install-hooks + IOC + Obfuscation + Sensitive-API over `node_modules` |
| Python | install-hooks + all three over the repo + site-packages |
| Rust | IOC + Obfuscation + Sensitive-API over `src/` |
| Ruby / PHP / Go / Java | all three over the repo |

> C / C++ / Perl have no package manager, so they are **never reached** by
> `scan` / `tree`.

**2. `system inspect --deep`** - runs **every analyzer × every language** over the
whole cloned source tree, regardless of ecosystem detection
(`analyze::scan_source_tree`). This is the only path that scans C / C++ / Perl.

| | scan / tree | deep-inspect |
| --- | --- | --- |
| The 7 "ecosystem" languages | yes (per detection) | yes (everything) |
| C / C++ / Perl | no | yes |
