# Source-code scanning

The **content analyzers** read package/dependency source files and flag malicious
or suspicious code. They power [`scan`](Scan) and the deep audit of
[`system inspect --deep`](Homebrew#inspect-a-single-package).

## What each analyzer detects

| Analyzer | Looks for |
| --- | --- |
| **IOC** | Indicators of compromise in source - hard-coded IPs, suspicious/bare domains, exfil URLs. Language-agnostic (text + allowlists). |
| **Obfuscation** | High-entropy blobs, long `\xNN`/`\uNNNN` runs, base64 blobs, and per-language markers (`eval()`, base64 decode, `include_bytes!`, inline asm, `pack/unpack`, …). |
| **Sensitive-API** | Dangerous primitives per language - process spawning, raw sockets, dynamic loading, HTTP clients. Also EtherHiding markers (`eth_call` — C2 fetched from a smart contract). |
| **Install-hooks** | Install-time code execution (see below) - ecosystem-specific, not language-generic. |
| **IDE / agent hooks** | Autostart that runs code without an install: `.vscode/tasks.json` (`runOn: folderOpen`), `.claude`/`.cursor` `settings.json` (`SessionStart`), dropped loaders, and Python `.pth` files that execute at interpreter startup. |
| **Behaviour** | High-signal malicious objectives with tight, rarely-legit markers: credential/secret harvesting (cloud-metadata, `~/.aws`/`.ssh`/`.npmrc`, TruffleHog), self-propagation/worm (writing `.github/workflows`, minting npm tokens), persistence (LaunchAgent/systemd/cron/Run-key), paste/webhook exfil. |
| **GitHub Actions** | Workflow risk in `.github/workflows/*.yml` — see [GitHub Actions](GitHub-Actions). |

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
| Shell | `sh bash zsh ksh` | yes | yes | yes |
| Lua | `lua` | yes | yes | yes |

Shell and Lua cover the OS-package install-hook surface (Debian maintainer
scripts, pacman `.install`, RPM scriptlets which are shell or Lua).

Adding a language: extend that analyzer's `Lang` enum (extensions), plus the
per-language patterns for Obfuscation and Sensitive-API. IOC needs only the
extensions. Next candidates: C#, Swift, PowerShell.

## Test directories

By default, **IOC** findings inside test or fixture directories (`test`, `tests`,
`testdata`, `__tests__`, `spec`, `fixtures`, `__mocks__`) are dropped: test code
routinely embeds fake IPs, URLs, and domains that are pure noise. The check is
relative to the scanned project root. Pass `--allow-test-files` to keep them.
Only IOC is filtered; obfuscation, sensitive-API, and install-hook findings in
tests are always kept.

## Install-hooks & autostart (ecosystem-specific)

| Ecosystem | Detects |
| --- | --- |
| **Node** | Lifecycle scripts in `package.json` (`preinstall` / `install` / `postinstall`). |
| **Python** | Payload in `setup.py`; `.pth` files that run code at every interpreter startup (`litellm_init.pth`-style). |
| **Any** | IDE/agent autostart config a dependency ships (`.vscode`/`.claude`), which runs on repo-open with no install. |

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
