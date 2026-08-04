<p align="center">
  <img src=".github/banner.png" alt="postmortem">
</p>

<h1 align="center">postmortem</h1>

<p align="center">
  <b>Catch a supply-chain attack before it ships.</b><br>
  A fast, offline-first security scanner for the code you depend on.
</p>

<p align="center">
  Single static binary&nbsp;&middot;&nbsp;No telemetry&nbsp;&middot;&nbsp;No daemon&nbsp;&middot;&nbsp;Network only when you ask
</p>

---

Modern software is mostly other people's code. postmortem inspects that code the
way an attacker's payload actually reaches you: through install hooks, typosquats,
hijacked maintainer accounts, and freshly-transferred repos. It reads your
lockfiles across seven language ecosystems, reconstructs the full dependency
graph, and flags what real compromises look like. All offline by default.

## Why postmortem

* **Offline by default.** `scan` never touches the network. Nothing leaves your
  machine unless you explicitly pass `--online` or `--vulns`.
* **Finds attacks, not just CVEs.** Malicious install scripts, obfuscated
  payloads, embedded IOCs (IPs, domains, wallets), typosquats, and provenance
  anomalies (new publisher, dormant release, an install script that appeared out
  of nowhere).
* **Reputation intelligence.** Score every dependency on its real source repo
  (stars, age, activity, language) across GitHub, GitLab, and Codeberg.
* **Audit your machine too.** `system` inspects your OS packages (Homebrew and
  Arch/pacman): unsigned packages, third-party taps and AUR builds, unverified
  downloads, install-time hooks, and anything that runs at boot.
* **Deep source inspection.** `system inspect <pkg> --deep` clones every
  dependency's real source and runs the full detection suite over it.
* **CI-ready.** JSON and SARIF (GitHub Code Scanning) output, plus a configurable
  gate that fails the build on risk.
* **Honest.** A flat or unparseable graph raises a diagnostic, so `0 findings` is
  never mistaken for "clean".

## Quick start

```bash
postmortem scan .                       # find malicious code, fully offline
postmortem tree . --online              # score dependencies by repo reputation
postmortem tree . --online --vulns      # add known CVE / GHSA / OSV advisories
postmortem system                       # audit installed Homebrew packages
postmortem system inspect wget --deep   # clone + audit one package's full source
```

## Install

**Homebrew**

```bash
brew tap mlab-sh/postmortem https://github.com/mlab-sh/postmortem.git
brew install postmortem
```

**Prebuilt binary** (macOS and Linux, arm64 and x86_64): grab a tarball from the
[releases page](https://github.com/mlab-sh/postmortem/releases).

**From source** (a recent Rust toolchain):

```bash
git clone https://github.com/mlab-sh/postmortem.git
cd postmortem && cargo build --release
```

## What's inside

| Command | What it does |
|---|---|
| [`scan`](https://github.com/mlab-sh/postmortem/wiki/Scan) | Offline static analysis of dependency code for malicious patterns. |
| [`tree`](https://github.com/mlab-sh/postmortem/wiki/Tree) | Dependency graph, plus online reputation, provenance, and known-vulnerability intelligence. |
| [`system`](https://github.com/mlab-sh/postmortem/wiki/System) | Audit your machine's OS package managers, and deep-inspect any package's real source. |
| [`cache`](https://github.com/mlab-sh/postmortem/wiki/Cache) | Manage the local cache used by the online paths. |

**Ecosystems:** Node (npm / pnpm / yarn), Python, Rust, Ruby, PHP, Go, and
Java / Kotlin. Source-code scanning additionally covers C, C++, and Perl.

## Documentation

The full manual lives in the
**[wiki](https://github.com/mlab-sh/postmortem/wiki)**:

* [Commands](https://github.com/mlab-sh/postmortem/wiki/Home): scan, tree, system, cache
* [Ecosystems and hosts](https://github.com/mlab-sh/postmortem/wiki/Ecosystems-and-Hosts)
* [Online resolution and scoring](https://github.com/mlab-sh/postmortem/wiki/Online-Resolution)
* [Source-code scanning](https://github.com/mlab-sh/postmortem/wiki/Source-Code-Scanning)
* [CI gate](https://github.com/mlab-sh/postmortem/wiki/CI-Gate) and [Configuration](https://github.com/mlab-sh/postmortem/wiki/Configuration)

## License

See [LICENSE](LICENSE).

<p align="center"><i>
Don't dig up the corpse to find the cause of death after the breach.<br>
Do it before you ship the dependency.
</i></p>
