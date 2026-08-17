<p align="center">
  <img src=".github/banner.png" alt="postmortem">
</p>

<h1 align="center">postmortem</h1>

<p align="center">
  <b>Catch a supply-chain attack before it ships.</b><br>
  A fast supply-chain security scanner for the code you depend on.
</p>

<p align="center">
  Single static binary&nbsp;&middot;&nbsp;No telemetry&nbsp;&middot;&nbsp;No daemon&nbsp;&middot;&nbsp;Network only when you ask
</p>

---

Modern software is mostly other people's code. postmortem inspects that code the
way an attacker's payload actually reaches you: through install hooks, typosquats,
hijacked maintainer accounts, and freshly-transferred repos. It reads your
lockfiles across seven language ecosystems, reconstructs the full dependency
graph, and flags what real compromises look like.

## Why postmortem

* **No telemetry.** postmortem never phones home. It reaches the network only on
  the paths that need it — `--online` reputation and `--vulns` / `system --vulns`
  advisory lookups — and even then only sends the package coordinates being
  queried.
* **Finds attacks, not just CVEs.** Malicious install scripts, obfuscated
  payloads, embedded IOCs (IPs, domains, wallets), typosquats, and provenance
  anomalies (new publisher, dormant release, an install script that appeared out
  of nowhere).
* **Reputation intelligence.** Score every dependency on its real source repo
  (stars, age, activity, language) across GitHub, GitLab, and Codeberg.
* **Audit your machine too.** `system` inspects your OS packages (Homebrew,
  Arch/pacman, Debian/Ubuntu apt, Fedora/RHEL dnf, Nix, and Alpine apk): unsigned
  or third-party sources, PPAs and AUR builds, unverified store paths,
  install-time hooks, setuid binaries and file diversions, weakened signing
  trust, and tampered files — plus `system --vulns` for known CVEs (OSV for
  apt/apk/dnf, the Arch Security Tracker for pacman).
* **Deep source inspection.** `system inspect <pkg> --deep` clones every
  dependency's real source and runs the full detection suite over it.
* **CI-ready.** JSON and SARIF (GitHub Code Scanning) output, plus a configurable
  gate that fails the build on risk.
* **Ships-only view.** `--omit dev` drops your test and build tooling from every
  count, score and CVE tally. Scope is computed by reachability, not by what a
  manifest happens to list — so a package your application also uses is never
  dropped, however deep the dev tree it also appears in.
* **Honest.** A flat or unparseable graph raises a diagnostic, so `0 findings` is
  never mistaken for "clean" — and an `--omit` that removed packages says so, in
  the terminal and in the JSON.

## Quick start

```bash
postmortem scan .                       # find malicious code in your dependencies
postmortem tree . --online              # score dependencies by repo reputation
postmortem tree . --online --vulns      # add known CVE / GHSA / OSV advisories
postmortem tree . --omit dev            # only what actually ships
postmortem audit . --online --vulns     # one graded verdict: malware + risk + CVEs
postmortem why left-pad .               # why is this package installed?
postmortem diff ./main ./pr-branch      # what dependencies did this change add?
postmortem sbom . -o sbom.json          # export a CycloneDX 1.5 SBOM
postmortem system                       # audit your installed OS packages
postmortem system --vulns               # + known CVEs for what's installed
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
| [`scan`](https://github.com/mlab-sh/postmortem/wiki/Scan) | Static analysis of dependency code for malicious patterns, fully local. |
| [`tree`](https://github.com/mlab-sh/postmortem/wiki/Tree) | Dependency graph, plus online reputation, provenance, and known-vulnerability intelligence. |
| [`audit`](https://github.com/mlab-sh/postmortem/wiki/Audit) | One-shot graded health check: malware scan + inventory, plus optional reputation and vulns. |
| [`why`](https://github.com/mlab-sh/postmortem/wiki/Why) | Explain why a package is installed: its dependency paths up to the roots. |
| [`diff`](https://github.com/mlab-sh/postmortem/wiki/Diff) | Compare two project states: added / removed / version-changed dependencies. |
| [`sbom`](https://github.com/mlab-sh/postmortem/wiki/Sbom) | Export the resolved dependency graph as a CycloneDX 1.5 SBOM. |
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
