# postmortem

**A static supply-chain scanner for your dependencies - no network by default.**

postmortem reads your project's lockfiles (and, with `system`, your machine's OS
packages), reconstructs the full dependency graph, and surfaces supply-chain
risk: malicious install code, typosquats, suspicious provenance, low-reputation
or freshly-transferred source repos, and known vulnerabilities.

Everything is **offline and static by default**. The only commands that touch the
network are opt-in (`--online`, `--vulns`), and every response is cached locally.

---

## The four commands

| Command | What it does |
| --- | --- |
| [`scan`](Scan) | Static analysis of dependency code for malicious patterns (IOCs, obfuscation, install hooks, sensitive APIs). |
| [`tree`](Tree) | Reconstruct the dependency forest from lockfiles; `--online` adds source-repo reputation, `--vulns` adds known CVEs. |
| [`system`](System) | Audit the machine's OS package managers (Homebrew, pacman/AUR, apt/dpkg, dnf/rpm, and Nix) with the same risk scoring. |
| [`cache`](Cache) | Manage the on-disk cache used by the online paths. |

## Key concepts

- **[Ecosystems & Hosts](Ecosystems-and-Hosts)** - the 7 language ecosystems and
  3 code hosts postmortem understands.
- **[Online resolution](Online-Resolution)** - how `--online` turns a package
  into a `risk:dep` score, plus `--languages`.
- **[System package managers](System)** - the Homebrew, [pacman](Pacman), [apt](Apt), [dnf](Dnf), and [Nix](Nix) backends in depth.
- **[CI gate](CI-Gate)** - turn scores and vulns into a pass/fail build.
- **[Configuration](Configuration)** - tokens, thresholds, and per-project policy.

---

## Install

**From source** (requires a recent Rust toolchain):

```bash
git clone https://github.com/mlab-sh/postmortem
cd postmortem
cargo build --release
# binary at ./target/release/postmortem
```

**Homebrew** (a formula is published in the repo on each release):

```bash
brew tap mlab-sh/postmortem https://github.com/mlab-sh/postmortem
brew install postmortem
```

## Quick start

```bash
postmortem scan .                      # static scan of the current project
postmortem tree . --depth 2            # offline dependency forest
postmortem tree . --online --vulns     # + repo reputation + known CVEs
postmortem system --online             # audit your installed OS packages
```

> This wiki is generated from the [`wiki/`](https://github.com/mlab-sh/postmortem/tree/main/wiki)
> folder in the repo and synced automatically - edit the markdown there, not here.
