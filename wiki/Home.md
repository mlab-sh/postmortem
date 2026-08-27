# postmortem

**A supply-chain security scanner for your dependencies and your machine.**

postmortem reads your project's lockfiles (and, with `system`, your machine's OS
packages), reconstructs the full dependency graph, and surfaces supply-chain
risk: malicious install code, typosquats, suspicious provenance, low-reputation
or freshly-transferred source repos, and known vulnerabilities.

postmortem sends **no telemetry**. `scan` and the default `tree` / `system` views
run entirely on your machine; the network is touched only on the paths that need
it (`--online` reputation, `--vulns` advisories), and every response is cached
locally.

---

## The commands

| Command | What it does |
| --- | --- |
| [`scan`](Scan) | Static analysis of dependency code for malicious patterns (IOCs, obfuscation, install hooks, sensitive APIs). |
| [`tree`](Tree) | Reconstruct the dependency forest from lockfiles; `--online` adds source-repo reputation, `--vulns` adds known CVEs, `--human` shows which accounts control it. |
| [`audit`](Audit) | One-shot graded health check: malware scan + inventory, plus optional reputation and vulns — and the same [CI gate](CI-Gate) as `tree`. |
| [`licenses`](Licenses) | Inventory the licenses of the dependency graph and enforce a policy (deny / allow / fail-on-unknown). |
| [`fix`](Fix) | Turn the vulnerability report into the change that clears it: the minimum upgrade per package, and where to make it. |
| [`why`](Why) | Explain why a package is installed — and with `--blast`, what a compromise of it would reach. |
| [`diff`](Diff) | Compare two project states — or a GitHub PR by URL — and assess what the change introduces. |
| [`sbom`](Sbom) | Export the resolved dependency graph as a CycloneDX 1.5 SBOM. |
| [`system`](System) | Audit the machine's OS package managers (Homebrew, pacman/AUR, apt/dpkg, dnf/rpm, Nix, apk, and on [Windows](Windows) WinGet, MSIX, Chocolatey, Scoop and the registry) with the same risk scoring. |
| [`scripts`](Install-Time) | Which dependencies execute code at install time, whether each is approved, and what its script does. |
| [`hook`](Install-Time) | The git pre-commit hook that scans staged dependency changes. |
| [`watch`](Install-Time) | Re-scan whenever a lockfile changes. |
| [`timeline`](Timeline) | Lay a package's release history out in order: handovers, install scripts, repository moves. |
| [`ci`](CI-Templates) | Print a ready-to-commit pipeline for GitLab CI, Azure DevOps, Jenkins or GitHub Actions. |
| [`allowlist`](Allowlist) | Every suppression the project declares, with how long each has left to run. |
| [`cache`](Cache) | Inspect (`info`, `path`) and clear (`prune`) the on-disk cache used by the online paths. |

## Key concepts

- **[Ecosystems & Hosts](Ecosystems-and-Hosts)** - the 7 language ecosystems and
  3 code hosts postmortem understands.
- **[Online resolution](Online-Resolution)** - how `--online` turns a package
  into a `risk:dep` score, plus `--languages`.
- **[Licenses](Licenses)** - where license data comes from per ecosystem, SPDX
  normalization, and the policy gate.
- **[Typosquatting](Typosquatting)** - the offline corpora, per ecosystem, and
  the rules that keep the check quiet.
- **[Dependency scopes](Dependency-Scopes)** - what `--omit dev` removes, and why
  a package your app also uses is never dropped.
- **[System package managers](System)** - the Homebrew, [pacman](Pacman), [apt](Apt), [dnf](Dnf), [Nix](Nix), and [apk](Apk) backends in depth.
- **[Windows](Windows)** - the five coexisting layers ([WinGet](WinGet), [MSIX](MSIX),
  [Chocolatey](Chocolatey), [Scoop](Scoop), [Add/Remove Programs](Add-Remove-Programs))
  and per-binary [trust](Binary-Trust).
- **[CI gate](CI-Gate)** - turn scores and vulns into a pass/fail build, from
  `tree`, `audit` or `system`.
- **[CI templates](CI-Templates)** - generated pipelines for GitLab, Azure and
  Jenkins, and why GitLab needs its own report format rather than SARIF.
- **[Configuration](Configuration)** - tokens, thresholds, per-project policy, and
  the `network` block for proxies and internal mirrors.

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

**Scoop** (Windows; the bucket is the repo itself, same as the tap):

```powershell
scoop bucket add postmortem https://github.com/mlab-sh/postmortem.git
scoop install postmortem
```

**Prebuilt binary**: a tarball per target — a zip on Windows — on the
[releases page](https://github.com/mlab-sh/postmortem/releases), for macOS,
Linux and Windows on x86_64, plus arm64 on macOS and Linux.

## Quick start

```bash
postmortem scan .                      # static scan of the current project
postmortem tree . --depth 2            # offline dependency forest
postmortem tree . --online --vulns     # + repo reputation + known CVEs
postmortem tree . --omit dev           # only what actually ships
postmortem tree . --online --human     # which humans control your tree
postmortem licenses . --online         # license inventory + policy
postmortem diff <github-pr-url>        # what does this PR do to my tree?
postmortem fix .                       # the upgrade that clears the CVEs
postmortem system --online             # audit your installed OS packages
```

> This wiki is generated from the [`wiki/`](https://github.com/mlab-sh/postmortem/tree/main/wiki)
> folder in the repo and synced automatically - edit the markdown there, not here.
