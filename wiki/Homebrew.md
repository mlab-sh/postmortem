# Homebrew

The first [`system`](System) backend. Reads what `brew` has installed and audits
it with the same `risk:dep` model as [`tree`](Tree).

## Data sources

| Command | Used for |
| --- | --- |
| `brew info --json=v2 --installed` | Formulae (versions, `installed_on_request` roots, `declared_directly` edges) and casks. |
| `brew tap-info --json --installed` | Configured taps and their **real** git remotes. |
| `brew outdated --json` | Version drift. |
| `brew cat [--cask] <name>` | A third-party package's install recipe (Ruby), for static analysis. |

## Formulae vs casks

- **Formulae** - built/bottled packages with a real dependency graph;
  `installed_on_request` formulae are the roots.
- **Casks** - apps installed as **prebuilt vendor binaries**. They're shown as
  flat roots and carry an extra download-and-run risk surface (below).

## Source repos (taps)

`--repos` lists the configured taps with their real remotes (read from
`brew tap-info`, **not** guessed - taps don't follow a fixed `homebrew-<name>`
naming, e.g. `sn0walice/sshm` → `github.com/Sn0wAlice/sshm`), flagging anything
outside `homebrew/*`.

Third-party packages resolve online to their **tap's own repo** (so they get a
reputation, not a "no repository").

## Risk signals

### Provenance & maintenance

| Signal | Severity | Meaning |
| --- | --- | --- |
| `third-party-tap (owner/name)` | Medium | Installed from a tap outside `homebrew/*` - bypasses core review. |
| `unofficial-bottle (host)` | Medium | The prebuilt binary is pulled from a bottle registry outside Homebrew's official `ghcr.io/v2/homebrew/*`. |
| `insecure-tap-remote (http)` | High | The tap's git remote is plain HTTP. |
| `exotic-tap-host (host)` | Low | The tap's remote is on a host we can't vouch for (not GitHub/GitLab/Codeberg/…). |
| `deprecated` | Medium | Formula/cask marked deprecated or disabled - unmaintained. |
| `outdated (installed → current)` | Low | Behind the current version - missing upstream (incl. security) fixes. |
| `installs-service (runs at boot/login)` | Info | Installs a launchd/systemd service - runs automatically, higher attack surface. |

### Casks - the download-and-run surface

| Signal | Severity | Meaning |
| --- | --- | --- |
| `unverified-download (sha256 :no_check)` | High | No integrity pin - brew runs whatever bytes arrive. |
| `insecure-url (http)` | High | Download over plain HTTP. |
| `download-host-mismatch (host)` | Low | Download host unrelated to the homepage and not a known release mirror (GitHub/GitLab/SourceForge/…). |
| `runs-installer` | Info | Ships a `pkg`/`installer` artifact (elevated install), not a plain `.app`. |
| `auto-updates` | Info | Self-updates outside brew - later versions bypass this audit. |

### Install-recipe static analysis (third-party only)

For **third-party** packages (core recipes are review-gated), postmortem fetches
the recipe with `brew cat` and runs the same analyzers as [`scan`](Scan) over its
Ruby (`Lang::Ruby`), plus a brew-specific check:

| Signal | Severity | Meaning |
| --- | --- | --- |
| `install-remote-exec (pipe to shell)` | High | The recipe pipes a download into a shell/interpreter (`curl … \| bash`). |
| `install-ioc (…)` | varies | An IOC (IP/domain/URL) in the recipe. |
| `install-obfuscation (…)` | varies | Encoded/obfuscated payload in the recipe. |
| `install-sensitive_api (…)` | varies | A sensitive API call (exec, network, filesystem) in the recipe. |

### Reputation (`--online`)

The formula `homepage` (or a cask's download URL, often a GitHub release)
resolves to the source repo, pulling the same stars/age/activity/language signals
as [`tree --online`](Online-Resolution). A curated `homebrew/core` formula whose
homepage isn't a code host resolves to *no repository* - reported as **unchecked**,
not suspicious.

## Inspect a single package

`system inspect <pkg>` focuses on one installed package - its dependency subtree
only, not the whole machine.

```bash
postmortem system inspect wget          # just wget's subtree + scoring
```

### `--deep` - clone & audit the real source

A heavyweight audit that reuses the **full** detection suite on actual upstream
code (not just metadata):

```bash
postmortem system inspect wget --deep     # gochi asks to confirm first
postmortem system inspect wget --deep -y  # skip the confirmation
```

1. gochi warns it's slow (network + disk) and asks `[y/N]` (`-y` bypasses).
2. Resolves every dependency to its source repo (reputation, as `--online`).
3. Creates a temp workspace under `~/.postmortem/inspect/`.
4. `git clone`s each dependency's repo (shallow; `git` must be installed).
5. Runs the [`scan`](Scan) analyzers + a best-effort vuln scan over the cloned
   source, capped at 60 repos.
6. Writes a Markdown report to `./postmortem-inspect-<pkg>.md`.
7. **Deletes** the cloned source.

> Coverage: the analyzers cover a fixed set of languages (JS/TS, Python, Rust,
> Ruby, PHP, Go, Java/Kotlin, C/C++, Perl) - see the
> [source-code scanning matrix](Source-Code-Scanning). A dependency whose
> upstream is in another language (C#, Shell, Swift, …) yields no static findings
> yet.

## Examples

```bash
postmortem system                       # offline tree + provenance/cask/install risk
postmortem system --repos               # just the taps
postmortem system --online              # + source-repo reputation
postmortem system --online --languages  # + repo language breakdown
postmortem system inspect wget --deep   # deep-audit one package's whole source
```
