# Scoop

A [`system`](System) backend, and one of the five [Windows](Windows) layers.

Scoop installs per-user, without admin, from Git **buckets** of JSON manifests.
The risk is not the binary - manifests pin SHA hashes - it is the bucket: adding
one means trusting a Git repository to describe what gets run.

## Data sources

Everything is read from disk. Scoop's entry point is `scoop.ps1` with a `.cmd`
shim, and Windows' `CreateProcess` resolves only `.exe`, so spawning `scoop`
fails outright. The filesystem is also the more robust source: it depends on
neither `PATH`, the execution policy, nor Scoop's shims being intact.

| Path | Used for |
| --- | --- |
| `<root>\apps\<app>\current\install.json` | The bucket the app came from. |
| `<root>\apps\<app>\current\manifest.json` | Version, download URLs and hashes, install hooks. |
| `<root>\buckets\<name>\.git\config` | The bucket's real Git remote. |
| `<root>\shims\<name>.shim` | What each shim on `PATH` actually points at. |

## Bucket provenance

| Signal | Severity | Meaning |
| --- | --- | --- |
| `bucket 'x' is third-party Git (url)` | High | The remote is not under `github.com/ScoopInstaller/`. |
| `bucket 'x' has no Git remote` | Medium | Its origin cannot be checked. |
| `bucket 'x' (official, outside main)` | Low | An official bucket, but a wider surface than `main`. |

Two things a naive reading gets wrong:

- **`main` is not a Git repository.** Modern Scoop ships it as a plain extracted
  directory, which is why `scoop export` reports a local path for it while
  `extras` reports a GitHub URL. Treating "no remote" as unverifiable would flag
  the official bucket on every machine, so `main` without a remote is exempt.
- **Remotes are matched on host and organisation.** A repository merely *named*
  after the project (`github.com/someone/scoopinstaller-extras`) does not pass,
  and SSH remotes (`git@github.com:...`) are normalised before comparison.

## Manifests

| Signal | Severity | Meaning |
| --- | --- | --- |
| `download-without-hash` | Critical | A `url` with no `hash` beside it. |
| `install-script (runs code at install)` | Info | Declares `pre_install`, `post_install` or an `installer.script`. |

Manifest fields are polymorphic and handled as such: `bin` is a string in one
manifest and an array in the next, `hash` is a bare `sha256` here and a prefixed
`sha512:` there, and hooks are either a string or an array of lines. A single
unpinned architecture is the finding - that is the one installed on the machine
that matches it.

Hooks are PowerShell and go through the same analyzers as a Chocolatey install
script (see [source-code scanning](Source-Code-Scanning)).

## Shims

A shim is a pair: a generated `<name>.exe` wrapper and a `<name>.shim` text file
naming the real binary. Only the **target** is verified for
[binary trust](Binary-Trust) - the wrappers are Scoop's own plumbing and nobody
signs them.

A shim resolving outside Scoop's tree is reported as a caveat: it sits on `PATH`
and is resolved before anything later on it.

## Execution policy

Scoop's installer asks users to lower the PowerShell execution policy.
`RemoteSigned` is what it actually needs; `Unrestricted` or `Bypass` is a
machine-wide loosening that outlives the install, and is reported as a caveat.
