# `postmortem system`

Audit the **OS-level** package managers installed on *this machine*. Where `scan`
and `tree` read a project's committed lockfiles, `system` inspects what is
actually installed by shelling out to the package manager.

**Homebrew** is the first (and today only) backend.

```bash
postmortem system [options]
```

## Detection

`system` scans `$PATH` for known managers (`brew`, `apt`, `dpkg`, `pacman`,
`dnf`, `apk`, `port`) and reports which are present and which postmortem can
actually audit:

```
detected package managers: homebrew
```

If no supported manager is found, it exits `2`.

## `--repos` — source repositories (taps)

Lists the configured Homebrew taps with their **real** git remotes (read from
`brew tap-info`, not guessed), flagging third-party taps that bypass core review:

```bash
postmortem system --repos
```

```
source repos (homebrew)
  homebrew/core
  homebrew/cask
  sn0walice/sshm  [https://github.com/Sn0wAlice/sshm]  third-party

⚠ 1 third-party tap(s) bypass Homebrew-core review
```

## The tree

Reads `brew info --json=v2 --installed` and builds the installed forest, reusing
the exact `tree` model (`risk:dep` scoring, colors, gochi recap):

- **Formulae** — versioned, with real dependency edges (`declared_directly`);
  `installed_on_request` formulae are the roots.
- **Casks** — apps installed as prebuilt vendor binaries, shown as flat roots.

```bash
postmortem system                 # offline tree + risk
postmortem system --online        # + source-repo reputation
postmortem system --online --languages
```

## Risk signals

### Provenance (offline)

| Signal | Severity | Meaning |
| --- | --- | --- |
| `third-party-tap (owner/name)` | Medium | Installed from a tap outside `homebrew/*` — bypasses core review. Its formulae/casks resolve to the **tap's own repo** for reputation, not "no repository". |

### Casks — the download-and-run surface (offline)

Casks download arbitrary binaries from vendor URLs, so they carry extra signals:

| Signal | Severity | Meaning |
| --- | --- | --- |
| `unverified-download (sha256 :no_check)` | High | No integrity pin — brew runs whatever bytes arrive. |
| `insecure-url (http)` | High | Download over plain HTTP. |
| `download-host-mismatch (host)` | Low | Download host is unrelated to the homepage and isn't a known release mirror (GitHub/GitLab/SourceForge/…). |
| `runs-installer` | Info | Ships a `pkg`/`installer` artifact (elevated install), not a plain `.app`. |
| `auto-updates` | Info | Self-updates outside brew — later versions bypass this audit. |
| `deprecated` | Medium | Marked deprecated/disabled — unmaintained. |

### Reputation (`--online`)

Formula `homepage` (or a cask's download URL, which is often a GitHub release)
resolves to the source repo, pulling the same stars/age/activity/language signals
as [`tree --online`](Online-Resolution). Curated `homebrew/core` formulae whose
homepage isn't a code host resolve to *no repository* — reported as **unchecked**,
not suspicious.

## Options

| Flag | Description |
| --- | --- |
| `--repos` | List the configured source repos (taps) and exit. |
| `--online` | Resolve each package to its source repo + reputation (network). |
| `--languages` | With `--online`, add the repo language breakdown. |
| `--depth <N>` | Limit tree depth. |
| `--json` | Emit the resolved forest as JSON. |
| `--no-progress` | Disable the animated progress UI. |
