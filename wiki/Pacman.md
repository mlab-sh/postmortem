# Pacman (Arch)

The second [`system`](System) backend, alongside [Homebrew](Homebrew). Reads
what `pacman` has installed and audits it with the same `risk:dep` model as
[`tree`](Tree). Selected automatically when `pacman` is the available manager.

## Data sources

| Command | Used for |
| --- | --- |
| `pacman -Qi` | Every installed package in one call: name, version, deps, URL, signature status, install-reason (explicit vs pulled-in), and whether it ships an install hook. |
| `pacman -Qm` | Foreign packages (AUR builds / manual installs), the untrusted surface. |
| `/etc/pacman.conf` | Configured repos (`core`, `extra`, custom). |
| `aur.archlinux.org/rpc` | AUR provenance for foreign packages (`--online`). |

## The tree

Direct roots are the explicitly-installed packages (`Install Reason:
Explicitly installed`); edges come from `Depends On` (version constraints and
`.so` soname deps are reduced to package names).

```bash
postmortem system                 # offline tree + risk
postmortem system --online        # + source-repo reputation + AUR provenance
```

## Risk signals

| Signal | Severity | Meaning |
| --- | --- | --- |
| `unsigned` | High | `Validated By: None`, the package isn't signature-verified. |
| `foreign-package (not from an official repo)` | Medium | Installed from the AUR or built/installed manually (bypasses the official, signed repos). |
| `aur-orphaned (no maintainer)` | Medium | AUR package with no maintainer (`--online`). |
| `aur-out-of-date` | Medium | Flagged out-of-date by AUR users (`--online`). |
| `aur-unpopular (N votes)` | Low | AUR package with few votes (`--online`). |
| `install-script (runs code at install)` | Info | Ships an `.install` hook that runs at install time. |
| `outdated (installed → current)` | Low | Behind the synced repos (needs `pacman -Sy`). |

### Install-recipe static analysis (foreign packages)

For **foreign/AUR** packages (official recipes are review-gated), postmortem runs
the same analyzers as [`scan`](Scan) over the actual install code:

- The local **`.install` hook** (`/var/lib/pacman/local/<pkg>/install`, shell) is
  analyzed **offline** - it is what runs on your machine at install/upgrade.
- With `--online`, the **AUR PKGBUILD** (the untrusted build recipe, including its
  `source=()` URLs) is fetched and analyzed too.

| Signal | Severity | Meaning |
| --- | --- | --- |
| `install-remote-exec (pipe to shell)` | High | Pipes a download into a shell (`curl … \| bash`). |
| `install-ioc (…)` | varies | An IOC (IP / domain / URL) in the recipe. |
| `install-obfuscation (…)` | varies | Encoded / obfuscated payload. |
| `install-sensitive_api (…)` | varies | A sensitive shell primitive (exec, socket, decode, escalate, persist). |

### Reputation (`--online`)

Each package's `URL` resolves to the source repo, pulling the same
stars/age/activity/language signals as [`tree --online`](Online-Resolution).
Official Arch packages mostly point at project sites (not code hosts), so they
resolve to *no repository* (reported as **unchecked**, like a curated Homebrew
core). Foreign/AUR packages far more often point at a real upstream repo, which
is where `--online` earns its keep.

## The synced-DB requirement

`pacman -Qm` (foreign detection) is only meaningful when the package databases
are synced. On an **un-synced** system it reports *every* package as foreign,
so postmortem detects that state and **skips** foreign detection, showing:

```
(@_@)  package DB not synced, so AUR/foreign detection is unavailable.
       Run `sudo pacman -Sy` first, or pass --force-aur to scan anyway.
```

`--force-aur` overrides the guard and flags everything foreign regardless.

## Options

Same as [`system`](System): `--repos`, `--online`, `--depth`, `--json`,
`--no-progress`, plus:

| Flag | Description |
| --- | --- |
| `--force-aur` | Run foreign/AUR detection even when the DB looks un-synced. |
