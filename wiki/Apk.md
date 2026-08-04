# apk (Alpine)

A [`system`](System) backend, alongside [Homebrew](Homebrew), [Pacman](Pacman),
[APT](Apt), [DNF](Dnf), and [Nix](Nix). Reads what `apk` has installed and audits
it with the same `risk:dep` model as [`tree`](Tree). Selected automatically when
`apk` is the available manager.

## Data sources

| Command / file | Used for |
| --- | --- |
| `/lib/apk/db/installed` | Every installed package (name, version, url, depends, provides). |
| `/etc/apk/world` | The explicitly-requested (direct) set. |
| `/lib/apk/db/scripts.tar.gz` | Install scripts, flagged and statically analyzed. |
| `/etc/apk/repositories` | Configured repos (official vs third-party). |

## The tree

Direct roots are the packages in `/etc/apk/world`; edges come from the
**capability graph**. Each package's `D:` requires (bare package names plus
`so:` / `cmd:` / `pc:` capabilities, with version constraints and `@tag` suffixes
stripped) are resolved through a `capability -> package` map built from every
`P:` name and `p:` provides, so a soname dependency links to the library that
provides it.

## Risk signals

| Signal | Severity | Meaning |
| --- | --- | --- |
| `install-script (runs code at install)` | Info | Ships an apk install script (`.pre-install` / `.post-install` / `.trigger` / …). |

Alpine's install scripts are few and curated, so postmortem statically analyzes
**every** one it finds (rather than gating to third-party as the dpkg/rpm
backends do), catching a malicious script whatever its origin:

| Signal | Severity | Meaning |
| --- | --- | --- |
| `install-remote-exec (pipe to shell)` | High | Pipes a download into a shell (`curl ... \| sh`). |
| `install-ioc (...)` | varies | An IOC (IP / domain / URL) in a script. |
| `install-obfuscation (...)` | varies | Encoded / obfuscated payload. |
| `install-sensitive_api (...)` | varies | A sensitive shell primitive (exec, socket, decode, escalate, persist). |

> Alpine's installed database records no per-package origin repo and no
> post-install signature state, so apk provenance is **repo-level**, not
> per-package (see below), unlike the dpkg/rpm backends.

## Source trust

`--repos` lists the configured repositories; `*.alpinelinux.org` archives are
official, a custom host or a local path is third-party. When any third-party repo
is configured, postmortem surfaces it as a gochi alert after loading:

```
N third-party apk repo(s) configured (outside the official Alpine archives)
```

## Reputation (`--online`)

Each package's `U:` (homepage) resolves to the source repo, pulling the same
stars/age/activity/language signals as [`tree --online`](Online-Resolution).
Packages that point at a project site rather than a code host resolve to *no
repository* (reported as **unchecked**).

## Options

Same as [`system`](System): `--repos`, `--online`, `--depth`, `--json`,
`--no-progress`.
