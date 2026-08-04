# APT (Debian / Ubuntu)

A [`system`](System) backend, alongside [Homebrew](Homebrew) and
[Pacman](Pacman). Reads what `dpkg`/`apt` has installed and audits it with the
same `risk:dep` model as [`tree`](Tree). Selected automatically when `apt` is the
available manager.

## Data sources

| Command | Used for |
| --- | --- |
| `dpkg-query -W` | Every installed package in one call: name, version, deps, homepage. |
| `apt-mark showmanual` | The manually-installed (direct) set (`:arch` qualifiers stripped). |
| `apt-cache policy <pkgs>` | Per-package provenance: non-official source (a PPA / custom repo, or a manual `.deb`) and the archive component it came from. |
| `apt-mark showhold` | Packages held back from upgrades. |
| `dpkg --print-architecture` + `dpkg-query ${Architecture}` | Native arch vs packages installed only for a foreign one. |
| `/var/lib/dpkg/info/*.postinst` | Maintainer scripts (install-time shell). |
| `/var/lib/dpkg/info/*.list` | The files each package ships (services / timers / auth config / setuid attribution). |
| `find /usr /opt -perm /6000` | Setuid / setgid binaries. |
| `dpkg-divert --list` | Packages diverting another package's file. |
| `dpkg --verify` | Installed files whose content no longer matches (md5). |
| `gpg --show-keys` | Expiry of keys in the apt keyrings. |
| `/etc/apt/sources.list(.d)` | Configured sources (and `[trusted=yes]` / `http://`). |
| `/etc/apt/preferences(.d)` | Pin rules (version / source overrides). |
| `/etc/apt/trusted.gpg`, `trusted.gpg.d`, `keyrings` | Signing keys (legacy monolithic keyring, and custom keys). |
| `apt list --upgradable` | Version drift. |

## The tree

Direct roots are the manually-installed packages (`apt-mark showmanual`); edges
come from `Depends` + `Pre-Depends` (version constraints, `:arch` qualifiers, and
`|` alternatives are reduced to a package name).

## Risk signals

| Signal | Severity | Meaning |
| --- | --- | --- |
| `third-party-source (host)` | Medium | Installed from a non-official archive (a PPA / custom repo host, or `manual`: a `.deb` with no archive backing the installed version at all). |
| `component (universe / multiverse / non-free …)` | Info | Installed from an official host but a less-curated section: Ubuntu's `universe`/`multiverse`/`restricted` or Debian's `contrib`/`non-free`. |
| `held (upgrades pinned off)` | Low | Held via `apt-mark hold`: excluded from upgrades, so stuck on its current version (security updates included). |
| `foreign-arch (arch)` | Low | Installed solely for a non-native architecture (a pure `i386` package on `amd64`). Ordinary multiarch libraries, which keep a native copy, are not flagged. |
| `install-script (runs code at install)` | Info | Ships a maintainer script (`preinst`/`postinst`/`prerm`/`postrm`). |
| `outdated (installed → current)` | Low | Behind the archive (`apt list --upgradable`). |

> There is no separate `obsolete` signal: a package no longer offered by any
> archive is indistinguishable from a sideloaded vendor `.deb` (both show only
> `/var/lib/dpkg/status` in `apt-cache policy`), so it is reported as
> `third-party-source (manual)` rather than mislabeling every vendor `.deb`.

### Execution & privilege surface

What a package sets up through the files it ships (`/var/lib/dpkg/info/*.list`),
plus dpkg diversions. The first three are contextual (Info, dimmed); a setuid
binary carries a little weight; a diversion is a genuine file-hijack vector.

| Signal | Severity | Meaning |
| --- | --- | --- |
| `installs-service (runs at boot)` | Info | Ships a systemd `.service` unit. |
| `installs-scheduled-task (cron/timer)` | Info | Ships a cron job or a systemd `.timer`. |
| `modifies-auth (sudoers.d/pam)` | Info | Ships a `sudoers.d` drop-in, a `pam.d` config, or a PAM module. |
| `setuid-binary (name)` | Low | Ships a setuid/setgid binary (privilege-escalation surface). Found via one `find /usr /opt -perm /6000` and attributed to its owning package. |
| `dpkg-divert (overrides path)` | Medium | Diverts another package's file in place of its own. The merged-usr (`*.usr-is-merged`) transition and admin-local diversions are excluded. |

### Install-recipe static analysis (third-party packages)

For **third-party** packages (official Debian/Ubuntu maintainer scripts are
review-gated), postmortem runs the same analyzers as [`scan`](Scan) over the
concatenated maintainer scripts (shell), which are what run on your machine at
install/upgrade/removal:

| Signal | Severity | Meaning |
| --- | --- | --- |
| `install-remote-exec (pipe to shell)` | High | Pipes a download into a shell (`curl … \| bash`). |
| `install-ioc (…)` | varies | An IOC (IP / domain / URL) in a script. |
| `install-obfuscation (…)` | varies | Encoded / obfuscated payload. |
| `install-sensitive_api (…)` | varies | A sensitive shell primitive (exec, socket, decode, escalate, persist). |

### Reputation (`--online`)

Each package's `Homepage` resolves to the source repo, pulling the same
stars/age/activity/language signals as [`tree --online`](Online-Resolution).
Official archives mostly point at project sites, so they resolve to *no
repository* (reported as **unchecked**).

## Source trust & integrity

Beyond per-package signals, postmortem surfaces machine-wide trust and integrity
caveats as a gochi alert after loading (they weaken or extend what apt accepts, or
show that installed bytes no longer match the archive):

| Caveat | Source |
| --- | --- |
| `N apt source(s) set [trusted=yes]` | A source with signature verification disabled (`[trusted=yes]` / `Trusted: yes`). |
| `N custom signing key(s) added to the apt keyring` | Keys in `trusted.gpg.d` / `keyrings` that are not the stock Debian/Ubuntu ones. |
| `N apt pin(s) configured` | Pin rules in `/etc/apt/preferences(.d)` that force a version, source, or priority. |
| `N apt source(s) over http` | A source served over `http://`: signatures still verify, but no transport encryption (easier MITM / downgrade, metadata leak). |
| `legacy monolithic keyring … in use` | The deprecated `/etc/apt/trusted.gpg` is present: keys there are trusted for *every* source, not scoped per-repo via `signed-by=`. |
| `N expired signing key(s)` | A key in the apt keyrings whose expiration date has passed (`gpg --show-keys`; skipped when gpg is absent). |
| `N installed file(s) modified since install` | A packaged file whose content no longer matches its recorded md5 (`dpkg --verify`); conffiles, expected to be edited, are excluded. |

## Options

Same as [`system`](System): `--repos`, `--online`, `--depth`, `--json`,
`--no-progress`.
