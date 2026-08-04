# DNF (Fedora / RHEL)

A [`system`](System) backend, alongside [Homebrew](Homebrew), [Pacman](Pacman),
and [APT](Apt). Reads what `rpm`/`dnf` has installed and audits it with the same
`risk:dep` model as [`tree`](Tree). Selected automatically when `dnf` is the
available manager.

## Data sources

| Command | Used for |
| --- | --- |
| `rpm -qa --qf ...` | Every installed package in one call: name, version, url, vendor. |
| `rpm -qa [%{PROVIDENAME}]` / `[%{REQUIRENAME}]` | The capability graph, resolved into dependency edges. |
| `dnf repoquery --userinstalled` | The user-installed (direct) set. |
| `dnf repoquery --installed %{from_repo}` | The origin repo per package (authoritative provenance where known). |
| `rpm -qa [%{FILENAMES}]` | The files each package ships (services / timers / auth config / setuid attribution). |
| `find /usr /opt -perm /6000` | Setuid / setgid binaries. |
| `rpm -qa %|PREIN?...|` | Which packages ship an install scriptlet (presence only, no bodies). |
| `rpm -q %{PREIN}...` | A third-party package's scriptlet bodies, for static analysis. |
| `rpm -qa %|RSAHEADER?...|` | Header-signature presence (unsigned detection). |
| `rpm -Va` | Installed files whose content no longer matches (digest). |
| `/etc/yum.repos.d/*.repo` | Configured repos (enabled ones, and `gpgcheck=0` / `http://`). |
| `dnf check-update` | Version drift (best-effort, needs metadata). |

## The tree

Direct roots are the user-installed packages (`dnf repoquery --userinstalled`;
if dnf is unavailable every package is treated as direct). Edges come from the
**RPM capability graph**: each package's `Requires` are resolved through a
`capability -> providing package` map built from every package's `Provides`
(which covers package names, sonames, and standard-path files). Build-time
`rpmlib(...)` pseudo-capabilities and self-edges are dropped.

## Risk signals

| Signal | Severity | Meaning |
| --- | --- | --- |
| `third-party-source (repo / vendor)` | Medium | Not from a distribution repo. The origin repo is authoritative when known (so a **copr** / **rpmfusion** build flags even though it keeps a `Fedora Project` vendor); otherwise the vendor decides (a non-distro vendor, or `local .rpm` for an empty vendor / a sideloaded package). |
| `unsigned` | High | No header signature. Suppressed when almost every package is unsigned (an image built with `--nogpgcheck`), so it only fires as the exception. |
| `install-script (runs code at install)` | Info | Ships an rpm scriptlet (`%pre`/`%post`/`%preun`/`%postun`). |
| `outdated (installed -> current)` | Low | Behind the repos (`dnf check-update`). |

### Execution & privilege surface

The same file-derived signals as the [apt backend](Apt), from each package's
`FILENAMES`: a systemd `.service` (`installs-service`, Info), a cron job or
`.timer` (`installs-scheduled-task`, Info), a `sudoers.d` / `pam.d` / PAM module
(`modifies-auth`, Info), and a setuid/setgid binary (`setuid-binary (name)`, Low,
found via one `find /usr /opt -perm /6000` and attributed to its owner).

### Install-recipe static analysis (third-party packages)

For **third-party** packages (distribution scriptlets are review-gated),
postmortem runs the same analyzers as [`scan`](Scan) over the concatenated
scriptlet bodies (shell), which are what run on your machine at
install/upgrade/erase:

| Signal | Severity | Meaning |
| --- | --- | --- |
| `install-remote-exec (pipe to shell)` | High | Pipes a download into a shell (`curl ... \| bash`). |
| `install-ioc (...)` | varies | An IOC (IP / domain / URL) in a scriptlet. |
| `install-obfuscation (...)` | varies | Encoded / obfuscated payload. |
| `install-sensitive_api (...)` | varies | A sensitive shell primitive (exec, socket, decode, escalate, persist). |

### Reputation (`--online`)

Each package's `URL` (homepage) resolves to the source repo, pulling the same
stars/age/activity/language signals as [`tree --online`](Online-Resolution).
Distribution packages mostly point at project sites, so they resolve to *no
repository* (reported as **unchecked**).

## Source trust & integrity

Machine-wide caveats surfaced as a gochi alert after loading:

| Caveat | Source |
| --- | --- |
| `N dnf repo(s) with gpgcheck=0` | An enabled repo with signature checking disabled (the analog of apt's `[trusted=yes]`). |
| `N dnf repo(s) over http` | An enabled repo whose `baseurl` / `metalink` / `mirrorlist` is plain `http://`. |
| `N installed file(s) modified since install` | A packaged file whose content no longer matches the rpm database (`rpm -Va` digest mismatch); config / doc / ghost files are excluded. |

## Options

Same as [`system`](System): `--repos`, `--online`, `--depth`, `--json`,
`--no-progress`.
