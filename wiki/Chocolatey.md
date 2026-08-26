# Chocolatey

A [`system`](System) backend, and one of the five [Windows](Windows) layers.

Chocolatey is the closest Windows gets to the AUR: **a package is a PowerShell
script** that downloads a binary from somewhere else, usually elevated. So this
backend audits two things - the machine's Chocolatey installation itself, and
the code each package runs.

## Data sources

| Source | Used for |
| --- | --- |
| `<root>\config\chocolatey.config` | Sources, features and settings - one ~9 KB file. |
| `choco list --limit-output` | Installed packages (`name\|version`). |
| `<root>\lib\<pkg>\**\chocolatey*.ps1` | The install code, statically analyzed. |
| `<root>\lib\<pkg>\**` | Installed binaries, for [binary trust](Binary-Trust). |
| ACLs + `Get-AuthenticodeSignature` | Who can write to the install root, and whether `choco.exe` is genuine. |

> Chocolatey's CLI is .NET and costs ~1.4-1.8s **per invocation**. Reading the
> config file it writes replaces three of the four calls and takes the backend
> from 7.6s to 3.0s. `choco list` stays: `lib\chocolatey\` holds only a
> `.nupkg`, so the manager's own version is not recoverable without opening a
> ZIP. If the config file cannot be read, the CLI is used as a fallback.

## Install posture

Reported as caveats - none of it belongs to a single package:

| Caveat | Severity | Meaning |
| --- | --- | --- |
| Install root is not `C:\ProgramData\chocolatey` | Critical | Historically these were paths unprivileged users could write, turning every elevated install into their code. |
| Root or `bin\` writable by a non-privileged identity | Critical | Anyone in that group can replace what Chocolatey runs elevated. |
| `choco.exe` signature is not `Valid` | High | The manager binary itself is not the one Chocolatey signed. |
| `cacheLocation` redirected | Info | Downloads land there before installation, so its permissions matter as much as Chocolatey's. |

## Features

Feature drift is judged against the values Chocolatey ships:

| Feature | Safe value | Severity if changed | What it costs |
| --- | --- | --- | --- |
| `checksumFiles` | enabled | Critical | Downloaded files are no longer checksummed. |
| `allowEmptyChecksums` | disabled | High | Packages may ship no checksum at all, plain HTTP included. |
| `allowGlobalConfirmation` | disabled | Medium | A package's prompts are auto-accepted. |
| `useRememberedArgumentsForUpgrades` | disabled | Medium | Upgrades silently replay the original install's arguments. |

Each caveat says whether the value was **set explicitly** or merely **differs
from the shipped default** - a distinction only the config file exposes, and the
difference between deliberately weakened and drifted.

> `virusCheck` is never reported. It is a licensed (Pro) feature, always
> disabled on an open-source install, so flagging it would fire on every free
> Chocolatey in existence.
>
> `allowEmptyChecksumsSecure` is **enabled by default** and is not drift.

## Sources

`--repos` lists the configured feeds. A source is judged on its **URL**, not its
name - a feed calling itself `chocolatey` while pointing elsewhere is exactly
what this catches. A feed ordered ahead of the community one is called out
separately: it can shadow a community package by name. Disabled sources are not
reported; they cannot serve anything.

## Install scripts

A Chocolatey package ships a recipe, not a binary. Every `chocolatey*.ps1` a
package installs - install, `chocolateyBeforeModify`, uninstall - is
concatenated and analyzed as PowerShell (see
[source-code scanning](Source-Code-Scanning)). Filenames are matched
case-insensitively: both `chocolateyInstall.ps1` and `chocolateyinstall.ps1`
occur in the wild.

| Signal | Severity | Meaning |
| --- | --- | --- |
| `install-script (runs code at install)` | Info | The package runs code at install time. |
| `download-without-checksum` | High | The script fetches a URL with no checksum beside it, so a substitution cannot be noticed. |
| `install-remote-exec (pipe to shell)` | High | Pipes a download straight into an interpreter. |
| `install-ioc` / `install-obfuscation` / `install-sensitive_api` | varies | See [source-code scanning](Source-Code-Scanning). |

## Options

Same as [`system`](System), plus `--no-signatures` to skip
[binary trust](Binary-Trust) verification.
