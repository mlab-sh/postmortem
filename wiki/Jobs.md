# Jobs & file-based persistence

A [`system`](System) backend, and one of the [Windows](Windows) layers.

Unlike [services](Services) and [scheduled tasks](Scheduled-Tasks), where the
problem is volume, **every location here is empty or default on a healthy
machine**. That makes them high-signal: on a reference Windows 11 box, BITS held
no jobs, `WER\LocalDumps` did not exist, `RunOnce\Setup` did not exist, and none
of the 36 `Image File Execution Options` subkeys carried a debugger.

## What is read

| Location | Finding |
| --- | --- |
| `Image File Execution Options` | `Debugger`, `MonitorProcess`, `VerifierDlls`, `GlobalFlag` |
| `SilentProcessExit` | `MonitorProcess` |
| `AeDebug` | A custom debugger attached to every process crash |
| `WER\LocalDumps` | Crash-dump collection redirected |
| `RunOnce\Setup` | A setup command queued for next logon |
| `%WINDIR%\Setup\Scripts` | Scripts that run as SYSTEM before the first session |
| `unattend.xml` | `<CommandLine>` elements — first-logon commands |
| BITS | Transfer jobs that persist across reboots |
| `%WINDIR%\Provisioning\Packages` | Third-party `.ppkg` |

## Two things this gets right on purpose

### An IFEO subkey is not a finding

Windows ships **36** of them. The subkey means nothing; the *values* do. Only
`Debugger`, `MonitorProcess`, `VerifierDlls` and `GlobalFlag` are read, and each
carries its own weight — a `Debugger` redirects every launch of that image and
is `Critical`, a `GlobalFlag` merely enables instrumentation and is `Medium`.

### Provisioning packages are judged on their signature

A reference machine carries **21**, all Windows' own. An earlier version of this
matched their file names — built from the first four it happened to see, which
missed the entire `Power.Settings.*` family and reported twelve Microsoft
packages as third-party.

They are all Authenticode-signed by Microsoft, so that is what decides. No name
list keeps up with a different Windows build.

## Answer files and credentials

`unattend.xml` routinely carries a plaintext local administrator password.
This backend extracts `<CommandLine>` elements and **nothing else** — no
credential element is ever read, quoted, or reported.

## Word boundaries matter

An interpreter in any of these locations raises the finding to `Critical`. The
match is on **word boundaries**, not substrings: `iex` occurs inside
`PCIExpress`, which is how a Windows provisioning package came to be reported as
running `Invoke-Expression`. An edge is only guarded where the pattern carries a
word character there, so `curl ` — which ends in a space — still matches
`cmd /c curl http://…`.

This rule is shared with [auto-start](Autostart) and
[scheduled tasks](Scheduled-Tasks).

## Not covered yet

`Image File Execution Options` under the WOW6432Node view, COM-based BITS job
enumeration (the PowerShell cmdlet is used), and the contents of a `.ppkg` —
a third-party package is reported, but what it applies is not read.
