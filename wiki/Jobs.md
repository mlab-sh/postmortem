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
| `AppCompatFlags\InstalledSDB` / `Custom` | A custom application-compatibility shim database |
| Printer drivers | A driver loaded by the spooler from outside the driver store |
| Windows Terminal `settings.json` | A profile carrying its own command line (Info) |

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

## Shim databases and printer drivers

An application-compatibility **shim database** rewrites how a process starts —
the original in-memory patching mechanism, and still a persistence one. Both
`InstalledSDB` and `Custom` are empty on a healthy machine, which is exactly
what makes them worth reading.

The **spooler** loads printer drivers into a process running as SYSTEM. All six
drivers on the reference machine sit in the protected driver store; one outside
it is the PrintNightmare shape, and only those are emitted.

A **Windows Terminal profile** can carry its own command line, but it only runs
when somebody opens that profile — recorded at `Info`, scored at nothing, unless
the command line carries an interpreter.

## Not covered yet

`Image File Execution Options` under the WOW6432Node view, COM-based BITS job
enumeration (the PowerShell cmdlet is used), and the contents of a `.ppkg` —
a third-party package is reported, but what it applies is not read.

Docker Desktop and WSL boot commands are not read: `wsl.exe` starting at logon
already appears in [auto-start](Autostart), and `/etc/wsl.conf` lives inside a
distribution's own filesystem. Hyper-V and VMware plugin directories are not
enumerated. PowerToys and AutoHotkey scripts appear as Run keys or Startup
entries and are covered by [auto-start](Autostart); the same goes for Run keys
pushed by MDM enrolment.
