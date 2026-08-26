# Auto-start (ASEP)

A [`system`](System) backend, and one of the [Windows](Windows) layers. This is
the Autoruns surface: what the machine runs at logon, whether or not a package
owns it.

It **enumerates and scores**. Each entry is resolved to a target, and the target
is what gets judged.

## What is enumerated

| Group | Locations |
| --- | --- |
| Run keys | `Run`, `RunOnce`, `RunOnceEx`, `RunServices`, `RunServicesOnce` — `HKLM`, `HKCU`, and the WOW6432Node view |
| Policy | `Policies\Explorer\Run` (`HKLM` and `HKCU`) |
| Startup folders | The user's and the common one |
| Winlogon | `Userinit`, `Shell`, `System`, `AppSetup`, `Taskman` |
| Legacy | `Windows\Load`, `Windows\Run`, `UserInitMprLogonScript` |

For each entry postmortem records the location, the raw command, the hive, the
resolved target, whether that target exists, and whether the directory holding
it can be written without elevation.

## Resolving the target

Registry commands are not quoted consistently. A quoted path is authoritative;
otherwise the longest leading prefix ending in an executable extension wins,
which is how Windows itself resolves the ambiguity:

```
"C:\Program Files (x86)\...\setup.exe" --on-logon   ->  quoted path + args
C:\Program Files\Thing\run.exe --flag               ->  split at .exe, not at the space
```

Two shapes that a naive resolver gets wrong, both found on a real machine:

- **A bare name is not a dangling entry.** `Shell = explorer.exe` has no path;
  Windows resolves it through `PATH` at run time.
- **`Userinit` is a comma-separated list.** Its trailing comma is not part of a
  path — each element is its own entry.

## Risk signals

| Signal | Severity | Meaning |
| --- | --- | --- |
| `autostart target is missing` | Medium / High | The entry points at a file that is not there. High when the directory is writable. |
| `autostart from a user-writable directory` | Low / High | See below. |
| `autostart command uses <interpreter>` | High | The command line runs something it does not name. |

Signature findings come from [binary trust](Binary-Trust) and apply to the
resolved target — an unsigned binary that runs at every logon is worse than one
that runs when asked.

### Why a writable path is not one severity

An **`HKCU`** entry runs as the very user who can write to that directory, so a
user-writable path crosses no privilege boundary. On a reference machine
OneDrive, Teams and Discord all auto-start from `%LOCALAPPDATA%` by design;
scoring those as highly as a real escalation would drown the signal.

An **`HKLM`** entry runs at machine scope. The same writable directory then
means an unprivileged user decides what runs for everyone — that is `High`.

### Why a missing target matters

A dangling entry is not untidy, it is a standing invitation: whoever can create
that file inherits the auto-start. When the directory is also writable the two
facts compound, so the finding is raised to `High`.

### Interpreters in the command line

`powershell -enc`, `mshta`, `wscript`/`cscript`, `rundll32`, `regsvr32`,
`certutil`, `bitsadmin`, an inline `curl`, `Invoke-Expression`,
`DownloadString`, `FromBase64String`. One finding per entry — the command is the
subject, not each token it contains.

## Winlogon

These hooks run before the desktop does, and Windows ships exactly one value for
each. A value that is not the shipped one is reported as a caveat rather than
merely listed. The trailing comma on `Userinit` is present or absent depending
on the build and means the same thing either way.

## Not covered yet

This page covers the **logon registry and Startup folders**.
[Scheduled tasks](Scheduled-Tasks), [services and drivers](Services) and
[jobs and file-based persistence](Jobs) have their own pages. WMI subscriptions
and COM hijacks are not enumerated yet.
