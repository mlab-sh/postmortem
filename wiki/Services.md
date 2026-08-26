# Services & drivers

A [`system`](System) backend, and one of the [Windows](Windows) layers. What the
machine runs before anyone logs in.

`HKLM\SYSTEM\CurrentControlSet\Services` holds **761 keys** on a stock Windows 11
machine — 404 drivers, and 473 that never start unless something asks.

## Data sources

Read straight from the registry rather than through `Win32_Service`: the
registry preserves `ImagePath` exactly as stored, quotes and all, which is the
whole subject of the main check.

| Value | Used for |
| --- | --- |
| `ImagePath` | The executable and its arguments. |
| `Parameters\ServiceDll` | The DLL behind a svchost-hosted service. |
| `Start` | 0 Boot, 1 System, 2 Auto, 3 Manual, 4 Disabled. |
| `Type` | 1/2/8 drivers, 16/32 Win32 services. |
| `FailureCommand` | The program run when the service fails. |

## Risk signals

| Signal | Severity | Meaning |
| --- | --- | --- |
| `unquoted service path with spaces` | Medium / Critical | See below. |
| `service image is missing` | Medium / High | High when the service starts automatically. |
| `runs a program on failure` | Low | A recovery action that executes something. |
| `service/driver starts automatically from outside System32` | Info | Context for the findings above. |

Signature findings come from [binary trust](Binary-Trust), applied to what
starts on its own from outside `System32` — verifying all 761 would restate that
Windows signs Windows, slowly.

### The unquoted path check

Matching "an unquoted `ImagePath` containing a space" flags **255 of 761**,
nearly all of them:

```
C:\WINDOWS\system32\svchost.exe -k netsvcs -p
```

The space separates the *arguments*. The vulnerability needs a space **inside
the executable path**, so that Windows tries `C:\Program.exe` before the real
target. Read that way the reference machine has exactly **one**:

```
UpcElevationService
  C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher Core\UpcElevationService.exe
```

Whether it is *exploitable* is a second question. postmortem walks every prefix
Windows would try — `C:\Program.exe`, `C:\Program Files (x86)\Ubisoft\Ubisoft.exe`
— and checks whether an ordinary user can create a file in the directory
holding it. If none can, the finding stays `Medium` and says so; if one can, it
is `Critical` and names the directory.

## Deciding who can write

Shared with [auto-start](Autostart) and [scheduled tasks](Scheduled-Tasks), and
subtler than it looks. Three things had to be handled before this stopped
producing nonsense:

- **Service and virtual accounts are not people.** `NT SERVICE\CryptSvc`,
  `LOCAL SERVICE`, and the per-task `NT TASK\<name>` accounts legitimately hold
  `FullControl`. Unprivileged writers are identified positively instead:
  `Everyone`, `BUILTIN\Users`, `Authenticated Users`, `INTERACTIVE`, or a named
  account.
- **Numeric rights masks are decoded.** Windows prints a raw integer when a mask
  has bits outside the `FileSystemRights` enum — `C:\` carries `-536805376`.
  Matching names alone read those as "not writable" without ever looking.
- **Inherit-only ACEs are skipped.** They govern child objects created later,
  never the object itself. That same `C:\` ACE grants `GENERIC_WRITE`
  inherit-only, while the ACE that actually governs `C:\` grants `AppendData` —
  the right to create a *subdirectory*, not a file. Which is precisely why
  `C:\Program.exe` cannot be planted, and why the machine's one unquoted service
  path is not exploitable.

## Not covered yet

Service SDDL (`sc sdshow`) is not read, so a service an ordinary user can
reconfigure or restart is not detected — only one whose *binary* they could
replace. Driver WHQL status and test-signing mode are not checked. `ServiceDll`
is read but not yet verified separately from its svchost host.
