# Privilege posture & trust policy

A [`system`](System) backend, and one of the [Windows](Windows) layers.

Windows has no setuid. Its privilege primitives are the **DACL**, the **token**,
and **auto-elevation** — so this layer reads the machine's own configuration
rather than any package.

Each check is a node of its own.

## A default is not a decision

One principle runs through the scoring, and without it the layer would be
useless: **hardening that was never turned on is a gap; a protection somebody
switched off is a finding.**

Credential Guard is unconfigured on very nearly every consumer machine. Reporting
that at the same weight as a disabled UAC would bury the thing that matters.

| State | Weight |
| --- | --- |
| Never configured | `Low` / `Info` |
| Present and set to a weakening value | `Medium` → `Critical` |

## Checks

| Check | Finding | Severity |
| --- | --- | --- |
| `AlwaysInstallElevated` (HKLM **and** HKCU) | Any MSI installs as SYSTEM | Critical |
| `EnableLUA = 0` | UAC switched off entirely | Critical |
| `ConsentPromptBehaviorAdmin = 0` | Administrators elevate with no prompt | High |
| `LocalAccountTokenFilterPolicy = 1` | Remote UAC filtering disabled | High |
| `FilterAdministratorToken = 0` | Built-in Administrator exempt from UAC | Medium |
| `WDigest UseLogonCredential = 1` | Plaintext credentials back in memory | High |
| `RunAsPPL` not enabled | LSA Protection absent | Low / Medium |
| `LsaCfgFlags` not enabled | Credential Guard not configured | Info |
| A user-writable directory on the machine `PATH` | Hijacks every bare command name | High |
| A `Program Files` subdirectory writable without elevation | Tamper, then persistence | High |
| The global Scoop root writable | Critical |

### Two checks that only mean something in context

**`AlwaysInstallElevated`** needs *both* hives set to work at all, so the pair is
what is reported — one half alone is a misconfiguration, not a working
escalation.

**`FilterAdministratorToken`** only matters while the built-in Administrator can
log in. That account is disabled by default, so the check first reads whether it
is enabled; otherwise the exemption is moot and nothing is reported.

## What this finds on a stock machine

One thing, and it is real:

```
C:\Program Files (x86)\Steam is writable without elevation
  (BUILTIN\Users: FullControl)
```

Steam grants every user full control of its own install directory, and it
[auto-starts](Autostart). Anyone able to log in can replace what it runs.

Everything else on the reference machine sits at its default — `EnableLUA=1`,
`RunAsPPL=2`, WDigest unset, no `AlwaysInstallElevated`, and no user-writable
directory anywhere on the machine `PATH`.

## Policy that weakens trust

The same layer reads the configuration that decides how much verification the
machine still does. The scoring principle above is what makes this section
usable rather than a wall of red on every consumer machine.

| Reading | Finding | Severity |
| --- | --- | --- |
| Defender real-time protection off | | Critical |
| Defender tamper protection off | Its own settings can be rewritten | High |
| A **broad** Defender exclusion | A drive root, a profile root, `Downloads`, a package manager's directory | High |
| A narrow Defender exclusion | One program or file | Medium |
| Secure Boot disabled **on UEFI firmware** | | High |
| Test signing enabled | Unsigned drivers load | High |
| Memory integrity (HVCI) not running | Not enabled by default on all hardware | Low |
| Machine execution policy `Unrestricted` / `Bypass` | | High |
| SmartScreen switched off | | Medium |
| Application-control policy in **audit** mode | It logs, it does not block | Low |
| No WDAC or AppLocker policy | postmortem cannot know if this machine was meant to be gated | Info |
| Script block logging / transcription off | Missing evidence, not a weakened protection | Info |
| Controlled Folder Access off | | Info |

### Two readings that would otherwise mislead

**Secure Boot** reads the firmware type first. `Confirm-SecureBootUEFI` returns
false on legacy BIOS too — that is a different machine, not a weakened one, so
only `UEFISecureBootEnabled = 0` on UEFI firmware is reported.

**Defender exclusions** are counted after filtering: `@($null).Count` is 1 in
PowerShell, so an empty exclusion list reports one of each unless the empty
entries are dropped first. A machine with no exclusions must say zero.

Developer mode and MSIX sideloading are read by [MSIX](MSIX); Store certificate
pinning by [WinGet](WinGet); the per-user PowerShell execution policy by
[Scoop](Scoop).

## Firmware & boot

Info by design: a machine without a TPM, or with BitLocker off, is a
configuration rather than a compromise.

| Reading | Severity |
| --- | --- |
| No TPM present or ready | Info |
| BitLocker not protecting the system volume | Info |
| Kernel DMA protection not running | Info |
| Boot manager outside the Microsoft path | Medium |
| `nointegritychecks` / `disableintegritychecks` set | High |

### The one combination that is Critical

Test signing on its own is a developer machine. A third-party driver on its own
is ordinary. **Together** they mean the machine will load kernel code nobody
vouched for — so when the boot flags are loosened *and* a driver starts from
outside `System32`, that driver is raised to `Critical`.

That check runs after every layer is read, because the boot flag comes from here
and the drivers from [services](Services); neither can see it alone.

## Not covered yet

Service token privileges (`SeDebug`, `SeImpersonate`, `SeLoadDriver`, `SeTcb`
held by non-Microsoft services), auto-elevate manifests
(`requestedExecutionLevel` + `autoElevate` outside Microsoft), and weak service
security descriptors — the last needs SDDL parsing, so a service an ordinary
user can reconfigure or restart is still not detected. Related checks that *are*
implemented live in [services](Services) and [Chocolatey](Chocolatey).
