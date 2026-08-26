# Scheduled tasks

A [`system`](System) backend, and one of the [Windows](Windows) layers. The
other half of the persistence surface, beside [auto-start](Autostart).

## The problem of scale

A stock Windows 11 machine has **252 scheduled tasks, 243 of them under
`\Microsoft\`**. Scoring a task for running as SYSTEM (154 of 252) or elevated
(91 of 252) would describe Windows, not a threat.

So privilege is scored **in combination**, never alone. The folder is the
provenance signal the surface actually offers — only **9** tasks sat outside
`\Microsoft\` on the reference machine.

## Data sources

| Source | Used for |
| --- | --- |
| `Get-ScheduledTask` | Folder, principal, run level, triggers, action. |
| `C:\Windows\System32\Tasks\**` | The definition file, and its ACL. |
| `…\Schedule\TaskCache\Tasks` | What the scheduler service actually reads. |

## Risk signals

| Signal | Severity | Meaning |
| --- | --- | --- |
| `task definition is writable without elevation` | High / Critical | Whoever can rewrite the definition owns what it runs. Critical when the task runs privileged. |
| `third-party task runs privileged at <trigger>` | Medium | Outside `\Microsoft\`, privileged, and fires on its own. |
| `task action target is missing` | Medium / High | The action points at a file that is not there. |
| `task command uses <interpreter>` | Info / High | `rundll32`, `mshta`, encoded PowerShell… Info for Windows' own tasks — 22 of them drive `rundll32` — and High for anyone else's. |
| `third-party task runs a COM handler` | Low | No executable to verify. 155 of 252 tasks use one, so it is only surfaced outside `\Microsoft\`. |

### The folder attests registration, not execution

A task under `\Microsoft\Windows\Application Experience\` whose action was
repointed at somebody else's binary is a documented hijack — and the folder rule
above would excuse it. So when a Windows-registered task runs something from
**outside the Windows directory**, the folder stops vouching for it: the entry is
surfaced and its target is signature-verified.

Measured before choosing that rule: **7** of the machine's own tasks legitimately
do this — Defender's platform under `%ProgramData%`, Windows Media Player. So it
is context at `Info`, never a finding on its own; the signature is what decides.

### Hidden tasks

A task present in the scheduler's registry cache but absent from the task
listing runs without being visible. Both sides held 252 entries on the reference
machine, so this correctly found nothing there.

### Who counts as an unprivileged writer

Deciding this by listing *privileged* principals does not work — it reported 48
stock Windows tasks as writable. Task files legitimately grant `FullControl` to:

- the service that owns them (`NT SERVICE\CryptSvc`, `LOCAL SERVICE`),
- a **virtual task account** Windows creates per task (`NT TASK\<task name>`),
- and a **raw, unresolvable SID** inherited from the image the machine was built
  from (`S-1-5-21-…-500`, another machine's built-in Administrator).

So unprivileged writers are identified **positively**: `Everyone`,
`BUILTIN\Users`, `Authenticated Users`, `INTERACTIVE`, or a named account. An
unresolvable SID is *unknown*, and unknown is not asserted to be a person.

The rights matter too: `WriteAttributes` is not the ability to replace a file,
and matching the substring `Write` treated it as though it were.

## What this finds on a stock machine

Roughly twenty of Windows' own tasks ship with a definition file writable by
`Authenticated Users` or `BUILTIN\Users` — the `\Microsoft\Windows\input\*`
family, `Printing\PrintJobCleanupTask`, `Application Experience\MareBackup`
among them. Several of those run at `RunLevel=Highest` or as `SYSTEM`.

These are **not false positives**: a task that runs elevated whose definition
any authenticated user can rewrite is a local privilege-escalation primitive.
They are reported as found.

## Not covered yet

Task SDDL is approximated by the definition file's ACL, which has the same
consequence. COM handler CLSIDs are reported but not resolved to their
`InprocServer32` DLL, so those actions carry no signature verification.
