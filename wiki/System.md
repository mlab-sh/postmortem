# `postmortem system`

Audit the machine's **OS-level** package managers. Where `scan` and `tree` read
a project's committed lockfiles, `system` inspects what is actually installed on
*this machine* by shelling out to the package manager.

```bash
postmortem system [options]
```

## Detection

`system` scans `$PATH` for known managers and reports which are present and which
postmortem can actually audit:

```
detected package managers: homebrew
```

Recognized: `brew`, `apt`, `dpkg`, `pacman`, `dnf`, `rpm`, `nix`, `apk`, `port`.
If no **supported** manager is found, it exits `2`.

## Supported managers

Each backend has its own page - the metadata, quirks, and risk signals differ per
manager.

| Manager | Status | Page |
| --- | --- | --- |
| Homebrew | supported | [Homebrew](Homebrew) |
| pacman (+ AUR) | supported | [Pacman](Pacman) |
| apt / dpkg | supported | [APT](Apt) |
| dnf / rpm | supported | [DNF](Dnf) |
| Nix | supported | [Nix](Nix) |
| apk (Alpine) | supported | [apk](Apk) |
| macports | planned | (roadmap) |

## Common options

| Flag | Description |
| --- | --- |
| `--repos` | List the configured source repos and exit. |
| `--online` | Resolve each package to its source repo + reputation (network). |
| `--languages` | With `--online`, add the repo language breakdown. |
| `--depth <N>` | Limit tree depth. |
| `--json` | Emit the resolved forest as JSON. |
| `--no-progress` | Disable the animated progress UI. |

The output reuses the [`tree`](Tree) model: a forest with `(risk:dep)` scores,
inline signals, a flagged summary, and the gochi recap. See the per-manager page
for the signals that manager can raise.
