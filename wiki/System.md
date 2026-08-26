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

Recognized: `brew`, `apt`, `dpkg`, `pacman`, `dnf`, `rpm`, `nix`, `apk`, `port`,
and on Windows `winget`, `msix`, `choco`, `scoop`, `arp`, `asep`, `task`, `service`. If no **supported**
manager is found, it exits `2`.

On Windows, executables are resolved through `PATHEXT` - what sits on disk is
`winget.exe`, never `winget`.

### One manager, or all of them

A Linux box has a single distro manager, so `system` audits the first supported
one it finds. **Windows layers coexist** - WinGet, MSIX, Chocolatey, Scoop and
the registry all describe the same machine - so there `system` reads every layer
it can and merges them into one forest. See [Windows](Windows).

`--manager <name>` pins the audit to a single manager on any platform. An
unknown name, or one detected but unusable, exits `2`.

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
| WinGet | supported | [WinGet](WinGet) |
| MSIX / AppX | supported | [MSIX](MSIX) |
| Chocolatey | supported | [Chocolatey](Chocolatey) |
| Scoop | supported | [Scoop](Scoop) |
| Add/Remove Programs | supported | [Add/Remove Programs](Add-Remove-Programs) |
| Auto-start (ASEP) | supported | [Auto-start](Autostart) |
| Scheduled tasks | supported | [Scheduled tasks](Scheduled-Tasks) |
| Services & drivers | supported | [Services](Services) |
| macports | planned | (roadmap) |

## Common options

| Flag | Description |
| --- | --- |
| `--repos` | List the configured source repos and exit. |
| `--online` | Resolve each package to its source repo + reputation (network). |
| `--languages` | With `--online`, add the repo language breakdown. |
| `--vulns` | Scan installed packages for known vulnerabilities (network). |
| `--release <id:ver>` | Override the detected OS release for the vuln lookup (e.g. `debian:12`). |
| `--depth <N>` | Limit tree depth. |
| `--json` | Emit the resolved forest as JSON. |
| `--manager <name>` | Audit this manager instead of the detected default. |
| `--no-signatures` | Skip [binary trust](Binary-Trust) verification (Windows). |
| `--no-progress` | Disable the animated progress UI. |

The output reuses the [`tree`](Tree) model: a forest with `(risk:dep)` scores,
inline signals, a flagged summary, and the gochi recap. See the per-manager page
for the signals that manager can raise.

## Known vulnerabilities (`--vulns`)

`system --vulns` cross-references every installed package against public
advisory data and lists the affected packages with their CVE/advisory ids,
worst-severity-first. Coverage is per backend:

| Backend | Source | Notes |
| --- | --- | --- |
| apt (Debian/Ubuntu) | OSV via `vuln.mlab.sh` | needs the OS release (auto from `/etc/os-release`) |
| apk (Alpine) | OSV via `vuln.mlab.sh` | |
| dnf (Rocky/AlmaLinux) | OSV via `vuln.mlab.sh` | Fedora/RHEL not in OSV — see below |
| pacman (Arch) | Arch Security Tracker | separate source (Arch isn't in OSV) |
| brew, Nix | — | no advisory feed; reported as **un-scanned**, never "clean" |

The **release** matters: OSV keys distro advisories on the release
(`Debian:12`, `Alpine:v3.19`, …), read from `/etc/os-release`. Pass
`--release debian:12` to override it — useful when scanning an image whose
os-release isn't this machine's. **RHEL** users can approximate with
`--release almalinux:9` / `rocky:9` (binary-compatible). A backend OSV can't
scan emits an honest *diagnostic* ("packages were not scanned"), not a silent
zero.

```bash
postmortem system --vulns
postmortem system --vulns --release debian:12   # cross-scan / override
```

## CI gate

`system` accepts the same threshold flags as [`tree`](CI-Gate) and exits
non-zero when they trip, so a server audit can gate a pipeline:

| Flag | Trips (exit 1) when… |
| --- | --- |
| `--max-vulns <N>` | more than N known vulnerabilities are present (needs `--vulns`) |
| `--fail-on-vuln <sev>` | any vulnerability is at least this severe (needs `--vulns`) |
| `--max-risk` / `--max-dep` | the worst risk / dep score exceeds N |
| `--max-high` / `--max-sus` | more than N high-risk / suspicious packages |
| `--allow <pkg>` / `--config <file>` | allowlist packages / load a `[gate]` policy |

**Fail-closed:** a vuln gate over a backend OSV can't scan (brew/Nix,
Fedora/RHEL) or a scan that errored is *inconclusive* — it exits `2`, never a
silent pass. `0` = clean, `1` = tripped, `2` = inconclusive/misconfigured.

```bash
postmortem system --vulns --fail-on-vuln high --max-vulns 0
```
