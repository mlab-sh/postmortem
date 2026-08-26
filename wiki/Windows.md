# Windows

Windows is the one platform where `system` does **not** pick a single manager.
A Linux box has one distro manager; a Windows machine has several layers that
coexist and overlap, and reading only one of them describes a slice of the
machine while implying it covered all of it.

So on Windows, [`system`](System) reads **every** layer it can and merges them
into one forest. `--manager <name>` narrows it to one.

| Layer | Page | What it covers |
| --- | --- | --- |
| WinGet | [WinGet](WinGet) | Microsoft's package manager, its sources and admin policy. |
| MSIX / AppX | [MSIX](MSIX) | Store and sideloaded app packages, their signing and capabilities. |
| Chocolatey | [Chocolatey](Chocolatey) | Install posture, sources, config drift, install scripts. |
| Scoop | [Scoop](Scoop) | Git buckets, per-manifest hashes, install hooks. |
| Add/Remove Programs | [Add/Remove Programs](Add-Remove-Programs) | Everything the registry records — including what no manager claims. |
| Auto-start | [Auto-start (ASEP)](Autostart) | What the machine runs at logon, package-owned or not. |
| Scheduled tasks | [Scheduled tasks](Scheduled-Tasks) | What the machine runs on a trigger. |
| Services & drivers | [Services & drivers](Services) | What the machine runs before anyone logs in. |
| Jobs & file-based | [Jobs & file-based](Jobs) | Image hijacks, setup scripts, BITS jobs, answer files. |

Every binary those layers install is then checked against
[binary trust](Binary-Trust).

## Why all of them

WinGet reports a slice of Add/Remove Programs, not all of it: on a reference
machine it surfaced **15** ARP entries against **163** in the registry. A scan
that stopped at WinGet would have called that machine covered.

The layers also overlap: the same application can appear as a WinGet package, an
MSIX package and a registry entry. Merging is what lets postmortem tell "managed
by something" from "installed by someone".

## Reading the merged forest

Each package keeps its own ecosystem (`winget`, `msix`, `choco`, `scoop`, `arp`),
so a name present in two managers stays two packages with two sets of findings.
A summary line counts what no manager governs:

```
 53  unmanaged   present on the machine, not installed through this manager
```

That line is a count, not a verdict — see [Add/Remove Programs](Add-Remove-Programs)
for what "unclaimed" actually means and why most of it is normal.

## A layer that cannot be read

If one layer fails while others succeed, the scan continues and says so:

```
(@_@)  1 trust caveat(s) - review before trusting this inventory
- msix could not be read: powershell failed
```

An incomplete machine view is stated, never implied. With `--manager` naming a
single layer, that layer's failure is the command's failure instead.

## Flat by nature

Every Windows layer produces a **flat** forest (`depth 1`). None of these
managers publishes a dependency graph the way Homebrew or apk do, so there are
no transitive edges to walk — the tree is the installed set.
