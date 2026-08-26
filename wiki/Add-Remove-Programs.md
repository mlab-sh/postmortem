# Add/Remove Programs

A [`system`](System) backend, and one of the five [Windows](Windows) layers.
This is the layer that answers "what is installed that **no** package manager
claims" - without it, a Windows scan describes the packages a manager happens to
know and implies the machine is covered.

On a reference machine, WinGet surfaced **15** Add/Remove entries against
**163** in the registry.

## Data sources

| Source | Used for |
| --- | --- |
| `HKLM\...\Uninstall\*` | Machine-scope entries. |
| `HKLM\SOFTWARE\WOW6432Node\...\Uninstall\*` | 32-bit registry view. |
| `HKCU\...\Uninstall\*` | Per-user entries. |
| `%LOCALAPPDATA%\Apps\2.0` | Whether ClickOnce deployments exist. |

> `Win32_Product` is deliberately never used: it is slow, and querying it
> triggers an MSI self-repair on every package it touches. The registry holds
> the same data with no side effects.

## Risk signals

| Signal | Severity | Meaning |
| --- | --- | --- |
| `unclaimed (no package manager reports this install)` | Medium | No other layer accounts for this entry. |
| `user-scope install (writable without elevation)` | Low | Recorded under `HKCU`. |
| `no publisher recorded` | Low | The installer left nothing to attribute it to. |
| `hidden-from-add-remove (SystemComponent)` | Info | Hidden from Add/Remove Programs by design. |

### Why hidden components are never orphans

**130 of the 163 entries carry `SystemComponent=1`** - runtimes,
redistributables and driver pieces that Windows deliberately hides. Only 33 are
user-visible. Treating hidden entries as orphan candidates would make the
finding 90% of the machine.

They are labelled rather than dropped, because setting `SystemComponent` is also
how something hides itself from Add/Remove Programs.

## How "unclaimed" is decided

An entry is compared against every identity the other layers published:

- **The registry key**, when another layer exposes it. WinGet names ARP packages
  `ARP\<scope>\<arch>\<key>`, so the key is an exact join - never a fuzzy match
  on a localized display name.
- **Display-name aliases.** For packages WinGet resolves to its *own* source it
  shows a bare id (`Ubisoft.Connect`) and never reveals the registry key it
  covers, so each layer also publishes the display names it knows. Localization
  is safe here: the registry on the same machine is localized identically.

Without the alias, `Ubisoft Connect` and `Visual Studio Build Tools 2022` read
as unclaimed while WinGet was actively managing them.

### Nothing is pronounced orphaned alone

Running `--manager arp` on its own reads every entry as an orphan by
construction - there is nothing to compare against. That is an artefact of the
question not being asked, so the pass abstains and says why:

```
- no package manager layer was read alongside Add/Remove Programs, so nothing
  could be cross-referenced - this view cannot tell managed installs from
  orphaned ones
```

## Not covered yet

Portable executables on `PATH` or the Desktop, and Store-vs-Win32 duplicate
detection, are not implemented.
