# WinGet

A [`system`](System) backend, and one of the five [Windows](Windows) layers.
Reads WinGet's configured sources, its installed table, and the admin settings
that govern how much it verifies.

## Data sources

| Command | Used for |
| --- | --- |
| `winget source export` | Configured sources as **JSON lines** (name, URL, type, trust level). |
| `winget list --disable-interactivity` | The installed table across every layer WinGet sees. |
| `winget --info` | The admin settings that weaken verification. |

`winget export` is deliberately **not** used. It silently drops every package it
cannot resolve to a source - which is exactly the set worth looking at:

```
Installed package is not available from any source: NVIDIA Control Panel
```

## Reading the installed table

`winget list` has no machine-readable output, so the table is parsed from its own
header on every run (WinGet sizes columns to their content, so the offsets are
not constant). Two rules matter:

- **Slicing is by character, not byte.** A localized `Name` column is multi-byte
  in UTF-8, and byte offsets cut the following `Id` in half.
- **The `Name` column is never an identity.** It is localized - a French machine
  reports `Bloc-notes Windows`. `Id` is stable.

The `Id` prefix says which layer an entry came from:

| `Id` shape | Layer |
| --- | --- |
| `Microsoft.AppInstaller` | A package WinGet resolves to one of its sources. |
| `MSIX\...` | An MSIX/AppX package. |
| `ARP\Machine\...` | A registry Uninstall entry, machine scope. |
| `ARP\User\...` | A registry Uninstall entry, per-user scope. |

## Risk signals

| Signal | Severity | Meaning |
| --- | --- | --- |
| `unmanaged-by-winget` | Info | WinGet does not govern this entry (MSIX or registry). |
| `user-scope install (writable without elevation)` | Low | Installed under `ARP\User`. |
| `outdated (installed → current)` | Low | WinGet's `Available` column reports a newer release. |

> `unmanaged-by-winget` is **Info at 0 points on purpose**. On a stock machine
> 53 of 88 entries are MSIX or registry entries that WinGet was never going to
> manage; scoring that would light up two thirds of every scan and mean nothing.
> A genuine shadow install - a package WinGet *knows* that was installed around
> it - needs cross-referencing, which [Add/Remove Programs](Add-Remove-Programs)
> does.

## Source trust

`--repos` lists the configured sources. A source is judged on its **trust level
and URL host**, never on its name:

```json
{"Name":"winget","Type":"Microsoft.PreIndexed.Package","TrustLevel":["Trusted","StoreOrigin"]}
```

> A stock Windows ships **three** Microsoft sources, not two: `winget`,
> `msstore` and `winget-font`. An allowlist of the first two reports a
> third-party source on a clean install.

A source outside Microsoft's is surfaced as a caveat, with its type explained -
a custom `Microsoft.PreIndexed.Package` outranks a custom REST source, because
its MSIX index is signed by a certificate somebody made this machine trust.

## Admin settings

`winget --info` reports the settings that trade away a guarantee. Each is
reported as a caveat when enabled:

| Setting | Severity | What it costs |
| --- | --- | --- |
| `InstallerHashOverride` | Critical | The SHA256 in a manifest stops being binding. |
| `LocalManifestFiles` | High | Packages installable from arbitrary local manifests. |
| `BypassCertificatePinningForMicrosoftStore` | High | Store traffic is open to interception. |
| `LocalArchiveMalwareScanOverride` | High | The malware scan on local archives can be skipped. |
| `ConfigurationProcessorPath` | High | A custom configuration processor loads from an arbitrary path. |
| `ProxyCommandLineOptions` | Medium | A per-invocation proxy can redirect where installers are fetched from. |

The Group Policy key (`HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller`)
is absent on an unmanaged machine; both cases are handled.

## Not covered yet

Manifest SHA256 verification, `InstallerType`, and `InstallerUrl` domain checks
need the manifest itself - that is `inspect --deep` territory. Per-package
community-vs-Store provenance and `winget pin` are not read.
