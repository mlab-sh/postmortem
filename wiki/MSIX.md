# MSIX / AppX

A [`system`](System) backend, and one of the five [Windows](Windows) layers.
Covers Microsoft Store and sideloaded app packages: how they are signed, what
they are allowed to do, and whether Windows still considers them intact.

## Data sources

Everything comes from **one** PowerShell invocation - `Get-AppxPackage` joined
with each package's manifest. A stock machine has ~106 packages, and a process
per package would dominate the scan.

| Source | Used for |
| --- | --- |
| `Get-AppxPackage` | Identity, version, publisher, `SignatureKind`, `Status`. |
| `Get-AppxPackageManifest` | Declared capabilities and startup extensions. |
| `HKLM\...\AppModelUnlock` | Whether sideloading or developer mode was turned on. |

## Signing

| Signal | Severity | Meaning |
| --- | --- | --- |
| `unsigned-msix (no signature at all)` | Critical | No signature. |
| `sideloaded (X signature, publisher outside Microsoft)` | High | Signed with a `Developer`/`Enterprise` certificate by someone other than Microsoft. |
| `package not healthy (Windows reports X)` | High | Windows' own `Status` is not `Ok` - the files on disk are not what it installed. |

> `SignatureKind` alone is **not** provenance. Microsoft ships
> `Developer`-signed packages - Edge, DevHome and QuickAssist were all
> `Developer` on a reference machine. The publisher decides, and it is matched
> on the **organisation** (`O=`) rather than the common name: a genuine system
> package signs `CN=Microsoft Windows, O=Microsoft Corporation`, so a `CN=`
> check would call it third-party.

## Capabilities and persistence

| Signal | Severity | Meaning |
| --- | --- | --- |
| `capability allowelevation` | Medium | Can request elevation. |
| `capability broadfilesystemaccess` | Medium | Reads and writes the whole user file system. |
| `capability packagemanagement` | Low | Can install and remove other packages. |
| `capability internetclientserver` | Low | Accepts inbound network connections. |
| `installs-startup-task (runs at logon)` | Low | Declares a `windows.startupTask` extension. |
| `registers-background-task` | Info | Declares background tasks. |

Two calibrations, both measured rather than assumed:

- **`runFullTrust` is never reported.** It sits on 31 of 106 packages on a stock
  machine - it is how desktop-bridge apps work. Reporting it would bury the rare
  capabilities below it.
- **First-party capabilities are context, not findings.** Of the 18 packages
  carrying a notable capability, **17 were Microsoft's own** - the Store
  declaring `packageManagement` is its job. Those stay visible at `Info` and
  **0 points**: they no longer move the score, but they are not dropped either,
  because a first-party component can still be abused.

Capability names are matched case-insensitively: manifests in the wild carry
both `broadFileSystemAccess` and `broadFilesystemAccess`, sometimes in the same
package.

## Machine posture

Reported as caveats rather than attached to any package:

| Caveat | Meaning |
| --- | --- |
| `sideloading is enabled (AllowAllTrustedApps)` | Packages can be installed outside the Store. |
| `developer mode is enabled` | Unsigned packages can be deployed. |

## Not covered yet

The per-file hash comparison of your own row is out of reach from the CLI;
postmortem relies on Windows' `Status` verdict instead. Store certificate
pinning is covered by [WinGet](WinGet), which owns the `msstore` source.
