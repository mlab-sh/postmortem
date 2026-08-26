# Binary trust (Authenticode)

Linux trusts a signed repository, and everything the archive ships inherits that
trust. Windows signs **files**, so trust has to be established per binary.

This is a cross-cutting check, not a manager: it runs over the binaries the
[Windows](Windows) layers install. On by default; `--no-signatures` skips it.

## What is verified

For each binary a package installed:

| Signal | Severity | Meaning |
| --- | --- | --- |
| `signed hash does not match the file` | Critical | The signature verifies but the bytes changed after signing. |
| `not signed` | High | No signature at all. |
| `signed by a publisher this machine does not trust` | High | The chain does not validate here. |
| `signing certificate has expired` | High | |
| `signature could not be verified (status)` | Medium | Windows could not check it - unverified is not unsigned, and not fine. |
| `signature is not timestamped` | Medium | Without a countersignature the signature stops being verifiable once the certificate expires. |
| `signed with SHA-1` | Medium | |
| `still carries Mark-of-the-Web` | Medium | An installed file still has the browser's download marker. |
| `Microsoft-signed (catalog\|authenticode)` | Info / Low | The baseline - see below. |

Both signature forms are accepted: **catalog** (the system catalog covers the
file) and **embedded** Authenticode. Verification covers `.exe`, `.dll`, `.msi`,
`.msix` and `.sys`, not only executables.

## The Microsoft baseline

A Microsoft signature is reported at `Info` and scores nothing - the equivalent
of hiding Microsoft entries in Autoruns. Windows' own `IsOSBinary` flag decides,
falling back to the certificate's organisation field.

It is **never a silent skip**. A Microsoft-signed binary outside `System32`,
`SysWOW64`, `WinSxS` or `Program Files` is raised to `Low` and stays visible: a
genuine Microsoft binary in an unexpected place is what a proxying attack looks
like.

## What is *not* verified

**Shims.** Scoop and Chocolatey generate their own wrappers in `shims\` and
`bin\`, and nobody signs them - 13 of 16 came back `NotSigned` on a clean
machine. Reporting those would be thirteen findings about files the package
manager wrote itself. What matters is the binary a shim points at, so
[Scoop](Scoop) resolves `<name>.shim` to its target and
[Chocolatey](Chocolatey) verifies the payload under `lib\<pkg>\` instead.

## Repeated findings are folded

A package with many unsigned binaries is one finding about that package, not
many. `7zip.portable` ships twelve:

```
not signed (12 files, e.g. 7-zip.dll)
```

Scored **once**. As twelve separate signals it would both flood the node and
push its score to the cap, as though it were twelve times worse than a package
with one.

## Cost

Verification is batched into a single call per layer, which makes it
effectively free - a Chocolatey scan measured 3.03s with it and 3.04s without.
`--no-signatures` exists for machines with enough packages for the per-file cost
to add up.

## Not covered yet

Driver WHQL status and test-signing mode, certificate revocation beyond what
Windows' own status reports, and SmartScreen reputation (which would need the
network).
