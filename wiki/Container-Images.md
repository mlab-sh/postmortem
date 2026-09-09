# Container images

`--image <ref>` points `scan`, `tree`, `audit` and `sbom` at a container image
instead of a directory.

```bash
postmortem tree  --image alpine:3.19
postmortem tree  --image ghcr.io/acme/api:1.4.2 --vulns
postmortem scan  --image node:20-alpine
postmortem audit --image acme/api:1.4.2 --vulns --fail-on-vuln high
postmortem sbom  --image acme/api:1.4.2 -o api.cdx.json
```

## What it reads

An image has two layers of dependencies and the report carries both in one tree.

| Layer | Where it comes from |
| --- | --- |
| Application | Every project manifest and lockfile found inside the image |
| System | The image's own OS package database |

The two are merged into a single graph, so `risk:dep`, the CI gate, the SBOM and
the vulnerability scan all see the whole artifact rather than half of it. The
report header names both, e.g. `image acme/api:1.4.2 (node, apk)`.

## How the image is acquired

`docker create` makes a container without starting it, `docker export` streams
its filesystem, and the container is removed straight away. **Nothing inside the
image is ever executed** — that is the entire point of reading an artifact whose
code you do not yet trust. The extraction lands in a temporary directory and is
deleted when the command ends, the same discipline
[`system inspect --deep`](System) applies to the repositories it clones.

A reference that is not present locally is pulled. A reference that cannot be
resolved is an error and exits non-zero: an image postmortem could not read must
never be reported as an image with nothing wrong in it.

### Platform

A multi-arch reference resolves to one of its manifests, and which one is the
daemon's choice rather than postmortem's. The platform actually read is recorded
in the report:

```
— platform linux/arm64 (resolved by the daemon)
```

Scanning `linux/amd64` from an arm64 machine means scanning a different set of
packages. Pin the platform on the daemon side if that matters:

```bash
docker pull --platform linux/amd64 acme/api:1.4.2
postmortem tree --image acme/api:1.4.2
```

## Finding the applications

Every directory holding a manifest is a project root. The walk skips kernel
directories (`proc`, `sys`, `dev`) and vendored trees (`node_modules`, `vendor`,
`site-packages`, `dist-packages`), and stops descending once it has found a
project.

That exclusion is not an optimisation. A `package.json` under `node_modules/`
describes a package the application installed, not the application; treating
each one as a project root would report a single image as hundreds of projects
and count the same dependency many times over.

An image can hold several applications, and all of them are reported.

## OS package databases

| Database | Backend | Read from an image |
| --- | --- | --- |
| `lib/apk/db/installed` | apk (Alpine) | yes |
| `var/lib/dpkg/status` | apt (Debian, Ubuntu) | not yet |
| `var/lib/rpm` | dnf (Fedora, Rocky, Alma) | not yet |

A database whose backend cannot yet read an alternate root is reported rather
than skipped in silence:

```
⚠ 1 graph diagnostic(s) — results may be incomplete
  [apt] os-layer-unread  the apt backend cannot yet read an alternate root — its packages were not examined
```

## Vulnerabilities

`--vulns` covers both layers. Application lockfiles go through the mlab SBOM
scan; OS packages go through the same OSV route [`system --vulns`](System) uses.

The OS release is read from **the image's** `etc/os-release`, never from the
machine running the scan. Matching an Alpine image's packages against the
scanning host's Debian advisories would produce a confident and entirely wrong
answer, so an image with no release file reports that it could not be matched
instead of falling back:

```
[apk] no-release  the image carries no /etc/os-release — its OS packages cannot be matched to a vulnerability ecosystem
```

Distroless and `scratch` images carry no package database at all. That is stated
too, rather than reported as an image with no OS packages:

```
[image] no-os-database  no apk/dpkg/rpm database in the image (scratch or distroless?) — no OS packages were examined
```

## Policy comes from your project, not from the image

`postmortem.conf` and the [`[gate]`](CI-Gate) policy are read from the working
directory, never from inside the image. A configuration file shipped in someone
else's image must not be able to suppress findings about that image.

Everything else behaves as it does for a directory: `--json`, `--sarif`,
`--html`, `--gitlab`, `--omit`, the gate flags and the exit codes are unchanged.

## Requirements

A working `docker` CLI and daemon, and `tar`. Nothing is installed into the
image and no code from it runs.
