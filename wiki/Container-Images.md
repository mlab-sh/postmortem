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

`create` makes a container without starting it, `export` streams its filesystem,
and the container is removed straight away. **Nothing inside the image is ever
executed** — that is the entire point of reading an artifact whose code you do
not yet trust. The extraction lands in a temporary directory and is deleted when
the command ends, the same discipline [`system inspect --deep`](System) applies
to the repositories it clones.

### Runtimes

Whichever of these is on `PATH` is used, in this order. There is nothing to
configure.

| Runtime | Notes |
| --- | --- |
| `docker` | |
| `podman` | The default on Fedora and RHEL, where Docker is often absent |
| `nerdctl` | containerd |

Apple's `container` is **not** supported. Its `export` materialises a container's
root filesystem only once the container has been *started*, and starting an image
is exactly what a tool built to read untrusted artifacts must never do. It needs
the `save`-based path below rather than another name on this list.

### `--layers`

`tree --image <ref> --layers` acquires through `save` instead and stacks the
layers itself. Two things come out of that:

- **Attribution.** Every file remembers the layer that last wrote it and every
  layer remembers its build instruction, so a finding names the line that caused
  it: not "this image contains a vulnerable curl" but "curl entered at
  `RUN apt-get install -y --no-install-recommends curl`".
- **No container at all.** `save` reads the image store directly, so unlike
  `export` there is nothing to create, leak or clean up.

It costs roughly twice the image's size in scratch space and noticeably more
time, which is why it is opt-in.

A layer removes a file from the layers below by adding a marker rather than
deleting anything (`.wh.<name>`, and `.wh..wh..opq` for a whole directory).
Applying those in order is what separates stacking from concatenating: get it
wrong and a credential or build tool the author deliberately removed reappears in
the report as though it shipped.

A reference that is not present locally is pulled. A reference that cannot be
resolved is an error and exits non-zero: an image postmortem could not read must
never be reported as an image with nothing wrong in it.

### Platform

A multi-arch reference resolves to one of its manifests, and which one is the
runtime's choice rather than postmortem's. The platform actually read, and which
runtime resolved it, are recorded in the report:

```
— platform linux/arm64 (resolved by docker)
```

Scanning `linux/amd64` from an arm64 machine means scanning a different set of
packages. Pin the platform on the runtime side if that matters:

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

| Database | Backend | Read by | Needs a tool on your machine |
| --- | --- | --- | --- |
| `lib/apk/db/installed` | apk (Alpine) | parsing the file | no |
| `var/lib/dpkg/status` | apt (Debian, Ubuntu) | parsing the file | no |
| `var/lib/rpm` or `usr/lib/sysimage/rpm` | dnf (Fedora, Rocky, Alma) | `rpm --root` | **yes**, an `rpm` binary |

apk and dpkg keep their databases as text, so postmortem reads them directly and
a Debian image can be inventoried from a macOS laptop that has never seen dpkg.
rpm's database is a binary store, so reading one needs an `rpm` binary present.
When there is none, that is reported rather than passed off as an image with no
packages:

```
⚠ 1 graph diagnostic(s) — results may be incomplete
  [dnf] os-layer-unread  running `rpm -qa` — is rpm installed on this machine?
```

Where the rpm database lives differs between distributions — Fedora moved it to
`usr/lib/sysimage/rpm` while RHEL 9 and its rebuilds keep `var/lib/rpm` — so the
location is probed inside the image rather than taken from the reading machine's
own default. Taking the default is how a scanner reports zero packages for an
image full of them.

### What an image cannot tell you

Some signals need the package manager to be describing *its own* system, and an
image carries no repository metadata. Those are collected for `system` on this
machine and reported as not collected for an image:

| Not available in an image | Why |
| --- | --- |
| Per-package provenance (third-party source) | Needs `apt-cache policy` / `dnf repoquery` and the repo lists an image deletes |
| Available upgrades | Same |
| File tampering (apt) | Needs `dpkg --verify` |
| Direct vs transitive (rpm) | Needs `dnf repoquery --userinstalled` |

Because provenance is unknown, install scripts and rpm scriptlets are still
statically analyzed — reading an untrusted artifact and looking at none of the
code it runs would be worse — but their findings are reported **unscored** and
tagged `[unattributed source]`. Those analyzers were calibrated on untrusted
install code, and a URL in a distribution's own maintainer script is how the
distribution works. Scoring a premise that could not be checked would make every
stock base image look compromised.

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

A distroless image *does* carry a package database, just not in the usual shape:
one dpkg stanza per package under `var/lib/dpkg/status.d/`, with no `status` file.
Both layouts are read.

A `scratch`-derived image genuinely has no database. That is stated rather than
reported as an image with no OS packages:

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

One of the [runtimes](#runtimes) above, and `tar`. An `rpm` binary as well for
rpm-based images. Nothing is installed into the image and no code from it runs.

## What the image declares

`scan --image` and `audit --image` read the image's own configuration, which
needs no Dockerfile and no repository — only the ability to pull.

| Checked | Severity | Why |
| --- | --- | --- |
| A credential in `Env` | Critical | It ships inside the image and anyone who can pull it can read it. Deleting the file later does not take it out of the config |
| A credential in `Labels` | Critical | Same |
| A start command piping a remote script to a shell | High | It runs on every start of every container from the image |
| A root main process | Low | An unset `User` is the common case and nothing defaults it to an unprivileged account |

A value that is empty or an unsubstituted build argument is not a credential and
is not reported. Credential *names* are matched per segment, so `AWS_SECRET_ACCESS_KEY`
matches and `AUTHOR_NAME` does not.

These are the same rules the Dockerfile analyzer applies, on the artifact instead
of the recipe. Running both is how the two get compared: a Dockerfile that sets no
`USER` and an image that reports root agree, and a disagreement is worth a look.

## Dockerfiles

The recipe is analyzed too, and needs no image and no runtime: `scan` picks up
every `Dockerfile`, `Containerfile` and their `.prod` / `prod.` variants found in
a project.

```bash
postmortem scan .
```

| Checked | Why it matters |
| --- | --- |
| A base pinned by tag rather than digest | Whoever controls that tag controls the bottom of your image on the next build |
| `curl … \| sh` | The fetched code is never reviewed and can change between builds |
| `ADD` from a URL | Pulls a remote artifact in with no checksum |
| A credential in `ENV` / `ARG` | Stays in the layer, readable by anyone who pulls the image |
| `--no-check-certificate`, `gpgcheck=0`, and friends | Turns a signed supply chain into an unsigned one |
| No `USER` instruction | The container's main process runs as root |

A `FROM` that names an earlier stage of the same file is not an unpinned base,
and a bare `ARG NPM_TOKEN` with no value bakes nothing in — both are the correct
patterns and neither is flagged.


## Comparing two images

`diff` takes an `image://` reference on either side.

```bash
postmortem diff image://acme/api:1.2.0 image://acme/api:1.2.1
```

This is the review a lockfile diff cannot give you, because the OS layer moves
underneath the application and that is where compromises land. Both sides are
filtered identically, and `--online` / `--vulns` assess only what the change
*introduces*.

A source tree on one side and an image on the other works too, and answers a
different question: what the build added on top of what the project declares.

```bash
postmortem diff ./api image://acme/api:1.2.1
```
