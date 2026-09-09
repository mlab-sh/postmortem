# Changelog

All notable changes to postmortem are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`--image <ref>` on `scan`, `tree`, `audit` and `sbom`.** A container image is
  now a target the way a directory is. `docker create` + `docker export` flattens
  it into a temporary directory that is deleted when the command ends, and
  **nothing inside the image is ever executed** — the point is to read an
  artifact whose code you do not yet trust. Both of its layers land in one graph:
  every application found inside it, and the OS package database underneath them,
  so `risk:dep`, the gate, the SBOM and `--vulns` see the whole artifact instead
  of half of it. The application layer is the existing detection and parsers with
  a different root; the only new reading is the OS one.
- **The apk backend reads an alternate root.** It is the first of the OS backends
  to stop assuming the machine it runs on, which is what lets an Alpine-based
  image be inventoried from a macOS laptop with no apk installed. Verified
  against `apk info` inside the container: same 15 packages, no additions, no
  omissions. Debian and rpm images are detected and reported as *not examined*
  rather than silently contributing nothing.
- **Debian, Ubuntu and the rpm distributions read from an image too.** dpkg's
  database is text, so it is now *parsed* rather than queried through
  `dpkg-query` / `apt-mark` / `dpkg-divert`: those tools only ever describe the
  machine they run on, and reading the files they read is what lets a Debian
  image be inventoried from a macOS laptop that has never seen dpkg. rpm's
  database is a binary store, so it is read with `rpm --root`, which does need an
  `rpm` binary present — and says so plainly when there is none. Checked against
  each distribution's own tool on a stock base image: **identical package sets,
  no additions and no omissions**, on Debian 12 (88), Ubuntu 24.04 (92),
  AlmaLinux 9 (101), Rocky 9 (147) and Fedora 41 (124).
- **Where the rpm database lives is probed, not assumed.** `_dbpath` is a
  property of the rpm *doing the reading*: Fedora moved its database to
  `/usr/lib/sysimage/rpm` while RHEL 9 and its rebuilds keep `/var/lib/rpm`.
  Reading an AlmaLinux image from a Fedora machine with the default therefore
  found an empty directory and reported **zero packages** — a silent, confident,
  wrong answer, and the worst failure a scanner has.
- **podman and nerdctl join docker** as image acquisition runtimes; whichever is
  on `PATH` is used. podman matters because it is the default on Fedora and RHEL,
  where Docker is often absent entirely. Apple's `container` is deliberately not
  supported: its `export` materialises a root filesystem only once the container
  has been *started*, and starting an image is precisely what a tool built to
  read untrusted artifacts must never do.
- **Dockerfiles are analyzed by `scan`.** A Dockerfile is the same object the
  `system` backends already read for Homebrew formulae, PKGBUILDs and maintainer
  scripts — a build recipe whose every instruction runs as root — except that it
  is the one recipe nearly every project keeps in its own repository, where a
  lockfile scanner never looks. Flagged: a base pinned by tag rather than digest,
  a remote script piped to a shell, `ADD` from a URL, a credential in `ENV`/`ARG`,
  verification switched off, and no `USER` instruction. A `FROM` naming an earlier
  stage of the same file is not an unpinned base, and a valueless `ARG NPM_TOKEN`
  bakes nothing in; neither is flagged.
- **`tree --image <ref> --layers` stacks the image itself and attributes every
  package to the build step that introduced it.** Acquisition goes through `save`
  rather than `export`, so no container is created at all, and each layer carries
  the instruction from the image's own build history. The result is a report that
  names the line to change: not "this image contains a vulnerable curl" but
  "curl entered at `RUN apt-get install -y --no-install-recommends curl`". It
  costs roughly twice the image's size in scratch space, which is why it is
  opt-in. Whiteouts are applied in order, so a file the author deliberately
  deleted in a later layer stays deleted — verified end to end against the
  runtime's own flattening: identical package sets on Alpine, Debian, Ubuntu and
  a purpose-built three-layer image.
- **The image's own configuration is analyzed.** A Dockerfile is only available
  to whoever holds the repository; the config is available to anyone who can pull
  the image, and it is what actually ships. `scan --image` and `audit --image` now
  report a credential set in `Env` or `Labels` (critical — in a pushed image that
  is a leaked secret readable by everyone with pull access, and deleting the file
  later does not take it back out of the config), a start command that fetches a
  remote script and pipes it to a shell (high — it runs on every start of every
  container from the image), and a main process running as root (low). The rules
  are shared with the Dockerfile analyzer rather than restated, so a recipe and
  the artifact it built cannot be judged by different standards. On stock
  `alpine`, `debian`, `node:20-alpine` and `distroless`, the only finding is the
  root one, which is true of all four.
- **Credential-name matching now works per segment rather than by substring.**
  `contains("auth")` fired on `AUTHOR_NAME`, and a check that cries wolf on an
  author's name is a check people switch off.
- **Distroless images are inventoried.** They keep one dpkg stanza per package
  in `var/lib/dpkg/status.d/` and have no `status` file at all, so postmortem
  reported the images people pick *for* their small attack surface as containing
  no packages whatsoever. Both layouts are read now; `gcr.io/distroless/base-debian12`
  comes back with its 7 packages, matching its stanzas exactly.
- **`diff` compares two container images.** An `image://<ref>` on either side
  compares built artifacts instead of source trees, which is the review a lockfile
  diff cannot give you: the OS layer moves underneath the application, and that is
  where compromises land. A source tree on one side and an image on the other
  works too, and answers what the build added on top of what the project declares.
- **Vulnerability intelligence spans both layers of an image.** Lockfiles go
  through the mlab SBOM scan, OS packages through the OSV route `system --vulns`
  already used, and the OS release is read from the **image's** `etc/os-release`.
  A release cannot fall through to the scanning machine's: matching an Alpine
  image against the host's Debian advisories would be confidently wrong, so an
  image with no release file reports that it could not be matched.

### Changed

- **The tree hid packages nothing depends on.** Roots were the direct
  dependencies, falling back to parent-less nodes only when *nothing* was marked
  direct. A package that was neither declared direct nor reachable from one
  rendered nowhere at all, while still being counted, scanned and exported — the
  tree quietly understated what was installed. Roots are now the direct
  dependencies *and* anything nothing else depends on. Real data produces this:
  Alpine's `ssl_client` has no reverse dependency in the apk database, and a
  package sitting in an image with no manifest naming it has no parent either.
- **A signal whose premise could not be checked is reported but not scored.**
  Inside an image no package can be shown to come from a third party, so install
  scripts and rpm scriptlets are still statically analyzed — reading an untrusted
  artifact and looking at none of the code it runs would be worse — but their
  findings arrive at `Info` with no risk points and an `[unattributed source]`
  tag. Those analyzers were calibrated on untrusted install code, and a URL in a
  distribution's own maintainer script is how the distribution works: scoring
  them took a stock `debian:12` to 60/100. It now scores 20.
- **`dpkg-query` counted packages that are not installed.** A package removed but
  not purged keeps a `deinstall ok config-files` stanza, and it was entering the
  graph — and the vulnerability scan — despite shipping no code. Only packages in
  state `installed` are now reported.
- **Diagnostics gained an `info` kind**, for facts about how a scan was obtained
  rather than holes in it. The platform a multi-arch reference resolved to is one
  — worth carrying into `--json`, but not something that should drag an `audit`
  verdict down the way an unparsed lockfile does.
- **`postmortem.conf` and the `[gate]` policy are read from the working directory
  when the target is an image**, never from inside it. A configuration file
  shipped in someone else's image must not be able to suppress findings about
  that image.

### Fixed

- **`--image` failed outright on an image that declares no command.** Acquisition
  goes through `create`, and `create` refuses an image with neither `Cmd` nor
  `Entrypoint` — which is exactly what a distroless or scratch-derived base looks
  like. A placeholder argv is passed now; nothing is ever started, so it is never
  resolved or run.
- **The Linux release binaries would not start on Debian 12 or Ubuntu 22.04.**
  They were linked on `ubuntu-latest` — 24.04, glibc 2.39 — and a glibc binary
  never runs against a glibc older than the one it was built with. The two GNU
  targets are pinned to 22.04, which lowers the floor to glibc 2.35.

## [2.3.1] - 2026-08-27

### Added

- **Webhook authentication.** `--webhook` could only reach a collector that
  accepted anonymous requests. It now carries a credential: `bearer`, `basic`,
  or an arbitrary header name — `X-API-Key`, and whatever else a collector
  expects. The credential is **never a command-line argument**: `ps` shows it to
  every user on the machine, shells record it, and CI prints the command it ran.
  It comes from the environment or from `config.yml`, like the registry tokens.
  A scheme configured with no credential behind it is an error rather than a
  silent anonymous POST, and the credential is applied after the configured
  `headers`, so a stray entry there cannot quietly replace it with something
  weaker.
- **Windows binaries, a Scoop bucket, and a signed apt repository.** Releases
  publish Windows zips alongside the macOS and Linux tarballs, `scoop bucket add
  postmortem` installs them, and Debian and Ubuntu install from `apt.mlab.sh`.
  The repository is signed and the key fingerprint is published in the README,
  so it can be checked before the repository is trusted.

### Changed

- **A credential over plain HTTP is refused outright**, not warned about.
  Sending the report itself in clear text is a trade-off a deployment may
  accept; handing a bearer token to everything on the path is not one, and no
  scan is worth it. A collector on the loopback address stays exempt.
- The UTF-16LE base64 encoder the Windows backend uses to drive PowerShell moved
  into `encoding`, where basic authentication shares it rather than growing a
  second copy.

## [2.3.0] - 2026-08-26

### Added

- **`system` runs on Windows.** A Windows machine has no single package
  manager, so the backend reads every layer and merges them into one inventory:
  WinGet, MSIX/AppX, Chocolatey, Scoop, and everything Add/Remove Programs
  records — including the software no manager claims. On top of the inventory it
  reads what the machine actually *runs*: auto-start entries, scheduled tasks,
  services and drivers, image hijacks and BITS jobs, and the privilege posture
  (UAC, LSA, `PATH` and ACL weaknesses, Defender policy, firmware) — with
  network posture, meaning the hosts file, proxies, DNS and root CAs, under
  `--deep`. Every binary is checked against its Authenticode signature,
  calibrated around the fact that Microsoft ships `Developer`-signed packages of
  its own. All of it shells out to tools already present on the machine; no
  Windows-specific crate is pulled in.
- **Provenance signals beyond npm.** The release-history comparison behind
  `dormant-release`, `new-publisher`, `provenance-removed`, `fresh-release` and
  `newborn-package` was npm-only. crates.io and PyPI publish a history too, and
  now feed the same signals. Rust gets five of them for **no additional
  request**: the crate record already fetched for the repository and the license
  carries every version, with `created_at`, `published_by` and `trustpub_data`
  — Trusted Publishing, crates.io's equivalent of an npm attestation. Python
  gets the three time-relative ones from one further call to the name-only
  project document, because the version-pinned one postmortem fetches (a licence
  is per-version) carries no release map.
- **Maintainer sets for Python.** PyPI's `ownership.roles` names every account
  that can publish, so `tree --human` and `why --blast` now attribute Python
  packages instead of counting them as unattributed.

- **Typosquat detection for Maven, and a real corpus for Go.** The corpus
  generator ranked every registry by download count, but ecosyste.ms returns
  `downloads: null` for Go and Maven — so neither was ever in its target list.
  Go ran on 59 hand-curated module paths and Java had no corpus at all. Both are
  now built from `dependent_packages_count`, which ranks them sanely
  (`golang.org/x/sys`, `junit:junit`, `guava` at the top): Go goes from 59 to
  1 207 paths and Maven gets 1 200 `group:artifact` coordinates.

  Maven is not Packagist with another separator, and the rules say so. A name
  that carries its own version is not a near-miss of itself (Scala's `_2.12` /
  `_2.13`, `retrofit` → `retrofit2`, `kotlin-stdlib-jre7` vs `-jre8`), and two
  coordinates sharing a groupId are siblings rather than impostors, because
  Central verifies a groupId against a domain its publisher controls. The
  "same name, other vendor" rule stays off there — an artifactId is unique only
  within its group. Both rules apply to Go for the same reasons
  (`gopkg.in/yaml.v1` vs `.v3`; `github.com/aws/…/service/sqs` vs `sts`).
  Measured against 1 200 legitimate packages ranked just below each corpus:
  0 false positives on Maven, 2 on Go, down from 65 and 11 before the rules.
- **Fixed: a Go module path with a capital letter was flagged as a typosquat of
  itself.** 67 of the popular paths carry one (`github.com/BurntSushi/toml`,
  `Azure`, `Microsoft`) and the input was lowercased while the corpus was not,
  so the membership test missed and the name came back one edit from itself.
- **Two install-time execution paths npm runs and its own flag does not record.**
  A dependency npm builds locally — a `git+`, `file:`, `link:` or
  remote-tarball source — also runs its `prepare` on the installing machine, and
  a package with a `binding.gyp` and no install script of its own gets
  `node-gyp rebuild` synthesised for it. npm gates both behind `allowScripts`,
  but computes `hasInstallScript` as `preinstall || install || postinstall`
  alone, so `scripts` — the command whose job is to help you decide what to
  approve — was silent on exactly the packages npm was asking about. Both now
  appear in `scripts` and `scan`. A **registry** dependency's `prepare` stays
  unreported: it ran at publish time on the publisher's machine, and
  `"prepare": "tsc"` is half of npm.
- Which lifecycle scripts count as install-time now lives in one place rather
  than three diverging lists.

### Changed

- **A signal that could not be evaluated is no longer reported as clean.** The
  verdicts became tri-state: the anomaly, its absence, and *this registry does
  not publish what the comparison needs*. A single `false` covering the last two
  was harmless while one ecosystem was involved; across three it would have
  implied checks nobody ran. `install-script-added` stays npm's alone (no other
  registry records what a package runs at install time), `new-publisher` is
  unanswerable on PyPI (no per-release uploader), and PyPI's PEP 740
  attestations need a per-file request that is not made — all three now read as
  unevaluated rather than clean. The full matrix is in the online-resolution
  documentation.
- **`main.rs` and `resolve.rs` were split up.** `main.rs` had grown to 2 489
  lines holding every command's orchestration and rendering, and `resolve.rs` to
  2 369 holding repository identity, registry reads, history reads, scoring and
  the network layer at once. Both were the files any further work on provenance
  had to touch. `main.rs` is now dispatch only, with one module per command
  under `cmd/` and the shared work in `cmd::common` / `cmd::gate_policy`;
  `resolve` became a module split by concern (`repo`, `registry`, `history`,
  `signal`, `net`). No behaviour changed: the code moved verbatim, and each
  test moved next to what it tests.
- **Cache record format 4 → 5**, for that shape change. Entries written by 2.2.0
  and earlier are refetched on first use: no action needed, the first online run
  is simply slower.

## [2.2.0] - 2026-08-18

The largest release so far: eight new commands, and a pass over every existing
one. The theme running through it is that **postmortem now tells you what it
does not know** — a graph it could not fully resolve, a script it has not read,
a license it could not determine, and a gate it could not evaluate all say so
explicitly instead of reporting a clean result.

### Added — new commands

| Command | What it does |
|---|---|
| `licenses` | License inventory across the graph, with a deny / allow / fail-on-unknown policy. SPDX normalization and aliasing. |
| `fix` | Turns the vulnerability report into the change that clears it: minimum upgrade target, direct command, or override snippet. Never writes to a manifest. |
| `scripts` | Which dependencies execute code at install time, whether each is approved, and what its script actually does. Reads npm 11.17's native `allowScripts` approvals. |
| `hook` | Installs a git pre-commit hook that scans staged dependency changes. Detects and refuses to clobber a foreign hook. |
| `watch` | Re-scans whenever a lockfile changes. No file-watching dependency — polling on size and mtime. |
| `timeline` | Lays a package's release history out in order: maintainer handovers, install scripts appearing, repository moves. |
| `allowlist` | Every suppression the project declares, with how long each has left to run. `--expired` lists the lapsed ones. |
| `ci` | Prints a ready-to-commit pipeline for GitLab CI, Azure DevOps, Jenkins or GitHub Actions. |

### Added — existing commands

- **`tree --human`** — the maintainer graph: which accounts control the largest
  share of your tree, measured by what a compromise of each would reach.
  Concentration is a set union, not a sum, so overlapping reach is not
  double-counted.
- **`why --blast`** — blast radius. Separates what a package's *position* in the
  graph would expose (a ceiling) from what its current code is observed to do
  (a floor).
- **`diff` takes a GitHub PR URL** — `postmortem diff https://github.com/o/r/pull/42`
  fetches both sides and diffs them. Only manifests are downloaded, and always
  from the base repository even when the PR comes from a fork.
- **`diff` assesses risk and vulnerabilities**, not just set membership: what a
  change *introduces*, not merely what it adds.
- **`--omit dev|optional`** on `scan`, `tree` and `audit`. Scope is propagated by
  reachability, so a package that also ships in production is never dropped.
- **`--gitlab`** on `tree` and `audit` — a native GitLab Dependency Scanning
  report. GitLab does not read SARIF; publishing SARIF there yields a green
  pipeline with an empty security widget.
- **`tree --html`**, and machine output (`--json`) for `audit`, `why` and `diff`.
- **The CI gate now applies to `audit`**, sharing `tree`'s `[gate]` policy and
  threshold flags.
- **`cache` gained actions** — `info`, `path` and `prune`.
- **Corporate networks**: a `[network]` block in `postmortem.conf` for proxies,
  `no_proxy`, and internal registry/host endpoints. Deliberately configuration
  only — not CLI flags, not environment variables.
- **Typosquatting corpus expanded** across every ecosystem.

### Changed

- **The on-disk cache is now versioned.** Every record is wrapped in an envelope
  carrying a format version (currently 4); a record whose version does not match
  is treated as a cache miss and refetched. Previously a cached record written by
  an older postmortem was deserialized against the newer shape, and because serde
  defaults a missing `Option` field to `None` rather than failing, a field added
  after the record was written silently read as absent — a stale cache could
  report "no license", "no fix", "no maintainers" indefinitely. Caches written by
  2.1.2 and earlier carry no envelope and are refetched on first use: no action
  needed, the first online run is simply slower.
- **`scan --json` schema version 2 → 3.** Findings now carry dependency scope
  and license fields, and the report carries diagnostics.
- **Suppressions are unified and expirable.** `[[ignore]]` rules accept an
  `expires` date; a lapsed rule stops suppressing and is reported rather than
  silently ignored.
- `help` was rewritten to group commands by the question they answer.

### Fixed

- **`audit` never applied `postmortem.conf`.** It was the third command
  bypassing project policy; all three now load it.
- **The fix target was silently dropped on one of two advisory parse paths**, so
  `fix` could report "no known fix" for an advisory that had one. The
  version-less code path was removed entirely so no path can lose it again.
- **Typosquatting false positives.** Scoped names such as `@babel/core` were
  matched on their last segment only, flagging `@babel/core` as a typosquat of
  `cors`. Full names are now checked for corpus membership, and scoped names
  only match on verbatim reuse. On a real project: 9 false positives → 0.
- **`why --blast` claimed "runtime only" without evidence** when dependency code
  was not present to scan. It now reports the trigger as unknown.
- **An incomplete dependency graph is now a diagnostic**, not a silent success.
  Go and Java are marked as flat graphs, and Go `replace` directives are
  surfaced.
- `wiki/Configuration.md` documented a `[[suppress]]` table that does not exist;
  the real table is `[[ignore]]`, and with `deny_unknown_fields` a copy-paste
  from the docs failed.

### Notes

- `postmortem ci` templates pin the release matching the binary that printed
  them, so a generated pipeline can never reference a version that does not
  exist.
- The `github-action` `version` input now defaults to `v2.2.0`.
- Test suite grew from 224 to 516 tests.

## [2.1.2] - 2026-08-16

- Homebrew formula and release packaging fixes.

## [2.1.1] - 2026-08-05

- Source-code security scanning.
- System security auditing improvements.
- gochi companion updates.

## [2.1.0] - 2026-08-04

- `diff` and `sbom` commands (CycloneDX 1.5).
- OS package manager backends: apt/dpkg, dnf/rpm, pacman/AUR, Nix, and apk.
- IOC detection.
- Lua and shell script scanning.
- Test and fixture directories excluded from the default scan.

## [2.0.1] - 2026-08-04

- GitHub Action fixes.

## [2.0.0] - 2026-08-04

- Initial 2.x release.

[2.3.1]: https://github.com/mlab-sh/postmortem/releases/tag/v2.3.1
[2.3.0]: https://github.com/mlab-sh/postmortem/releases/tag/v2.3.0
[2.2.0]: https://github.com/mlab-sh/postmortem/releases/tag/v2.2.0
[2.1.2]: https://github.com/mlab-sh/postmortem/releases/tag/v2.1.2
[2.1.1]: https://github.com/mlab-sh/postmortem/releases/tag/v2.1.1
[2.1.0]: https://github.com/mlab-sh/postmortem/releases/tag/v2.1.0
[2.0.1]: https://github.com/mlab-sh/postmortem/releases/tag/v2.0.1
[2.0.0]: https://github.com/mlab-sh/postmortem/releases/tag/v2.0.0
