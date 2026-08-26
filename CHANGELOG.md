# Changelog

All notable changes to postmortem are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

[2.2.0]: https://github.com/mlab-sh/postmortem/releases/tag/v2.2.0
[2.1.2]: https://github.com/mlab-sh/postmortem/releases/tag/v2.1.2
[2.1.1]: https://github.com/mlab-sh/postmortem/releases/tag/v2.1.1
[2.1.0]: https://github.com/mlab-sh/postmortem/releases/tag/v2.1.0
[2.0.1]: https://github.com/mlab-sh/postmortem/releases/tag/v2.0.1
[2.0.0]: https://github.com/mlab-sh/postmortem/releases/tag/v2.0.0
