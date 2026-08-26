# Python (pip / Poetry)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix.

## Lockfiles

| File | Notes |
| --- | --- |
| `requirements.txt` | pip. |
| `poetry.lock` | Poetry - carries the resolved graph. |

Package names are normalized (case, `-`/`_`/`.`) so `Foo_Bar` and `foo-bar`
match.

## Graph

Poetry lockfiles give a full graph; a bare `requirements.txt` is flatter.

## Licenses

Needs `--online`. PyPI's `license` field is hand-written prose, so postmortem
prefers the PEP 639 `license_expression`, then the free text, then the trove
classifiers — whichever first maps to a real SPDX identifier.
See [Licenses](Licenses).

## Dependency scopes

Varies by format. `Pipfile.lock` is authoritative (`default` vs `develop`).
`poetry.lock` uses `groups` (poetry >= 1.5) or the legacy `category` field.
A bare `requirements.txt` carries no metadata, so only the filename convention
(`requirements-dev.txt`, `requirements/dev.txt`, ...) marks it as development.
See [Dependency scopes](Dependency-Scopes).

## Online resolution

- **Registry:** `pypi.org/pypi/<name>/json`.
- **Repo discovery:** PyPI has no single repo field, so postmortem scans
  `info.project_urls` for a repo-ish key (`Source`, `Source Code`,
  `Repository`, `Code`, `GitHub`, `Git`), then any project URL, then falls back
  to `info.home_page`. The first candidate that parses to a known
  [host](Ecosystems-and-Hosts#code-hosts) wins.

### Release history

The registry call above asks for the **pinned version** (`/<name>/<version>/json`),
because a project can relicense between releases. That document carries no
`releases` map, so the provenance signals that need a timeline —
`dormant-release`, `fresh-release`, `newborn-package` — read the name-only
document in one further request, cached per version forever. It also carries
`ownership.roles`, which is where Python's maintainer sets for
[`tree --human`](Tree) come from.

PyPI records no per-release uploader, so `new-publisher` is unanswerable for
Python, and PEP 740 attestations need a per-file request that postmortem does
not make — neither is reported as clean. See
[provenance coverage](Online-Resolution#provenance-coverage).

### Gotcha

Many packages list only a documentation/homepage URL, not a code repo - those
resolve to *no repository* (reported as **unchecked**, not suspicious).
