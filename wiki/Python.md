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

## Online resolution

- **Registry:** `pypi.org/pypi/<name>/json`.
- **Repo discovery:** PyPI has no single repo field, so postmortem scans
  `info.project_urls` for a repo-ish key (`Source`, `Source Code`,
  `Repository`, `Code`, `GitHub`, `Git`), then any project URL, then falls back
  to `info.home_page`. The first candidate that parses to a known
  [host](Ecosystems-and-Hosts#code-hosts) wins.

### Gotcha

Many packages list only a documentation/homepage URL, not a code repo - those
resolve to *no repository* (reported as **unchecked**, not suspicious).
