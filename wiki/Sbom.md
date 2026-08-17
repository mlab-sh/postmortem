# `postmortem sbom`

Export the resolved dependency graph as a **CycloneDX 1.5** SBOM (JSON). postmortem
already reconstructs the full forest for every [ecosystem](Ecosystems-and-Hosts),
so producing a standard, portable bill of materials is a thin projection of what
[`tree`](Tree) already computes.

```bash
postmortem sbom <path>                 # writes postmortem-sbom-[date].json
postmortem sbom <path> -o sbom.json    # to a named file
postmortem sbom <path> -o -            # to stdout
```

## What it emits

A CycloneDX document with:

- **`components`** — one `library` component per dependency, each with a
  [package URL](https://github.com/package-url/purl-spec) (`purl`) as its stable
  `bom-ref`.
- **`dependencies`** — the dependency graph, rebuilt from the parent edges: the
  root application depends on the direct dependencies, and each component lists
  what it depends on.
- **`licenses`** — per component, when known. See [Licenses](Licenses) for where
  the data comes from; `--online` fills in the ecosystems whose lockfile does not
  record it.
- **`metadata`** — timestamp, the postmortem tool version, and the root component.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    { "type": "library", "bom-ref": "pkg:npm/event-stream@3.3.6",
      "name": "event-stream", "version": "3.3.6", "purl": "pkg:npm/event-stream@3.3.6",
      "licenses": [{ "license": { "id": "MIT" } }] }
  ],
  "dependencies": [
    { "ref": "postmortem:root", "dependsOn": ["pkg:npm/event-stream@3.3.6"] }
  ]
}
```

## License shapes

CycloneDX gives the `licenses` array three mutually exclusive entry shapes, and
mixing them up is the usual reason a document gets rejected:

| Shape | When | Example |
| --- | --- | --- |
| `{"license": {"id": ...}}` | a valid SPDX identifier | `{"license": {"id": "MIT"}}` |
| `{"expression": ...}` | a compound expression — a **sibling** of `license`, never nested inside it | `{"expression": "MIT OR Apache-2.0"}` |
| `{"license": {"name": ...}}` | free text that could not be tied to SPDX | `{"license": {"name": "see LICENSE"}}` |

postmortem never emits an unverified value as an `id`: consumers validate it
against the SPDX list and reject the whole BOM on a miss, so an honest `name` is
worth more than a confident guess. A component with no known license omits the
field entirely rather than emitting an empty array, which would assert that we
checked and found none.

## Package-URL types

Each ecosystem maps to its purl type, so the SBOM is meaningful to any CycloneDX
consumer:

| Ecosystem | purl type | Ecosystem | purl type |
| --- | --- | --- | --- |
| Node | `npm` | Homebrew | `brew` |
| Python | `pypi` | pacman | `alpm` |
| Rust | `cargo` | apt / dpkg | `deb` |
| Ruby | `gem` | dnf / rpm | `rpm` |
| PHP | `composer` | Nix | `nix` |
| Go | `golang` | apk | `apk` |
| Java | `maven` | | |

## Options

| Flag | Description |
| --- | --- |
| `-o`, `--output` | Output file (`-` for stdout). Defaults to a dated file in the cwd. |
| `--online` | Resolve licenses the lockfile does not record (network). Adds no request beyond the ones repo resolution already makes. |
| `--omit <dev\|optional>` | Drop a dependency set. Repeatable. A package reachable from production is always kept — see [Dependency scopes](Dependency-Scopes). |
| `--no-progress` | Disable the animated progress UI. |
