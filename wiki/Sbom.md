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
- **`metadata`** — timestamp, the postmortem tool version, and the root component.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    { "type": "library", "bom-ref": "pkg:npm/event-stream@3.3.6",
      "name": "event-stream", "version": "3.3.6", "purl": "pkg:npm/event-stream@3.3.6" }
  ],
  "dependencies": [
    { "ref": "postmortem:root", "dependsOn": ["pkg:npm/event-stream@3.3.6"] }
  ]
}
```

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
| `--no-progress` | Disable the animated progress UI. |
