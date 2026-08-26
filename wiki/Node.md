# Node (npm / pnpm / yarn)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix. Node is postmortem's
richest ecosystem - the only one with **identity/provenance** signals.

## Lockfiles

| File | Notes |
| --- | --- |
| `package-lock.json` | npm; `npm-shrinkwrap.json` treated the same. |
| `pnpm-lock.yaml` | pnpm (YAML). |
| `yarn.lock` | Yarn v1 (classic) and Berry (v2+). |

Scoped names (`@scope/pkg`) are handled throughout, including cache keys.

## Graph

Full transitive graph with real parent/child edges. Diamond deps and cycles are
collapsed to `(*)` to keep output finite.

## Licenses

Read **offline** from the `license` field on each `package-lock.json` entry —
present on ~99% of entries in practice, so Node needs no network for this. The
legacy `{"type": ...}` object and `licenses` array shapes are handled too.
See [Licenses](Licenses).

## Dependency scopes

Seeded from `dependencies` / `devDependencies` / `optionalDependencies` — the
lockfile root entry (npm), `importers:` (pnpm), or `package.json` (yarn) — then
propagated through the graph. A name listed under two fields keeps the strongest
scope. See [Dependency scopes](Dependency-Scopes).

## Online resolution

- **Registry:** `registry.npmjs.org/<pkg>/<version>` → the `repository` field
  (string or `{ url }`).
- Resolves to a [host](Ecosystems-and-Hosts#code-hosts) for reputation stats.

### Provenance signals

These come from the npm **packument** (version history). crates.io and PyPI
publish a history too and answer some of the same questions — see
[provenance coverage](Online-Resolution#provenance-coverage) — but
`install-script-added` is npm's alone, because no other registry records what a
package runs at install time:

| Signal | Meaning | Elsewhere |
| --- | --- | --- |
| `install-script-added` | A lifecycle script (`preinstall`/`install`/`postinstall`) appears in this version but not the previous one. | npm only |
| `dormant-release (Nd gap)` | Published after a long dormancy (the event-stream pattern). | crates.io, PyPI |
| `new-publisher` | A different npm publisher than every earlier version. | crates.io |

See [Online resolution](Online-Resolution) for the full signal/scoring model.
