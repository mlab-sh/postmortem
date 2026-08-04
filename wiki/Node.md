# Node (npm / pnpm / yarn)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix. Node is postmortem's
richest ecosystem — the only one with **identity/provenance** signals.

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

## Online resolution

- **Registry:** `registry.npmjs.org/<pkg>/<version>` → the `repository` field
  (string or `{ url }`).
- Resolves to a [host](Ecosystems-and-Hosts#code-hosts) for reputation stats.

### npm-only provenance signals

These come from the npm **packument** (version history) and a corpus of popular
names, so they are **Node-only**:

| Signal | Meaning |
| --- | --- |
| `typosquat of <pkg>` | Name is a near-miss of a popular package. |
| `install-script-added` | A lifecycle script (`preinstall`/`install`/`postinstall`) appears in this version but not the previous one. |
| `dormant-release (Nd gap)` | Published after a long dormancy (the event-stream pattern). |
| `new-publisher` | A different npm publisher than every earlier version. |

See [Online resolution](Online-Resolution) for the full signal/scoring model.
