# Haskell (Cabal, Stack)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix.

| File | Notes |
| --- | --- |
| `cabal.project.freeze` | `constraints: any.aeson ==2.2.3.0, ...` - every package of the plan, pinned. **Flat**. Ignored when it pins nothing (only an `index-state`). |
| `stack.yaml.lock` | Pins the `extra-deps` only; every other package's version is the snapshot's (`lts-24.48`), not resolved offline: **`managed`**. |
| `*.cabal` / `package.yaml` | `build-depends` (hpack: `dependencies`) give the direct set; `test-suite` / `benchmark` (hpack: `tests` / `benchmarks`) are dev. |

**Online:** the release's `.cabal` on Hackage (`hackage.haskell.org/package/<name>-<version>/<name>.cabal`, or the latest one for a `managed` package) → `source-repository` `location`, `homepage`, `bug-reports`, `license`. New `hackage` endpoint.

**Vulnerabilities:** through vuln.mlab.sh as OSV `Hackage` coordinates (HSEC advisories). A `managed` package has no version to match.

**Not covered:** `dist-newstyle/cache/plan.json` (the full graph), Stack snapshot resolution, source scanning, typosquatting.
