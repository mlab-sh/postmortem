# `postmortem licenses`

Inventory the licenses of the dependency graph, and enforce a policy over them.

```bash
postmortem licenses .                          # what am I shipping, legally
postmortem licenses . --online                 # fill the gaps from the registries
postmortem licenses . --omit dev               # only what I distribute
postmortem licenses . --unknown-only           # the actionable subset
postmortem licenses . --deny AGPL-3.0          # fail the build on copyleft
```

Exits **1** on a policy violation, so it drops into CI as its own step.

## Output

```
licenses  (466 deps, 1 unresolved)

  MIT                375
  ISC                 55
  BSD-3-Clause        14
  Apache-2.0          11
  MIT OR CC0-1.0       1
  see LICENSE file     1  non-SPDX
  (unknown)            1
```

Three colours, three meanings:

- **green** — resolved to a valid SPDX identifier or expression.
- **yellow** — the package declares *something*, but not something we could tie
  to SPDX. Shown verbatim so you can read what it actually claims. A policy
  cannot match on it.
- **orange `(unknown)`** — the package declares nothing at all. This is the
  number worth acting on: a dependency with no license is not permissive, it is
  legally unusable until someone checks.

`--packages` lists the packages under each license; `--unknown-only` narrows the
view to the unresolved ones.

## Where the data comes from

Two ecosystems declare licenses in the lockfile, so they need **no network**:

| Ecosystem | Source | Coverage |
| --- | --- | --- |
| **Node** | `license` on each `package-lock.json` entry | ~99% in practice |
| **PHP** | `license` array per package in `composer.lock` | complete |

Everything else needs `--online`, which reads the license out of the **same
registry document** the repo lookup already fetches — so it adds no request, and
reuses the [cache](Cache):

| Ecosystem | Registry field |
| --- | --- |
| **Python** | `license_expression` (PEP 639), then `license`, then the trove classifiers |
| **Rust** | the pinned version's `license` in the crates.io response |
| **Ruby** | `licenses` from the version-pinned RubyGems endpoint |
| **Java** | `licenses` from deps.dev |
| **Go** | `licenses` from deps.dev — **the one genuinely extra call**, since Go's repo comes from the module path with no request at all |

### Version matching

A project can relicense between releases — Redis, Terraform, Elasticsearch,
MongoDB and Sentry all did. Reading the license off the *latest* version while
your lockfile pins an older one is therefore wrong in exactly the cases that
matter legally.

So the license is always taken for the **pinned** version: from the versioned
document where the registry offers one (npm, PyPI, RubyGems v2, deps.dev), and by
looking the version up inside the response where it returns all of them
(crates.io, Packagist). Where a version-pinned endpoint has no record of that
exact spelling — a yanked release, or a platform-suffixed gem like
`nokogiri-1.13.9-x86_64-linux` — postmortem falls back to the name-only document
rather than lose the answer entirely.

## SPDX normalization

Registries do not agree on what a license is. npm mostly emits valid SPDX but has
legacy shapes (`{"type":"MIT"}`, a `licenses` array). PyPI's field is prose
written by hand (`Apache 2.0`, `BSD`, `see LICENSE`). Cargo manifests still carry
the pre-SPDX slash form (`MIT/Apache-2.0`). So every value is normalized before
it is trusted.

The rule that governs the output: **an identifier we cannot verify is never
emitted as an SPDX id.** CycloneDX consumers validate `license.id` against the
SPDX list and reject the whole document on a miss, so a wrong guess costs more
than an honest free-text value. When in doubt, postmortem degrades — it does not
invent.

Coverage of the SPDX list is deliberately partial: it has ~600 entries, most of
which never appear in a dependency tree. Anything unrecognised survives as
free text — visible, flagged as non-SPDX, never silently dropped.

Normalization is applied on **every read, including cache hits**. The cache
stores what the registry said, not what postmortem made of it, so improving the
identifier tables benefits every already-cached package instead of being frozen
out until someone clears the cache.

## Policy

```bash
postmortem licenses . --deny AGPL-3.0 --deny SSPL-1.0
postmortem licenses . --allow MIT --allow Apache-2.0 --allow ISC
postmortem licenses . --online --fail-on-unknown
```

| Flag | Description |
| --- | --- |
| `--deny <SPDX>` | Fail if this identifier is present. Repeatable. |
| `--allow <SPDX>` | Permit only these; anything else fails. Repeatable. |
| `--fail-on-unknown` | Fail if any package has no resolvable license. |
| `--online` | Resolve licenses the lockfile does not record. |
| `--omit <dev\|optional>` | See [Dependency scopes](Dependency-Scopes). |
| `--unknown-only` | Show only the unresolved packages. |
| `--packages` | List the packages under each license. |
| `--json` / `-o <FILE>` | Machine output. |
| `--config <FILE>` | A `postmortem.conf` supplying a `[license]` policy. |

### Dual licensing is respected

`MIT OR AGPL-3.0` means *you may take MIT*. So:

- a **denylist** flags a package only when **every** alternative it offers is
  denied — denying AGPL alone does not flag a package that also offers MIT;
- an **allowlist** is satisfied when **any** one alternative is permitted.

Getting this backwards would flag half of crates.io, where dual licensing under
`MIT OR Apache-2.0` is the norm.

### Declarative policy

Put it in `postmortem.conf` and it is auto-loaded from the project directory:

```toml
[license]
deny = ["AGPL-3.0", "SSPL-1.0"]
fail_on_unknown = true
```

CLI flags are **additive** on top of the file, not a replacement — so a stricter
one-off run does not require editing the policy.

## The combination worth knowing

```bash
postmortem licenses . --online --omit dev --deny AGPL-3.0
```

This answers the actual business question — *do I distribute anything under
strong copyleft* — without being blocked by a GPL linter in your dev
dependencies. See [Dependency scopes](Dependency-Scopes) for why `--omit dev`
never drops a package your application also uses.

## JSON

```json
{
  "schema_version": 1,
  "total": 466,
  "unresolved": 1,
  "licenses": [
    { "license": "MIT", "spdx": true, "count": 375, "packages": ["..."] },
    { "license": "(unknown)", "spdx": false, "count": 1, "packages": ["seq-queue@0.0.5"] }
  ],
  "violations": [
    { "package": "copyleft", "version": "1.0.0", "license": "AGPL-3.0", "reason": "denied" }
  ]
}
```

`reason` is `denied`, `not-allowed` or `unknown`.

## In the SBOM

The same data feeds [`sbom`](Sbom), which is where most consumers will read it —
`postmortem sbom . --online` emits a `licenses` array per component. See that
page for the CycloneDX shapes.

## Not covered

- **OS packages.** `system` does not resolve licenses; distro licensing is a
  different model.
- **License compatibility.** postmortem reports what you have and what your
  policy forbids. Whether MIT is compatible with GPL-3.0 in your particular
  distribution is a legal question, not a tool output.
