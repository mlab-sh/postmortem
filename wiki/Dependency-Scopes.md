# Dependency scopes and `--omit`

Most projects ship far less code than they install. Test runners, linters,
bundlers and their transitive trees never reach production, yet they show up in
every count, every risk score and every CVE tally. `--omit` removes them.

```bash
postmortem tree . --omit dev              # what actually ships
postmortem audit . --vulns --omit dev     # a CVE gate that ignores your test runner
postmortem sbom . --omit dev -o sbom.json # an SBOM of the shipped artifact
```

Available on `scan`, `tree`, `audit`, `sbom`, `why` and `diff`. Not on `system`:
OS packages have no development scope.

## The three scopes

Every dependency carries a `scope` in the JSON output:

| Scope | Meaning |
| --- | --- |
| `prod` | Ships with the application — or is reachable from something that does. |
| `dev` | Reachable **only** through a development / test edge. |
| `optional` | Reachable only through an optional edge. Ships when it installs, so it outranks `dev`. |

`--omit` accepts `dev` and `optional`, and is repeatable:

```bash
postmortem tree . --omit dev --omit optional
```

`--omit prod` is deliberately not accepted. Its only possible effect would be to
hide the code that actually runs in production.

## Scope is reachability, not a label

This is the part that matters, and the part most tools get wrong.

A manifest only states the scope of its **direct** dependencies. `jest` being
listed under `devDependencies` says nothing about the ~300 packages underneath
it. So postmortem does not treat the manifest as the answer — it treats it as a
*seed*, then walks the graph:

> A package is `dev` only when **every** path from a root reaches it through a
> development edge. If any production path also reaches it, it is `prod`.

Two consequences, both intentional:

**Nothing that ships is ever hidden.** A package pulled in by both a dev tool and
your application stays `prod` and survives `--omit dev`. A naive "is it under
devDependencies" filter would drop it and quietly shrink your attack surface on
paper only.

**The whole dev subtree goes, not just its root.** Omitting `jest` also omits
everything reachable only through `jest`, which is where the actual volume is.

Packages that no root reaches — a detached lockfile entry, or an ecosystem with
no edges at all — keep the safe default, `prod`. **Unknown means kept, never
hidden.**

## What each ecosystem can tell us

Accuracy is bounded by what the lockfile actually records. Three tiers:

### Complete — the lockfile resolves the dev tree itself

| Ecosystem | Source | Notes |
| --- | --- | --- |
| **PHP** | `composer.lock` `packages` vs `packages-dev` | Composer resolves the dev tree separately and promotes anything also required in production into `packages`. Transitives included. |
| **Python (pipenv)** | `Pipfile.lock` `default` vs `develop` | Pipenv's own resolved split. |
| **Java (Gradle)** | `gradle.lockfile` configuration list | Each line records every configuration that resolved it (`…=testCompileClasspath,testRuntimeClasspath`). Transitives included. |

### Seeded — the manifest classifies direct deps, the graph does the rest

| Ecosystem | Source |
| --- | --- |
| **Node (npm / pnpm / yarn)** | `dependencies` / `devDependencies` / `optionalDependencies`, from the lockfile root entry (npm), `importers:` (pnpm) or `package.json` (yarn) |
| **Rust** | `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, including `[target.'cfg(…)'.…]` variants |
| **Python (poetry)** | `category` (poetry < 1.5) or `groups` (poetry ≥ 1.5) |
| **Ruby** | Gemfile `group :development, :test do … end` blocks and inline `group:` / `groups:` options |
| **Java (Maven)** | `<scope>test</scope>` |

### None — no distinction exists

| Ecosystem | Why |
| --- | --- |
| **Go** | `go.mod` records one module set; test-only imports look exactly like the rest. `--omit dev` is a no-op. |
| **Python (requirements.txt)** | The format has no scope metadata — only the filename convention below. |

## Ecosystem-specific rules worth knowing

**Rust build-dependencies are production.** A build script's dependencies execute
on your build machine with full privileges. They never ship in the binary, but
they are squarely part of the supply chain — omitting them would hide the most
dangerous class of Rust dependency. Only `[dev-dependencies]` is `dev`.

**Maven `provided` and `system` are production.** The artifact is absent from
your package because the container or JDK supplies it at runtime, so the code
still executes in production. Only `<scope>test</scope>` is `dev`.

**Ruby needs the Gemfile.** `Gemfile.lock` records no groups at all — its
`DEPENDENCIES` section is flat. Without a `Gemfile` alongside it, every gem stays
`prod`. A gem in a mixed group (`group :default, :test`) stays `prod`.

**Python requirements files are classified by name**, since the format carries no
metadata. Recognised as `dev`: `requirements-dev.txt`, `requirements_dev.txt`,
`dev-requirements.txt`, `requirements/dev.txt`, and the `test` / `tests` / `lint`
/ `docs` variants of each. Anything else — including a plain `requirements.txt` —
stays `prod`.

**Poetry `groups` wins over `category`.** Poetry 1.5 kept writing the legacy
`category` field for a while; when both are present, `groups` is authoritative.
A package in any non-dev group ships.

## Omitting is always disclosed

An omitted run reports what it dropped:

```
✓ parsed 3 dependencies — 2 of 5 dependencies omitted (2 dev)
```

That line goes through the progress UI, which is suppressed when stderr is not a
TTY — so in CI it would vanish. The fact is therefore **also recorded as a
diagnostic**, which reaches `--json` and `--sarif`:

```json
{
  "diagnostics": [
    { "ecosystem": "*", "kind": "scope_omitted",
      "message": "2 of 5 dependencies omitted (2 dev)" }
  ]
}
```

This follows the same principle as the [graph diagnostics](Tree#diagnostics): a
smaller result must never be mistakable for a cleaner one.

Unlike the other diagnostic kinds, `scope_omitted` does **not** count as graph
incompleteness — it was asked for, so it never degrades an
[`audit`](Audit) verdict or trips a [gate](CI-Gate).

## Interaction with the CI gate

`--omit` runs before the [gate](CI-Gate), so thresholds apply to the filtered
set. This is usually what you want:

```bash
postmortem tree . --online --vulns --omit dev --fail-on-vuln high
```

That fails the build on a High CVE in shipped code, while a CVE in your test
runner does not block the release. Drop `--omit dev` if your threat model
includes the build machine — a compromised dev dependency still executes on
whoever runs the tests.

## JSON

`scope` is emitted on every dependency as of **schema version 3**:

```json
{
  "schema_version": 3,
  "dependencies": [
    { "name": "prod-lib",  "version": "1.0.0", "direct": true,  "scope": "prod" },
    { "name": "shared-lib","version": "1.0.0", "direct": false, "scope": "prod" },
    { "name": "dev-tool",  "version": "1.0.0", "direct": true,  "scope": "dev" },
    { "name": "opt-lib",   "version": "1.0.0", "direct": true,  "scope": "optional" }
  ]
}
```

The bump is additive: a consumer written against schema 2 keeps working and
simply ignores the field.
