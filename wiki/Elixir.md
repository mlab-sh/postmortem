# Elixir / Erlang (Hex)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix.

## Manifests

| File | Notes |
| --- | --- |
| `mix.lock` | Every resolved package with its own dependencies: **full graph**. |
| `mix.exs` | `defp deps` gives the direct set; `only:` without `:prod` marks a dev/test dependency. Best-effort (read, never evaluated). |

The lock's key is the OTP app name; the **package** name (what Hex and OSV know
it by) is what is reported. A package from a private Hex organisation is
reported as `org/pkg`, as its purl spells it.

## Sources

- **hex** - a Hex package, with its outer checksum kept as integrity.
- **git** - `{:git, url, rev, ...}`: the version is the locked revision, and the
  package resolves to that repo, never to a same-named Hex package.

## Dependency scopes

Seeded from `mix.exs` (`only: [:dev, :test]` is dev), then propagated over the
graph. See [Dependency scopes](Dependency-Scopes).

## Online resolution

- **Registry:** **hex.pm** - `hex.pm/api/packages/<name>` → `meta.links`
  (repo-looking labels first: GitHub, Source, …) and `meta.licenses`. Hex
  publishes both per package, not per release: they are the **latest**
  release's.
- A private organisation's package is never looked up on the public API.
- hex.pm allows 100 anonymous requests a minute. A larger project waits for the
  window the server announces (once, at most a minute) instead of losing the
  rest of its packages.

## Vulnerabilities

Through vuln.mlab.sh, which reads `mix.lock` as is (OSV `Hex`, EEF and GHSA
advisories).

## Not covered yet

- Source-code scanning of Elixir / Erlang (`deps/` is not read).
- Typosquatting (no corpus).
