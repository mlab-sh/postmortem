# Dart / Flutter (pub)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix.

## Manifests

| File | Notes |
| --- | --- |
| `pubspec.lock` | Every resolved package, its kind (`direct main` / `direct dev` / `direct overridden` / `transitive`) and its source. |
| `pubspec.yaml` | Accepted as a target; the lockfile alongside it is what is read. |

`sdk` packages (`flutter`, `flutter_test`) and `path` packages are the toolchain
and the project's own code: they are not reported as dependencies.

## Graph - flat

`pubspec.lock` records no edges: the graph is **flat** and a `flat_graph`
diagnostic is emitted. The direct/transitive split is exact, though - the
lockfile states it.

## Dependency scopes

Seeded: `direct dev` is dev, every other package prod. With no edges, a
transitive package reached only through dev tools cannot be told apart and
stays prod (the safe default). See [Dependency scopes](Dependency-Scopes).

## Online resolution

- **Registry:** **pub.dev** - `pub.dev/api/packages/<name>/versions/<version>`
  → `pubspec.repository`, then `pubspec.homepage`.
- A **git** package resolves to its own `url`, never to the same-named pub.dev
  package (often the upstream of the fork in use).
- A package from a **private pub server** is not looked up on pub.dev at all:
  it resolves to no repository (**unchecked**) rather than to a stranger's.

## Vulnerabilities

Through vuln.mlab.sh, which reads `pubspec.lock` as is (OSV `Pub`).

## Not covered yet

- Licenses (the pub.dev version API does not carry one).
- Source-code scanning of Dart.
- Typosquatting (no corpus).
