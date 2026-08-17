# Java (Maven / Gradle)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix. Dependency identity on
the JVM is `groupId:artifactId`.

## Manifests

| File | Notes |
| --- | --- |
| `pom.xml` | Maven - direct `<dependencies>` (BOM imports skipped). |
| `build.gradle` / `.kts` | Gradle - `group:artifact:version` strings. |

## Graph - flat

Like Go, transitive edges aren't reconstructed offline; the graph is **flat**
and a **diagnostic** is emitted.

## Licenses

Needs `--online`, from deps.dev, which is already version-pinned and returns SPDX
identifiers. See [Licenses](Licenses).

## Dependency scopes

The two build systems differ sharply:

- **Maven** - `<scope>test</scope>` on a direct dependency. `provided` and
  `system` stay production: the container or JDK supplies the jar at runtime, so
  the code still executes in production.
- **Gradle** - the lockfile records every configuration that resolved each
  coordinate (`...=testCompileClasspath,testRuntimeClasspath`), so scope is known
  for **transitives too**, despite the graph itself being flat.

See [Dependency scopes](Dependency-Scopes).

## Online resolution

- **Registry:** **deps.dev** -
  `api.deps.dev/v3/systems/maven/packages/<group%3Aartifact>/versions/<version>`
  → the `links` array, preferring the `SOURCE_REPO` label. This avoids parsing
  Maven POM XML.

### Apache gitbox mirror

Many Apache artifacts report `gitbox.apache.org` (a GitWeb frontend with no
stats API) as their SOURCE_REPO. postmortem rewrites it to the GitHub mirror:
`gitbox.apache.org/repos/asf?p=commons-lang.git` → `github.com/apache/commons-lang`.

### Gotcha

An artifact whose SCM is on an unsupported host (and has no GitHub link) resolves
to *no repository* (**unchecked**).
