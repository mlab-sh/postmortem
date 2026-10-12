# JVM (Maven / Gradle / sbt / Leiningen)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix. Dependency identity on
the JVM is `groupId:artifactId`.

## Manifests

| File | Notes |
| --- | --- |
| `pom.xml` | Maven - direct `<dependencies>` (BOM imports skipped). |
| `build.gradle` / `.kts` | Gradle - `group:artifact:version` strings. |
| `build.sbt` + `project/*.scala` | **Scala / sbt** - declared dependencies (see below). |
| `project.clj` | **Clojure / Leiningen** - declared dependencies (see below). |

sbt and Leiningen publish Maven coordinates, so their dependencies are
reported as `java` (purl `pkg:maven`), detected as `scala` / `clojure`. Neither
has a lockfile: like `pom.xml`, the graph is the **declared** set, flat.

### sbt

A dependency is `org %% artifact % version [% config]`, each part a string or a
`val`:

- `%%` appends the Scala binary version from `scalaVersion` (`_2.13`, `_3`;
  sbt 1's default `_2.12` when unset). `%%%` (Scala.js) is read as `%%`.
- An identifier resolves to the nearest `val` above it in the same file (which
  is how `object chess: val version = ...` blocks work), then to a `val` in any
  build file. Comments are ignored. An unresolvable version is `managed`; an
  unresolvable org or artifact (`s"flexmark-$ext"`) is dropped, not guessed.
- `% Test` / `% "test"` is dev; `% "provided"` stays prod.
- `project/plugins.sbt` (build plugins) is not read.

### Leiningen

`project.clj` is read, never evaluated. `:dependencies` (a bare `ring` is
`ring:ring`; `:scope "test"` is dev), plus `:profiles` - every profile but
`:provided` is dev. `:managed-dependencies` supplies missing versions; `:plugins`
are not read. `deps.edn` (tools.deps) is not supported yet.

## Vulnerabilities

Through vuln.mlab.sh: `pom.xml` and `gradle.lockfile` are uploaded as is;
`build.sbt` and `project.clj` are sent as OSV `Maven` coordinates.

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

### Clojars and JitPack

When deps.dev does not know an artifact (404), postmortem asks **Clojars**
(`clojars.org/api/artifacts/<group>/<artifact>` → `scm.url`, `homepage`,
licenses - the latest release's). A **JitPack** coordinate names its GitHub repo
(`com.github.<user>.<repo>:<module>`, `com.github.<user>:<repo>`) and resolves
to it last.

### Gotcha

An artifact whose SCM is on an unsupported host (and has no GitHub link) resolves
to *no repository* (**unchecked**).

## Typosquatting

Covered since the Maven corpus was added — 1 200 coordinates ranked by dependent
count, `group:artifact` matched whole. Maven's rules are its own: a name
carrying its version (`enumeratum_2.13`, `retrofit2`) is not a near-miss of
itself, and two artifacts sharing a groupId are siblings, because Central
verifies a groupId against a domain its publisher controls. The Packagist
"same name, other vendor" rule is deliberately **off** here — an artifactId is
unique only within its group, so `core` and `annotations` live under dozens.
See [Typosquatting](Typosquatting).
