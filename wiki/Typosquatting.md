# Typosquatting

A dependency whose name is a near-miss of a popular package is flagged during
[`tree --online`](Tree). The check itself is **fully offline and
deterministic**: the corpora of popular names are compiled into the binary, and
nothing is fetched at scan time.

## Coverage

| Ecosystem | Corpus | Name shape |
| --- | --- | --- |
| **npm** | 5 000 | flat, plus `@scope/name` |
| **PyPI** | 2 000 | flat |
| **crates.io** | 1 200 | flat |
| **RubyGems** | 1 200 | flat |
| **Packagist** | 1 200 | `vendor/name` |
| **Go** | 1 200 | `host/owner/repo` |
| **Maven** | 1 200 | `group:artifact` |

The OS package managers have no corpus and are never flagged — an absent list
returns nothing rather than borrowing another registry's.

Lists come from [ecosyste.ms](https://packages.ecosyste.ms), ranked by downloads
— **except Go and Maven, which publish no download counts**: the API returns
`downloads: null` for every package there, so those two are ranked by
`dependent_packages_count` instead. It measures being *depended upon* rather
than being fetched, which for impersonation targets is arguably the better axis:
a squat aims at a name people type. Rebuild with
`scripts/build-typosquat-corpus.py`; postmortem itself never runs it.

## Each corpus is consulted alone

Cross-checking would be actively wrong. `requests` is the canonical PyPI package
— on PyPI it is silent, while on npm the same string is one edit from npm's own
`request` and is flagged, naming *npm's* package. A shared corpus would report
half of one registry as squatting the other.

## What is flagged

| Kind | Example |
| --- | --- |
| `1 edit away` | `expres` → `express` |
| `transposed` | `recat` → `react` |
| `punctuation variant` | `crossenv` → `cross-env` (the real 2017 attack); `rustdecimal` → `rust_decimal` (2022) |
| `homoglyph` | `l0dash` → `lodash` |
| `unicode confusable` | Cyrillic `е` in `rеact` |
| `popular name under a foreign scope` | `@evil/lodash` |
| `vendor variant` *(Packagist)* | `evilcorp/monolog` → `monolog/monolog` |
| `owner variant` *(Go)* | `boltdb-go/bolt` → `boltdb/bolt` |
| the Maven shape | `com.gogle.guava:guava` → `com.google.guava:guava` |

Distance-2 and looser matches are deliberately excluded: at that radius the
noise exceeds the signal.

## Three registries, three sets of rules

The same edit distance means different things depending on how a registry hands
out names, so the two-part ecosystems do not share a rule set.

**A name that carries its own version is not a near-miss of itself.** Maven and
Go put the version *in* the name — Scala's `_2.12` / `_2.13` cross-build suffix,
a major bump baked into the artifact (`retrofit` → `retrofit2`, `okhttp3`,
`antlr4`), a gopkg.in `.v1` / `.v3`, a `/v2` element, a JDK target
(`kotlin-stdlib-jre7` vs `-jre8`). Two releases of one project are then exactly
one edit apart. Before anything is called a squat, the two names are compared
with their digits removed; if they match, it is a version. On a sample of 1 200
legitimate Maven coordinates just outside the corpus, this rule alone removed
63 of 65 false positives.

**A namespace its owner had to prove is not forgeable.** Maven Central verifies
a groupId against a domain or repository the publisher controls, and nobody but
`github.com/aws` can publish under `github.com/aws`. So two coordinates sharing
a group (or a host + owner) are siblings of one project — `aether-api` and
`aether-spi`, `service/sqs` and `service/sts` — never an impersonation. That
removed the last 2 Maven false positives and 5 of the remaining 9 in Go.

**"Same name, other vendor" reads differently per registry.** On Packagist it is
the squat that matters: one flat namespace, a name claimed once, so a second
vendor publishing `monolog` is impersonating the first. On Maven an artifactId
is unique only *within* its group — `core`, `annotations` and `commons-io` each
sit under several unrelated groups in the corpus alone — so the rule is off
there; it would fire on every one of them.

Measured over 1 200 legitimate packages ranked just below each corpus: **0 of
1 200 flagged on Maven, 2 of 1 200 on Go** (an owner one edit from another owner
publishing the identical repo name, and the `awslabs` / `aws` owner-variant rule
working as designed).

## Two rules that keep it quiet

**A scoped name is judged whole, not by its bare segment.** `@babel/core` is
itself a popular package; comparing only `core` reported it as a near-miss of
`cors`. Under a scope, only *verbatim* reuse of a popular name is flagged — a
scope cannot be forged, so a merely similar name under one carries no
impersonation. This is a deliberate trade: edit-distance there cost far more in
noise than it caught.

**Corpus depth is a false-positive control**, not only a coverage one. Every
entry is a potential target, but it is also a name recognised as *itself*:
`mysql2` (npm rank 2634) and `random-bytes` (rank 4486) are legitimate packages
that a 2 000-entry list flagged as near-misses of `mysql` and `randombytes`.

Measured on a real 466-package npm tree:

| Corpus | False positives |
| --- | --- |
| 182 entries (the original list) | — (too small to reach them) |
| 2 000, bare-segment scoping | 9 |
| 2 000, scoped names judged whole | 2 |
| 5 000, scoped names judged whole | **0** |
