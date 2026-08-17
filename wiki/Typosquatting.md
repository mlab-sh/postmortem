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
| **Go** | curated | `host/owner/repo` |

Java (`group:artifact`) and the OS package managers have no corpus and are never
flagged — an absent list returns nothing rather than borrowing another
registry's.

Lists are the most-downloaded packages per registry, newest first, from
[ecosyste.ms](https://packages.ecosyste.ms). Rebuild them with
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

Distance-2 and looser matches are deliberately excluded: at that radius the
noise exceeds the signal.

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
