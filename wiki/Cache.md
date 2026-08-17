# `postmortem cache`

Manage the on-disk cache that backs the networked paths
([`tree --online`](Online-Resolution), `--vulns`, and [`system --online`](System)).

```bash
postmortem cache info                     # what's in there
postmortem cache path                     # where it is
postmortem cache prune --stale            # drop entries an upgrade invalidated
```

## Where it lives

`~/.postmortem/cache/`, as one JSON file per entry, grouped by namespace:

| Namespace | Contents |
| --- | --- |
| `registry/` | package → source-repo resolution (immutable per `name@version`). |
| `repo/` | source-repo stats, keyed by `host/owner/repo`. |
| `repo-pkgname/` | package-name → repo lookups that needed a second hop. |
| `languages/` | repo language breakdowns (`--languages`). |
| `npm-meta/` | npm packument provenance (per `name@version`). |
| `vuln/`, `vuln-scan/` | advisory lookups (`--vulns`), keyed by package and by lockfile content-hash. |

Because a published version's metadata never changes, resolutions are cached
indefinitely; re-runs are near-instant.

## Record format and versioning

Every entry is stored inside an envelope:

```json
{ "v": 1, "fetched_at": 1786988285, "data": { "repo": null } }
```

`v` is the **record format version**, and it is what makes "cache forever" safe
to evolve. When postmortem changes the shape of something it caches, it bumps
that number; entries written by any other version are treated as a **miss** and
deleted, so the data is refetched instead of misread.

This is not belt-and-braces. Without the version check, adding a field to a
cached struct is silently destructive: serde fills a missing `Option` field with
`None` **even without `#[serde(default)]`**, so every pre-existing entry would
deserialize *successfully* and report the new field as absent — permanently,
since nothing ever expires it. You would get a cache full of plausible, wrong
answers with no error anywhere.

An entry is recognised as current only if it has both the right `v` **and** the
`data` wrapper. Some payloads carry their own top-level fields — `repo/` records
have a `fetched_at` of their own — so matching on `v` alone could mistake an old
bare payload for a current record.

Invalidation is **lazy by default**: stale entries are dropped as they are
touched, so an upgrade costs nothing up front and each entry is refetched once,
on demand. `cache prune --stale` does the same sweep eagerly.

## `info`

Entries, size and age per namespace, plus how many entries an upgrade has
invalidated.

```
cache  /Users/you/.postmortem/cache
record format v1

  NAMESPACE       ENTRIES       SIZE     STALE  NEWEST
  languages            58     6.0 KB         -  2h ago
  npm-meta              1      186 B         -  just now
  registry            126     4.8 KB       125  just now
  repo                 59     6.8 KB         -  2h ago

  244 entries · 17.8 KB · oldest 13d ago · newest just now

⚠ 125 entries predate record format v1 — they are refetched as they are
  touched, or run `postmortem cache prune --stale` to sweep them now
```

`STALE` counts entries from another record format. They are harmless — they are
never served as data — and cost only a refetch the next time each is needed.

## `path`

Prints the cache directory and nothing else, so it composes:

```bash
du -sh "$(postmortem cache path)"
rm -rf "$(postmortem cache path)"
```

Exits 2 if there is no `$HOME` to derive it from.

## `prune`

Remove cached entries. With no filter it prunes everything.

```bash
postmortem cache prune                    # remove all cached entries
postmortem cache prune --older-than 30    # keep entries fetched in the last 30 days
postmortem cache prune --stale            # only entries from an older record format
postmortem cache prune --dry-run          # report what would be removed, delete nothing
```

| Flag | Description |
| --- | --- |
| `--older-than <DAYS>` | Only remove entries older than N days (by file mtime). |
| `--stale` | Only remove entries written by a different record format version. |
| `--dry-run` | Show what would be removed without deleting. |

Filters combine: `--stale --older-than 30` removes only entries that are both
from an older format and older than 30 days.

The report gives the number of entries removed/kept, bytes freed, and the cache
path.
