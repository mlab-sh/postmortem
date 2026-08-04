# `postmortem cache`

Manage the on-disk cache that backs the networked paths
([`tree --online`](Online-Resolution), `--vulns`, and [`system --online`](System)).

```bash
postmortem cache <action>
```

## Where it lives

`~/.postmortem/cache/`, as one JSON file per entry, grouped by namespace:

| Namespace | Contents |
| --- | --- |
| `registry/` | package → source-repo resolution (immutable per `name@version`). |
| `repo/` | source-repo stats, keyed by `host/owner/repo`. |
| `languages/` | repo language breakdowns (`--languages`). |
| `npm-meta/` | npm packument provenance (per `name@version`). |

Because a published version's metadata never changes, resolutions are cached
indefinitely; re-runs are near-instant. Each entry records when it was fetched.

## `prune`

Remove cached entries. With no filter it prunes everything.

```bash
postmortem cache prune                    # remove all cached entries
postmortem cache prune --older-than 30    # keep entries fetched in the last 30 days
postmortem cache prune --dry-run          # report what would be removed, delete nothing
```

| Flag | Description |
| --- | --- |
| `--older-than <DAYS>` | Only remove entries older than N days (by file mtime). |
| `--dry-run` | Show what would be removed without deleting. |

The report gives the number of entries removed/kept, bytes freed, and the cache
path.
