# `postmortem hunt`

An attack drops: keyv, Shai-Hulud, event-stream. The first question is not "is
it bad?", it is **"were we exposed, where, and since when?"** `scan` answers
that for one project, today. `hunt` answers it for every project on the disk,
across their whole git history.

```bash
postmortem hunt event-stream@3.3.6 --in ~/code
postmortem hunt @ctrl/tinycolor@4.1.1 @ctrl/tinycolor@4.1.2 --in ~/code --in ~/work
postmortem hunt --feed compromised.txt --in ~ --json -o hunt.json
postmortem hunt keyv --no-history       # any version, current state only
```

```
hunt 1 target(s) · 1 project(s) found in 2 dirs (2 ms) · 1 with git history · 42 ms total

  ☠ event-stream@3.3.6               1 project(s), 0 still pinned now
      ~/code/app package-lock.json  gone now
        exposed 6d314d00 2018-09-16 → a2f133ec 2018-11-27  (72 d)  in by dev-bob: bump deps
  ✓ flatmap-stream                   never pinned anywhere

  1 project(s) exposed
```

## Targets

| Form | Matches |
| --- | --- |
| `name@1.2.3` | that exact version |
| `@scope/name@1.2.3` | scoped npm package, exact version |
| `name` or `name@*` | any version |
| `--feed FILE` | one target per line: `name@version`, `name,version` or `name version`; `#` starts a comment |

Names compare case-insensitively, with `-`, `_` and `.` treated alike (PyPI's
rule). A leading `v` on a version is ignored (Go, Composer).

## What it reports

For each target and each project that pins it now or ever did:

- **Pinned now:** the versions the lockfile resolves today, read with the same
  parsers as every other command.
- **Installed (npm):** whether `node_modules` holds that version right now. A
  pinned but uninstalled package has not run yet. An installed one has.
- **Exposure windows:** each stretch of the pinning file's first-parent
  history during which the target was pinned. A window has the commit that
  brought the target in (author, subject, date) and the commit that removed it,
  or `HEAD` if it is still there.

Exit code: **1** if any project was exposed, now or in the past. A package
removed last week still ran its install scripts on every machine that
installed it in between. That is when credentials get rotated.

## How it stays fast

1. **Discovery** runs `ignore`'s parallel directory walker. It prunes
   directories that hold dependencies, build output or caches *before*
   descending: `node_modules`, `bower_components`, `target`, `vendor`, `venv`,
   `site-packages`, `dist`, `build`, `Pods`, `DerivedData`, `Library` and every
   dot-directory. A project is any directory holding a lockfile or pinning
   manifest.
2. **Current state** parses one project per core.
3. **History** costs one `git log --first-parent -- <file>` and one
   `git cat-file --batch` stream per pinning file. Every revision is scanned
   once by a single regex compiled from all target names, so a 500-entry feed
   costs about what a single target does.

Measured on a laptop: a whole home directory (4 878 directories, 124 projects,
116 git repositories) in **1.45 s**, 132 ms of it discovery.

## Limits

- History matching is textual rather than parsed, because a revision from years
  ago may predate the formats the parsers read. A name counts when it is bounded
  like a package name, with the version right after it (`name@1.2.3`,
  `name (1.2.3)`, `path v1.2.3`) or on the first `version` line that follows.
- History follows the first parent of the current branch: when a package
  **landed on** the mainline, not when a feature branch first tried it.
- "Installed" is checked for npm only, at the top level of `node_modules`.
