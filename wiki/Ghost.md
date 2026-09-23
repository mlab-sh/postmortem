# `postmortem ghost`

Every analyzer reads code that exists somewhere. The supply-chain attacks that
hurt most put their payload in exactly one place: the **published tarball**.
event-stream's `flatmap-stream`, ua-parser-js, the xz backdoor's release
tarball. The repository everyone reviewed was clean. The artifact everyone
installed was not.

`ghost` compares the two.

```bash
postmortem ghost                       # direct npm dependencies
postmortem ghost . --all               # transitive too
postmortem ghost . --package left-pad  # just this one
postmortem ghost . --all --json -o ghost.json
```

```
ghost . · published tarball vs source

  ? @types/node@22.20.4   published without a gitHead, and DefinitelyTyped/DefinitelyTyped has no tag for 22.20.4
  ≈ esbuild@0.28.2        4 file(s) differ, nothing unexplained  github.com/evanw/esbuild@609683d89297
  ≈ prettier@3.8.4        53 file(s) differ, nothing unexplained  github.com/prettier/prettier@3.8.4
      ! published from commit fbf300f9d898, which prettier/prettier does not have (unpushed or force-pushed away)
  ✓ dotenv@16.6.1         11 file(s) identical  github.com/motdotla/dotenv@076ba3b6a225

  0 ghost · 1 unverifiable · 2 rebuilt · 1 identical
```

## How it works

For each npm dependency:

1. Read the version manifest from the registry: tarball URL, repository,
   `repository.directory`, and `gitHead`, the commit it was published from.
2. Download the tarball (capped at 50 MiB) and unpack it with the system `tar`.
3. Check out the repository at `gitHead`, shallow. Without one, use the release
   tag: `v1.2.3`, `1.2.3`, `name@1.2.3`, `short@1.2.3`, `short-v1.2.3` or
   `short-1.2.3`.
4. Find the package in the checkout: `repository.directory`, the root, or the
   first `package.json` carrying its name (monorepos).
5. Compare every published file with its source. Line endings are normalized.
   `package.json` is compared by its install hooks only.
6. Run the [scan](Scan) analyzers over **only the files that differ**, and drop
   any finding whose evidence the source also contains.

## Verdicts

| Verdict | Meaning | Exit |
| --- | --- | --- |
| `ghost` ☠ | Code or an install hook in the tarball that the source does not explain. | 1 |
| `unverifiable` ? | No repository on a known host, a private or deleted one, or no commit/tag for the version. **Never read as clean.** | 0 |
| `rebuilt` ≈ | Files differ because a build ran, and nothing in the difference is unexplained. | 0 |
| `identical` ✓ | Every published file matches the source byte for byte. | 0 |

An **install hook** (`preinstall`/`install`/`postinstall`) in the published
`package.json` that the source does not declare is always `ghost`. The one hook
npm writes itself, `install: node-gyp rebuild` for a package with a
`binding.gyp`, is exempt.

## Built packages

Bundles inline third-party code the repo never contains, and minifiers produce
escape tables that look like obfuscation. So the bar depends on where the file
comes from:

| Where | What makes it a ghost |
| --- | --- |
| Hand-written (no build step, not a `dist`-like path) | any finding of medium severity or higher |
| Build output: a build script, a `Makefile`, a bundler or `tsconfig` config (package or repo root), or a `dist/`, `build/`, `esm/`, `cjs/`, `umd/`, `*.min.*` path | high or higher, and obfuscation only when it **executes a decoded blob** (`eval`/`Function` plus base64 or an escape run), the event-stream shape |
| Vendored (`compiled/`, `vendor/`, `third_party/`, `node_modules/`) | critical only |

This is the known limit: a medium-severity payload dropped into a built package's
`dist/` does not trip it. Closing that gap takes rebuilding the package locally
and diffing against the result.

## Notes

- **`gitHead` missing from the repo.** The manifest names a commit the
  repository does not have. That usually means a release published from an
  unpushed working tree, or history rewritten afterwards. It is shown as a note,
  and the comparison falls back to the tag.
- **Unverifiable is common.** DefinitelyTyped never tags `@types/*` releases, and
  many monorepos publish without a `gitHead` or a per-package tag. The reason is
  always printed.

## Requirements and safety

- Needs `git` and `tar`. Both ship with macOS, Linux and Windows 10+.
- The tarball is attacker-controlled. It is size-capped and unpacked by `tar`,
  which refuses `..` and absolute member names. Nothing from it is executed.
- `git` runs with `GIT_TERMINAL_PROMPT=0`, so a private repo fails instead of
  prompting, and with `GIT_LFS_SKIP_SMUDGE=1`.
- Work happens under `~/.postmortem/ghost/<pid>/`. Each package's directory is
  deleted as soon as it has been compared, and the whole workspace at exit.

## Output

`--json`, `--webhook` and `-o/--output` behave as in every other command.
The JSON carries per package: `verdict`, `repo`, `git_ref`, `reason`, `notes`,
`identical_files`, `modified`, `only_in_tarball`, `scripts`, `has_build_step`
and the unexplained `findings`.
