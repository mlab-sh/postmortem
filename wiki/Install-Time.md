# Install-time execution

A dependency can run code the moment you install it, before you have read a line
of it. That is the vector behind event-stream, ua-parser-js and node-ipc, and it
is the one place where scanning *after the fact* is too late.

Three commands cover it, and they protect at three different moments. Being
clear about which is which matters more than any of them individually.

| | Blocks what | Has the payload run? |
| --- | --- | --- |
| npm `allowScripts` | the script executing | **no** — the only real gate |
| [`postmortem scripts`](#postmortem-scripts) | nothing — it informs the decision | not yet |
| [`postmortem hook`](#postmortem-hook) | the *commit* of a bad lockfile | **yes**, on your machine |
| [`postmortem watch`](#postmortem-watch) | nothing — it reacts | **yes** |

## npm already withholds the execution

npm 11 stopped running dependency lifecycle scripts by default:

```
npm warn allow-scripts 1 package has install scripts not yet covered by allowScripts:
npm warn allow-scripts   some-pkg@1.0.0 (postinstall: …)
npm warn allow-scripts Run `npm approve-scripts <pkg>` to review
```

Approvals are recorded in `package.json` as `"allowScripts": { "pkg": true }`.

That closed the execution hole. postmortem does **not** reimplement it — two
sources of truth for "may this run" would be worse than one. What npm leaves
open is the decision itself: it tells you *that* seven packages want to run code,
and nothing about whether any of them should.

## `postmortem scripts`

```bash
postmortem scripts .
```

```
install scripts  .

  3 package(s) execute code at install time — 1 awaiting approval

  ✗ node-ipc@9.2.1       pending   references network/exec primitives
  · esbuild@0.21.5       approved  script read, nothing flagged
  ? unrs-resolver@1.12.2 pending   script not on disk — not checked

  to approve the quiet ones: npm approve-scripts esbuild
```

**Which packages run code** comes from the lockfile — npm records
`hasInstallScript` per entry — so the decision list works with nothing installed.
**What the script does** needs the script, which lives in `node_modules`; without
it that column reads `not checked`, never "looks fine". An unread script is not a
clean one.

### Approvals rot, and that is the part npm cannot catch

`allowScripts` records a *name*. Not a version, not a hash. A package you
approved last year publishes a new release with a different script, and the
approval carries over silently. So approved packages are still analyzed:

```
⚠ 1 approved package(s) have a script that looks hostile now — an approval
  records a name, not a version, so it carries across releases
```

Those approvals also show up in [`postmortem allowlist`](Allowlist) alongside
the project's other suppressions, because they suppress the same way.

### Other ecosystems have no gate at all

Python's `setup.py` runs arbitrary code with nothing to withhold it; the same
goes for gem extensions and composer scripts. Those are reported as `runs`
rather than `pending` — saying "pending" would imply an approval step that does
not exist.

### Exit codes

| Exit | When |
| --- | --- |
| `1` | A script looks hostile, or `--fail-on-pending` and something awaits approval. |
| `0` | Otherwise. Merely-pending does not fail by default: a fresh project has everything pending, and that is not a finding. |

## `postmortem hook`

```bash
postmortem hook install     # write .git/hooks/pre-commit
postmortem hook status
postmortem hook uninstall
```

**This does not stop a malicious install script.** By the time git runs a
pre-commit hook, `npm install` has finished and anything it was going to execute
has executed. What it stops is that bad lockfile reaching the rest of the team.

The generated hook:

- **runs only when a manifest or lockfile is staged** — every other commit costs
  nothing, because a hook that adds seconds to every commit gets deleted;
- **runs offline** by default (`scan . --severity high`), configurable with
  `--run`;
- **exits 0 when postmortem is not on PATH**, so a colleague without it installed
  is not blocked.

It **never clobbers**. An existing hook is somebody's work, so installing over
one is refused, and husky / lefthook / pre-commit are named so you add postmortem
to their config instead. `--force` takes the file over. `uninstall` refuses to
delete a hook postmortem did not write.

And it is not a control: `git commit --no-verify` skips every hook, and hooks
live in `.git/hooks`, which is not cloned. The [CI gate](CI-Gate) is the control.

## `postmortem watch`

```bash
postmortem watch . --interval 2
```

Re-runs a scan whenever a lockfile changes. A **feedback loop, not a gate** — it
reacts after an install has finished. Add a dependency, see within seconds what
came with it.

Implemented by polling `stat` on the project's lockfiles. Pulling in a
filesystem-notification crate and its transitive tree so a supply-chain scanner
could watch three files would be exactly what this tool flags in other people's
projects. Size *and* mtime are compared, since a rewrite can land inside a
filesystem's mtime granularity.

Only the project root is watched, not the tree: a recursive watch would fire on
every install that touched `node_modules` without changing the project at all.
