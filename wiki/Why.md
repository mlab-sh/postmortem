# `postmortem why`

Explain why a package is in the tree: the dependency paths from it back up to the
direct dependencies, like `npm why` / `cargo tree -i`. Answers "what pulled this
in?" when you spot a suspicious package in a [`scan`](Scan), [`tree`](Tree), or
[`audit`](Audit).

```bash
postmortem why <package> <path>
```

## Output

```
why  flatmap-stream  (in ./myproject)

flatmap-stream@0.1.1
  └─ required by event-stream@3.3.6  [direct]
```

- The target is shown once per installed version.
- Each line walks one step up the `required by` chain, ending at a **[direct]**
  dependency (a root of the tree).
- When a package is installed at several versions, or reached through several
  paths, each is listed.
- Cyclic edges are broken (a node is never revisited within one path), so the walk
  always terminates.

If the package isn't in the graph, `why` says so and stops.

## `--blast` — what a compromise would reach

`why` answers *how did this get here*. `--blast` answers *what happens if it
turns hostile tomorrow* — the question that decides whether you act on a signal
or file it.

```bash
postmortem why brace-expansion . --blast
```

```
blast radius  brace-expansion  (in .)

  installed    1.1.12, 1.1.15, 2.0.2
  reach        27 of 466 packages depend on it (6%)
  ships        yes — prod (it is in the shipped artifact)
  runs         runtime only — executes when the code is called
  entered via  bcrypt@5.1.1, ejs@3.1.10, jest@30.4.2

  if compromised, it reaches
    • the running application, and whatever it can reach in production

(@_@)  brace-expansion ships to production and 27 package(s) depend on it —
       a compromise reaches your users
```

### Position is the ceiling; current code is only a floor

The report has two sections, and the split is the whole point.

**`if compromised, it reaches`** follows from *where the package sits*. An
install hook executes on every machine that installs, with that machine's
environment — CI secrets, cloud credentials, the developer's SSH agent. That is
true regardless of what the code does today, and a hostile version inherits all
of it.

**`what its current code does`** is the sensitive APIs the published code already
calls. It is a **lower bound, not a limit** — a package that reads no files today
can read every file tomorrow. The output says so explicitly, because presenting
it as the limit would be the dangerous mistake.

### Positions, worst first

| Position | Reach |
| --- | --- |
| **Install hook** | Every machine that installs — CI runners and laptops — before any review or test runs. The highest-leverage position there is; scope does not soften it, a dev-only package with a hook still runs everywhere. |
| **Ships to production** | The running application and whatever it can reach. |
| **Dev/test, no hook** | The build machine only, and only when the tooling that pulls it in actually runs. |

### "unknown" is a real answer

Most ecosystems keep dependencies outside the project — Rust in
`~/.cargo/registry`, Ruby in the bundle path, Go in the module cache — so a
lockfile-only scan reads none of their code:

```
runs  unknown — dependency code not on disk, so not checked
```

That is deliberately **not** reported as "runtime only". Install-time execution
is the highest-leverage thing to be wrong about, so a clean-looking verdict
nobody measured is exactly what this refuses to print. Install the project's
dependencies and re-run to settle it.

## JSON

```json
{
  "schema_version": 1,
  "package": "flatmap-stream",
  "installed": [
    { "name": "flatmap-stream", "version": "0.1.1", "direct": false, "ecosystem": "node",
      "paths": [[{ "name": "event-stream", "version": "3.3.6" }]] }
  ]
}
```

Paths are grouped per **installed version**, because "why is this here" has a
different answer per version — which is the case you read this command for. Each
path lists what lies *above* the target, starting at its parent. A package absent
from the graph yields `installed: []` and exit 0: not being there is a valid
answer, not a failure.

## Options

| Flag | Description |
| --- | --- |
| `--blast` | Report the blast radius instead of the paths. |
| `--json` / `-o <FILE>` | Emit the paths (or the blast radius) as JSON. |
| `--omit <dev\|optional>` | Drop a dependency set. Repeatable. A package reachable from production is always kept — see [Dependency scopes](Dependency-Scopes). |
| `--no-progress` | Disable the animated progress UI. |
