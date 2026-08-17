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
| `--json` / `-o <FILE>` | Emit the paths as JSON. |
| `--omit <dev\|optional>` | Drop a dependency set. Repeatable. A package reachable from production is always kept — see [Dependency scopes](Dependency-Scopes). |
| `--no-progress` | Disable the animated progress UI. |
