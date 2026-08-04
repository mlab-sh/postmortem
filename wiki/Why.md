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

## Options

| Flag | Description |
| --- | --- |
| `--no-progress` | Disable the animated progress UI. |
