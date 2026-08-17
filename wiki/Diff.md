# `postmortem diff`

Compare two project states and report what changed in the dependency set:
packages **added**, **removed**, or **version-changed**. It answers the question
a reviewer actually has on a lockfile change ("what did this PR pull in?"), and is
the companion to the CI [gate](CI-Gate)'s `--baseline` mode.

```bash
postmortem diff <old> <new>
```

Both arguments are project directories (for example two branches or commits
checked out side by side). Each is resolved with the same offline parsers as
[`tree`](Tree), then the two dependency sets are compared by ecosystem + name.

## Output

```
dependency diff  ./main  →  ./pr-branch

+ 2 added
  + event-stream@3.3.6 (node)
  + flatmap-stream@0.1.1 (node)

- 1 removed
  - leftpad-clean@1.0.0 (node)

~ 1 changed
  ~ react  17.0.2 → 18.2.0 (node)

summary  +2 -1 ~1  (312 unchanged)
```

- `+` **added** (green): present in `new`, absent from `old`.
- `-` **removed** (red): present in `old`, absent from `new`.
- `~` **changed** (yellow): present in both at a different version.

When the two sides resolve to the same dependency set, it prints *no dependency
changes* and nothing else.

## Scope

`diff` is an **offline set-diff** today. Layering online risk / vulnerability
deltas on top (does this change *raise* the risk score, add an unsigned package,
or introduce a known CVE) is the intended next step, and already has a foothold in
the gate's [`--baseline`](CI-Gate) flow.

## Options

| Flag | Description |
| --- | --- |
| `--omit <dev\|optional>` | Drop a dependency set. Repeatable. A package reachable from production is always kept — see [Dependency scopes](Dependency-Scopes). |
| `--no-progress` | Disable the animated progress UI. |
