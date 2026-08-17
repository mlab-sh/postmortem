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

## `--online` / `--vulns` — assess what the change introduces

A set-diff says *what* moved. These say whether it should worry you:

```bash
postmortem diff ./main ./pr-branch --online --vulns
```

```
+ 2 added
  + istanbul-lib-report@3.0.1 (node)  [risk 90]
      ⚠ dormant-release (1312d gap)
      ⚠ new-publisher
      ⚠ starjacking (istanbuljs/istanbuljs doesn't own it)
  + ms@2.1.2 (node)  [risk 90]
      ⚠ dormant-release (552d gap)
      ⚠ new-publisher

(T_T)  +2 -0 ~0  (1 unchanged)  ⚠ introduces 2 flagged packages, 0 advisories
```

Two rules govern what gets assessed:

**Only what the change introduces** — the additions, and the *new* side of a
version bump. A removed package's risk is moot: it is leaving, which is the good
outcome, and reporting it would argue against a fix. The version being left
behind is likewise ignored.

**The cost scales with the diff, not the tree.** A one-package bump resolves one
package, not five hundred. (`--vulns` still scans the new project's lockfile
whole, because advisories are looked up per file — the results are then filtered
to the introduced set.)

Nothing is assessed without the flags, and an unassessed package carries **no**
`assessment` at all rather than a zeroed one: "not checked" is not "clean".

## Gating a PR

`diff` reports; it does not fail the build. For that, [`tree`](Tree)'s
[gate](CI-Gate) already has `--baseline`, which counts only risk absent from a
recorded snapshot — the same question with an exit code:

```bash
postmortem tree ./main --online --json -o baseline.json
postmortem tree ./pr-branch --online --max-high 0 --baseline baseline.json
```

## JSON

```json
{
  "schema_version": 2,
  "summary": { "added": 5, "removed": 1, "changed": 0, "unchanged": 0 },
  "added":   [{ "ecosystem": "node", "name": "ms", "version": "2.1.2",
                "assessment": { "risk": 90, "signals": ["new-publisher"],
                                "vulnerabilities": [] } }],
  "removed": [{ "ecosystem": "node", "name": "leftpad-clean", "version": "1.0.0" }],
  "changed": [{ "ecosystem": "node", "name": "ms", "from": "2.1.2", "to": "2.1.3" }]
}
```

The ecosystem travels with every name: one project can hold two ecosystems with
a colliding package name, and a consumer must not merge them.

## Options

| Flag | Description |
| --- | --- |
| `--online` | Assess the introduced packages' source-repo reputation and provenance (network). |
| `--vulns` | Report known advisories against the introduced packages (network). |
| `--json` / `-o <FILE>` | Emit the diff as JSON. |
| `--omit <dev\|optional>` | Drop a dependency set. Repeatable. A package reachable from production is always kept — see [Dependency scopes](Dependency-Scopes). |
| `--no-progress` | Disable the animated progress UI. |
