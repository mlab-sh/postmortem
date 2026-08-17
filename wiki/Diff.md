# `postmortem diff`

Compare two project states and report what changed in the dependency set:
packages **added**, **removed**, or **version-changed**. It answers the question
a reviewer actually has on a lockfile change ("what did this PR pull in?"), and is
the companion to the CI [gate](CI-Gate)'s `--baseline` mode.

```bash
postmortem diff <pr-url>                # both sides from a GitHub PR
postmortem diff <old> <new>
```

Either give it two project directories (for example two branches checked out
side by side), or a single GitHub pull-request URL and it works out both sides
itself. Each side is resolved with the same offline parsers as [`tree`](Tree),
then the two dependency sets are compared by ecosystem + name.

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

## From a GitHub pull request

Give it the URL and it works out both sides itself:

```bash
postmortem diff https://github.com/owner/repo/pull/42
postmortem diff https://github.com/owner/repo/pull/42 --online --vulns
```

```
dependency diff  master (949f18e2)  →  dependabot/cargo/execute-0.3.0 (e6ac6ce0)

~ 4 changed
  ~ execute 0.2.15 → 0.3.0 (rust)
  ~ execute-command-macro 0.1.11 → 0.3.0 (rust)
  ...
```

The URL forms from the review UI all work — with or without a scheme, with a
trailing `/files`, with a `#discussion_r…` anchor.

**Only the manifests and lockfiles are fetched, never the repository.** A
dependency diff needs nothing else, and cloning a large repo twice to read two
JSON files would dominate the runtime. Each side costs one tree listing plus one
download per manifest, so a typical project is a handful of requests and a few
seconds.

**Forks are handled transparently.** GitHub keeps a PR's head commit reachable
from the *base* repository, so both sides are read from there — the fork's name
is never needed, and a deleted fork does not break the lookup. When the head does
come from a fork it is labelled, so you know whose code you are reading:

```
master (b671e53c)  →  fix-terminal-format-controls [contributor/bat] (42276c13)
```

Uses the `github_token` from [configuration](Configuration) when present. Without
one the anonymous GitHub limit is 60 requests/hour, which a few PRs will exhaust;
the error says so. The `github` and `github_raw` [endpoints](Configuration#corporate-networks---network)
are overridable, so this works against GitHub Enterprise.

Two caveats worth knowing:

- The comparison is the **base branch tip vs the PR head**, which is what the API
  reports — not a three-dot merge-base diff. On a PR whose base has moved a long
  way, some of the difference belongs to the base branch rather than to the PR.
- A repository whose tree is too large for one listing gets a warning saying that
  manifests below the cut are missing, rather than a silently partial diff.

Only GitHub is supported. A GitLab merge-request URL is not recognised and falls
through to being treated as a path.

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
