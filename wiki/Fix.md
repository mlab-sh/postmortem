# `postmortem fix`

Every other command answers *what is wrong*. This one answers *what do I edit*.

```bash
postmortem fix .
postmortem fix . --omit dev          # only what ships
postmortem fix . --json -o plan.json
```

```
fix  .

  31 advisories across 10 packages

  CRIT  tar@6.2.1  →  7.5.21
        · GHSA-34x7-hfp2-rc4v  node-tar Vulnerable to Arbitrary File Creation…
        · GHSA-83g3-92jg-28cx  Arbitrary File Read/Write via Hardlink Target…
        pulled in by bcrypt@5.1.1
        override in package.json (npm) — or "resolutions" for yarn, "pnpm.overrides" for pnpm
          "overrides": { "tar": "^7.5.21" }

(@_@)  10 of 10 fixable by upgrading
```

Always looks up advisories — a fix plan without them would have nothing to plan.

## The target clears *every* advisory

A package usually carries more than one. The target is the **highest** of their
individual fix versions, not the lowest: taking the lowest would clear one and
leave another open, which makes the advice worse than none.

Targets are per version line. Two copies of `brace-expansion` in one tree get
different answers:

```
brace-expansion@2.0.2   → 2.1.4
brace-expansion@1.1.12  → 1.1.18
```

Recommending `2.1.4` to the `1.1.12` copy would be a major upgrade dressed up as
a patch.

## Direct vs transitive

**A direct dependency** is yours to move, so the instruction is exact:

```
HIGH  lodash@4.17.15  →  4.18.0
      direct — npm install lodash@^4.18.0
```

**A transitive dependency** is pinned by whatever pulls it in. postmortem names
those ancestors — that is a fact read from the resolved graph — and offers the
**override**, which is exact because it does not depend on anyone else's
constraints.

What it deliberately does **not** do is claim which ancestor release accepts the
fix. Answering that needs every candidate version's declared constraints: a
package-manager resolution problem, a great deal of network traffic, and a wrong
answer sends someone chasing an upgrade that cannot work.

An override is a real tool with a real cost — it forces a version the parent
never declared support for. The output says so, because the honest sentence is
"this will clear the advisory, and you should run your tests".

| Ecosystem | Direct | Override |
| --- | --- | --- |
| Node | `npm install pkg@^X` | `overrides` / `resolutions` / `pnpm.overrides` |
| Python | `pip install --upgrade 'pkg>=X'` | `constraints.txt` |
| Rust | `cargo update -p pkg --precise X` | `[patch.crates-io]` |
| Ruby | `bundle update pkg --conservative` | `Gemfile` pin |
| PHP | `composer require pkg:^X` | `require` pin |
| Go | `go get pkg@vX` | `require` (highest wins) |
| Java | — | `<dependencyManagement>` |

OS packages (`brew`, `apt`, `dnf`, `pacman`, `apk`) get their manager's upgrade
command instead.

## Advisories with no fix

Some have no published fix. Those are marked `✗`, the package is reported as **not
actionable**, and the count is called out:

```
⚠ 3 advisories have no published fix — an upgrade cannot clear them
```

A package with one unfixed advisory still shows a target for the rest, but is
excluded from the "fixable" count — upgrading it would silently leave one open.

## Nothing is written

The plan is printed, never applied. Editing a manifest is a decision, and the
snippets are emitted ready to paste. A test pins this.

## Exit codes

| Exit | When |
| --- | --- |
| `0` | Nothing outstanding, or `--no-fail`. |
| `1` | Advisories remain — so it drops into CI as a blocking step. |
| `2` | No supported ecosystem found. |

An ecosystem the advisory API cannot read is reported as **unassessed**, not
clean.

## Options

| Flag | Description |
| --- | --- |
| `--omit <dev\|optional>` | Drop a dependency set. Repeatable — see [Dependency scopes](Dependency-Scopes). |
| `--json` / `-o <FILE>` | Emit the plan as JSON. |
| `--no-fail` | Exit 0 even with advisories outstanding. |
| `--no-progress` | Disable the animated progress UI. |
