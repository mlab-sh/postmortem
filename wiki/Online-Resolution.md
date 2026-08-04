# Online resolution

`--online` is the **only networked part of postmortem**. For each unique
dependency it:

1. asks the ecosystem's **registry** for the source repository
   (npm's `repository`, PyPI's `project_urls`, crates.io's `repository`, …),
2. resolves it to a `host/owner/repo` and pulls **reputation stats** from that
   host (stars, created-at, last activity, archived, primary language),
3. scores it against risk thresholds and surfaces the suspicious ones.

See [Ecosystems & Hosts](Ecosystems-and-Hosts) for the registry/host matrix.
Everything is cached under `~/.postmortem/cache/` — see [Cache](Cache).

## Risk signals

| Signal | Tier | Points |
| --- | --- | --- |
| `typosquat of <pkg>` | High (red) | 45 |
| `install-script-added` *(npm)* | High | 40 |
| `recently-created (Nd ago)` | High | 40 |
| `low-stars (N★)` | High | 30 |
| `archived` | Medium (amber) | 30 |
| `new-publisher` *(npm)* | Medium | 25 |
| `stale (Nd idle)` | Medium | 20 |
| `dormant-release (Nd gap)` *(npm)* | Medium | 20 |
| `no-repository` / `resolve-failed` / `stats-*` | Info (unchecked) | 0 |

- **Reputation** signals come from the source repo's stats vs. your
  [thresholds](Configuration) (`min_stars`, `recent_days`, `stale_days`).
- **Provenance** signals (`typosquat`, `install-script-added`,
  `dormant-release`, `new-publisher`) are npm-specific today — the typosquat
  corpus and version anomalies come from the npm packument.
- **`no-repository`** means "we couldn't find a source repo to assess" — an
  *absence of information*, so it's counted as **unchecked**, not suspicious.

## The `risk:dep` score

Every node shows a **`(risk:dep)`** pair, each `0–100`:

- **`risk`** — the package's *own* risk, summed from its signal points (capped).
- **`dep`** — its *dependency-subtree* risk: distinct flagged deps weighted by
  severity. Platform/scope splits of the same module (e.g. `@napi-rs/nice-*`)
  don't inflate it.

Coloring: a package flagged on its own is red/amber; a **clean package that drags
in a rotten tree** (high `dep`) is painted **blue**. The closing *gochi's recap*
aggregates the whole forest into `overall risk N · dep M` plus a headcount of
high-risk / suspicious / unchecked packages.

## `--languages`

By default the node shows the repo's **primary language** (free — GitHub returns
it in the repo object): `express@4.18.2 ★66000 (0:0) (JavaScript)`.

`--languages` fetches the full breakdown (one extra, **cached**, `/languages`
call per repo — paid once per repo, ever):

```
ripgrep@14.1.0 ★66000 (0:0) (Rust:95.0|Python:2.4|Shell:1.9|Other:0.7)
```

- `(Lang)` — primary only (GitHub, free).
- `(L1:%|L2:%|Other:%)` — full breakdown (`--languages`).
- `(?)` — a repo resolved but the host reported no language (e.g. GitLab/Codeberg
  without `--languages`).

## Tokens & rate limits

Without a token, GitHub's anonymous API is **60 requests/hour** — the tightest
budget, so postmortem fans out gently (2 workers) and wide (8) with a token.
GitLab and Codeberg resolve anonymously for public repos. See
[Configuration](Configuration).
