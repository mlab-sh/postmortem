# Performance

How postmortem spends its time, what runs in parallel, and the rules that keep
the answers identical while it does. Useful if you run it over large trees or in
CI, and required reading before touching the analysis pipeline or the resolver.

## Measured

M-series laptop (10 cores), warm page cache, best of three. The Node project
has 67 160 files in `node_modules`, 837 unique npm packages.

| command | v2.6.0 | v2.7.0 | |
|---|---|---|---|
| `scan` | 7.67 s | 1.37 s | 5.6× |
| `audit` | 5.75 s | 1.16 s | 5.0× |
| `scripts` | 5.42 s | 0.31 s | 17× |
| `why --blast <pkg>` | 5.58 s | 0.22 s | 25× |
| `tree --online`, registry cache empty, no GitHub token | 140.4 s | 6.1 s | 23× |
| `system` — apt (Ubuntu 24.04) | 2.83 s | 1.30 s | 2.2× |
| `system` — dnf (Fedora 41) | 1.44 s | 0.47 s | 3.0× |
| `system` — pacman (Arch) | 1.30 s | 0.80 s | 1.6× |
| `system inspect sudo` — pacman | 1.69 s | 0.22 s | 7.7× |
| `system inspect libarchive --deep` (4 repos) | 13.0 s | 5.5 s | 2.4× |
| `tree` — poetry.lock, 3 060 packages | 6.98 s | 0.23 s | 30× |
| `tree` — Cargo.lock, 3 060 packages | 0.61 s | 0.04 s | 15× |

Every one of these was checked against v2.6.0 for identical output on real
projects — same dependency sets, same findings, same exit codes — except for
the corrections listed in the changelog (IOC line numbers, detection fixes).

## Where the time goes

**Offline commands are bound by the kernel, not the CPU.** Once the analysis
runs on every core, a scan of a large `node_modules` spends most of its time in
`open` and `read`. The design goal is therefore *each file listed once, read
once*:

- **One walk per project root.** `util::Listing` walks the root once with
  `ignore`'s parallel walker, keeps the readable files (regular files and
  symlinked files, within the 1 MiB cap) and sorts them by path. Every analyzer
  selects its files from that list — a subdirectory such as `node_modules` is a
  contiguous range of it, so it is never walked again.
- **One read per file.** The content pass (IOC, obfuscation, sensitive-API)
  also runs the behaviour markers on the `node_modules` JavaScript it reads,
  instead of a second pass reading the same files.
- **Every analyzer at once.** The analysis units run concurrently
  (`run_steps`), and the two heavy ones fan out further over a shared-cursor
  pool (`par_scan`), one worker per core.
- **Multi-pattern search.** The behaviour, sensitive-API and obfuscation
  markers are matched by one Aho-Corasick automaton per language instead of one
  substring scan per marker; the IOC regexes are ASCII-only so the lazy DFA
  never falls back to the slow engine on non-ASCII text.

**Online commands are bound by round trips.** The resolver runs 16 workers,
and the limits that matter are applied to *requests actually sent*, per host —
never to packages, so a cache hit is never throttled:

| host | concurrent requests |
|---|---|
| GitHub API | 2 without a token, 8 with one |
| crates.io | 1 (their crawler policy) |
| everything else (npm, PyPI, deps.dev, RubyGems, Packagist, GitLab, Codeberg) | 8 |

On top of that:

- all versions of one package go to one worker, which downloads the release
  history (and, for npm, the registry record) **once per name**;
- repo stats, languages and the `package.json` name are fetched **once per repo
  per run**, however many packages point at it, and a repo that 404s is
  remembered for a day;
- when GitHub reports its rate limit spent, the rest of the run stops asking it;
- connections are kept alive (16 idle per host), a transient 502/503/504 or
  connection reset is retried once, and the timeout is between reads rather
  than for the whole response — a 15 MB packument on a slow link is not a
  failure;
- `--vulns` uploads run alongside the repo resolution instead of after it.

The limiting factor left is crates.io's one-request-at-a-time policy: a cold
Rust project costs roughly 240 ms per crate.

**`system` is bound by the tools it shells out to.** Each backend now starts its
long integrity sweep (`dpkg --verify`, `rpm -Va`, `pacman -Qkk`) first and runs
every independent query beside it; dnf merges its scalar `rpm -qa` queries and
its per-package scriptlet queries into one each; the Windows layers are read
four at a time and each binary's Authenticode signature is checked once per run.
`system inspect` skips the whole-system integrity sweeps, whose results it never
shows.

## Rules that keep the output stable

Parallel work finishes in any order. None of that order may reach the report:

- Findings are merged **in plan order**, and within a pass **by file index**
  (then by location for the content pass) — never in completion order.
- The listing is **sorted by path**, so what an analyzer reports in walk order is
  the same on every machine (directory order is filesystem-dependent).
- Symlinked **files** are read, symlinked **directories** are not descended
  (pnpm's `node_modules` is almost entirely symlinks; descending links risks
  loops). A subdirectory that is itself a link is walked on its own.
- Per-host limits wrap the request, not the package; a new network call must go
  through `get_json` / `get_typed` / `get_bytes` to inherit them.
- Cache writes are atomic (write aside, rename), so concurrent workers never read
  a torn entry.

## Profiling

The release profile strips symbols. Build the profiling profile, which is the
release build with the symbol table kept, and sample it:

```bash
cargo build --profile profiling
./target/profiling/postmortem scan ~/big-project > /dev/null & sample $! 5 -file scan.sample
```

Aggregate by function (`grep` the `postmortem` frames and sum the counts), and
look at the per-thread totals first: a main thread with most of the samples
and idle workers means something serial is on the critical path.
