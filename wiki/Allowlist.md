# `postmortem allowlist`

Every suppression the project declares, in one place, with how long each has
left to run.

```bash
postmortem allowlist                     # everything, worst first
postmortem allowlist --expired           # only the lapsed ones; exit 1 if any
postmortem allowlist --expiring-in 30    # flag what lapses within 30 days
postmortem allowlist --json
```

```
allowlist  ./postmortem.conf

  ✗ ignore             path=**/test/**            invalid date "demain"
      fixtures
  ✗ ignore             dependency=event-stream    expired 2026-08-01
      triaged, waiting on upstream
  · gate.allow         flatmap-stream             15d left
      tracked in SEC-42
  · ignore             dependency=uglify-js       136d left
  · skip_dependencies  left-pad                   no expiry
  · skip_categories    ioc                        no expiry

⚠ 2 suppression(s) have lapsed — they no longer hide anything, so whatever
  they covered is being reported again
· 2 have no expiry — those never come back for review
```

## Why suppressions expire

A permanent suppression is how a scanner quietly stops finding things. Adding
`expires` turns each one into a dated decision that somebody has to renew:

```toml
[[ignore]]
dependency = "uglify-js"
reason = "known minifier, expected high-entropy output"
expires = "2026-12-31"
```

Past that date the rule **stops suppressing** — the finding comes back — and the
run says so:

```
warn: ignore rule no longer applies — dependency=uglify-js (expired 2026-12-31)
```

That warning goes to stderr unconditionally, not through the progress UI, so it
is visible in CI too.

An **unparseable** date is treated as lapsed, not as permanent. A typo must not
grant an indefinite exemption.

The date is inclusive: an entry expiring today is still in force today.

## What carries an expiry

| Table | Suppresses | Expirable |
| --- | --- | --- |
| `[[ignore]]` | matching findings in [`scan`](Scan) / [`audit`](Audit) | **yes** |
| `[[gate.allow]]` | a package, in every [gate](CI-Gate) count | **yes** |
| `skip_dependencies` | every finding for a package | no — bare strings in the schema |
| `skip_categories` | a whole finding category | no |

The blunt forms appear in the listing as `no expiry` rather than being omitted:
a listing that showed only the expirable entries would understate how much is
being hidden.

`[[ignore]]` and `[[gate.allow]]` share one date implementation, so a date that
lapses in one cannot still be in force in the other.

## In CI

`--expired` is the check; a plain listing is a report and always exits 0.

```yaml
- name: fail on suppression debt nobody renewed
  run: postmortem allowlist --expired
```

## Options

| Flag | Description |
| --- | --- |
| `--expired` | Only lapsed entries; exit 1 if any. |
| `--expiring-in <DAYS>` | Also flag entries lapsing within the window. |
| `--json` / `-o <FILE>` | Emit the listing as JSON. |
| `--config <FILE>` | Read this config instead of `<PATH>/postmortem.conf`. |
