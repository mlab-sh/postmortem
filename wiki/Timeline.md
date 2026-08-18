# `postmortem timeline`

The risk signals elsewhere are *point-in-time*: this version added an install
script, this version has a new publisher. Each is a boolean about one release,
and a boolean is hard to weigh. The same facts in order tell you something a flag
cannot.

```bash
postmortem timeline event-stream
postmortem timeline debug ./my-project    # marks the version you have
postmortem timeline lodash --all --json
```

```
timeline  debug

  77 release(s), 25 carrying a change

  2011-11-29   0.0.1        first release
  2014-06-05 ! 1.0.0        publisher changed  tjholowaychuk → tootallnate
  2016-11-07 ! 2.3.0        publisher changed  tootallnate → thebigredgeek
                            released after 547d of silence
  2017-09-22   2.6.9         ← installed
  2018-09-11 ! 3.2.0        publisher changed  tootallnate → qix

  … 52 release(s) with no change of publisher, scripts, repository or provenance
```

## Events are transitions, not properties

Every entry is a **change** between one release and the one before it. A property
("this version has an install script") says nothing on its own; the transition
("the install script appeared here, in a package that had none for four years")
is the signal.

| Event | Meaning |
| --- | --- |
| `first release` | Nothing before it to compare against. |
| `publisher changed` | A different npm account published this one. |
| `install script added` / `removed` | A `preinstall`/`install`/`postinstall` hook appeared or went. |
| `repository moved` | The declared source repo changed — a transfer, rename, or redirect. |
| `provenance added` / `removed` | A Trusted-Publishing attestation appeared or vanished. |
| `released after Nd of silence` | A long dormancy broken. |
| `deprecated` | Marked deprecated at this release. |

## Why the sequence matters

```
2018-09-09  v3.3.6   ! publisher changed  dominictarr → right9ctrl
2018-09-16  v0.1.1   ! install script added
```

That is the event-stream compromise. A handover, then — a week later — the first
install hook the package ever had. Either fact alone is unremarkable; in
sequence it is obviously a takeover. That is the whole reason this view exists.

## An installed version the registry has dropped

```
⚠ you have event-stream@3.3.6 installed, and the registry no longer lists it —
  versions get unpublished, and malice is the usual reason
```

Reported as a **finding**, not as a failed lookup. Versions disappear because
somebody unpublished them, and for a package still in your lockfile that is
worth knowing loudly.

## What is collapsed, and what is not

Releases that changed nothing are collapsed with a count — a package with 300
versions is unreadable otherwise — but they are **counted, never dropped**, and
`--all` lists them. The installed version is always shown even when quiet: "where
am I on this line" is the reason to look.

`--json` always carries every release, collapsed or not.

## npm only

The npm packument is the one registry document carrying per-version publisher,
scripts, repository and attestation together. The others publish a current view,
not a history, so there is nothing to lay out.

The packument is **not cached**: everything else postmortem reads from one is
immutable per `(name, version)`, but a history gains an entry whenever someone
publishes, and a cached copy would go quiet exactly when a new release is the
thing worth seeing.

## Options

| Flag | Description |
| --- | --- |
| `--all` | List every release, including those that changed nothing. |
| `--json` / `-o <FILE>` | Emit the history as JSON. |
