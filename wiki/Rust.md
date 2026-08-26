# Rust (Cargo)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix.

## Lockfile

`Cargo.lock` (v3/v4). When a sibling `Cargo.toml` is present, its
`[dependencies]` / `[dev-dependencies]` / `[build-dependencies]` (and workspace
deps) mark the **direct** set.

## Graph

Full graph from the lock's `dependencies` edges.

**Exception:** workspace member crates have no `source` field - they're local,
not dependencies, so they're skipped (the scan target isn't its own dependency).

## Licenses

Needs `--online`. `crate.license` is null on crates.io — the license lives per
version, so the pinned one is looked up inside the response. The pre-SPDX slash
form (`MIT/Apache-2.0`) is read as `OR`. See [Licenses](Licenses).

## Dependency scopes

Read from `Cargo.toml` (`Cargo.lock` is a flat resolved set with no dev/prod
split), including `[target.'cfg(...)'.dev-dependencies]`, then propagated
through the lock's edges.

**`[build-dependencies]` counts as production.** A build script's dependencies
execute on the build machine with full privileges — omitting them would hide the
most dangerous class of Rust dependency. Only `[dev-dependencies]` is `dev`.
See [Dependency scopes](Dependency-Scopes).

## Online resolution

- **Registry:** `crates.io/api/v1/crates/<name>` → the `crate.repository` field.
- crates.io requires a `User-Agent` (postmortem always sends one).

### Release history

The crate record is one document for the whole crate: it carries every version
with its `created_at`, its `published_by` account, and `trustpub_data` (the
Trusted Publishing record — crates.io's equivalent of an npm attestation). So
`dormant-release`, `fresh-release`, `newborn-package`, `new-publisher` and
`provenance-removed` all come out of the request already made for the repo and
the license, at no extra cost.

Two things are not in it: whether the crate has a `build.rs` (so
`install-script-added` is npm's alone) and the owner list (a separate `/owners`
call, not made). Neither is reported as clean. See
[provenance coverage](Online-Resolution#provenance-coverage).

### Gotcha

A crate that omits `repository` resolves to *no repository* (**unchecked**).
