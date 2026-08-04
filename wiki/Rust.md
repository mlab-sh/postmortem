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

## Online resolution

- **Registry:** `crates.io/api/v1/crates/<name>` → the `crate.repository` field.
- crates.io requires a `User-Agent` (postmortem always sends one).

### Gotcha

A crate that omits `repository` resolves to *no repository* (**unchecked**).
