# Nix (store / profiles)

A [`system`](System) backend, alongside [Homebrew](Homebrew), [Pacman](Pacman),
[APT](Apt), and [DNF](Dnf). Reads the installed Nix **store closure** and audits
it with the same `risk:dep` model as [`tree`](Tree). Selected automatically when
`nix-store` is available.

Nix is different from dpkg/rpm/pacman: there is no flat "installed set" and no
install-time scripts run on the host (builds are pure and sandboxed). Packages
are immutable `/nix/store/<hash>-<name>-<version>` paths, and the security
question is **provenance**: was a store path signed by a trusted binary cache,
built locally, or served unverified by some substituter.

## Data sources

| Command | Used for |
| --- | --- |
| `/nix/var/nix/profiles/*` (+ `per-user/*/profile`) | The installed roots: the store paths each profile references. |
| `nix-store -q --references <path>` | A store path's direct references (the graph edges). |
| `nix-store -qR <roots>` | The full closure (every reachable store path = the node set). |
| `nix path-info --json --sigs <paths>` | Per path: references, signatures, content-address, `ultimate` (built locally). |
| `/etc/nix/nix.conf` (+ user config) | Trusted cache keys, `require-sigs`, and configured substituters. |

## The tree

Roots are the store paths referenced by the current profile generations
(top-level pointers plus `per-user/*/profile`). Edges are the store
**references** between paths, restricted to the closure. A package's output
suffix (`-bin` / `-lib` / `-man` / …) is folded into its version so distinct
outputs remain distinct nodes.

## Risk signals

| Signal | Severity | Meaning |
| --- | --- | --- |
| `unverified (no trusted signature)` | Medium | Nothing vouches for the path: no signature from a trusted binary cache (`trusted-public-keys`), not content-addressed, and not built locally. Suppressed when almost the whole store is unverified (a store shipped without signatures, e.g. a container image), so it only fires as the exception. |
| `built-locally` | Info | The path was built on this machine (`ultimate`), not fetched from a cache. |

There is no `install-script` signal: Nix builds are pure, so nothing from a
package runs on the host at install time.

## Source trust

Machine-wide caveats from `nix.conf`, surfaced as a gochi alert after loading:

| Caveat | Source |
| --- | --- |
| `nix signature verification disabled` | `require-sigs = false` (the analog of apt's `[trusted=yes]`). |
| `N extra binary cache(s) configured` | `substituters` beyond `cache.nixos.org`: an extra source of prebuilt binaries. |

`--repos` lists the configured substituters (binary caches); `cache.nixos.org`
is official, anything else is third-party.

## Reputation (`--online`)

The Nix store carries no per-package source-repo URL, so there is nothing to
resolve: nodes are reported as **unchecked**. The value here is the closure graph
and the provenance signals, not repo reputation.

## Options

Same as [`system`](System): `--repos`, `--depth`, `--json`, `--no-progress`.
