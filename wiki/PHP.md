# PHP (Composer)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix.

## Lockfile

`composer.lock` - the `packages` (and `packages-dev`) arrays. Names are
`vendor/package`.

## Graph

Built from the lock; Composer vendors dependencies under `vendor/` when
installed, so a committed vendor tree is also covered by [`scan`](Scan).

## Licenses

Read **offline** from each package's `license` array in `composer.lock`. The
array means "any of these", so several entries collapse into one `OR`
expression. See [Licenses](Licenses).

## Dependency scopes

The most complete of any ecosystem: composer resolves the dev tree separately
into `packages-dev`, **transitives included**, and promotes anything also
required in production into `packages`. No propagation needed.
See [Dependency scopes](Dependency-Scopes).

## Online resolution

- **Registry:** `packagist.org/packages/<vendor>/<package>.json` → the
  `package.repository` field.

### Gotcha

Platform packages (`php`, `ext-*`, `lib-*`) aren't real Composer packages and are
skipped.
