# Ruby (Bundler)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix.

## Lockfile

`Gemfile.lock` - the `GEM` specs section (name + version), with the
`DEPENDENCIES` section marking the direct set.

## Licenses

Needs `--online`, via the **version-pinned** RubyGems v2 endpoint: the v1
name-only endpoint reports the latest release's license, which is wrong whenever
a gem has relicensed. See [Licenses](Licenses).

## Dependency scopes

`Gemfile.lock` records no groups — its `DEPENDENCIES` section is flat — so the
scope comes from the `Gemfile` alongside it: `group :development, :test do ... end`
blocks and inline `group:` / `groups:` options. Without a Gemfile, every gem
stays production. A mixed group (`group :default, :test`) stays production.
See [Dependency scopes](Dependency-Scopes).

## Online resolution

- **Registry:** `rubygems.org/api/v1/gems/<name>.json`.
- **Repo discovery:** `source_code_uri`, then `homepage_uri`. First to parse to
  a known [host](Ecosystems-and-Hosts#code-hosts) wins.

### Gotcha

A gem that sets only a homepage (not a code URI) resolves to *no repository*
(**unchecked**).
