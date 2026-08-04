# Ruby (Bundler)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix.

## Lockfile

`Gemfile.lock` - the `GEM` specs section (name + version), with the
`DEPENDENCIES` section marking the direct set.

## Online resolution

- **Registry:** `rubygems.org/api/v1/gems/<name>.json`.
- **Repo discovery:** `source_code_uri`, then `homepage_uri`. First to parse to
  a known [host](Ecosystems-and-Hosts#code-hosts) wins.

### Gotcha

A gem that sets only a homepage (not a code URI) resolves to *no repository*
(**unchecked**).
