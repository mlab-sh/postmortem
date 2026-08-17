# Configuration

postmortem uses two distinct config files, plus environment variables.

## Machine settings - `~/.postmortem/config.yml`

Machine-wide knobs for the networked paths: API tokens and risk thresholds.
Written `0600`. GitHub can be entered once at an interactive prompt (it offers to
save); the others are read from config or the environment only.

```yaml
# ~/.postmortem/config.yml
github_token: ghp_xxx        # or $GITHUB_TOKEN
gitlab_token: glpat_xxx      # or $GITLAB_TOKEN   (public repos need no token)
codeberg_token: xxx          # or $CODEBERG_TOKEN (public repos need no token)
vuln_token: xxx              # or $VULN_MLAB_TOKEN (anonymous = 8/hr limit)

tree:
  min_stars: 20              # flag repos below this many stars
  recent_days: 30            # flag repos created within this many days
  stale_days: 365            # flag repos with no push in this many days
```

### Environment variables

| Variable | Used for |
| --- | --- |
| `GITHUB_TOKEN` | GitHub repo stats - raises the 60/h anonymous limit. |
| `GITLAB_TOKEN` | GitLab repo stats (optional; public repos resolve anonymously). |
| `CODEBERG_TOKEN` | Codeberg repo stats (optional). |
| `VULN_MLAB_TOKEN` | `vuln.mlab.sh` scans - raises the anonymous 8/hr limit. |

Resolution order for GitHub: `config.yml` → `$GITHUB_TOKEN` → interactive prompt.

## Corporate networks - `network`

Proxy and endpoint overrides for a machine that cannot reach the public
internet directly. This lives in the **config file only** — not in flags, not in
environment variables. It is a property of the *machine*, not of a run: a build
agent behind a proxy needs it on every invocation of every command, and
expressing that as flags means every CI step repeats them and drifts out of sync.

```yaml
# ~/.postmortem/config.yml
network:
  # Applied to every outbound request.
  proxy: "http://user:pass@proxy.corp:3128"
  # Hosts reached directly, bypassing the proxy. Suffix-matched, so
  # `corp.example` also covers `nexus.corp.example`.
  no_proxy: ["corp.example"]
  # Any subset — absent entries keep the public default.
  endpoints:
    npm:      "https://nexus.corp/repository/npm-proxy"
    pypi:     "https://nexus.corp/repository/pypi"
    crates:   "https://nexus.corp/repository/crates"
    github:   "https://github.corp/api/v3"      # GitHub Enterprise
    vuln:     "https://vuln.internal"
```

### Every endpoint

| Key | Default | Used by |
| --- | --- | --- |
| `npm` | `https://registry.npmjs.org` | Node resolution + licenses |
| `pypi` | `https://pypi.org` | Python |
| `crates` | `https://crates.io` | Rust |
| `rubygems` | `https://rubygems.org` | Ruby |
| `packagist` | `https://packagist.org` | PHP |
| `deps_dev` | `https://api.deps.dev` | Java and Go licenses |
| `github` | `https://api.github.com` | repo stats — set for GitHub Enterprise |
| `github_raw` | `https://raw.githubusercontent.com` | reading a repo's `package.json` |
| `gitlab` | `https://gitlab.com/api/v4` | repo stats — set for a self-hosted GitLab |
| `codeberg` | `https://codeberg.org/api/v1` | repo stats — Forgejo works too |
| `vuln` | `https://vuln.mlab.sh` | `--vulns`, and the OS-package advisories that route through it |
| `arch_security` | `https://security.archlinux.org` | `system --vulns` on Arch |
| `aur` | `https://aur.archlinux.org` | AUR provenance + PKGBUILD analysis |
| `brew` | `https://formulae.brew.sh` | Homebrew formula metadata |

Values are the origin plus any base path, **without** a trailing slash — one is
trimmed if present.

### A typo is an error, not a silent fallback

Unknown keys under `network` are rejected, and a config that fails to parse
prints a warning naming the bad key and the valid ones:

```
warn: ignoring ~/.postmortem/config.yml — network.endpoints: unknown field `npmm`,
      expected one of `npm`, `pypi`, `crates`, ...
warn: continuing with defaults; any `network` overrides in it are NOT applied
```

This is deliberate. Silently falling back to the public registry would look like
an outage on an air-gapped network — and on a connected one it would send your
internal package names to a public service. An unusable proxy URL is likewise
warned about and skipped rather than aborting the run.

## Project policy - `postmortem.conf`

A per-project **TOML** file, auto-loaded from the scanned directory (disable with
`--no-config`, or point elsewhere with `--config`). Two roles:

**Suppress accepted findings** (`scan` and `audit`):

```toml
# postmortem.conf
[[ignore]]
dependency = "some-pkg"
category   = "install_hook"
reason     = "known-good build script"
expires    = "2026-12-31"   # past this date the rule stops suppressing
```

A rule matches when **all** its stated fields match; `path` accepts globs
(`"**/test/**"`). The blunter forms are `skip_categories`, `skip_dependencies`
and `min_severity`.

`expires` turns a suppression into a dated decision rather than a permanent
hole — past the date the finding comes back and the run says so. See
[`allowlist`](Allowlist) for the whole picture, including
`postmortem allowlist --expired` as a CI check.

**Gate policy** (`tree`, `audit`, `system`): see [CI gate](CI-Gate) for the
`[gate]` block and `[[gate.allow]]` entries, which take the same `expires`.

## License policy - `[license]`

Consumed by [`licenses`](Licenses); ignored by every other command. CLI flags are
additive on top of it.

```toml
# postmortem.conf
[license]
deny = ["AGPL-3.0", "SSPL-1.0"]
# allow = ["MIT", "Apache-2.0", "ISC"]   # when set, nothing else is permitted
fail_on_unknown = true
```

| Key | Meaning |
| --- | --- |
| `deny` | SPDX ids that fail the run. A dual-licensed package is flagged only when every alternative it offers is denied. |
| `allow` | When non-empty, the only ids permitted. Satisfied if *any* one alternative is allowed. |
| `fail_on_unknown` | Fail when a package has no resolvable license. Pair with `--online`, since coverage depends on the ecosystem. |

## Cache

All networked responses are cached under `~/.postmortem/cache/`. A published
package version is immutable, so its repo resolution is cached indefinitely;
repo stats and language breakdowns are cached per repo. Manage it with the
[`cache`](Cache) command.
