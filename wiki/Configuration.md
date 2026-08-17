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

## Project policy - `postmortem.conf`

A per-project **TOML** file, auto-loaded from the scanned directory (disable with
`--no-config`, or point elsewhere with `--config`). Two roles:

**Suppress accepted findings** (`scan`):

```toml
# postmortem.conf
[[suppress]]
dependency = "some-pkg"
category   = "install_hook"
reason     = "known-good build script"
```

**Gate policy** (`tree`): see [CI gate](CI-Gate) for the `[gate]` block and
`[[gate.allow]]` entries.

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
