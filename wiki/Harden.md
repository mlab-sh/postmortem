# harden

`postmortem harden` evaluates a project against the **CIRSEC dependency baseline**
([CB-DEP](https://baselines.cirsec.org/b/dependencies)): 36 controls on *how* a
project consumes third-party packages — a release-age gate, frozen installs,
install scripts off by default, approved registries, a pipeline that scans.

The other commands ask *is something bad in my dependencies right now*. `harden`
asks the question one step earlier: *is this project set up so that something bad
has a hard time getting in*. Most of that is configuration, so most of it is
checked offline, from the repository alone.

```bash
postmortem harden .                       # baseline profile (30 controls)
postmortem harden . --level hardened      # all 36 (`--level high` works too)
postmortem harden . --online --vulns      # + registry history and advisories
postmortem harden . --json -o harden.json
postmortem harden info                    # the catalogue: what is checked, and how
```

## Output

Controls are grouped by domain. Each gets one status:

| Status | Meaning |
| --- | --- |
| `PASS` | Verified from evidence in the repository (or the registry, with `--online`). |
| `FAIL` | Evidence shows the control is not met. The baseline's remediation follows, with the profile's parameters filled in. |
| `MANUAL` | Not automatable from the repository (a proxy policy, a branch protection rule, a written procedure), or partly verified. The evidence says which part. |
| `SKIP` | Needs data this run did not collect: `--online` or `--vulns`. |
| `N/A` | Nothing in the project the control applies to. |
| `WAIVED` | Declared not applicable in `[[harden.waive]]`. |

A control passes only on evidence. Something postmortem cannot see is `MANUAL`,
never a silent `PASS`.

Exit codes: `0` nothing failed, `1` at least one control failed, `2` the
`[harden]` settings cannot be used (unknown parameter, value outside the
baseline's bounds, unknown level). A broken policy never reads as a passing one.

## `harden info`

Lists every control with its severity, its profile, CIRSEC's own assessment
(`automated` / `partial` / `manual`) and postmortem's coverage:

| Coverage | Meaning |
| --- | --- |
| `auto` | Decided offline from the repository. |
| `online` | Decided with `--online` (registry history, source repositories). |
| `partial` | Part is checked; the rest is a setting the repository does not show. |
| `manual` | Not automated; reported `MANUAL` with whatever evidence helps. |

`--level baseline|hardened` filters, `--json` for machines. Today: 15 auto,
2 online, 11 partial, 8 manual.

## What it reads

| Source | Used for |
| --- | --- |
| `.npmrc`, `pnpm-workspace.yaml`, `.yarnrc.yml`, `.yarnrc`, `bunfig.toml`, `package.json` | release age, install scripts, registry, scopes, TLS |
| `uv.toml` / `[tool.uv]`, `pip.conf`, `requirements*.txt`, `poetry`/`pdm`/`Pipfile` sources | release age, source builds, indexes, hashes |
| `.cargo/config.toml`, `Gemfile`, `composer.json`, `nuget.config`, `GOPROXY` | registry |
| Lockfiles (through the graph parsers, plus `pnpm-lock.yaml`, `uv.lock`, `poetry.lock`) | hashes, sources, non-registry packages |
| Pipeline files of 21 CI platforms (see below) | install mode, secrets, caches, scanners, schedules, SBOM |
| `Dockerfile*` (last stage) | install mode, dev dependencies |
| `*.sh`, `Makefile`, `justfile`, `README.md`, `package.json` scripts | unpinned `npx` / `dlx` / `uvx` / `go run @latest` |
| `.github/dependabot.yml`, Renovate config (JSON or JSON5) | update coverage, cooldown, automerge |
| `CODEOWNERS` | reviewers on manifests and lockfiles |

Test fixtures (`tests/`, `fixtures/`, `testdata/`, `examples/`, …) and vendored
trees are skipped: their Dockerfiles and lockfiles are not the project's.

### CI platforms

Every platform that keeps its pipeline in the repository is recognised:

| Platform | Files |
| --- | --- |
| GitHub Actions | `.github/workflows/*.yml` |
| Forgejo / Gitea Actions | `.forgejo/workflows/`, `.gitea/workflows/` |
| GitLab CI | `.gitlab-ci.yml`, `.gitlab/ci/*.yml` |
| CircleCI | `.circleci/*.yml` |
| Azure Pipelines | `azure-pipelines.yml`, `.azure-pipelines/`, `.azuredevops/` |
| Bitbucket Pipelines | `bitbucket-pipelines.yml` |
| Jenkins | `Jenkinsfile`, `Jenkinsfile.*`, `*.jenkinsfile` |
| Travis CI | `.travis.yml` |
| Drone / Woodpecker | `.drone.yml`, `.woodpecker.yml`, `.woodpecker/` |
| Buildkite | `.buildkite/*.yml` |
| Google Cloud Build / AWS CodeBuild | `cloudbuild.yaml`, `buildspec.yml` |
| Cirrus, Semaphore, AppVeyor | `.cirrus.yml`, `.semaphore/`, `appveyor.yml` |
| Tekton, Harness, Bitrise, Codemagic, Taskcluster | `.tekton/`, `.harness/`, `bitrise.yml`, `codemagic.yaml`, `.taskcluster.yml` |

For CB-DEP-VULN-001 (continuous scanning), postmortem finds the scanner
(`postmortem`, osv-scanner, npm/pnpm/yarn audit, pip-audit, cargo audit/deny,
trivy, grype, snyk, govulncheck, GitLab Dependency-Scanning, GitHub
dependency-review, …; mentions in comments are ignored), then the schedule:

- **in the file** — a `cron:` (GitHub, Forgejo, Azure, CircleCI) or Jenkins
  `cron('…')`. The expression is read and its longest gap compared with
  `scan_interval_hours` (24h): `0 6 * * 1` is weekly and fails.
- **gated** — a job that only runs on scheduled pipelines (GitLab
  `$CI_PIPELINE_SOURCE == "schedule"`, Drone/Woodpecker `event: cron`, Cirrus
  `CIRRUS_CRON`): a schedule exists, set outside the repository → `MANUAL`.
- **remote only** — GitLab, Bitbucket, Travis, Buildkite, Cloud Build, … can be
  scheduled in their UI, invisible here → `MANUAL`. GitHub Actions cannot, so
  no cron there → `FAIL`.

Each detected platform adds a *check remotely* line naming where its
out-of-repository settings live (Dependabot alerts, GitLab pipeline schedules
and security policies, CircleCI triggers, …).

For CB-DEP-CI-001 (install without secrets) and CB-DEP-CI-004 (caches),
pipelines are parsed into jobs, steps and caches, in each platform's own terms
— because each hands out secrets differently:

| Platform | A step installing dependencies sees secrets when… | Dependency cache passes when… |
| --- | --- | --- |
| GitHub / Forgejo Actions | its step, job or workflow `env` references `secrets.` | `actions/cache` key is `hashFiles()` of a lockfile, or a `setup-*` cache; never on `pull_request_target` |
| GitLab CI | the job has `environment:`, `secrets:`, `id_tokens:`, or `variables:` pulling in `$…TOKEN`-like names | `cache: key: files:` lists a lockfile |
| Azure Pipelines | its `env:` maps a `$(…)` secret-like variable (secrets are never implicit) | the `Cache@2` key names a lockfile |
| CircleCI | its job runs with a `context:` in any workflow | `save_cache` key is a `checksum` of a lockfile |
| Bitbucket | its step has `deployment:` or `oidc: true` | a custom cache with `key: files:` (predefined caches fail) |
| Drone / Woodpecker | its `environment` uses `from_secret`, or it lists `secrets:` | the cache plugin key is a `checksum` of a lockfile |
| Jenkins | it runs inside `withCredentials`, a stage `environment` with `credentials()`, or under a pipeline-level one | — (no native cache) |

Only dependency caches are judged (`node_modules`, `~/.cache/pip`, `~/.m2`,
`vendor`, `.cargo`, …); a compiler cache, a dataset or a build output is not,
and `cache: {}` is caching turned off. Variables that reach every job from the
platform itself (GitLab project variables, Bitbucket repository variables,
CircleCI project env vars) and fork cache isolation outside GitHub are
`MANUAL` lines to check remotely. A file the platform accepts but strict YAML
does not (CircleCI's duplicate anchors) is reported as unparsed.

### Release age per package manager (CB-DEP-AGE-001)

Every tool spells it differently, and in a different unit:

| Package manager | Setting | Unit |
| --- | --- | --- |
| npm ≥ 11.10 | `.npmrc` `min-release-age` | days |
| pnpm ≥ 10.16 | `pnpm-workspace.yaml` `minimumReleaseAge` | minutes (pnpm 11 defaults to 1440) |
| yarn ≥ 4.10 | `.yarnrc.yml` `npmMinimalAgeGate` | minutes, or `3d` |
| bun ≥ 1.3 | `bunfig.toml` `[install] minimumReleaseAge` | seconds |
| uv | `exclude-newer = "3 days"` | duration (a fixed date is reported as a frozen cutoff) |
| pip | `uploaded-prior-to` | ISO duration (`P3D`) |
| Renovate | `minimumReleaseAge` | duration |
| Dependabot | `cooldown: default-days` | days |

cargo, go, bundler, composer, maven, gradle and nuget have no native setting:
the control is `MANUAL` (enforce it in the registry proxy). With `--online`, every
installed version is also checked against its publish date, at the profile's
window (48h baseline, 72h hardened).

## Configuration — `[harden]` in `postmortem.conf`

```toml
[harden]
level = "hardened"                       # default profile (CLI --level wins)
registries = ["npm.corp.example", "pypi.corp.example"]   # approved registries
internal_scopes = ["@acme"]              # internal namespaces (CB-DEP-SRC-002)

[harden.params]                          # override the profile's values
min_release_age_hours = 96               # within the baseline's bounds (24..720)

[[harden.waive]]                         # a control the project does not apply
control = "CB-DEP-LOCK-001"
reason = "library: consumers resolve their own versions"
expires = "2027-03-31"                   # evaluated again after this date
```

- `registries` is what the baseline calls *approved registries*. Without it,
  approved means the public registries plus any registry configured in committed
  files, and SRC-001 accepts any non-public registry as the org's.
- `internal_scopes` adds to the scopes postmortem infers (a scoped npm package
  resolved from a private host is internal).
- Parameter names and bounds are the baseline's own; `postmortem harden info`
  lists them. An unknown name or an out-of-bounds value exits 2.
- `[[gate.allow]]` entries count as release-age exceptions for CB-DEP-AGE-003:
  each needs an `expires` within `max_exception_days` (7).

## Updating the embedded baseline

The controls ship inside the binary, verbatim from
[cirsec/baselines](https://github.com/cirsec/baselines)
(`src/data/cirsec-dependencies.yml`). To refresh from a checkout:

```bash
{ head -3 src/data/cirsec-dependencies.yml; for f in ../baselines/categories/supply-chain/dependencies/controls/CB-DEP-*.yml; do echo "---"; grep -v '^# yaml-language-server' "$f"; done; } > /tmp/cb.yml && mv /tmp/cb.yml src/data/cirsec-dependencies.yml
```

Update the commit in the header. A control added upstream fails `cargo test`
until it has a row in `src/harden/checks.rs` `SUPPORT` (and a check, or an
explicit manual verdict).

The baseline references postmortem back: each control postmortem covers carries
an `audit.checks` entry with `engine: postmortem` (`spec.control`,
`spec.coverage`, `spec.flags`).
