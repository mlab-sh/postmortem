# CI templates

postmortem ships a [GitHub Action](https://github.com/mlab-sh/postmortem), and
generates ready-to-commit pipelines for the other three major platforms:

```bash
postmortem ci gitlab  > .gitlab-ci.yml
postmortem ci azure   > azure-pipelines.yml
postmortem ci jenkins > Jenkinsfile
postmortem ci github  > .github/workflows/postmortem.yml
```

The templates are **generated, not committed**. A checked-in YAML file drifts
the first time a release URL or a flag name changes, and the person who finds
out is a user whose pipeline broke. Generating them means the install snippet
lives in exactly one place, and the pinned version is always the version of the
binary that printed it — a template can never reference a release that does not
exist.

Pin a different release with `--version`:

```bash
postmortem ci gitlab --version v2.0.0
```

## What differs between platforms

Installing the binary and running the gate are the same everywhere — plain
shell. The only real difference is how each platform ingests the report.

| Platform | Format | Ingestion |
|---|---|---|
| GitHub | SARIF | Code Scanning (`upload-sarif`) |
| Azure DevOps | SARIF | the `CodeAnalysisLogs` artifact, read by the *SARIF SAST Scans Tab* extension |
| Jenkins | SARIF | the *Warnings Next Generation* plugin's SARIF parser |
| GitLab | its own schema | `artifacts:reports:dependency_scanning` |

### GitLab does not read SARIF

This is the one that catches people out. GitLab defines its own [Dependency
Scanning report format][gl] and ignores SARIF entirely — a job that publishes
SARIF to GitLab produces a green pipeline with an empty security widget, which
is the worst possible failure mode: it looks like nothing was found.

So postmortem emits GitLab's native format:

```bash
postmortem audit . --online --vulns --gitlab -o gl-dependency-scanning-report.json
```

`--gitlab` is available on both `audit` and `tree`. The generated template uses
`audit`, because it does both jobs in one pass: it writes the report the
merge-request widget reads, and its exit code is the gate.

[gl]: https://docs.gitlab.com/ee/development/integrations/secure.html#dependency-scanning

#### What goes in the report

Findings land as `vulnerabilities[]`, keyed by advisory + package + version so
GitLab tracks a finding across pipelines instead of re-raising it each run.
Identifiers are typed (`cve`, `ghsa`, `rustsec`, `osv`) so GitLab can
deduplicate against other scanners.

The upgrade target from [`fix`](Fix) is reported as the finding's `solution`.

**Not** as `remediations` — the schema requires that block to carry a `diff`, an
actual patch GitLab can apply from the merge request. postmortem deliberately
never writes to a manifest, so it has no patch to offer, and emitting the field
without one would fail validation and take the whole report down. `solution` is
free text and can hold the advice honestly.

A graph postmortem could not fully resolve is reported as `scan.status:
"failure"` rather than a clean pass — the same rule the
[diagnostics](Dependency-Scopes) follow everywhere else: *unknown must never
read as clean*.

## The detail that makes these work

A tripped gate exits non-zero, and on every one of these platforms the default
is to abandon the job at that point — **including the step that publishes the
report**. That is exactly backwards: the run you most need the findings from is
the one that failed.

Every generated template forces the publish to happen anyway:

| Platform | How |
|---|---|
| GitHub | `if: always()` |
| GitLab | `artifacts.when: always` |
| Azure | `condition: succeededOrFailed()` |
| Jenkins | `post { always { … } }` |

If you write your own pipeline instead of generating one, this is the thing to
remember.

## Tokens

`--online` reads `$GITHUB_TOKEN` for the repo-reputation lookups. Without one
you will hit the unauthenticated GitHub API rate limit on any real dependency
set. Each template wires it up in that platform's idiom — a masked CI/CD
variable on GitLab, a secret pipeline variable on Azure, a credential binding on
Jenkins, and the built-in `secrets.GITHUB_TOKEN` on GitHub.

## What is and is not tested

The templates are covered by tests asserting their *content*: that they parse as
YAML, that they pin a real version, that each declares its report where its
platform looks for it, that the publish survives a failed gate, and that the
install snippet stays in sync with `action.yml`.

They are **not** executed against a live GitLab, Azure or Jenkins instance the
way the GitHub Action is dogfooded by `self-scan.yml`. Treat them as a
well-checked starting point, not as a pipeline verified end-to-end.

## Tuning the gate

Every template ships the same starting thresholds:

```
--max-high 0 --fail-on-vuln high
```

See [CI gate](CI-Gate) for the full set, and [Allowlist](Allowlist) for suppressing a
finding you have decided to accept.
