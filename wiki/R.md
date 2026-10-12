# R (renv)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix.

| File | Notes |
| --- | --- |
| `renv.lock` | Every package, its version and source. renv >= 1.0 records `Requirements` (the edges); older lockfiles do not: **flat**, with a diagnostic. |
| `DESCRIPTION` | `Depends` / `Imports` / `LinkingTo` give the direct set; `Suggests` is dev. |

Sources: CRAN / RSPM (`Repository`), **Bioconductor**, and GitHub / GitLab /
Bitbucket / git remotes - a remote package resolves to its own repo, never to
the same-named CRAN package.

**Online:** crandb (`crandb.r-pkg.org/<name>/<version>`) → `URL` (a list), `BugReports`, `License`. New `crandb` endpoint. Many CRAN packages have no repo (R-Forge, a homepage only): they stay **unchecked**.

**Vulnerabilities:** through vuln.mlab.sh as OSV coordinates - `CRAN`, or `Bioconductor` for Bioconductor packages (RSEC advisories).

**Not covered:** source scanning, typosquatting.
