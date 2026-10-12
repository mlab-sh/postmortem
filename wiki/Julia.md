# Julia (Pkg)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix.

| File | Notes |
| --- | --- |
| `Manifest.toml` / `JuliaManifest.toml` | Every package, its `version` and the names it `deps` on: the **full graph**. Formats 1 and 2.0. A standard library (no `version`) is not reported. |
| `Project.toml` | `[deps]` is the direct set; `[extras]` named by `[targets] test` are dev. |

**Online:** the General registry's `Package.toml` (`JuliaRegistries/General`, `jll/` for binary wrappers) → `repo`. A package added by URL (`repo-url`) resolves to that repo. No license is recorded there.

**Vulnerabilities:** through vuln.mlab.sh as OSV `Julia` coordinates (JLSEC). The binary wrappers (`*_jll`) carry most of them: SciMLBenchmarks' Jumps manifest gives 104 (LibCURL, LibGit2, MbedTLS).

**Not covered:** source scanning, typosquatting.
