# C / C++ (Conan, vcpkg)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix. Two ecosystems, reported
separately: `conan` and `vcpkg`. Both also turn on the C/C++ source scan of the
project's own code.

## Conan

| File | Notes |
| --- | --- |
| `conan.lock` (Conan 2, `"version": "0.5"`) | `requires` (shipped), `build_requires` / `python_requires` (build-time tools, **dev**). **Flat** - no edges. |
| `conan.lock` (Conan 1, `graph_lock`) | The node graph: **full graph** with edges; the consumer's `build_requires` are dev. |
| `conanfile.txt` / `conanfile.py` | `[requires]` / `self.requires(...)` give the direct set; `tool_requires` are dev. Alone (no lock), they are all there is. |

A reference is `name/version[@user/channel][#revision]`. A package listed both
as a requirement and as a tool is one package, prod. A `@user/channel` package
is not ConanCenter's: it is never described by the same-named ConanCenter
recipe.

**Online:** the ConanCenter recipe in `conan-io/conan-center-index` (through
the `github_raw` endpoint): `config.yml` → the recipe folder (`master` keeps
only recent versions, so an older pin uses its major line's folder), then
`conanfile.py` → `homepage` and `license`. When the homepage is not a repo
(`opencv.org`), the source archive URLs of `conandata.yml` are tried. Many C/C++
projects live on their own servers (GNU savannah, SourceForge, ffmpeg.org):
those resolve to no repository (**unchecked**), not to a guess.

## vcpkg

vcpkg has **no lockfile**: versions come from a registry baseline.

| File | Notes |
| --- | --- |
| `vcpkg_installed/vcpkg/status` | Written by a build: every installed port, exact version, `Depends` → **full graph**. Feature paragraphs add their dependencies to the port's. |
| `vcpkg.json` | The direct set - its `features`' dependencies included, since the manifest cannot tell which are enabled. Without `status`: **flat**, versioned only by `overrides` / `version>=`, otherwise `baseline`. |

Host dependencies (`"host": true`) and `vcpkg-*` helper ports (`vcpkg-cmake`, …)
are build tools: **dev**. A port overridden by an **overlay** (`overlay-ports`
in `vcpkg-configuration`) is the project's own recipe, never described by the
same-named port of microsoft/vcpkg.

**Online:** the port's `vcpkg.json` on microsoft/vcpkg `master` → `homepage` and
its SPDX `license` (the current port's).

## Vulnerabilities

Through vuln.mlab.sh, as coordinates:

- **Conan** - sent as OSV `ConanCenter`. **That ecosystem is nearly empty in
  OSV today**: an empty answer does not mean the C/C++ code is clean.
- **vcpkg** - no OSV ecosystem exists: reported as **unassessed** (`fix` and
  `audit` say so).

## Not covered yet

- Typosquatting (no corpus).
- vcpkg version resolution from `builtin-baseline` without a build.
