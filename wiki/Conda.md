# Conda (environment.yml, conda-lock)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix.

| File | Notes |
| --- | --- |
| `conda-lock.yml` | conda-lock: every package once per platform, with its dependencies by name: the **full graph**, one node per `name@version` across platforms. `category` other than `main` is dev. Virtual packages (`__glibc`) are left out. |
| `environment.yml` | The declared set (the direct packages). Alone, it is **flat** and mostly unpinned: `==1.2.3` or `=1.2.3=build` pin a version, anything else is `managed`. |

Conda packages are reported as `conda`; `pip:` entries and `pip`-managed lock
entries are PyPI packages, reported as `python`.

**Online:** the conda-forge feedstock's recipe (`recipe/recipe.yaml`, else
`recipe/meta.yaml`) → `repository` / `dev_url`, `homepage`, the source archive
URL, and `license`. A package from another channel is not looked up there. A
package built by a multi-output feedstock of another name (`libgdal-core`
from `gdal-feedstock`) is not found: **unchecked**.

**Vulnerabilities:** pip packages go to vuln.mlab.sh as OSV `PyPI`
coordinates. Conda packages have no OSV ecosystem: not assessed (an info
diagnostic says so).

**Not covered:** `pixi.lock`, `@EXPLICIT` spec files.
