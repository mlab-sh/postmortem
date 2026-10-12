# .NET (NuGet)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix. Package ids are
case-insensitive (`Newtonsoft.Json` = `newtonsoft.json`); postmortem keeps the
lockfile's spelling and folds case for every lookup.

## Manifests

| File | Notes |
| --- | --- |
| `packages.lock.json` | NuGet lockfile (`RestorePackagesWithLockFile`) - full graph. |
| `*.csproj` / `*.fsproj` / `*.vbproj` | Direct `<PackageReference>`s, used only without a lockfile. |
| `Directory.Packages.props` | Central package management - the nearest one above the project supplies `<PackageVersion>`s. |

## Graph

With `packages.lock.json` the graph is **complete**: every package records its
own `dependencies`, and each edge points at the version resolved *in the same
target framework*. A lockfile covering several frameworks (`net8.0`,
`net6.0`, `net8.0/win-x64`) yields one entry per `id@version` with the union of
its parents. `Project` entries (project references) are local code, not
packages: what they pull in counts as **direct**.

Without a lockfile only the project file is read, the graph is **flat**, and a
`flat_graph` diagnostic says so. A reference with no version anywhere is
reported as `managed`, like Maven.

Detection is root-only, as for every ecosystem: point postmortem at the
project directory (or the `.csproj` / `packages.lock.json`), not the `.sln`.

## Dependency scopes

None. Neither the lockfile nor `<PackageReference>` records a test/dev split
(`PrivateAssets="all"` is about flowing to dependents, not production), so
everything is `prod`.

## Licenses

Needs `--online`, from deps.dev (version-pinned, SPDX). See [Licenses](Licenses).

## Online resolution

- **Registry:** **deps.dev** -
  `api.deps.dev/v3/systems/nuget/packages/<id>/versions/<version>` → the `links`
  array, preferring `SOURCE_REPO`.

## Not covered yet

- Source-code scanning of C# / F# (no content analyzer for those languages).
- Typosquatting (no NuGet corpus).
- `--vulns` (the mlab scan API has no NuGet format).
