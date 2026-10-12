# Perl (CPAN, Carton)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix.

| File | Notes |
| --- | --- |
| `cpanfile.snapshot` | Carton: every **distribution** (`Moo-2.005005`), the modules it `provides` and `requires` - the full graph once each module is mapped to its distribution. Core modules and `perl` have no node. |
| `cpanfile` | The modules required; mapped through the snapshot they are the direct set. `on test` / `develop` / `build` / `configure` and `test_requires`, ... are dev. Without a snapshot: the declared modules, **flat**. |

**Online:** MetaCPAN (`fastapi.metacpan.org/v1/release/<dist>`) → `resources.repository`, `homepage`, `license` (the latest release's). New `metacpan` endpoint.

**Vulnerabilities:** none - OSV has no CPAN ecosystem; Perl is reported as **unassessed**.

**Source scanning:** the project's own Perl is scanned (IOC / obfuscation / sensitive APIs).

**Reputation caveat:** CPAN distributions' GitHub repos carry few stars (median
3), so `low-stars` is off for Perl by default. Set
`tree.min_stars_by_ecosystem.perl` to turn it back on.
