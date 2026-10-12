# Deno (deno.lock)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix.

`deno.lock` (v3, v4, v5) holds two registries:

- **npm** packages, reported as `node` - they are npm's: same registry, same
  OSV ecosystem. A key's peer suffix (`a@1.0.0_b@2.0.0`) is the same package.
- **JSR** packages (`@std/fs`), reported as `jsr`.

Every package lists its dependencies (specifiers, names, or `name@version`),
resolved through the lock's `specifiers`: the **full graph**. The workspace's
`dependencies` (and its `members'`) are the direct set. URL imports (`remote`:
deno.land/x, esm.sh, ...) belong to no registry: they are **counted** in a
diagnostic, not assessed.

**Online:** npm packages through the npm registry; JSR packages through
`api.jsr.io/scopes/<scope>/packages/<name>` → `githubRepository`. New `jsr`
endpoint.

**Vulnerabilities:** npm packages go to vuln.mlab.sh as OSV `npm` coordinates.
JSR has no OSV ecosystem: JSR packages are not assessed (an info diagnostic
says so).

**Source scanning:** the project's own TypeScript / JavaScript is scanned.
