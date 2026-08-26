# Go (modules)

Part of the [ecosystems](Ecosystems-and-Hosts) matrix. Go is special: a module
path **is** its repository.

## Files

`go.mod` (declared modules) + `go.sum` (the full set with versions).

## Graph - flat

Go's transitive parent edges can't be reconstructed offline (that needs
`go mod graph`). postmortem builds a **flat** graph and emits a **diagnostic**
saying so, plus surfaces `replace` directives - so a flat result is never read as
"clean".

## Licenses

Needs `--online`, from deps.dev. This is the **one** ecosystem where resolving a
license costs a request postmortem would not otherwise make: a Go module's repo
comes straight from its module path, with no registry call at all.
See [Licenses](Licenses).

## Dependency scopes - none

Go has no development-dependency concept: `go.mod` records one module set, and
test-only imports look exactly like the rest. Every module is production and
`--omit dev` is a no-op here. See [Dependency scopes](Dependency-Scopes).

## Online resolution - no registry call

The module path already points at the repo, so it's parsed directly:
`github.com/gin-gonic/gin` → `gin-gonic/gin`. Works for GitHub, GitLab, and
Codeberg module paths.

### Vanity import rewrites

Well-known custom domains are rewritten to their GitHub mirror
(see [Ecosystems & Hosts → Mirror rewrites](Ecosystems-and-Hosts#mirror-rewrites)):

| Path | Repo |
| --- | --- |
| `golang.org/x/<r>` | `golang/<r>` |
| `k8s.io/<r>` | `kubernetes/<r>` |
| `sigs.k8s.io/<r>` | `kubernetes-sigs/<r>` |
| `gopkg.in/<pkg>.vN` | `go-<pkg>/<pkg>` |
| `gopkg.in/<user>/<pkg>.vN` | `<user>/<pkg>` |

### Gotcha

Irregular vanity paths (e.g. `google.golang.org/grpc`) have no fixed mapping and
resolve to *no repository* (**unchecked**) - deliberately not guessed.

## Typosquatting

1 200 module paths ranked by dependent count (`golang.org/x/sys`,
`stretchr/testify`, …), matched whole plus an owner-squat rule
(`boltdb-go/bolt` → `boltdb/bolt`). A path that differs only in a version
element — `gopkg.in/yaml.v1` vs `.v3`, `hcl2` vs `hcl`, a trailing `/v2` — is
not flagged, and neither are two modules under one owner: nobody but
`github.com/aws` can publish under `github.com/aws`, so `service/sqs` and
`service/sts` are siblings. See [Typosquatting](Typosquatting).
