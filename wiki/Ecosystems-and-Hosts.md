# Ecosystems & Hosts

## Language ecosystems

postmortem parses lockfiles for **7 ecosystems**. Offline parsing (the graph)
works for all of them; the registry column is used by
[`tree --online`](Online-Resolution) to find each package's source repo. Each
ecosystem has its own page with lockfiles, quirks, and exceptions.

| Ecosystem | Package managers / lockfiles | Online registry |
| --- | --- | --- |
| [**Node**](Node) | npm, pnpm, yarn (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`) | npm registry |
| [**Python**](Python) | pip, Poetry (`requirements.txt`, `poetry.lock`) | PyPI |
| [**Rust**](Rust) | Cargo (`Cargo.lock`) | crates.io |
| [**Ruby**](Ruby) | Bundler (`Gemfile.lock`) | RubyGems |
| [**PHP**](PHP) | Composer (`composer.lock`) | Packagist |
| [**Go**](Go) | modules (`go.mod`, `go.sum`) | *(none - the module path is the repo)* |
| [**Java**](Java) | Maven, Gradle (`pom.xml`, `build.gradle`) | deps.dev |
| [**Homebrew**](Homebrew) | via [`system`](System) | formulae.brew.sh |
| [**pacman**](Pacman) | via [`system`](System) | AUR RPC *(+ homepage → repo)* |
| [**apt / dpkg**](Apt) | via [`system`](System) | *(none - homepage → repo)* |
| [**dnf / rpm**](Dnf) | via [`system`](System) | *(none - homepage → repo)* |

> Go and Java are **flat-graph** ecosystems offline (transitive parent edges
> can't be reconstructed without the toolchain). postmortem emits a
> **diagnostic** when the graph is incomplete, so a small result is never
> silently read as "clean".

## Code hosts

Reputation stats (stars, creation date, last activity, archived, primary
language) are pulled from three hosts:

| Host | API | Auth (optional) |
| --- | --- | --- |
| **GitHub** | `api.github.com` | `GITHUB_TOKEN` (raises the 60/h anonymous limit) |
| **GitLab** | `gitlab.com/api/v4` (nested groups supported) | `GITLAB_TOKEN` |
| **Codeberg** | `codeberg.org/api/v1` (Forgejo) | `CODEBERG_TOKEN` |

A repo on any other host still resolves (its slug is shown) but its stats come
back unavailable. See [Configuration](Configuration) for tokens.

### Mirror rewrites

Some canonical SCM hosts have no stats API but mirror to GitHub. postmortem
rewrites those automatically:

- **Apache gitbox** (`gitbox.apache.org`, `git-wip-us.apache.org`) →
  `github.com/apache/<repo>`.
- **Go vanity import paths** → their GitHub mirror:
  `golang.org/x/<r>` → `golang/<r>`, `k8s.io/<r>` → `kubernetes/<r>`,
  `sigs.k8s.io/<r>` → `kubernetes-sigs/<r>`, `gopkg.in/<pkg>.vN` →
  `go-<pkg>/<pkg>` (and `gopkg.in/<user>/<pkg>.vN` → `<user>/<pkg>`).

Hosts and paths that don't map (Bitbucket, sr.ht, `google.golang.org/*`) resolve
to *no repository* - reported honestly as **unchecked**, never guessed.
