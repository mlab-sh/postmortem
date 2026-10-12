use anyhow::Result;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Detected {
    Node {
        root: PathBuf,
        manifest: PathBuf,
        lockfile: PathBuf,
        /// Path to `node_modules/` if it exists on disk — analyzers need it.
        node_modules: Option<PathBuf>,
    },
    Python {
        root: PathBuf,
        manifest: PathBuf,
        lockfile: Option<PathBuf>,
        /// Local virtualenv site-packages if discoverable.
        site_packages: Option<PathBuf>,
    },
    Rust {
        root: PathBuf,
        manifest: PathBuf,
        lockfile: PathBuf,
    },
    Ruby {
        root: PathBuf,
        /// `Gemfile` or a `*.gemspec` if present — informational only; direct
        /// deps come from the lockfile's own `DEPENDENCIES` section.
        manifest: Option<PathBuf>,
        lockfile: PathBuf,
    },
    Php {
        root: PathBuf,
        /// `composer.json` if present — supplies the direct-dependency set.
        manifest: Option<PathBuf>,
        lockfile: PathBuf,
    },
    Go {
        root: PathBuf,
        /// `go.mod` — lists every module with a direct/indirect marker.
        manifest: PathBuf,
        /// `go.sum` if present — supplies module checksums.
        lockfile: Option<PathBuf>,
    },
    Java {
        root: PathBuf,
        /// `pom.xml` (Maven) or `build.gradle`(`.kts`) (Gradle), if present.
        manifest: Option<PathBuf>,
        /// `gradle.lockfile` if present — the full resolved Gradle set.
        lockfile: Option<PathBuf>,
    },
    Dotnet {
        root: PathBuf,
        /// `*.csproj` / `*.fsproj` / `*.vbproj` if present — direct
        /// `<PackageReference>`s, used only when there is no lockfile.
        manifest: Option<PathBuf>,
        /// `packages.lock.json` if present — the full resolved NuGet graph.
        lockfile: Option<PathBuf>,
    },
    Cocoapods {
        root: PathBuf,
        lockfile: PathBuf,
    },
    Swift {
        root: PathBuf,
        /// `Package.swift` if present — its `.package(url:)`s are the direct set.
        manifest: Option<PathBuf>,
        /// `Package.resolved`, at the root or inside an Xcode project/workspace.
        lockfile: PathBuf,
    },
    Dart {
        root: PathBuf,
        /// `pubspec.lock` — marks the direct set itself; `pubspec.yaml` is not
        /// needed.
        lockfile: PathBuf,
    },
    Elixir {
        root: PathBuf,
        /// `mix.exs` if present — its `deps` are the direct set.
        manifest: Option<PathBuf>,
        lockfile: PathBuf,
    },
    Conan {
        root: PathBuf,
        /// `conanfile.txt` or `conanfile.py` — the declared (direct) set.
        manifest: Option<PathBuf>,
        /// `conan.lock` if present — the resolved set.
        lockfile: Option<PathBuf>,
    },
    /// Scala / sbt — Maven coordinates, reported as `java`.
    Scala {
        root: PathBuf,
        /// `build.sbt`; `project/*.scala` beside it is read too.
        manifest: PathBuf,
    },
    /// Clojure / Leiningen — Maven coordinates, reported as `java`.
    Clojure {
        root: PathBuf,
        /// `project.clj`.
        manifest: PathBuf,
    },
    Haskell {
        root: PathBuf,
        /// `*.cabal` or hpack's `package.yaml` — the direct set.
        manifest: Option<PathBuf>,
        /// `cabal.project.freeze` or `stack.yaml.lock`.
        lockfile: Option<PathBuf>,
    },
    R {
        root: PathBuf,
        /// `DESCRIPTION` if present — the direct set.
        manifest: Option<PathBuf>,
        /// `renv.lock`.
        lockfile: PathBuf,
    },
    Perl {
        root: PathBuf,
        /// `cpanfile`.
        manifest: Option<PathBuf>,
        /// `cpanfile.snapshot` (Carton).
        lockfile: Option<PathBuf>,
    },
    Julia {
        root: PathBuf,
        /// `Project.toml` — the direct set.
        manifest: Option<PathBuf>,
        /// `Manifest.toml` (or `JuliaManifest.toml`).
        lockfile: PathBuf,
    },
    Vcpkg {
        root: PathBuf,
        /// `vcpkg.json`.
        manifest: PathBuf,
        /// `vcpkg_installed/vcpkg/status` — what a build installed, if one ran.
        status: Option<PathBuf>,
    },
}

impl Detected {
    pub fn name(&self) -> &'static str {
        match self {
            Detected::Node { .. } => "node",
            Detected::Python { .. } => "python",
            Detected::Rust { .. } => "rust",
            Detected::Ruby { .. } => "ruby",
            Detected::Php { .. } => "php",
            Detected::Go { .. } => "go",
            Detected::Java { .. } => "java",
            Detected::Dotnet { .. } => "dotnet",
            Detected::Cocoapods { .. } => "cocoapods",
            Detected::Swift { .. } => "swift",
            Detected::Dart { .. } => "dart",
            Detected::Elixir { .. } => "elixir",
            Detected::Conan { .. } => "conan",
            Detected::Vcpkg { .. } => "vcpkg",
            Detected::Haskell { .. } => "haskell",
            Detected::R { .. } => "r",
            Detected::Perl { .. } => "perl",
            Detected::Julia { .. } => "julia",
            Detected::Scala { .. } => "scala",
            Detected::Clojure { .. } => "clojure",
        }
    }

    /// The detected project root (shared by all variants).
    pub fn root(&self) -> &std::path::Path {
        match self {
            Detected::Node { root, .. }
            | Detected::Python { root, .. }
            | Detected::Rust { root, .. }
            | Detected::Ruby { root, .. }
            | Detected::Php { root, .. }
            | Detected::Go { root, .. }
            | Detected::Java { root, .. }
            | Detected::Dotnet { root, .. }
            | Detected::Cocoapods { root, .. }
            | Detected::Swift { root, .. }
            | Detected::Dart { root, .. }
            | Detected::Elixir { root, .. }
            | Detected::Conan { root, .. }
            | Detected::Vcpkg { root, .. }
            | Detected::Haskell { root, .. }
            | Detected::R { root, .. }
            | Detected::Perl { root, .. }
            | Detected::Julia { root, .. }
            | Detected::Scala { root, .. }
            | Detected::Clojure { root, .. } => root,
        }
    }
}

const NODE_LOCKS: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
];

const PY_LOCKS: &[&str] = &["poetry.lock", "uv.lock", "Pipfile.lock"];

/// Detect every supported ecosystem present at `root`, picking one lockfile per
/// ecosystem by the priority order of [`NODE_LOCKS`] / [`PY_LOCKS`]. Only the
/// directory itself is inspected — there is no recursion into subprojects.
pub fn detect(root: &Path) -> Result<Vec<Detected>> {
    let mut out = Vec::new();

    if root.join("package.json").is_file() {
        match first_existing(root, NODE_LOCKS) {
            Some(lock) => out.push(node_at(root, lock)),
            None => eprintln!(
                "warn: {}: package.json found but no supported lockfile",
                root.display()
            ),
        }
    }

    if let Some(m) = py_manifest(root) {
        out.push(python_at(root, m, py_lock(root)));
    }

    if root.join("Cargo.toml").is_file() && root.join("Cargo.lock").is_file() {
        out.push(rust_at(root));
    }

    // Bundler always resolves a Gemfile into a Gemfile.lock, whose own
    // DEPENDENCIES section marks the direct gems — so the lock alone suffices.
    let gemfile_lock = root.join("Gemfile.lock");
    if gemfile_lock.is_file() {
        out.push(ruby_at(root, gemfile_lock));
    }

    // Composer resolves composer.json into composer.lock; the manifest supplies
    // the direct set (require / require-dev).
    let composer_lock = root.join("composer.lock");
    if composer_lock.is_file() {
        out.push(php_at(root, composer_lock));
    }

    // go.mod lists every module (direct, plus `// indirect` transitives); go.sum
    // adds checksums. The manifest alone is enough for the SBOM.
    let go_mod = root.join("go.mod");
    if go_mod.is_file() {
        out.push(go_at(root, go_mod));
    }

    // JVM: Maven `pom.xml` lists direct deps; Gradle `gradle.lockfile` is the
    // full resolved set. Prefer Maven when both are present at the root.
    let pom = root.join("pom.xml");
    let gradle_lock = root.join("gradle.lockfile");
    if pom.is_file() {
        out.push(maven_at(root, pom));
    } else if gradle_lock.is_file() {
        out.push(gradle_at(root, gradle_lock));
    }

    // .NET: `packages.lock.json` is the full graph; a project file alone still
    // gives the direct references.
    let nuget_lock = root.join("packages.lock.json");
    let project = dotnet_project(root);
    if nuget_lock.is_file() || project.is_some() {
        out.push(Detected::Dotnet {
            root: root.to_path_buf(),
            manifest: project,
            lockfile: nuget_lock.is_file().then_some(nuget_lock),
        });
    }

    // CocoaPods always resolves the Podfile into a Podfile.lock.
    let podfile_lock = root.join("Podfile.lock");
    if podfile_lock.is_file() {
        out.push(Detected::Cocoapods {
            root: root.to_path_buf(),
            lockfile: podfile_lock,
        });
    }

    if let Some(resolved) = swift_resolved(root) {
        out.push(swift_at(root, resolved));
    }

    let conan = conan_at(root, None);
    if matches!(&conan, Detected::Conan { manifest, lockfile, .. } if manifest.is_some() || lockfile.is_some()) {
        out.push(conan);
    }

    // sbt and Leiningen publish Maven coordinates; neither has a lockfile.
    let build_sbt = root.join("build.sbt");
    if build_sbt.is_file() {
        out.push(Detected::Scala {
            root: root.to_path_buf(),
            manifest: build_sbt,
        });
    }
    let project_clj = root.join("project.clj");
    if project_clj.is_file() {
        out.push(Detected::Clojure {
            root: root.to_path_buf(),
            manifest: project_clj,
        });
    }

    if let Some(d) = haskell_at(root, None) {
        out.push(d);
    }
    if let Some(d) = r_at(root, None) {
        out.push(d);
    }
    if let Some(d) = perl_at(root) {
        out.push(d);
    }
    if let Some(d) = julia_at(root, None) {
        out.push(d);
    }

    let vcpkg_json = root.join("vcpkg.json");
    if vcpkg_json.is_file() {
        out.push(vcpkg_at(root, vcpkg_json));
    }

    let mix_lock = root.join("mix.lock");
    if mix_lock.is_file() {
        out.push(elixir_at(root, mix_lock));
    }

    let pubspec_lock = root.join("pubspec.lock");
    if pubspec_lock.is_file() {
        out.push(Detected::Dart {
            root: root.to_path_buf(),
            lockfile: pubspec_lock,
        });
    }

    Ok(out)
}

/// Resolve one `tree`/`scan` target: either a project **directory** (full
/// detection, see [`detect`]) or an explicit **manifest/lockfile**, which pins a
/// single ecosystem — and, where several coexist, a single flavor: pass
/// `yarn.lock` and a stale `package-lock.json` in the same directory is ignored.
///
/// A pinned file still resolves its sibling manifest from the parent directory,
/// so direct-dependency classification is unaffected.
pub fn detect_target(target: &Path) -> Result<Vec<Detected>> {
    if target.is_dir() {
        return detect(target);
    }
    if !target.is_file() {
        anyhow::bail!("{}: not a directory or a readable file", target.display());
    }

    let root = target.parent().unwrap_or(Path::new("."));
    let file = target.to_path_buf();
    let missing = |what: &str| {
        anyhow::anyhow!(
            "{}: no {what} in {} — it supplies the direct-dependency set",
            target.display(),
            root.display()
        )
    };

    let detected = match target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
    {
        "package-lock.json" | "npm-shrinkwrap.json" | "pnpm-lock.yaml" | "yarn.lock" => {
            if !root.join("package.json").is_file() {
                return Err(missing("package.json"));
            }
            node_at(root, file)
        }
        "package.json" => match first_existing(root, NODE_LOCKS) {
            Some(lock) => node_at(root, lock),
            None => anyhow::bail!("{}: no supported lockfile alongside it", target.display()),
        },
        "poetry.lock" | "uv.lock" | "Pipfile.lock" => {
            let m = py_manifest(root).ok_or_else(|| missing("pyproject.toml/setup.py/Pipfile"))?;
            python_at(root, m, Some(file))
        }
        // A requirements file is its own manifest and its own pinned set — any
        // name (`requirements/base.txt`, `constraints.txt`) once it is named.
        name if name.ends_with(".txt") => python_at(root, file.clone(), Some(file)),
        "pyproject.toml" | "setup.py" | "Pipfile" => python_at(root, file, py_lock(root)),
        "Cargo.lock" | "Cargo.toml" => {
            if !root.join("Cargo.toml").is_file() {
                return Err(missing("Cargo.toml"));
            }
            if !root.join("Cargo.lock").is_file() {
                anyhow::bail!("{}: no Cargo.lock alongside it", target.display());
            }
            rust_at(root)
        }
        "Gemfile.lock" => ruby_at(root, file),
        "composer.lock" => php_at(root, file),
        // go.sum carries no module list of its own — go.mod is always the input.
        "go.mod" | "go.sum" => {
            let go_mod = root.join("go.mod");
            if !go_mod.is_file() {
                return Err(missing("go.mod"));
            }
            go_at(root, go_mod)
        }
        "pom.xml" => maven_at(root, file),
        "gradle.lockfile" => gradle_at(root, file),
        "packages.lock.json" => Detected::Dotnet {
            root: root.to_path_buf(),
            manifest: dotnet_project(root),
            lockfile: Some(file),
        },
        "Podfile.lock" => Detected::Cocoapods {
            root: root.to_path_buf(),
            lockfile: file,
        },
        "Package.resolved" => swift_at(root, file),
        "conan.lock" => conan_at(root, Some(file)),
        "conanfile.txt" | "conanfile.py" => match conan_at(root, None) {
            Detected::Conan { root, lockfile, .. } => Detected::Conan {
                root,
                manifest: Some(file),
                lockfile,
            },
            other => other,
        },
        "vcpkg.json" => vcpkg_at(root, file),
        "cabal.project.freeze" | "stack.yaml.lock" => {
            haskell_at(root, Some(file)).ok_or_else(|| missing("lockfile"))?
        }
        name if name.ends_with(".cabal") || name == "package.yaml" => match haskell_at(root, None) {
            Some(Detected::Haskell { root, lockfile, .. }) => Detected::Haskell {
                root,
                manifest: Some(file),
                lockfile,
            },
            _ => unreachable!("a manifest was found"),
        },
        "renv.lock" => r_at(root, Some(file)).ok_or_else(|| missing("renv.lock"))?,
        "cpanfile" | "cpanfile.snapshot" => perl_at(root).ok_or_else(|| missing("cpanfile"))?,
        "Manifest.toml" | "JuliaManifest.toml" => {
            julia_at(root, Some(file)).ok_or_else(|| missing("Manifest.toml"))?
        }
        "Project.toml" | "JuliaProject.toml" => julia_at(root, None)
            .ok_or_else(|| anyhow::anyhow!("{}: no Manifest.toml alongside it", target.display()))?,
        "build.sbt" => Detected::Scala {
            root: root.to_path_buf(),
            manifest: file,
        },
        "project.clj" => Detected::Clojure {
            root: root.to_path_buf(),
            manifest: file,
        },
        "mix.lock" => elixir_at(root, file),
        "mix.exs" => {
            let lock = root.join("mix.lock");
            if !lock.is_file() {
                anyhow::bail!("{}: no mix.lock alongside it", target.display());
            }
            elixir_at(root, lock)
        }
        "pubspec.lock" => Detected::Dart {
            root: root.to_path_buf(),
            lockfile: file,
        },
        "pubspec.yaml" => {
            let lock = root.join("pubspec.lock");
            if !lock.is_file() {
                anyhow::bail!("{}: no pubspec.lock alongside it", target.display());
            }
            Detected::Dart {
                root: root.to_path_buf(),
                lockfile: lock,
            }
        }
        "Package.swift" => match swift_resolved(root) {
            Some(resolved) => swift_at(root, resolved),
            None => anyhow::bail!("{}: no Package.resolved alongside it", target.display()),
        },
        name if is_dotnet_project(name) => {
            let lock = root.join("packages.lock.json");
            Detected::Dotnet {
                root: root.to_path_buf(),
                manifest: Some(file),
                lockfile: lock.is_file().then_some(lock),
            }
        }
        other => anyhow::bail!(
            "{other}: not a recognised manifest or lockfile — expected one of \
             package.json, package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock, \
             pyproject.toml, setup.py, Pipfile, Pipfile.lock, poetry.lock, uv.lock, requirements*.txt, \
             Cargo.toml, Cargo.lock, Gemfile.lock, composer.lock, go.mod, go.sum, pom.xml, \
             gradle.lockfile, packages.lock.json, *.csproj, *.fsproj, *.vbproj, Podfile.lock, \
             Package.resolved, Package.swift, pubspec.lock, pubspec.yaml, mix.lock, mix.exs, \
             conan.lock, conanfile.txt, conanfile.py, vcpkg.json, build.sbt, project.clj, \
             cabal.project.freeze, stack.yaml.lock, *.cabal, package.yaml, renv.lock, cpanfile, \
             cpanfile.snapshot, Manifest.toml, Project.toml"
        ),
    };
    Ok(vec![detected])
}

fn node_at(root: &Path, lockfile: PathBuf) -> Detected {
    let nm = root.join("node_modules");
    Detected::Node {
        root: root.to_path_buf(),
        manifest: root.join("package.json"),
        lockfile,
        node_modules: nm.is_dir().then_some(nm),
    }
}

fn python_at(root: &Path, manifest: PathBuf, lockfile: Option<PathBuf>) -> Detected {
    Detected::Python {
        root: root.to_path_buf(),
        manifest,
        lockfile,
        site_packages: find_site_packages(root),
    }
}

fn rust_at(root: &Path) -> Detected {
    Detected::Rust {
        root: root.to_path_buf(),
        manifest: root.join("Cargo.toml"),
        lockfile: root.join("Cargo.lock"),
    }
}

fn ruby_at(root: &Path, lockfile: PathBuf) -> Detected {
    Detected::Ruby {
        root: root.to_path_buf(),
        manifest: ["Gemfile", "gems.rb"]
            .iter()
            .map(|f| root.join(f))
            .find(|p| p.is_file())
            .or_else(|| first_gemspec(root)),
        lockfile,
    }
}

fn php_at(root: &Path, lockfile: PathBuf) -> Detected {
    let manifest = root.join("composer.json");
    Detected::Php {
        root: root.to_path_buf(),
        manifest: manifest.is_file().then_some(manifest),
        lockfile,
    }
}

fn go_at(root: &Path, manifest: PathBuf) -> Detected {
    let go_sum = root.join("go.sum");
    Detected::Go {
        root: root.to_path_buf(),
        manifest,
        lockfile: go_sum.is_file().then_some(go_sum),
    }
}

fn maven_at(root: &Path, pom: PathBuf) -> Detected {
    Detected::Java {
        root: root.to_path_buf(),
        manifest: Some(pom),
        lockfile: None,
    }
}

fn gradle_at(root: &Path, lockfile: PathBuf) -> Detected {
    Detected::Java {
        root: root.to_path_buf(),
        manifest: ["build.gradle", "build.gradle.kts"]
            .iter()
            .map(|f| root.join(f))
            .find(|p| p.is_file()),
        lockfile: Some(lockfile),
    }
}

/// A `Package.resolved` sitting next to an Xcode file is not the package's
/// own: the manifest is not consulted then.
fn swift_at(root: &Path, lockfile: PathBuf) -> Detected {
    let manifest = root.join("Package.swift");
    Detected::Swift {
        root: root.to_path_buf(),
        manifest: (manifest.is_file() && lockfile.parent() == Some(root)).then_some(manifest),
        lockfile,
    }
}

/// SwiftPM's resolved pins: at the root for a package, or where Xcode keeps
/// them — `X.xcworkspace/xcshareddata/swiftpm/` (preferred: it covers every
/// project in it) or `X.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/`.
fn swift_resolved(root: &Path) -> Option<PathBuf> {
    let direct = root.join("Package.resolved");
    if direct.is_file() {
        return Some(direct);
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(root).ok()?.flatten().map(|e| e.path()).collect();
    entries.sort();
    let tail = Path::new("xcshareddata/swiftpm/Package.resolved");
    let in_ext = |ext: &str, sub: &str| {
        entries
            .iter()
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some(ext))
            .map(|p| p.join(sub).join(tail))
            .find(|p| p.is_file())
    };
    in_ext("xcworkspace", "").or_else(|| in_ext("xcodeproj", "project.xcworkspace"))
}

/// Haskell at `root`: a lock (`cabal.project.freeze`, else `stack.yaml.lock`)
/// and/or a package manifest (`*.cabal`, else hpack's `package.yaml`).
fn haskell_at(root: &Path, lockfile: Option<PathBuf>) -> Option<Detected> {
    // A freeze file with no `constraints:` (only an `index-state`) pins
    // nothing; a Stack lock beside it is then the better source.
    let freeze = root.join("cabal.project.freeze");
    let pins = std::fs::read_to_string(&freeze).is_ok_and(|s| s.contains("constraints:"));
    let lockfile = lockfile
        .or_else(|| pins.then_some(freeze))
        .or_else(|| first_existing(root, &["stack.yaml.lock"]));
    let manifest = first_with_ext(root, "cabal").or_else(|| {
        let p = root.join("package.yaml");
        p.is_file().then_some(p)
    });
    (lockfile.is_some() || manifest.is_some()).then(|| Detected::Haskell {
        root: root.to_path_buf(),
        manifest,
        lockfile,
    })
}

fn r_at(root: &Path, lockfile: Option<PathBuf>) -> Option<Detected> {
    let lockfile = lockfile.or_else(|| first_existing(root, &["renv.lock"]))?;
    Some(Detected::R {
        root: root.to_path_buf(),
        manifest: first_existing(root, &["DESCRIPTION"]),
        lockfile,
    })
}

fn perl_at(root: &Path) -> Option<Detected> {
    let manifest = first_existing(root, &["cpanfile"]);
    let lockfile = first_existing(root, &["cpanfile.snapshot"]);
    (manifest.is_some() || lockfile.is_some()).then(|| Detected::Perl {
        root: root.to_path_buf(),
        manifest,
        lockfile,
    })
}

fn julia_at(root: &Path, lockfile: Option<PathBuf>) -> Option<Detected> {
    let lockfile = lockfile.or_else(|| first_existing(root, &["Manifest.toml", "JuliaManifest.toml"]))?;
    Some(Detected::Julia {
        root: root.to_path_buf(),
        manifest: first_existing(root, &["Project.toml", "JuliaProject.toml"]),
        lockfile,
    })
}

/// First file at `root` with extension `ext` (sorted, so the pick is stable).
fn first_with_ext(root: &Path, ext: &str) -> Option<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(root)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().and_then(|e| e.to_str()) == Some(ext))
        .collect();
    found.sort();
    found.into_iter().next()
}

fn conan_at(root: &Path, lockfile: Option<PathBuf>) -> Detected {
    let lock = root.join("conan.lock");
    Detected::Conan {
        root: root.to_path_buf(),
        manifest: first_existing(root, &["conanfile.txt", "conanfile.py"]),
        lockfile: lockfile.or_else(|| lock.is_file().then_some(lock)),
    }
}

fn vcpkg_at(root: &Path, manifest: PathBuf) -> Detected {
    let status = root.join("vcpkg_installed").join("vcpkg").join("status");
    Detected::Vcpkg {
        root: root.to_path_buf(),
        manifest,
        status: status.is_file().then_some(status),
    }
}

fn elixir_at(root: &Path, lockfile: PathBuf) -> Detected {
    let manifest = root.join("mix.exs");
    Detected::Elixir {
        root: root.to_path_buf(),
        manifest: manifest.is_file().then_some(manifest),
        lockfile,
    }
}

fn is_dotnet_project(name: &str) -> bool {
    [".csproj", ".fsproj", ".vbproj"]
        .iter()
        .any(|ext| name.ends_with(ext))
}

/// First .NET project file at `root` (sorted, so the pick is stable).
fn dotnet_project(root: &Path) -> Option<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(root)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.file_name().and_then(|n| n.to_str()).is_some_and(is_dotnet_project))
        .collect();
    found.sort();
    found.into_iter().next()
}

/// The Python manifest at `root`, preferring a real manifest over the bare
/// `requirements.txt` fallback.
fn py_manifest(root: &Path) -> Option<PathBuf> {
    ["pyproject.toml", "setup.py", "Pipfile"]
        .iter()
        .map(|f| root.join(f))
        .find(|p| p.is_file())
        .or_else(|| {
            let req = root.join("requirements.txt");
            req.is_file().then_some(req)
        })
}

/// The Python lockfile at `root`, falling back to a pinned `requirements.txt`.
fn py_lock(root: &Path) -> Option<PathBuf> {
    first_existing(root, PY_LOCKS).or_else(|| {
        let req = root.join("requirements.txt");
        req.is_file().then_some(req)
    })
}

/// First `*.gemspec` at the repo root, if any.
fn first_gemspec(root: &Path) -> Option<PathBuf> {
    std::fs::read_dir(root)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().and_then(|s| s.to_str()) == Some("gemspec"))
}

fn first_existing(root: &Path, names: &[&str]) -> Option<PathBuf> {
    names.iter().map(|n| root.join(n)).find(|p| p.is_file())
}

/// Look for `.venv/lib/python*/site-packages` or `venv/lib/python*/site-packages`.
fn find_site_packages(root: &Path) -> Option<PathBuf> {
    for venv in &[".venv", "venv", "env"] {
        let lib = root.join(venv).join("lib");
        if !lib.is_dir() {
            continue;
        }
        let Ok(rd) = std::fs::read_dir(&lib) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            let sp = p.join("site-packages");
            if sp.is_dir() {
                return Some(sp);
            }
        }
    }
    None
}
