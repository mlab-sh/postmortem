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
            | Detected::Java { root, .. } => root,
        }
    }
}

const NODE_LOCKS: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
];

const PY_LOCKS: &[&str] = &["poetry.lock", "Pipfile.lock"];

/// Detect every supported ecosystem present at `root`, picking one lockfile per
/// ecosystem by the priority order of [`NODE_LOCKS`] / [`PY_LOCKS`]. Only the
/// directory itself is inspected — there is no recursion into subprojects.
pub fn detect(root: &Path) -> Result<Vec<Detected>> {
    let mut out = Vec::new();

    if root.join("package.json").is_file() {
        match first_existing(root, NODE_LOCKS) {
            Some(lock) => out.push(node_at(root, lock)),
            None => eprintln!("warn: package.json found but no supported lockfile"),
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
        "poetry.lock" | "Pipfile.lock" => {
            let m = py_manifest(root).ok_or_else(|| missing("pyproject.toml/setup.py/Pipfile"))?;
            python_at(root, m, Some(file))
        }
        // requirements.txt is its own manifest and its own pinned set.
        "requirements.txt" => python_at(root, file.clone(), Some(file)),
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
        other => anyhow::bail!(
            "{other}: not a recognised manifest or lockfile — expected one of \
             package.json, package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock, \
             pyproject.toml, setup.py, Pipfile, Pipfile.lock, poetry.lock, requirements.txt, \
             Cargo.toml, Cargo.lock, Gemfile.lock, composer.lock, go.mod, go.sum, pom.xml, \
             gradle.lockfile"
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
