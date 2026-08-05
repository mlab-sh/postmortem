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

pub fn detect(root: &Path) -> Result<Vec<Detected>> {
    let mut out = Vec::new();

    let pkg = root.join("package.json");
    if pkg.is_file() {
        if let Some(lock) = first_existing(root, NODE_LOCKS) {
            let nm = root.join("node_modules");
            out.push(Detected::Node {
                root: root.to_path_buf(),
                manifest: pkg,
                lockfile: lock,
                node_modules: if nm.is_dir() { Some(nm) } else { None },
            });
        } else {
            eprintln!("warn: package.json found but no supported lockfile");
        }
    }

    let py_manifest = ["pyproject.toml", "setup.py", "Pipfile"]
        .iter()
        .map(|f| root.join(f))
        .find(|p| p.is_file())
        .or_else(|| {
            let req = root.join("requirements.txt");
            if req.is_file() { Some(req) } else { None }
        });
    if let Some(m) = py_manifest {
        let lock = first_existing(root, PY_LOCKS).or_else(|| {
            let req = root.join("requirements.txt");
            if req.is_file() { Some(req) } else { None }
        });
        let site_packages = find_site_packages(root);
        out.push(Detected::Python {
            root: root.to_path_buf(),
            manifest: m,
            lockfile: lock,
            site_packages,
        });
    }

    let cargo = root.join("Cargo.toml");
    let cargo_lock = root.join("Cargo.lock");
    if cargo.is_file() && cargo_lock.is_file() {
        out.push(Detected::Rust {
            root: root.to_path_buf(),
            manifest: cargo,
            lockfile: cargo_lock,
        });
    }

    // Bundler always resolves a Gemfile into a Gemfile.lock, whose own
    // DEPENDENCIES section marks the direct gems — so the lock alone suffices.
    let gemfile_lock = root.join("Gemfile.lock");
    if gemfile_lock.is_file() {
        let manifest = ["Gemfile", "gems.rb"]
            .iter()
            .map(|f| root.join(f))
            .find(|p| p.is_file())
            .or_else(|| first_gemspec(root));
        out.push(Detected::Ruby {
            root: root.to_path_buf(),
            manifest,
            lockfile: gemfile_lock,
        });
    }

    // Composer resolves composer.json into composer.lock; the manifest supplies
    // the direct set (require / require-dev).
    let composer_lock = root.join("composer.lock");
    if composer_lock.is_file() {
        let manifest = root.join("composer.json");
        out.push(Detected::Php {
            root: root.to_path_buf(),
            manifest: manifest.is_file().then_some(manifest),
            lockfile: composer_lock,
        });
    }

    // go.mod lists every module (direct, plus `// indirect` transitives); go.sum
    // adds checksums. The manifest alone is enough for the SBOM.
    let go_mod = root.join("go.mod");
    if go_mod.is_file() {
        let go_sum = root.join("go.sum");
        out.push(Detected::Go {
            root: root.to_path_buf(),
            manifest: go_mod,
            lockfile: go_sum.is_file().then_some(go_sum),
        });
    }

    // JVM: Maven `pom.xml` lists direct deps; Gradle `gradle.lockfile` is the
    // full resolved set. Prefer Maven when both are present at the root.
    let pom = root.join("pom.xml");
    let gradle_lock = root.join("gradle.lockfile");
    if pom.is_file() {
        out.push(Detected::Java {
            root: root.to_path_buf(),
            manifest: Some(pom),
            lockfile: None,
        });
    } else if gradle_lock.is_file() {
        let manifest = ["build.gradle", "build.gradle.kts"]
            .iter()
            .map(|f| root.join(f))
            .find(|p| p.is_file());
        out.push(Detected::Java {
            root: root.to_path_buf(),
            manifest,
            lockfile: Some(gradle_lock),
        });
    }

    Ok(out)
}

/// First `*.gemspec` at the repo root, if any.
fn first_gemspec(root: &Path) -> Option<PathBuf> {
    std::fs::read_dir(root).ok()?.flatten().map(|e| e.path()).find(|p| {
        p.extension().and_then(|s| s.to_str()) == Some("gemspec")
    })
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
