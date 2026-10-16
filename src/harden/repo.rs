//! What `harden` reads from the repository: package-manager configuration,
//! pipeline definitions, Dockerfiles and scripts.
//!
//! The baseline is about *how* dependencies are consumed, and that lives in
//! files the dependency graph never looks at: `.npmrc`, `pnpm-workspace.yaml`,
//! `.yarnrc.yml`, `bunfig.toml`, `uv.toml`, `.cargo/config.toml`, the CI
//! workflows. Everything is read once, up front, and the checks only look.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Directories that never hold the project's own configuration.
const PRUNE: &[&str] = &[
    ".git", "node_modules", "target", "vendor", ".venv", "venv", "dist", "build", ".next",
    ".yarn", "__pycache__", ".tox", "bower_components",
    // Test fixtures carry Dockerfiles and lockfiles that are not the project's.
    "tests", "test", "fixtures", "testdata", "__fixtures__", "__tests__", "examples", "e2e",
];

/// Above this a "config file" is not one; skip rather than read a blob.
const MAX_FILE: u64 = 1 << 20;

pub struct TextFile {
    pub rel: String,
    pub text: String,
}

pub struct Repo {
    pub root: PathBuf,
    /// Pipeline definitions (GitHub Actions, GitLab, CircleCI, Azure, …).
    pub ci: Vec<TextFile>,
    pub dockerfiles: Vec<TextFile>,
    /// Shell scripts, Makefiles, the root README: where `npx foo` hides.
    pub scripts: Vec<TextFile>,
    /// `.csproj` / `.fsproj` paths, for NuGet's lockfile check.
    pub dotnet_projects: Vec<String>,
    git: bool,
}

impl Repo {
    pub fn load(root: &Path) -> Repo {
        let mut repo = Repo {
            root: root.to_path_buf(),
            ci: Vec::new(),
            dockerfiles: Vec::new(),
            scripts: Vec::new(),
            dotnet_projects: Vec::new(),
            git: root.join(".git").exists(),
        };
        let walk = ignore::WalkBuilder::new(root)
            .standard_filters(false)
            .hidden(false)
            .follow_links(false)
            .max_depth(Some(4))
            .filter_entry(|e| {
                e.depth() == 0
                    || !e.file_type().is_some_and(|t| t.is_dir())
                    || !PRUNE.contains(&e.file_name().to_string_lossy().as_ref())
            })
            .build();
        for entry in walk.flatten() {
            if !entry.file_type().is_some_and(|t| t.is_file()) {
                continue;
            }
            let Ok(rel) = entry.path().strip_prefix(root) else { continue };
            let rel = rel.to_string_lossy().replace('\\', "/");
            let name = entry.file_name().to_string_lossy().to_string();
            let kind = classify(&rel, &name);
            if kind == Kind::Dotnet {
                repo.dotnet_projects.push(rel);
                continue;
            }
            if kind == Kind::Other {
                continue;
            }
            if entry.metadata().map(|m| m.len() > MAX_FILE).unwrap_or(true) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(entry.path()) else { continue };
            let file = TextFile { rel, text };
            match kind {
                Kind::Ci => repo.ci.push(file),
                Kind::Docker => repo.dockerfiles.push(file),
                Kind::Script => repo.scripts.push(file),
                Kind::Dotnet | Kind::Other => {}
            }
        }
        for v in [&mut repo.ci, &mut repo.dockerfiles, &mut repo.scripts] {
            v.sort_by(|a, b| a.rel.cmp(&b.rel));
        }
        repo
    }

    pub fn read(&self, rel: &str) -> Option<String> {
        std::fs::read_to_string(self.root.join(rel)).ok()
    }

    pub fn has(&self, rel: &str) -> bool {
        self.root.join(rel).is_file()
    }

    /// Is `rel` committed? `None` outside a git checkout, where the question
    /// has no answer.
    pub fn tracked(&self, rel: &str) -> Option<bool> {
        if !self.git {
            return None;
        }
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["ls-files", "--error-unmatch", "--", rel])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .ok()?;
        Some(out.success())
    }

    pub fn toml(&self, rel: &str) -> Option<toml::Value> {
        toml::from_str(&self.read(rel)?).ok()
    }

    pub fn yaml(&self, rel: &str) -> Option<serde_yaml::Value> {
        serde_yaml::from_str(&self.read(rel)?).ok()
    }

    pub fn json(&self, rel: &str) -> Option<serde_json::Value> {
        serde_json::from_str(&self.read(rel)?).ok()
    }

    /// The project's `.npmrc` (also read by pnpm, yarn 1 and bun).
    pub fn npmrc(&self) -> BTreeMap<String, String> {
        self.read(".npmrc").map(|t| parse_ini(&t)).unwrap_or_default()
    }

    /// `[tool.uv]` from `pyproject.toml`, else `uv.toml` — uv reads one or the
    /// other, `uv.toml` winning when both exist.
    pub fn uv_settings(&self) -> Option<(toml::Value, &'static str)> {
        if let Some(v) = self.toml("uv.toml") {
            return Some((v, "uv.toml"));
        }
        let py = self.toml("pyproject.toml")?;
        Some((py.get("tool")?.get("uv")?.clone(), "pyproject.toml [tool.uv]"))
    }

    /// `pip.conf` / `pip.ini` committed at the root, as `key → value` with the
    /// section dropped (pip reads `[global]` and `[install]` alike for these).
    pub fn pip_conf(&self) -> Option<(BTreeMap<String, String>, &'static str)> {
        for f in ["pip.conf", "pip.ini"] {
            if let Some(t) = self.read(f) {
                return Some((parse_ini(&t), f));
            }
        }
        None
    }

    /// Root-level requirements files.
    pub fn requirements(&self) -> Vec<(String, String)> {
        let Ok(rd) = std::fs::read_dir(&self.root) else { return Vec::new() };
        let mut out: Vec<(String, String)> = rd
            .flatten()
            .filter_map(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                (n.starts_with("requirements") && n.ends_with(".txt"))
                    .then(|| std::fs::read_to_string(e.path()).ok().map(|t| (n, t)))
                    .flatten()
            })
            .collect();
        out.sort();
        out
    }

    /// Every text the checks grep for commands: CI, Dockerfiles, scripts.
    pub fn command_files(&self) -> impl Iterator<Item = &TextFile> {
        self.ci.iter().chain(&self.dockerfiles).chain(&self.scripts)
    }
}

#[derive(PartialEq)]
enum Kind {
    Ci,
    Docker,
    Script,
    Dotnet,
    Other,
}

fn classify(rel: &str, name: &str) -> Kind {
    let yaml = name.ends_with(".yml") || name.ends_with(".yaml");
    if (rel.starts_with(".github/workflows/") && yaml)
        || (rel.starts_with(".gitlab/ci/") && yaml)
        || matches!(
            rel,
            ".gitlab-ci.yml"
                | ".circleci/config.yml"
                | "azure-pipelines.yml"
                | "bitbucket-pipelines.yml"
                | "Jenkinsfile"
                | ".buildkite/pipeline.yml"
                | ".travis.yml"
                | "cloudbuild.yaml"
                | ".drone.yml"
                | ".woodpecker.yml"
        )
        || (rel.starts_with(".forgejo/workflows/") && yaml)
        || (rel.starts_with(".gitea/workflows/") && yaml)
    {
        Kind::Ci
    } else if name.starts_with("Dockerfile")
        || name.ends_with(".dockerfile")
        || name == "Containerfile"
    {
        Kind::Docker
    } else if name.ends_with(".sh")
        || matches!(name, "Makefile" | "justfile" | "Justfile" | "Taskfile.yml")
        || rel == "README.md"
    {
        Kind::Script
    } else if name.ends_with(".csproj") || name.ends_with(".fsproj") {
        Kind::Dotnet
    } else {
        Kind::Other
    }
}

/// `key=value` lines, `;`/`#` comments, `[section]` headers ignored. Keys are
/// lowercased: npm and pip both treat them case-insensitively.
pub fn parse_ini(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', ';', '[']) {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim().trim_matches(['"', '\'']);
            out.insert(k.trim().to_ascii_lowercase(), v.to_string());
        }
    }
    out
}

/// The package managers the baseline names, as the repository uses them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pm {
    Npm,
    Pnpm,
    Yarn1,
    YarnBerry,
    Bun,
    Uv,
    Poetry,
    Pdm,
    Pipenv,
    Pip,
    Cargo,
    Go,
    Bundler,
    Composer,
    Maven,
    Gradle,
    Nuget,
}

impl Pm {
    pub fn name(self) -> &'static str {
        match self {
            Pm::Npm => "npm",
            Pm::Pnpm => "pnpm",
            Pm::Yarn1 => "yarn 1",
            Pm::YarnBerry => "yarn",
            Pm::Bun => "bun",
            Pm::Uv => "uv",
            Pm::Poetry => "poetry",
            Pm::Pdm => "pdm",
            Pm::Pipenv => "pipenv",
            Pm::Pip => "pip",
            Pm::Cargo => "cargo",
            Pm::Go => "go",
            Pm::Bundler => "bundler",
            Pm::Composer => "composer",
            Pm::Maven => "maven",
            Pm::Gradle => "gradle",
            Pm::Nuget => "nuget",
        }
    }

    pub fn is_js(self) -> bool {
        matches!(self, Pm::Npm | Pm::Pnpm | Pm::Yarn1 | Pm::YarnBerry | Pm::Bun)
    }

    pub fn is_python(self) -> bool {
        matches!(self, Pm::Uv | Pm::Poetry | Pm::Pdm | Pm::Pipenv | Pm::Pip)
    }
}

pub struct PmUse {
    pub pm: Pm,
    pub manifest: String,
    /// `None`: the manifest is there, its lockfile is not.
    pub lockfile: Option<String>,
}

/// Which package managers the repository root uses, read from the files
/// rather than from the graph parsers: a manifest *without* its lockfile is
/// exactly what CB-DEP-LOCK-001 is about, and the parsers skip it.
pub fn detect_pms(repo: &Repo) -> Vec<PmUse> {
    let mut out = Vec::new();
    let lock = |f: &str| repo.has(f).then(|| f.to_string());
    let mut push = |pm, manifest: &str, lockfile: Option<String>| {
        out.push(PmUse { pm, manifest: manifest.to_string(), lockfile })
    };

    if repo.has("package.json") {
        let mut any = false;
        for (f, pm) in [
            ("pnpm-lock.yaml", Pm::Pnpm),
            ("bun.lock", Pm::Bun),
            ("bun.lockb", Pm::Bun),
            ("package-lock.json", Pm::Npm),
            ("npm-shrinkwrap.json", Pm::Npm),
        ] {
            if repo.has(f) {
                push(pm, "package.json", Some(f.into()));
                any = true;
            }
        }
        if repo.has("yarn.lock") {
            let berry = repo.has(".yarnrc.yml")
                || repo.read("yarn.lock").is_some_and(|t| t.contains("__metadata:"));
            push(if berry { Pm::YarnBerry } else { Pm::Yarn1 }, "package.json", lock("yarn.lock"));
            any = true;
        }
        if !any {
            let declared = repo
                .json("package.json")
                .and_then(|j| j.get("packageManager")?.as_str().map(str::to_string))
                .unwrap_or_default();
            let pm = match declared.split('@').next().unwrap_or("") {
                "pnpm" => Pm::Pnpm,
                "yarn" if declared.starts_with("yarn@1") => Pm::Yarn1,
                "yarn" => Pm::YarnBerry,
                "bun" => Pm::Bun,
                _ => Pm::Npm,
            };
            push(pm, "package.json", None);
        }
    }

    let py = repo.toml("pyproject.toml");
    let tool = |k: &str| py.as_ref().and_then(|p| p.get("tool")?.get(k)).is_some();
    let mut python = false;
    for (f, pm, manifest) in [
        ("uv.lock", Pm::Uv, "pyproject.toml"),
        ("poetry.lock", Pm::Poetry, "pyproject.toml"),
        ("pdm.lock", Pm::Pdm, "pyproject.toml"),
        ("Pipfile.lock", Pm::Pipenv, "Pipfile"),
    ] {
        if repo.has(f) {
            push(pm, manifest, Some(f.into()));
            python = true;
        }
    }
    if !python && repo.has("Pipfile") {
        push(Pm::Pipenv, "Pipfile", None);
        python = true;
    }
    if !python && py.is_some() {
        if tool("poetry") {
            push(Pm::Poetry, "pyproject.toml", None);
            python = true;
        } else if tool("uv") {
            push(Pm::Uv, "pyproject.toml", None);
            python = true;
        } else if tool("pdm") {
            push(Pm::Pdm, "pyproject.toml", None);
            python = true;
        }
    }
    let reqs = repo.requirements();
    if !reqs.is_empty() {
        let main = reqs
            .iter()
            .find(|(n, _)| n == "requirements.txt")
            .unwrap_or(&reqs[0]);
        push(Pm::Pip, &main.0.clone(), Some(main.0.clone()));
    } else if !python && py.is_some() {
        push(Pm::Pip, "pyproject.toml", None);
    }

    if repo.has("Cargo.toml") {
        push(Pm::Cargo, "Cargo.toml", lock("Cargo.lock"));
    }
    if repo.has("go.mod") {
        push(Pm::Go, "go.mod", lock("go.sum"));
    }
    if repo.has("Gemfile") {
        push(Pm::Bundler, "Gemfile", lock("Gemfile.lock"));
    }
    if repo.has("composer.json") {
        push(Pm::Composer, "composer.json", lock("composer.lock"));
    }
    if repo.has("pom.xml") {
        push(Pm::Maven, "pom.xml", None);
    }
    for g in ["build.gradle.kts", "build.gradle"] {
        if repo.has(g) {
            push(Pm::Gradle, g, lock("gradle.lockfile"));
            break;
        }
    }
    for proj in &repo.dotnet_projects {
        let dir = proj.rsplit_once('/').map_or("", |(d, _)| d);
        let l = if dir.is_empty() {
            "packages.lock.json".to_string()
        } else {
            format!("{dir}/packages.lock.json")
        };
        push(Pm::Nuget, proj, repo.has(&l).then_some(l));
    }
    out
}

/// A duration as the package managers write it, in hours.
///
/// A bare number is in `bare_unit_hours` (npm: days, pnpm/yarn: minutes, bun:
/// seconds — every tool picked a different one). Strings take a unit suffix
/// (`7d`, `48h`, `30m`, `1w`), words (`3 days`, `24 hours`) or ISO-8601
/// (`P3D`, `PT48H`).
pub fn duration_hours(raw: &str, bare_unit_hours: f64) -> Option<f64> {
    let s = raw.trim().trim_matches(['"', '\'']).to_ascii_lowercase();
    if let Ok(n) = s.parse::<f64>() {
        return Some(n * bare_unit_hours);
    }
    if let Some(c) = re!(r"^p(?:(\d+)w)?(?:(\d+)d)?(?:t(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?)?$").captures(&s)
        && s.len() > 1
    {
        let n = |i: usize| c.get(i).and_then(|m| m.as_str().parse::<f64>().ok()).unwrap_or(0.0);
        return Some(n(1) * 168.0 + n(2) * 24.0 + n(3) + n(4) / 60.0 + n(5) / 3600.0);
    }
    let c = re!(r"^(\d+(?:\.\d+)?)\s*([a-z]+)$").captures(&s)?;
    let n: f64 = c[1].parse().ok()?;
    let unit = match &c[2] {
        "s" | "sec" | "secs" | "second" | "seconds" => 1.0 / 3600.0,
        "m" | "min" | "mins" | "minute" | "minutes" => 1.0 / 60.0,
        "h" | "hr" | "hrs" | "hour" | "hours" => 1.0,
        "d" | "day" | "days" => 24.0,
        "w" | "week" | "weeks" => 168.0,
        _ => return None,
    };
    Some(n * unit)
}

/// Is `host` one of the public registries (as opposed to an org mirror)?
pub fn is_public_registry(host: &str) -> bool {
    const PUBLIC: &[&str] = &[
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "registry.npmjs.com",
        "pypi.org",
        "pypi.python.org",
        "files.pythonhosted.org",
        "crates.io",
        "index.crates.io",
        "static.crates.io",
        "rubygems.org",
        "index.rubygems.org",
        "repo.packagist.org",
        "packagist.org",
        "proxy.golang.org",
        "repo.maven.apache.org",
        "repo1.maven.org",
        "api.nuget.org",
        "www.nuget.org",
    ];
    PUBLIC.contains(&host)
}

/// Every regex `harden` matches install commands with, in one place so
/// `LOCK-002`, `CI-001` and `VET-004` agree on what an install is.
pub fn is_install_command(line: &str) -> bool {
    re!(r"(?x)
        \b(npm\s+(ci|install|i)\b
          |pnpm\s+(install|i)\b
          |yarn(\s+install)?\s*$|yarn\s+install\b|yarn\s+--
          |bun\s+(install|i|ci)\b
          |pip3?\s+install\b|python3?\s+-m\s+pip\s+install\b
          |uv\s+(sync|pip\s+install)\b
          |poetry\s+install\b|pdm\s+(install|sync)\b|pipenv\s+(install|sync)\b
          |bundle\s+install\b
          |composer\s+(install|update)\b
          |cargo\s+(build|fetch|install|test)\b
          |go\s+mod\s+download\b
          |dotnet\s+restore\b)")
    .is_match(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_in_every_dialect() {
        assert_eq!(duration_hours("7", 24.0), Some(168.0), "npm: days");
        assert_eq!(duration_hours("2880", 1.0 / 60.0), Some(48.0), "pnpm: minutes");
        assert_eq!(duration_hours("259200", 1.0 / 3600.0), Some(72.0), "bun: seconds");
        assert_eq!(duration_hours("3d", 1.0), Some(72.0));
        assert_eq!(duration_hours("\"7 days\"", 1.0), Some(168.0));
        assert_eq!(duration_hours("1 week", 1.0), Some(168.0));
        assert_eq!(duration_hours("P3D", 1.0), Some(72.0));
        assert_eq!(duration_hours("PT48H", 1.0), Some(48.0));
        assert_eq!(duration_hours("2026-01-01T00:00:00Z", 1.0), None);
    }

    #[test]
    fn install_commands() {
        for yes in ["npm ci", "  run: npm install --omit=dev", "yarn", "yarn install --immutable",
                    "pip install -r requirements.txt", "uv sync --locked", "cargo build --release"] {
            assert!(is_install_command(yes), "{yes}");
        }
        for no in ["yarn build", "npm run test", "echo pip", "cargo fmt"] {
            assert!(!is_install_command(no), "{no}");
        }
    }
}
