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
    if ci_platform(rel).is_some() {
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

/// A CI/CD platform whose pipeline definition lives in the repository.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Ci {
    GithubActions,
    /// Forgejo / Gitea Actions: GitHub Actions syntax, other directory.
    Forgejo,
    GitLab,
    Circle,
    Azure,
    Bitbucket,
    Jenkins,
    Travis,
    Drone,
    Woodpecker,
    Buildkite,
    CloudBuild,
    CodeBuild,
    Cirrus,
    Semaphore,
    AppVeyor,
    Tekton,
    Harness,
    Bitrise,
    Codemagic,
    Taskcluster,
}

impl Ci {
    pub fn name(self) -> &'static str {
        match self {
            Ci::GithubActions => "GitHub Actions",
            Ci::Forgejo => "Forgejo/Gitea Actions",
            Ci::GitLab => "GitLab CI",
            Ci::Circle => "CircleCI",
            Ci::Azure => "Azure Pipelines",
            Ci::Bitbucket => "Bitbucket Pipelines",
            Ci::Jenkins => "Jenkins",
            Ci::Travis => "Travis CI",
            Ci::Drone => "Drone",
            Ci::Woodpecker => "Woodpecker",
            Ci::Buildkite => "Buildkite",
            Ci::CloudBuild => "Google Cloud Build",
            Ci::CodeBuild => "AWS CodeBuild",
            Ci::Cirrus => "Cirrus CI",
            Ci::Semaphore => "Semaphore",
            Ci::AppVeyor => "AppVeyor",
            Ci::Tekton => "Tekton",
            Ci::Harness => "Harness",
            Ci::Bitrise => "Bitrise",
            Ci::Codemagic => "Codemagic",
            Ci::Taskcluster => "Taskcluster",
        }
    }

    /// GitHub Actions syntax (`on:`, `jobs:`, `steps:`).
    pub fn is_gha(self) -> bool {
        matches!(self, Ci::GithubActions | Ci::Forgejo)
    }

    /// Where else, outside the repository, this platform can schedule or
    /// configure scanning — what a human has to look at remotely.
    pub fn remote_settings(self) -> &'static str {
        match self {
            Ci::GithubActions => "Dependabot alerts and security updates are repository settings (Settings → Code security)",
            Ci::Forgejo => "scheduled runs can also be defined per repository in the Forgejo/Gitea UI",
            Ci::GitLab => "pipeline schedules live in the project (Build → Pipeline schedules); group security policies and compliance pipelines can inject scans",
            Ci::Circle => "scheduled pipelines live in Project Settings → Triggers",
            Ci::Azure => "schedules set in the pipeline UI (Triggers) override the YAML",
            Ci::Bitbucket => "schedules live in Pipelines → Schedules",
            Ci::Jenkins => "the job or Multibranch configuration on the server can add triggers",
            Ci::Travis => "cron jobs live in the repository settings (Cron Jobs)",
            Ci::Drone | Ci::Woodpecker => "cron jobs live in the repository settings (Cron)",
            Ci::Buildkite => "schedules live in Pipeline Settings → Schedules",
            Ci::CloudBuild => "triggers and schedules live in Cloud Build triggers / Cloud Scheduler",
            Ci::CodeBuild => "schedules are EventBridge rules in the AWS account",
            Ci::Cirrus => "cron builds live in the repository settings",
            Ci::Semaphore => "schedulers live in the project settings (Tasks)",
            Ci::AppVeyor => "the build schedule lives in the project settings",
            Ci::Tekton => "schedules are a CronJob or Trigger in the cluster",
            Ci::Harness | Ci::Bitrise | Ci::Codemagic | Ci::Taskcluster => "schedules are configured in the platform",
        }
    }
}

/// The CI platform a repository path belongs to, if any.
pub fn ci_platform(rel: &str) -> Option<Ci> {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let yaml = name.ends_with(".yml") || name.ends_with(".yaml");
    let under = |dir: &str| rel.starts_with(dir) && yaml;
    Some(if under(".github/workflows/") {
        Ci::GithubActions
    } else if under(".forgejo/workflows/") || under(".gitea/workflows/") {
        Ci::Forgejo
    } else if rel == ".gitlab-ci.yml" || under(".gitlab/ci/") {
        Ci::GitLab
    } else if under(".circleci/") {
        Ci::Circle
    } else if matches!(rel, "azure-pipelines.yml" | "azure-pipelines.yaml") || under(".azure-pipelines/") || under(".azuredevops/") {
        Ci::Azure
    } else if rel == "bitbucket-pipelines.yml" {
        Ci::Bitbucket
    } else if name == "Jenkinsfile" || name.starts_with("Jenkinsfile.") || name.ends_with(".jenkinsfile") {
        Ci::Jenkins
    } else if rel == ".travis.yml" {
        Ci::Travis
    } else if matches!(rel, ".drone.yml" | ".drone.yaml") {
        Ci::Drone
    } else if matches!(rel, ".woodpecker.yml" | ".woodpecker.yaml") || under(".woodpecker/") {
        Ci::Woodpecker
    } else if under(".buildkite/") {
        Ci::Buildkite
    } else if matches!(rel, "cloudbuild.yaml" | "cloudbuild.yml") {
        Ci::CloudBuild
    } else if matches!(rel, "buildspec.yml" | "buildspec.yaml") {
        Ci::CodeBuild
    } else if rel == ".cirrus.yml" {
        Ci::Cirrus
    } else if under(".semaphore/") {
        Ci::Semaphore
    } else if matches!(rel, "appveyor.yml" | ".appveyor.yml") {
        Ci::AppVeyor
    } else if under(".tekton/") {
        Ci::Tekton
    } else if under(".harness/") {
        Ci::Harness
    } else if rel == "bitrise.yml" {
        Ci::Bitrise
    } else if matches!(rel, "codemagic.yaml" | "codemagic.yml") {
        Ci::Codemagic
    } else if rel == ".taskcluster.yml" {
        Ci::Taskcluster
    } else {
        return None;
    })
}

/// Cron expressions a pipeline file declares for itself, and whether it has a
/// job gated on a schedule defined elsewhere (`$CI_PIPELINE_SOURCE ==
/// "schedule"`, `event: cron`): proof a schedule exists, not of how often.
pub fn ci_schedules(ci: Ci, text: &str) -> (Vec<String>, bool) {
    let crons: Vec<String> = match ci {
        Ci::Jenkins => re!(r#"\bcron\(\s*['"]([^'"]+)['"]"#)
            .captures_iter(text)
            .map(|m| m[1].trim().to_string())
            .collect(),
        Ci::GithubActions | Ci::Forgejo | Ci::Azure | Ci::Circle | Ci::Taskcluster => {
            re!(r##"(?m)^\s*-?\s*cron:\s*['"]?([^'"#\n]+?)['"]?\s*(?:#.*)?$"##)
                .captures_iter(text)
                .map(|m| m[1].trim().to_string())
                .collect()
        }
        _ => Vec::new(),
    };
    let gated = match ci {
        Ci::GitLab => re!(r#"CI_PIPELINE_SOURCE\s*==\s*['"]?schedule"#).is_match(text),
        Ci::Drone | Ci::Woodpecker => re!(r"event:\s*\[?[^\n]*\bcron\b").is_match(text),
        Ci::Cirrus => text.contains("CIRRUS_CRON"),
        Ci::Buildkite => text.contains("BUILDKITE_SOURCE") && text.contains("schedule"),
        Ci::Semaphore => text.contains("SEMAPHORE_WORKFLOW_TRIGGERED_BY_SCHEDULE"),
        _ => false,
    };
    (crons, gated)
}

/// The longest gap, in hours, between two runs of a 5-field cron expression
/// (`m h dom mon dow`, Jenkins `H` allowed) or a macro (`@daily`). An estimate:
/// enough to tell hourly from daily from weekly, not a scheduler.
pub fn cron_interval_hours(expr: &str) -> Option<f64> {
    let e = expr.trim();
    match e {
        "@hourly" => return Some(1.0),
        "@daily" | "@midnight" => return Some(24.0),
        "@weekly" => return Some(168.0),
        "@monthly" => return Some(744.0),
        "@yearly" | "@annually" => return Some(8784.0),
        _ => {}
    }
    let f: Vec<&str> = e.split_whitespace().collect();
    if f.len() != 5 {
        return None;
    }
    // How many values a field selects out of `full`.
    let count = |field: &str, full: u32| -> Option<u32> {
        let mut n = 0;
        for part in field.split(',') {
            let (range, step) = match part.split_once('/') {
                Some((r, s)) => (r, s.parse::<u32>().ok()?.max(1)),
                None => (part, 1),
            };
            let span = if range == "*" || range.starts_with('H') && range.contains('(') || range == "H" && step > 1 {
                full
            } else if let Some((a, b)) = range.split_once('-') {
                let (a, b) = (a.parse::<u32>().ok()?, b.parse::<u32>().ok()?);
                b.checked_sub(a)? + 1
            } else if range == "H" || range.parse::<u32>().is_ok() || range.chars().all(|c| c.is_ascii_alphabetic()) {
                1
            } else {
                return None;
            };
            n += span.div_ceil(step);
        }
        Some(n.clamp(1, full))
    };
    let (hours, dom, mon, dow) = (count(f[1], 24)?, count(f[2], 31)?, count(f[3], 12)?, count(f[4], 7)?);
    let per_day_gap = 24.0 / f64::from(hours);
    let gap = if mon < 12 {
        8784.0 / f64::from(mon * dom.min(28))
    } else if dow < 7 && f[2] == "*" {
        f64::max(168.0 / f64::from(dow), per_day_gap)
    } else if dom < 31 && f[4] == "*" {
        f64::max(744.0 / f64::from(dom), per_day_gap)
    } else {
        per_day_gap
    };
    Some(gap)
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
    fn ci_platforms_and_crons() {
        assert_eq!(ci_platform(".github/workflows/ci.yml"), Some(Ci::GithubActions));
        assert_eq!(ci_platform(".gitlab-ci.yml"), Some(Ci::GitLab));
        assert_eq!(ci_platform(".circleci/config.yml"), Some(Ci::Circle));
        assert_eq!(ci_platform("Jenkinsfile"), Some(Ci::Jenkins));
        assert_eq!(ci_platform(".woodpecker/build.yaml"), Some(Ci::Woodpecker));
        assert_eq!(ci_platform("buildspec.yml"), Some(Ci::CodeBuild));
        assert_eq!(ci_platform("src/main.yml"), None);
        assert_eq!(cron_interval_hours("0 3 * * *"), Some(24.0));
        assert_eq!(cron_interval_hours("0 */6 * * *"), Some(4.0_f64.max(6.0)));
        assert_eq!(cron_interval_hours("0 0,12 * * *"), Some(12.0));
        assert_eq!(cron_interval_hours("0 4 * * 1"), Some(168.0));
        assert_eq!(cron_interval_hours("0 4 * * 1-5"), Some(168.0 / 5.0));
        assert_eq!(cron_interval_hours("H H * * *"), Some(24.0));
        assert_eq!(cron_interval_hours("@daily"), Some(24.0));
        assert!(cron_interval_hours("0 0 1 * *").unwrap() > 168.0, "monthly");
        let (c, gated) = ci_schedules(Ci::GithubActions, "on:\n  schedule:\n    - cron: '17 3 * * *'\n");
        assert_eq!((c, gated), (vec!["17 3 * * *".to_string()], false));
        let (c, gated) = ci_schedules(Ci::GitLab, "scan:\n  rules:\n    - if: $CI_PIPELINE_SOURCE == \"schedule\"\n");
        assert!(c.is_empty() && gated);
        let (c, _) = ci_schedules(Ci::Jenkins, "triggers { cron('H 2 * * *') }");
        assert_eq!(c, vec!["H 2 * * *"]);
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
