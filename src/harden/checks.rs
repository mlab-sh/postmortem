//! One function per CB-DEP control.
//!
//! Each reads what [`super::Ctx`] collected and returns an [`Outcome`]. The
//! rule throughout: a check passes only on evidence. A setting postmortem
//! cannot see (a registry proxy policy, a branch protection rule, a written
//! procedure) is `manual` with the reason, never a silent `pass`.

use std::collections::{BTreeMap, BTreeSet};

use super::repo::{self, Pm, Repo, TextFile, duration_hours, is_install_command};
use super::{Ctx, Outcome, Status};
use crate::model::{Ecosystem, Scope};
use crate::settings::host_of;

/// How far postmortem automates a control.
#[derive(Copy, Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Support {
    /// Decided from the repository alone, offline.
    Auto,
    /// Decided only with `--online` (registry history, repositories).
    Online,
    /// Part of it is checked; the rest is a setting the repository does not show.
    Partial,
    /// Not automated: reported `manual`, with whatever evidence helps.
    #[serde(rename = "manual")]
    None,
}

impl Support {
    pub fn as_str(self) -> &'static str {
        match self {
            Support::Auto => "auto",
            Support::Online => "online",
            Support::Partial => "partial",
            Support::None => "manual",
        }
    }
}

/// What postmortem checks for each control. The bundle test keeps this in
/// sync with the embedded controls: a new upstream control fails the build
/// until it has a row here.
pub const SUPPORT: &[(&str, Support, &str)] = &[
    ("CB-DEP-AGE-001", Support::Auto, "release-age setting per package manager; --online: installed versions younger than the window"),
    ("CB-DEP-AGE-002", Support::Online, "first-publish date of every package"),
    ("CB-DEP-AGE-003", Support::Partial, "every [[gate.allow]] / AGE waiver has an expiry within the limit; approval is by hand"),
    ("CB-DEP-CI-001", Support::Partial, "GitHub Actions install steps vs secrets in their env; other CI by hand"),
    ("CB-DEP-CI-002", Support::None, "lists the registry tokens pipelines reference; scopes live in the registry"),
    ("CB-DEP-CI-003", Support::Partial, "harden-runner egress policy; network-level egress is not visible"),
    ("CB-DEP-CI-004", Support::Partial, "GitHub Actions cache keys and pull_request_target; other CI by hand"),
    ("CB-DEP-EXEC-001", Support::Auto, "script policy of npm, pnpm, yarn, bun and composer plugins"),
    ("CB-DEP-EXEC-002", Support::Auto, "Python: no-build / only-binary, and locked packages that ship no wheel"),
    ("CB-DEP-EXEC-003", Support::Auto, "npx / dlx / uvx / pipx run / go run @latest without a version, in CI, Dockerfiles, scripts"),
    ("CB-DEP-INV-001", Support::Partial, "an SBOM step in the pipelines; storage with releases is by hand"),
    ("CB-DEP-INV-002", Support::None, "organisation-wide: `postmortem hunt` answers it across projects"),
    ("CB-DEP-INV-003", Support::Partial, "`npm audit signatures` in CI; --online: versions that dropped provenance"),
    ("CB-DEP-IR-001", Support::None, "a written procedure"),
    ("CB-DEP-LOCK-001", Support::Auto, "every manifest has its lockfile, committed"),
    ("CB-DEP-LOCK-002", Support::Auto, "install commands in pipelines and Dockerfiles use frozen / locked mode"),
    ("CB-DEP-LOCK-003", Support::Auto, "a hash per package in the lockfile; config that turns verification off"),
    ("CB-DEP-LOCK-004", Support::Auto, "every lockfile source is an approved registry ([harden] registries)"),
    ("CB-DEP-LOCK-005", Support::Auto, "exact versions in package.json, Cargo.toml, pyproject.toml, composer.json"),
    ("CB-DEP-SRC-001", Support::Partial, "a non-public registry configured per package manager; the proxy itself is not visible"),
    ("CB-DEP-SRC-002", Support::Auto, "npm scope→registry mappings, pip --extra-index-url, uv unsafe index strategies"),
    ("CB-DEP-SRC-003", Support::None, "name ownership on public registries"),
    ("CB-DEP-SRC-004", Support::Auto, "git / URL / out-of-repo path dependencies in manifests and lockfiles"),
    ("CB-DEP-SRC-005", Support::Auto, "TLS bypasses and plain-http registries in config, CI, Dockerfiles, lockfiles"),
    ("CB-DEP-SRC-006", Support::Auto, "committed package-manager config; security settings only in ~/.npmrc"),
    ("CB-DEP-UPD-001", Support::Auto, "Dependabot / Renovate covers each ecosystem, with a cooldown ≥ the release age"),
    ("CB-DEP-UPD-002", Support::Auto, "Renovate automerge rules and Dependabot auto-merge workflows exclude majors"),
    ("CB-DEP-UPD-003", Support::None, "not automated yet"),
    ("CB-DEP-VET-001", Support::Partial, "CODEOWNERS covers manifests and lockfiles; branch protection is not visible"),
    ("CB-DEP-VET-002", Support::None, "a policy document; `postmortem audit --online` helps apply it"),
    ("CB-DEP-VET-003", Support::None, "not automated yet"),
    ("CB-DEP-VET-004", Support::Partial, "dev tools in production deps; the last Dockerfile stage omits dev deps"),
    ("CB-DEP-VULN-001", Support::Partial, "a scanner in pipelines, on change and on a schedule"),
    ("CB-DEP-VULN-002", Support::Partial, "a malware gate in CI; --vulns: installed packages with a MAL- advisory"),
    ("CB-DEP-VULN-003", Support::None, "deadlines are tracked outside the repo; --vulns summarises open advisories"),
    ("CB-DEP-VULN-004", Support::Online, "archived / inactive source repositories"),
];

pub fn support(id: &str) -> Option<(Support, &'static str)> {
    SUPPORT.iter().find(|(i, ..)| *i == id).map(|(_, s, n)| (*s, *n))
}

pub fn run(id: &str, c: &Ctx) -> Outcome {
    match id {
        "CB-DEP-AGE-001" => age_001(c),
        "CB-DEP-AGE-002" => age_002(c),
        "CB-DEP-AGE-003" => age_003(c),
        "CB-DEP-CI-001" => ci_001(c),
        "CB-DEP-CI-002" => ci_002(c),
        "CB-DEP-CI-003" => ci_003(c),
        "CB-DEP-CI-004" => ci_004(c),
        "CB-DEP-EXEC-001" => exec_001(c),
        "CB-DEP-EXEC-002" => exec_002(c),
        "CB-DEP-EXEC-003" => exec_003(c),
        "CB-DEP-INV-001" => inv_001(c),
        "CB-DEP-INV-002" => manual(
            "organisation-wide inventory: `postmortem hunt <dir> --package <name>@<version>` answers it \
             across every project under a directory, including git history",
        ),
        "CB-DEP-INV-003" => inv_003(c),
        "CB-DEP-IR-001" => manual("a written response procedure is not visible from the repository"),
        "CB-DEP-LOCK-001" => lock_001(c),
        "CB-DEP-LOCK-002" => lock_002(c),
        "CB-DEP-LOCK-003" => lock_003(c),
        "CB-DEP-LOCK-004" => lock_004(c),
        "CB-DEP-LOCK-005" => lock_005(c),
        "CB-DEP-SRC-001" => src_001(c),
        "CB-DEP-SRC-002" => src_002(c),
        "CB-DEP-SRC-003" => src_003(c),
        "CB-DEP-SRC-004" => src_004(c),
        "CB-DEP-SRC-005" => src_005(c),
        "CB-DEP-SRC-006" => src_006(c),
        "CB-DEP-UPD-001" => upd_001(c),
        "CB-DEP-UPD-002" => upd_002(c),
        "CB-DEP-UPD-003" => manual("not automated yet: compare each direct dependency with its latest major"),
        "CB-DEP-VET-001" => vet_001(c),
        "CB-DEP-VET-002" => manual(
            "written criteria are a policy document; `postmortem audit --online` covers maintenance, \
             reputation and typosquat checks for a candidate",
        ),
        "CB-DEP-VET-003" => manual("not automated yet: unused-dependency detection needs import analysis"),
        "CB-DEP-VET-004" => vet_004(c),
        "CB-DEP-VULN-001" => vuln_001(c),
        "CB-DEP-VULN-002" => vuln_002(c),
        "CB-DEP-VULN-003" => vuln_003(c),
        "CB-DEP-VULN-004" => vuln_004(c),
        _ => manual("no automated check for this control"),
    }
}

fn manual(note: &str) -> Outcome {
    Outcome::new(Status::Manual, vec![note.to_string()])
}

fn skipped(note: &str) -> Outcome {
    Outcome::new(Status::Skipped, vec![note.to_string()])
}

/// Evidence collector: any failure fails the control, an unverifiable part
/// makes it manual, and only verified parts make it pass. `info` lines ride
/// along without moving the verdict.
#[derive(Default)]
struct V {
    fail: Vec<String>,
    manual: Vec<String>,
    pass: Vec<String>,
    info: Vec<String>,
}

impl V {
    fn fail(&mut self, s: impl Into<String>) {
        self.fail.push(s.into());
    }
    fn pass(&mut self, s: impl Into<String>) {
        self.pass.push(s.into());
    }
    fn manual(&mut self, s: impl Into<String>) {
        self.manual.push(s.into());
    }
    fn info(&mut self, s: impl Into<String>) {
        self.info.push(s.into());
    }
    fn outcome(self, empty: Status, empty_note: &str) -> Outcome {
        let status = if !self.fail.is_empty() {
            Status::Fail
        } else if !self.manual.is_empty() {
            Status::Manual
        } else if !self.pass.is_empty() {
            Status::Pass
        } else {
            empty
        };
        let mut ev: Vec<String> = self.fail.into_iter().map(|s| format!("✗ {s}")).collect();
        ev.extend(self.manual.into_iter().map(|s| format!("? {s}")));
        ev.extend(self.pass.into_iter().map(|s| format!("✓ {s}")));
        if ev.is_empty() && !empty_note.is_empty() {
            ev.push(empty_note.to_string());
        }
        ev.extend(self.info);
        Outcome::new(status, ev)
    }
}

/// `a, b, c (+4 more)`.
fn list(items: &[String], max: usize) -> String {
    let mut s = items.iter().take(max).cloned().collect::<Vec<_>>().join(", ");
    if items.len() > max {
        s.push_str(&format!(" (+{} more)", items.len() - max));
    }
    s
}

fn hours(h: f64) -> String {
    if h >= 48.0 && (h / 24.0).fract() == 0.0 {
        format!("{}h ({}d)", h as i64, (h / 24.0) as i64)
    } else {
        format!("{}h", (h * 10.0).round() / 10.0)
    }
}

fn ystr(v: &serde_yaml::Value) -> Option<String> {
    match v {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn tstr(v: &toml::Value) -> Option<String> {
    match v {
        toml::Value::String(s) => Some(s.clone()),
        toml::Value::Integer(n) => Some(n.to_string()),
        toml::Value::Float(n) => Some(n.to_string()),
        toml::Value::Boolean(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Each package manager once, in detection order.
fn pms(c: &Ctx) -> Vec<Pm> {
    let mut seen = Vec::new();
    for p in c.pms {
        if !seen.contains(&p.pm) {
            seen.push(p.pm);
        }
    }
    seen
}

/// Lines of a command file that are not comments, 1-based.
fn code_lines(f: &TextFile) -> impl Iterator<Item = (usize, &str)> {
    f.text
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l))
        .filter(|(_, l)| !l.trim_start().starts_with('#'))
}

/// Pipelines and Dockerfiles: where builds happen. Not local scripts, and
/// not Markdown, where `npm install foo` is an instruction to a reader.
fn build_files(r: &Repo) -> impl Iterator<Item = &TextFile> {
    r.ci.iter().chain(&r.dockerfiles)
}

fn snippet(line: &str) -> String {
    let t = line.trim().trim_start_matches("- ").trim_start_matches("run:").trim();
    if t.chars().count() > 90 {
        format!("{}…", t.chars().take(89).collect::<String>())
    } else {
        t.to_string()
    }
}

// ---------------------------------------------------------------- AGE ----

enum Gate {
    Set(f64, String),
    /// An absolute cutoff (uv `exclude-newer = 2026-01-01`): old enough, but
    /// frozen — it never moves forward.
    Pinned(String, String),
    Unset(String),
    /// The tool has no such setting: only a proxy can enforce it.
    Unsupported,
}

fn release_age(r: &Repo, npmrc: &BTreeMap<String, String>, pm: Pm, need: f64) -> Gate {
    let days = (need / 24.0).ceil() as i64;
    let minutes = (need * 60.0).ceil() as i64;
    match pm {
        Pm::Npm => match npmrc.get("min-release-age").and_then(|v| duration_hours(v, 24.0)) {
            Some(h) => Gate::Set(h, ".npmrc min-release-age".into()),
            None => Gate::Unset(format!("add `min-release-age={days}` to .npmrc (npm ≥ 11.10, in days)")),
        },
        Pm::Pnpm => {
            let ws = r
                .yaml("pnpm-workspace.yaml")
                .and_then(|y| y.get("minimumReleaseAge").and_then(ystr));
            if let Some(h) = ws.as_deref().and_then(|v| duration_hours(v, 1.0 / 60.0)) {
                return Gate::Set(h, "pnpm-workspace.yaml minimumReleaseAge".into());
            }
            if let Some(h) = npmrc.get("minimum-release-age").and_then(|v| duration_hours(v, 1.0 / 60.0)) {
                return Gate::Set(h, ".npmrc minimum-release-age".into());
            }
            Gate::Unset(format!(
                "add `minimumReleaseAge: {minutes}` to pnpm-workspace.yaml (minutes; pnpm 11's own default is 1440 = 24h)"
            ))
        }
        Pm::YarnBerry => {
            match r
                .yaml(".yarnrc.yml")
                .and_then(|y| y.get("npmMinimalAgeGate").and_then(ystr))
                .and_then(|v| duration_hours(&v, 1.0 / 60.0))
            {
                Some(h) => Gate::Set(h, ".yarnrc.yml npmMinimalAgeGate".into()),
                None => Gate::Unset(format!(
                    "add `npmMinimalAgeGate: {minutes}` to .yarnrc.yml (yarn ≥ 4.10, minutes)"
                )),
            }
        }
        Pm::Bun => {
            match r
                .toml("bunfig.toml")
                .and_then(|t| t.get("install")?.get("minimumReleaseAge").and_then(tstr))
                .and_then(|v| duration_hours(&v, 1.0 / 3600.0))
            {
                Some(h) => Gate::Set(h, "bunfig.toml [install] minimumReleaseAge".into()),
                None => Gate::Unset(format!(
                    "add `minimumReleaseAge = {}` under [install] in bunfig.toml (bun ≥ 1.3, seconds)",
                    (need * 3600.0) as i64
                )),
            }
        }
        Pm::Uv => {
            let Some((v, at)) = r
                .uv_settings()
                .and_then(|(t, at)| Some((tstr(t.get("exclude-newer")?)?, at)))
            else {
                return Gate::Unset(format!("add `exclude-newer = \"{days} days\"` to uv.toml or [tool.uv]"));
            };
            match duration_hours(&v, 1.0) {
                Some(h) => Gate::Set(h, format!("{at} exclude-newer")),
                None => Gate::Pinned(v, format!("{at} exclude-newer")),
            }
        }
        Pm::Pip => match r.pip_conf().and_then(|(m, at)| Some((m.get("uploaded-prior-to")?.clone(), at))) {
            Some((v, at)) => match duration_hours(&v, 1.0) {
                Some(h) => Gate::Set(h, format!("{at} uploaded-prior-to")),
                None => Gate::Pinned(v, format!("{at} uploaded-prior-to")),
            },
            None => Gate::Unset("pip ≥ 26 `--uploaded-prior-to`, or enforce it in the registry proxy".into()),
        },
        _ => Gate::Unsupported,
    }
}

/// Packages whose `--online` signals carry `prefix` (`fresh-release`, …).
fn flagged(c: &Ctx, prefix: &str) -> Option<Vec<String>> {
    let res = c.online?;
    let mut out: Vec<String> = res
        .iter()
        .filter_map(|((n, v), r)| {
            r.signals
                .iter()
                .find(|s| s.starts_with(prefix))
                .map(|s| {
                    let detail = s.split_once('(').map_or("", |(_, d)| d.trim_end_matches(')'));
                    if detail.is_empty() { format!("{n}@{v}") } else { format!("{n}@{v} ({detail})") }
                })
        })
        .collect();
    out.sort();
    Some(out)
}

fn age_001(c: &Ctx) -> Outcome {
    let need = c.param("min_release_age_hours") as f64;
    let npmrc = c.repo.npmrc();
    let mut v = V::default();
    for pm in pms(c) {
        match release_age(c.repo, &npmrc, pm, need) {
            Gate::Set(h, at) if h + 1e-9 >= need => v.pass(format!("{}: {at} = {}", pm.name(), hours(h))),
            Gate::Set(h, at) => v.fail(format!("{}: {at} = {}, below {}", pm.name(), hours(h), hours(need))),
            Gate::Pinned(date, at) => v.pass(format!("{}: {at} pins a fixed cutoff ({date}), which never moves forward", pm.name())),
            Gate::Unset(hint) => v.fail(format!("{}: no release-age gate — {hint}", pm.name())),
            Gate::Unsupported => v.manual(format!(
                "{}: no native release-age setting — enforce it in the registry proxy",
                pm.name()
            )),
        }
    }
    match flagged(c, "fresh-release") {
        Some(fresh) if !fresh.is_empty() => v.fail(format!(
            "{} installed version(s) published less than {} ago: {}",
            fresh.len(),
            hours(need),
            list(&fresh, 8)
        )),
        Some(_) => v.info(format!("no installed version is younger than {}", hours(need))),
        None => v.info("installed versions not checked against publish dates (needs --online)"),
    }
    v.outcome(Status::NotApplicable, "no package manager detected")
}

fn age_002(c: &Ctx) -> Outcome {
    let days = c.param("min_package_age_days");
    match flagged(c, "newborn-package") {
        None => skipped("needs --online: the first-publish date of each package comes from its registry"),
        Some(young) if young.is_empty() => Outcome::new(
            Status::Pass,
            vec![format!("✓ no dependency first appeared on its registry less than {days} days ago")],
        ),
        Some(young) => Outcome::new(
            Status::Fail,
            vec![format!(
                "✗ {} package(s) first published less than {days} days ago, review before adoption: {}",
                young.len(),
                list(&young, 8)
            )],
        ),
    }
}

fn age_003(c: &Ctx) -> Outcome {
    let max = c.param("max_exception_days");
    let mut v = V::default();
    let entries = c
        .gate_allow
        .iter()
        .map(|a| (format!("[[gate.allow]] {}", a.package), a.expires.clone()))
        .chain(
            c.cfg
                .waive
                .iter()
                .filter(|w| w.control.starts_with("CB-DEP-AGE-"))
                .map(|w| (format!("[[harden.waive]] {}", w.control), w.expires.clone())),
        );
    for (name, expires) in entries {
        match expires.as_deref().map(|e| chrono::NaiveDate::parse_from_str(e, "%Y-%m-%d")) {
            None => v.fail(format!("{name}: no expiry date")),
            Some(Err(_)) => v.fail(format!("{name}: expiry is not a YYYY-MM-DD date")),
            Some(Ok(d)) if d < c.today => v.info(format!("{name}: expired {d}, no longer applies")),
            Some(Ok(d)) if (d - c.today).num_days() > max => {
                v.fail(format!("{name}: expires {d}, more than {max} days from now"))
            }
            Some(Ok(d)) => v.pass(format!("{name}: expires {d}")),
        }
    }
    if v.fail.is_empty() {
        v.info("who approved each exception and why is recorded by hand");
    }
    v.outcome(Status::Pass, "✓ no release-age exception declared")
}

// ----------------------------------------------------------------- CI ----

/// A GitHub Actions job, as far as these checks need it.
struct Job {
    file: String,
    name: String,
    /// Workflow- or job-level `env` references a secret: every step sees it.
    shared_secret: bool,
    steps: Vec<Step>,
    pr_target: bool,
}

struct Step {
    name: String,
    uses: String,
    run: String,
    secret: bool,
    with: serde_yaml::Value,
}

fn refs_secret(v: Option<&serde_yaml::Value>) -> bool {
    v.and_then(|v| serde_yaml::to_string(v).ok()).is_some_and(|s| s.contains("secrets."))
}

fn gha_jobs(r: &Repo) -> Vec<Job> {
    let mut out = Vec::new();
    for f in r.ci.iter().filter(|f| f.rel.starts_with(".github/workflows/")) {
        let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&f.text) else { continue };
        let wf_secret = refs_secret(doc.get("env"));
        let pr_target = doc.get("on").is_some_and(|o| {
            serde_yaml::to_string(o).is_ok_and(|s| s.contains("pull_request_target"))
        });
        let Some(jobs) = doc.get("jobs").and_then(|j| j.as_mapping()) else { continue };
        for (name, job) in jobs {
            let steps = job
                .get("steps")
                .and_then(|s| s.as_sequence())
                .map(|seq| {
                    seq.iter()
                        .map(|s| Step {
                            name: s.get("name").and_then(ystr).unwrap_or_default(),
                            uses: s.get("uses").and_then(ystr).unwrap_or_default(),
                            run: s.get("run").and_then(ystr).unwrap_or_default(),
                            secret: refs_secret(s.get("env")),
                            with: s.get("with").cloned().unwrap_or_default(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            out.push(Job {
                file: f.rel.clone(),
                name: ystr(name).unwrap_or_default(),
                shared_secret: wf_secret || refs_secret(job.get("env")),
                steps,
                pr_target,
            });
        }
    }
    out
}

fn ci_001(c: &Ctx) -> Outcome {
    let mut v = V::default();
    let jobs = gha_jobs(c.repo);
    let mut clean = 0;
    for j in &jobs {
        for s in &j.steps {
            if !s.run.lines().any(is_install_command) {
                continue;
            }
            if s.secret || j.shared_secret {
                let label = if s.name.is_empty() { snippet(s.run.lines().next().unwrap_or("")) } else { s.name.clone() };
                v.fail(format!(
                    "{}: job `{}` step `{label}` installs dependencies with secrets in its {}",
                    j.file,
                    j.name,
                    if s.secret { "env" } else { "job/workflow env" }
                ));
            } else {
                clean += 1;
            }
        }
    }
    if clean > 0 {
        v.pass(format!("{clean} GitHub Actions install step(s) run without secrets in their environment"));
    }
    for f in c.repo.ci.iter().filter(|f| !f.rel.starts_with(".github/")) {
        if f.text.lines().any(is_install_command) {
            v.manual(format!("{}: check that the install job holds no deployment or publish credentials", f.rel));
        }
    }
    if c.repo.ci.is_empty() {
        v.outcome(Status::Manual, "? no pipeline definition found")
    } else {
        v.outcome(Status::NotApplicable, "no pipeline step installs dependencies")
    }
}

fn ci_002(c: &Ctx) -> Outcome {
    let mut v = V::default();
    let mut seen = BTreeSet::new();
    for f in &c.repo.ci {
        for m in re!(r"secrets\.([A-Z0-9_]*(?:NPM|PYPI|CARGO|RUBYGEMS|GEM_HOST|NUGET|PACKAGIST|REGISTRY|PUBLISH|TWINE)[A-Z0-9_]*)")
            .captures_iter(&f.text)
        {
            seen.insert(format!("{} in {}", &m[1], f.rel));
        }
        if f.text.contains("id-token: write") && re!(r"gh-action-pypi-publish|npm publish|cargo publish|trusted.publish").is_match(&f.text) {
            v.info(format!("{}: publishes with OIDC trusted publishing (short-lived, no stored token)", f.rel));
        }
    }
    if !seen.is_empty() {
        v.info(format!(
            "registry credentials referenced: {} — confirm the install-time ones are read-only",
            list(&seen.into_iter().collect::<Vec<_>>(), 6)
        ));
    }
    v.manual("token scopes are set in the registry, not in the repository");
    v.outcome(Status::Manual, "")
}

fn ci_003(c: &Ctx) -> Outcome {
    let mut v = V::default();
    for f in &c.repo.ci {
        if !f.text.contains("harden-runner") {
            continue;
        }
        if re!(r"egress-policy:\s*block").is_match(&f.text) {
            v.pass(format!("{}: harden-runner blocks egress", f.rel));
        } else {
            v.fail(format!("{}: harden-runner in audit mode only logs egress — set egress-policy: block", f.rel));
        }
    }
    if v.fail.is_empty() && v.pass.is_empty() {
        v.manual("no egress policy in the pipelines — it may be enforced at the network layer, which the repository does not show");
    }
    v.outcome(Status::Manual, "")
}

fn ci_004(c: &Ctx) -> Outcome {
    let mut v = V::default();
    for j in gha_jobs(c.repo) {
        for s in &j.steps {
            let cache_action = s.uses.starts_with("actions/cache");
            let setup_cache = s.uses.starts_with("actions/setup-") && s.with.get("cache").is_some();
            if !cache_action && !setup_cache {
                continue;
            }
            if j.pr_target {
                v.fail(format!(
                    "{}: job `{}` restores a cache on pull_request_target — untrusted code shares the base branch's cache",
                    j.file, j.name
                ));
            } else if cache_action {
                let key = s.with.get("key").and_then(ystr).unwrap_or_default();
                if key.contains("hashFiles(") {
                    v.pass(format!("{}: `{}` cache keyed on {}", j.file, j.name, snippet(&key)));
                } else {
                    v.fail(format!("{}: job `{}` cache key `{}` is not derived from the lockfile", j.file, j.name, key));
                }
            } else {
                v.pass(format!("{}: `{}` uses {} cache (keyed on the lockfile)", j.file, j.name, s.uses));
            }
        }
    }
    if !v.pass.is_empty() {
        v.info("GitHub scopes caches per branch: a fork's PR cannot write the default branch's cache");
    }
    for f in c.repo.ci.iter().filter(|f| !f.rel.starts_with(".github/")) {
        if re!(r"(?m)^\s*cache:").is_match(&f.text) {
            v.manual(format!("{}: check that untrusted pipelines cannot write the caches trusted ones read", f.rel));
        }
    }
    v.outcome(Status::NotApplicable, "no dependency cache in the pipelines")
}

// --------------------------------------------------------------- EXEC ----

fn exec_001(c: &Ctx) -> Outcome {
    let mut v = V::default();
    let npmrc = c.repo.npmrc();
    let pkg = c.repo.json("package.json");
    let ignore_scripts = npmrc.get("ignore-scripts").is_some_and(|s| s == "true");
    for pm in pms(c) {
        match pm {
            Pm::Npm => {
                let approvals = crate::scripts::read_approvals(&c.repo.root);
                if ignore_scripts {
                    v.pass("npm: .npmrc ignore-scripts=true");
                } else if pkg.as_ref().is_some_and(|p| p.get("allowScripts").is_some()) {
                    v.pass(format!("npm: package.json allowScripts approves {} package(s)", approvals.len() / 2));
                } else {
                    v.fail("npm: every dependency may run install scripts — set ignore-scripts=true in .npmrc, or approve per package with `npm approve-scripts`");
                }
                let wanting: Vec<String> = c
                    .pms
                    .iter()
                    .filter(|p| p.pm == Pm::Npm)
                    .filter_map(|p| p.lockfile.as_ref())
                    .flat_map(|l| crate::scripts::lockfile_install_scripts(&c.repo.root.join(l)))
                    .filter(|n| !approvals.contains(n))
                    .collect();
                if !wanting.is_empty() && !ignore_scripts {
                    v.info(format!("{} package(s) declare install scripts without approval: {}", wanting.len(), list(&wanting, 6)));
                }
            }
            Pm::Pnpm => {
                let ws = c.repo.yaml("pnpm-workspace.yaml");
                let pnpm_field = pkg.as_ref().and_then(|p| p.get("pnpm"));
                let allow_all = ws.as_ref().and_then(|y| y.get("dangerouslyAllowAllBuilds")).and_then(ystr).as_deref() == Some("true")
                    || pnpm_field.and_then(|p| p.get("dangerouslyAllowAllBuilds")).and_then(|b| b.as_bool()) == Some(true);
                let major = pkg
                    .as_ref()
                    .and_then(|p| p.get("packageManager")?.as_str()?.strip_prefix("pnpm@")?.split('.').next()?.parse::<u32>().ok());
                if allow_all {
                    v.fail("pnpm: dangerouslyAllowAllBuilds lets every dependency run its build scripts");
                } else if major.is_some_and(|m| m < 10) && !ignore_scripts {
                    v.fail(format!("pnpm: packageManager pins pnpm {} — before 10 every dependency runs its scripts", major.unwrap_or(0)));
                } else {
                    let allowed: Vec<String> = ws
                        .as_ref()
                        .and_then(|y| y.get("onlyBuiltDependencies")?.as_sequence().cloned())
                        .map(|s| s.iter().filter_map(ystr).collect())
                        .or_else(|| {
                            pnpm_field
                                .and_then(|p| p.get("onlyBuiltDependencies")?.as_array().cloned())
                                .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                        })
                        .unwrap_or_default();
                    v.pass(format!(
                        "pnpm{}: dependency builds blocked unless allowed ({})",
                        if major.is_none() { " (assumed ≥ 10)" } else { "" },
                        if allowed.is_empty() { "none allowed".to_string() } else { list(&allowed, 6) }
                    ));
                }
            }
            Pm::YarnBerry => {
                let off = c.repo.yaml(".yarnrc.yml").and_then(|y| y.get("enableScripts").and_then(ystr)).as_deref() == Some("false");
                if off {
                    v.pass("yarn: .yarnrc.yml enableScripts: false");
                } else {
                    v.fail("yarn: dependencies run their postinstall scripts — set enableScripts: false and allow per package with dependenciesMeta.<pkg>.built");
                }
            }
            Pm::Yarn1 => {
                let yarnrc = c.repo.read(".yarnrc").unwrap_or_default();
                if ignore_scripts || re!(r"(?m)^\s*ignore-scripts\s+true").is_match(&yarnrc) {
                    v.pass("yarn 1: ignore-scripts true");
                } else {
                    v.fail("yarn 1: every dependency may run install scripts — set ignore-scripts true in .yarnrc");
                }
            }
            Pm::Bun => {
                let trusted: Vec<String> = pkg
                    .as_ref()
                    .and_then(|p| p.get("trustedDependencies")?.as_array().cloned())
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                v.pass(format!(
                    "bun: lifecycle scripts run only for trustedDependencies ({})",
                    if trusted.is_empty() { "bun's default list".to_string() } else { list(&trusted, 6) }
                ));
            }
            Pm::Composer => {
                let allow = c.repo.json("composer.json").and_then(|j| j.get("config")?.get("allow-plugins").cloned());
                match allow {
                    Some(serde_json::Value::Bool(true)) => v.fail("composer: allow-plugins: true lets every plugin run code"),
                    Some(serde_json::Value::Object(m)) => v.pass(format!("composer: allow-plugins lists {} plugin(s)", m.len())),
                    _ => v.pass("composer: plugins need explicit allow-plugins (Composer ≥ 2.2)"),
                }
            }
            _ => {}
        }
    }
    v.outcome(Status::NotApplicable, "no package manager with install-time scripts detected")
}

/// Packages a Python lockfile can only install by building from source.
fn sdist_only(r: &Repo, pm: Pm) -> Option<Vec<String>> {
    let lock = match pm {
        Pm::Uv => r.toml("uv.lock")?,
        Pm::Poetry => r.toml("poetry.lock")?,
        Pm::Pdm => r.toml("pdm.lock")?,
        _ => return None,
    };
    let pkgs = lock.get("package")?.as_array()?;
    let mut out = Vec::new();
    for p in pkgs {
        let name = p.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        let only_source = if pm == Pm::Uv {
            p.get("sdist").is_some() && p.get("wheels").is_none()
        } else {
            let files: Vec<&str> = p
                .get("files")
                .and_then(|f| f.as_array())
                .map(|a| a.iter().filter_map(|f| f.get("file")?.as_str()).collect())
                .unwrap_or_default();
            !files.is_empty() && !files.iter().any(|f| f.ends_with(".whl"))
        };
        if only_source {
            out.push(name.to_string());
        }
    }
    Some(out)
}

fn exec_002(c: &Ctx) -> Outcome {
    let mut v = V::default();
    let reqs = c.repo.requirements();
    for pm in pms(c).into_iter().filter(|p| p.is_python()) {
        let enforced = match pm {
            Pm::Uv => c
                .repo
                .uv_settings()
                .and_then(|(t, at)| (t.get("no-build").and_then(|b| b.as_bool()) == Some(true)).then_some(at)),
            Pm::Pip => c
                .repo
                .pip_conf()
                .and_then(|(m, at)| m.get("only-binary").is_some_and(|v| v.contains(":all:")).then_some(at))
                .or_else(|| {
                    reqs.iter()
                        .any(|(_, t)| re!(r"--only-binary[=\s]+:all:").is_match(t))
                        .then_some("requirements")
                }),
            _ => None,
        };
        if let Some(at) = enforced {
            v.pass(format!("{}: source builds disabled ({at})", pm.name()));
            continue;
        }
        match sdist_only(c.repo, pm) {
            Some(src) if !src.is_empty() => v.fail(format!(
                "{}: {} locked package(s) ship no wheel and build from source at install: {}",
                pm.name(),
                src.len(),
                list(&src, 8)
            )),
            Some(_) => v.pass(format!(
                "{}: every locked package ships a wheel{}",
                pm.name(),
                if pm == Pm::Uv { " (set no-build = true to enforce it)" } else { "" }
            )),
            None if pm == Pm::Pip => v.fail("pip: source distributions are built at install — use --only-binary=:all: with an allowlist"),
            None => v.manual(format!("{}: cannot tell from the lockfile which packages build from source", pm.name())),
        }
    }
    v.outcome(Status::NotApplicable, "no Python project (the ecosystem where install-time builds are the norm)")
}

/// Is a `npx foo@1.2.3`-style package token pinned?
fn pinned_token(tok: &str, uv_style: bool) -> bool {
    let at = tok.get(1..).and_then(|t| t.find('@')).map(|i| i + 1);
    let version = match at {
        Some(i) => &tok[i + 1..],
        None if uv_style => tok.split_once("==").map_or("", |(_, v)| v),
        None => "",
    };
    !version.is_empty() && !matches!(version, "latest" | "next" | "*")
}

fn exec_003(c: &Ctx) -> Outcome {
    let local: BTreeSet<&str> = c.deps.iter().filter(|d| d.direct).map(|d| d.name.as_str()).collect();
    let mut hits = Vec::new();
    let mut scan = |rel: &str, n: usize, line: &str| {
        for m in re!(r"(?:^|[\s;&|(`'\x22])(npx|bunx|pnpx|pnpm\s+dlx|yarn\s+dlx|uvx|pipx\s+run)\s+(.*)").captures_iter(line) {
            let runner = m[1].split_whitespace().next().unwrap_or("");
            let uv_style = matches!(runner, "uvx" | "pipx");
            let mut toks = m[2].split_whitespace();
            let mut pkg = None;
            while let Some(t) = toks.next() {
                if matches!(t, "--from" | "-p" | "--package" | "--spec") {
                    pkg = toks.next();
                    break;
                }
                if t.starts_with('-') {
                    continue;
                }
                pkg = Some(t);
                break;
            }
            let Some(pkg) = pkg else { continue };
            let pkg = pkg.trim_matches(['"', '\'', '`', ')', ';']);
            let bare = if let Some(rest) = pkg.strip_prefix('@') {
                format!("@{}", rest.split('@').next().unwrap_or(rest))
            } else {
                pkg.split(['@', '=']).next().unwrap_or(pkg).to_string()
            };
            if pkg.is_empty() || pkg.contains(['$', '{', '<']) || local.contains(bare.as_str()) || pinned_token(pkg, uv_style) {
                continue;
            }
            hits.push(format!("{rel}:{n}: {} {pkg}", &m[1]));
        }
        if let Some(m) = re!(r"\bgo\s+(?:run|install)\s+(\S+@latest)").captures(line) {
            hits.push(format!("{rel}:{n}: go … {}", &m[1]));
        }
    };
    for f in c.repo.command_files() {
        for (n, line) in code_lines(f) {
            scan(&f.rel, n, line);
        }
    }
    if let Some(scripts) = c.repo.json("package.json").and_then(|p| p.get("scripts")?.as_object().cloned()) {
        for (name, cmd) in scripts {
            if let Some(cmd) = cmd.as_str() {
                scan(&format!("package.json scripts.{name}"), 0, cmd);
            }
        }
    }
    let hits: Vec<String> = hits.into_iter().map(|h| h.replace(":0:", ":")).collect();
    if hits.is_empty() {
        Outcome::new(Status::Pass, vec!["✓ no unpinned npx / dlx / uvx / pipx run / go run @latest found".into()])
    } else {
        Outcome::new(
            Status::Fail,
            std::iter::once(format!("✗ {} on-demand package run(s) without an exact version:", hits.len()))
                .chain(hits.into_iter().take(10).map(|h| format!("  {h}")))
                .collect(),
        )
    }
}

// ---------------------------------------------------------------- INV ----

fn inv_001(c: &Ctx) -> Outcome {
    if c.repo.ci.is_empty() {
        return manual("no pipeline definition found: check where releases are built");
    }
    let hits: Vec<String> = c
        .repo
        .ci
        .iter()
        .filter_map(|f| re!(r"(?i)\b(postmortem\s+sbom|sbom|cyclonedx|spdx|syft|cdxgen)\b").find(&f.text).map(|m| format!("{} ({})", f.rel, m.as_str())))
        .collect();
    if hits.is_empty() {
        Outcome::new(
            Status::Fail,
            vec!["✗ no pipeline produces an SBOM — `postmortem sbom` writes CycloneDX 1.5 from the lockfiles".into()],
        )
    } else {
        Outcome::new(
            Status::Pass,
            vec![
                format!("✓ SBOM generation in {}", list(&hits, 4)),
                "check it is stored with each release artifact".into(),
            ],
        )
    }
}

fn inv_003(c: &Ctx) -> Outcome {
    let mut v = V::default();
    match flagged(c, "provenance-removed") {
        Some(dropped) if !dropped.is_empty() => v.fail(format!(
            "{} package(s) stopped publishing the provenance attestation earlier versions carried: {}",
            dropped.len(),
            list(&dropped, 8)
        )),
        Some(_) => v.pass("no installed version dropped a provenance attestation its predecessors had (npm, crates.io)"),
        None => v.info("provenance history not checked (needs --online)"),
    }
    let pms = pms(c);
    if pms.contains(&Pm::Npm) {
        if c.repo.ci.iter().any(|f| f.text.contains("audit signatures")) {
            v.pass("pipeline runs `npm audit signatures`");
        } else {
            v.fail("npm: no pipeline verifies registry signatures and attestations — add `npm audit signatures`");
        }
    }
    for pm in pms.iter().filter(|p| p.is_js() && **p != Pm::Npm) {
        v.manual(format!("{}: no built-in signature verification — verify attestations in the proxy or with npm on the installed tree", pm.name()));
    }
    if v.fail.is_empty() && v.pass.is_empty() && v.manual.is_empty() {
        v.manual("verify signatures where the ecosystem publishes them (sigstore, PEP 740)");
    }
    v.outcome(Status::Manual, "")
}

// --------------------------------------------------------------- LOCK ----

fn expected_lock(pm: Pm) -> &'static str {
    match pm {
        Pm::Npm => "package-lock.json",
        Pm::Pnpm => "pnpm-lock.yaml",
        Pm::Yarn1 | Pm::YarnBerry => "yarn.lock",
        Pm::Bun => "bun.lock",
        Pm::Uv => "uv.lock",
        Pm::Poetry => "poetry.lock",
        Pm::Pdm => "pdm.lock",
        Pm::Pipenv => "Pipfile.lock",
        Pm::Pip => "a lockfile (uv.lock, poetry.lock, or a fully pinned requirements.txt)",
        Pm::Cargo => "Cargo.lock",
        Pm::Go => "go.sum",
        Pm::Bundler => "Gemfile.lock",
        Pm::Composer => "composer.lock",
        Pm::Maven => "",
        Pm::Gradle => "gradle.lockfile (dependency locking)",
        Pm::Nuget => "packages.lock.json (RestorePackagesWithLockFile)",
    }
}

/// Requirement lines that do not pin one exact version.
fn unpinned_requirements(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty() && !l.starts_with('-') && !l.starts_with('\\'))
        .filter(|l| !l.contains("==") && !l.contains(" @ "))
        .map(|l| l.split([';', ' ']).next().unwrap_or(l).to_string())
        .collect()
}

fn lock_001(c: &Ctx) -> Outcome {
    let mut v = V::default();
    for p in c.pms {
        match (&p.lockfile, p.pm) {
            (_, Pm::Maven) => v.manual("maven: no lockfile format — pin every version and use the enforcer plugin"),
            (Some(l), Pm::Pip) => {
                let loose = unpinned_requirements(&c.repo.read(l).unwrap_or_default());
                if loose.is_empty() {
                    v.pass(format!("pip: {l} pins every requirement"));
                } else {
                    v.fail(format!("pip: {l} is not a lock — {} unpinned: {}", loose.len(), list(&loose, 6)));
                }
            }
            (Some(l), pm) => match c.repo.tracked(l) {
                Some(false) => v.fail(format!("{}: {l} exists but is not committed", pm.name())),
                _ => v.pass(format!("{}: {l}", pm.name())),
            },
            (None, Pm::Go) if !c.repo.read("go.mod").is_some_and(|t| t.contains("require")) => {
                v.pass("go: go.mod has no requirements")
            }
            (None, pm) => v.fail(format!("{}: {} without {}", pm.name(), p.manifest, expected_lock(pm))),
        }
    }
    v.outcome(Status::NotApplicable, "no package manifest detected")
}

/// What is wrong with one install command, if anything.
fn install_problem(line: &str, file_text: &str, pms: &[Pm], nuget_lock: bool) -> Option<&'static str> {
    let has = |p: &str| line.contains(p);
    if re!(r"\bnpm\s+(install|i)\b").is_match(line) && !re!(r"\s(-g|--global)\b").is_match(line) {
        return Some("use `npm ci`, which fails instead of rewriting the lockfile");
    }
    if re!(r"\byarn(\s+install)?\s*($|--|&&|;)").is_match(line) || re!(r"\byarn\s+install\b").is_match(line) {
        if pms.contains(&Pm::Yarn1) && !has("--frozen-lockfile") {
            return Some("add --frozen-lockfile");
        }
        if has("--no-immutable") {
            return Some("drop --no-immutable");
        }
    }
    if re!(r"\bpnpm\s+(install|i)\b").is_match(line) && has("--no-frozen-lockfile") {
        return Some("drop --no-frozen-lockfile");
    }
    if re!(r"\bbun\s+(install|i)\b").is_match(line) && !has("--frozen-lockfile") && !file_text.contains("BUN_CONFIG_FROZEN_LOCKFILE") {
        return Some("add --frozen-lockfile (or `bun ci`)");
    }
    if re!(r"\buv\s+sync\b").is_match(line)
        && !has("--locked")
        && !has("--frozen")
        && !re!(r"UV_(FROZEN|LOCKED)['\x22]?\s*[:=]\s*['\x22]?(1|true)").is_match(file_text)
    {
        return Some("add --locked");
    }
    if re!(r"\bpipenv\s+install\b").is_match(line) && !has("--deploy") {
        return Some("use `pipenv install --deploy` or `pipenv sync`");
    }
    if re!(r"\bbundle\s+install\b").is_match(line)
        && !has("--frozen")
        && !has("--deployment")
        && !re!(r"BUNDLE_(FROZEN|DEPLOYMENT)|bundle config (set )?(--local )?(frozen|deployment)").is_match(file_text)
    {
        return Some("set BUNDLE_FROZEN=true (or `bundle config set frozen true`)");
    }
    if re!(r"\bcomposer\s+update\b").is_match(line) {
        return Some("use `composer install`, which installs exactly composer.lock");
    }
    if re!(r"\bcargo\s+(build|test|install|fetch)\b").is_match(line) && !re!(r"--(locked|frozen|offline)\b").is_match(line) {
        return Some("add --locked");
    }
    if nuget_lock && re!(r"\bdotnet\s+restore\b").is_match(line) && !has("--locked-mode") {
        return Some("add --locked-mode");
    }
    None
}

fn lock_002(c: &Ctx) -> Outcome {
    let pms = pms(c);
    let nuget_lock = c.pms.iter().any(|p| p.pm == Pm::Nuget && p.lockfile.is_some());
    let (mut bad, mut ok) = (Vec::new(), 0);
    for f in build_files(c.repo) {
        for (n, line) in code_lines(f) {
            if !is_install_command(line) {
                continue;
            }
            match install_problem(line, &f.text, &pms, nuget_lock) {
                Some(fix) => bad.push(format!("{}:{n}: `{}` — {fix}", f.rel, snippet(line))),
                None => ok += 1,
            }
        }
    }
    let mut v = V::default();
    let more = bad.len().saturating_sub(10);
    for b in bad.into_iter().take(10) {
        v.fail(b);
    }
    if more > 0 {
        v.fail(format!("… and {more} more"));
    }
    if ok > 0 {
        v.pass(format!("{ok} install command(s) in pipelines and Dockerfiles use the lockfile as-is"));
    }
    v.outcome(Status::Manual, "? no install command found in pipelines or Dockerfiles")
}

fn lock_003(c: &Ctx) -> Outcome {
    let mut v = V::default();
    let pms = pms(c);
    // Ecosystems whose parser records the lockfile's hash per package.
    let mut by_eco: BTreeMap<&str, (usize, Vec<String>)> = BTreeMap::new();
    let js_from_parser = pms.iter().any(|p| matches!(p, Pm::Npm | Pm::Yarn1 | Pm::Bun));
    for d in c.deps {
        let registry = match d.ecosystem {
            Ecosystem::Node if js_from_parser => d
                .resolved_url
                .as_deref()
                .is_some_and(|u| crate::lifecycle::source_of(Some(u)) == crate::lifecycle::Source::Registry),
            Ecosystem::Rust => d.resolved_url.as_deref().is_some_and(|u| u.starts_with("registry+") || u.starts_with("sparse+")),
            Ecosystem::Go => true,
            _ => false,
        };
        if !registry {
            continue;
        }
        let e = by_eco.entry(d.ecosystem.as_str()).or_default();
        e.0 += 1;
        if d.integrity.as_deref().is_none_or(str::is_empty) {
            e.1.push(format!("{}@{}", d.name, d.version));
        }
    }
    for (eco, (total, missing)) in by_eco {
        if missing.is_empty() {
            v.pass(format!("{eco}: all {total} registry packages carry a recorded hash"));
        } else {
            v.fail(format!("{eco}: {} of {total} registry packages have no recorded hash: {}", missing.len(), list(&missing, 6)));
        }
    }
    for pm in &pms {
        match pm {
            Pm::Pnpm => v.pass("pnpm: pnpm-lock.yaml records an integrity hash for every registry tarball"),
            Pm::YarnBerry => {
                let behaviour = c.repo.yaml(".yarnrc.yml").and_then(|y| y.get("checksumBehavior").and_then(ystr));
                match behaviour.as_deref() {
                    Some("ignore") | Some("update") | Some("reset") => {
                        v.fail(format!("yarn: .yarnrc.yml checksumBehavior: {} turns verification off", behaviour.unwrap_or_default()))
                    }
                    _ => v.pass("yarn: yarn.lock checksums are verified on install"),
                }
            }
            Pm::Uv | Pm::Poetry | Pm::Pdm | Pm::Pipenv => {
                if c.pms.iter().any(|p| p.pm == *pm && p.lockfile.is_some()) {
                    v.pass(format!("{}: the lockfile records sha256 hashes for every file", pm.name()));
                }
            }
            Pm::Pip => {
                let reqs = c.repo.requirements();
                if reqs.iter().any(|(_, t)| t.contains("--hash=")) {
                    v.pass("pip: requirements carry --hash (pip then requires them for every package)");
                } else if !reqs.is_empty() {
                    v.fail("pip: requirements carry no hashes — generate them (`uv pip compile --generate-hashes`) and install with --require-hashes");
                }
            }
            Pm::Bundler => match c.repo.read("Gemfile.lock") {
                Some(t) if t.contains("\nCHECKSUMS\n") => v.pass("bundler: Gemfile.lock has a CHECKSUMS section"),
                Some(_) => v.fail("bundler: Gemfile.lock records no checksums — `bundle lock --add-checksums` (Bundler ≥ 2.6)"),
                None => {}
            },
            Pm::Gradle => {
                if c.repo.has("gradle/verification-metadata.xml") {
                    v.pass("gradle: gradle/verification-metadata.xml");
                } else {
                    v.fail("gradle: no dependency verification — `./gradlew --write-verification-metadata sha256`");
                }
            }
            Pm::Nuget => {
                if c.pms.iter().any(|p| p.pm == Pm::Nuget && p.lockfile.is_some()) {
                    v.pass("nuget: packages.lock.json records a contentHash per package");
                }
            }
            Pm::Composer => v.manual("composer: dist archives from GitHub carry no hash in composer.lock"),
            Pm::Maven => v.manual("maven: no hash verification by default — consider a checksum policy or the verifier plugin"),
            _ => {}
        }
    }
    for f in build_files(c.repo) {
        if let Some(m) = re!(r"GOSUMDB\s*[=:]\s*['\x22]?off|GONOSUMCHECK|GOFLAGS\s*[=:].*-insecure").find(&f.text) {
            v.fail(format!("{}: `{}` disables Go checksum verification", f.rel, m.as_str()));
        }
    }
    v.outcome(Status::NotApplicable, "no lockfile with hashes to check")
}

/// Source of one Python package in uv.lock / poetry.lock: `Ok(url)` for a
/// registry, `Err(kind)` for git / direct URL, `None` for a local path.
fn python_sources(r: &Repo) -> Vec<(String, Result<String, String>)> {
    let mut out = Vec::new();
    if let Some(lock) = r.toml("uv.lock")
        && let Some(pkgs) = lock.get("package").and_then(|p| p.as_array())
    {
        for p in pkgs {
            let name = p.get("name").and_then(|n| n.as_str()).unwrap_or("?").to_string();
            let Some(src) = p.get("source").and_then(|s| s.as_table()) else { continue };
            if let Some(u) = src.get("registry").and_then(|u| u.as_str()) {
                out.push((name, Ok(u.to_string())));
            } else if let Some(u) = src.get("git").or_else(|| src.get("url")).and_then(|u| u.as_str()) {
                out.push((name, Err(u.to_string())));
            }
        }
    }
    if let Some(lock) = r.toml("poetry.lock")
        && let Some(pkgs) = lock.get("package").and_then(|p| p.as_array())
    {
        for p in pkgs {
            let name = p.get("name").and_then(|n| n.as_str()).unwrap_or("?").to_string();
            let Some(src) = p.get("source").and_then(|s| s.as_table()) else { continue };
            let url = src.get("url").and_then(|u| u.as_str()).unwrap_or("").to_string();
            match src.get("type").and_then(|t| t.as_str()) {
                Some("legacy") => out.push((name, Ok(url))),
                Some("git") | Some("url") => out.push((name, Err(url))),
                _ => {}
            }
        }
    }
    out
}

/// A lockfile `resolved` that is not a registry tarball and not a workspace
/// path inside the repository.
fn non_registry(url: &str) -> bool {
    let local_workspace = !url.contains(':') && !url.starts_with("..");
    !local_workspace && crate::lifecycle::source_of(Some(url)) == crate::lifecycle::Source::NonRegistry
}

fn lock_004(c: &Ctx) -> Outcome {
    let configured: BTreeSet<String> = registries(c).into_iter().filter_map(|r| match r.2 {
        Reg::Set(u) => host_of(&u),
        _ => None,
    }).collect();
    let approved: BTreeSet<String> = if c.cfg.registries.is_empty() {
        configured
    } else {
        c.cfg.registries.iter().map(|r| host_of(r).unwrap_or_else(|| r.to_ascii_lowercase())).collect()
    };
    let ok_host = |h: &str| {
        approved.contains(h) || (c.cfg.registries.is_empty() && repo::is_public_registry(h))
    };
    let mut bad_hosts: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut odd: Vec<String> = Vec::new();
    let mut checked = 0;
    let mut judge = |name: String, url: &str| {
        let u = url.strip_prefix("registry+").or_else(|| url.strip_prefix("sparse+")).unwrap_or(url);
        let u = u.replace("github.com/rust-lang/crates.io-index", "index.crates.io");
        checked += 1;
        if u.starts_with("http://") && !u.contains("://localhost") && !u.contains("://127.0.0.1") {
            odd.push(format!("{name} over plain http ({u})"));
        } else if !u.starts_with("https://") {
            odd.push(format!("{name} from {u}"));
        } else if let Some(h) = host_of(&u)
            && !ok_host(&h)
        {
            bad_hosts.entry(h).or_default().push(name);
        }
    };
    for d in c.deps {
        let Some(url) = d.resolved_url.as_deref() else { continue };
        match d.ecosystem {
            Ecosystem::Node if non_registry(url) => judge(d.name.clone(), url),
            Ecosystem::Node if url.contains("://") => judge(d.name.clone(), url),
            Ecosystem::Rust | Ecosystem::Ruby if url.contains("://") => judge(d.name.clone(), url),
            _ => {}
        }
    }
    if let Some(lock) = c.repo.read("pnpm-lock.yaml") {
        // pnpm writes no URL for a package from the configured registry.
        let default_registry = c.repo.npmrc().get("registry").cloned().unwrap_or_else(|| "https://registry.npmjs.org/".into());
        let mut current = String::new();
        for line in lock.lines() {
            if let Some(k) = line.strip_prefix("  ").filter(|l| !l.starts_with(' ') && l.ends_with(':')) {
                current = k.trim_end_matches(':').trim_matches(['\'', '"']).to_string();
            }
            let Some(m) = re!(r"resolution:\s*\{([^}]*)\}").captures(line) else { continue };
            let res = &m[1];
            if let Some(t) = re!(r"tarball:\s*([^,\s]+)").captures(res) {
                judge(current.clone(), &t[1]);
            } else if res.contains("repo:") || res.contains("type: git") {
                judge(current.clone(), &format!("a git source ({res})"));
            } else if res.contains("integrity:") {
                judge(current.clone(), &default_registry);
            }
        }
    }
    for (name, src) in python_sources(c.repo) {
        match src {
            Ok(u) => judge(name, &u),
            Err(u) => judge(name, &format!("a direct URL / git source {u}")),
        }
    }
    let mut v = V::default();
    for (h, names) in &bad_hosts {
        v.fail(format!("{} package(s) resolved from unapproved host {h}: {}", names.len(), list(names, 5)));
    }
    if !odd.is_empty() {
        v.fail(format!("{} package(s) from a non-registry source: {}", odd.len(), list(&odd, 5)));
    }
    if checked > 0 && v.fail.is_empty() {
        v.pass(format!("{checked} lockfile source(s) all from approved registries"));
    }
    if c.cfg.registries.is_empty() && checked > 0 {
        v.info("approved = the public registries plus those in committed config; set [harden] registries to restrict");
    }
    v.info("run this on every change: `postmortem harden` in the pipeline");
    v.outcome(Status::NotApplicable, "the lockfiles here record no source URLs")
}

/// Is a manifest version spec one exact version?
fn exact_spec(spec: &str) -> bool {
    let s = spec.trim().trim_start_matches('=').trim_start_matches('v');
    re!(r"^\d+\.\d+\.\d+([-+][0-9A-Za-z.+-]*)?$").is_match(s)
}

fn lock_005(c: &Ctx) -> Outcome {
    let mut v = V::default();
    let mut judge = |manifest: &str, deps: Vec<(String, String)>| {
        if deps.is_empty() {
            return;
        }
        let ranged: Vec<String> = deps
            .iter()
            .filter(|(_, s)| !exact_spec(s))
            .map(|(n, s)| format!("{n} {s}"))
            .collect();
        if ranged.is_empty() {
            v.pass(format!("{manifest}: all {} direct dependencies pinned exactly", deps.len()));
        } else {
            v.fail(format!("{manifest}: {} of {} direct dependencies use a range: {}", ranged.len(), deps.len(), list(&ranged, 6)));
        }
    };
    if let Some(p) = c.repo.json("package.json")
        && let Some(d) = p.get("dependencies").and_then(|d| d.as_object())
    {
        let deps = d
            .iter()
            .filter_map(|(n, s)| Some((n.clone(), s.as_str()?.to_string())))
            .filter(|(_, s)| !re!(r"^(workspace:|file:|link:|git|github:|https?:|catalog:)").is_match(s))
            .map(|(n, s)| (n, s.rsplit('@').next().filter(|_| s.starts_with("npm:")).map_or(s.clone(), str::to_string)))
            .collect();
        judge("package.json", deps);
    }
    if let Some(t) = c.repo.toml("Cargo.toml")
        && let Some(d) = t.get("dependencies").and_then(|d| d.as_table())
    {
        let deps = d
            .iter()
            .filter_map(|(n, s)| match s {
                toml::Value::String(v) => Some((n.clone(), v.clone())),
                toml::Value::Table(t) if t.get("git").is_none() && t.get("path").is_none() && t.get("workspace").is_none() => {
                    Some((n.clone(), t.get("version")?.as_str()?.to_string()))
                }
                _ => None,
            })
            .map(|(n, s)| (n, if s.starts_with('=') { s } else { format!("^{s}") }))
            .collect();
        judge("Cargo.toml", deps);
    }
    if let Some(t) = c.repo.toml("pyproject.toml")
        && let Some(d) = t.get("project").and_then(|p| p.get("dependencies")).and_then(|d| d.as_array())
    {
        let deps = d
            .iter()
            .filter_map(|s| s.as_str())
            .map(|s| {
                let name = s.split(|ch: char| !(ch.is_alphanumeric() || ch == '-' || ch == '_' || ch == '.')).next().unwrap_or(s);
                let spec = s.split_once("==").map_or_else(|| s[name.len()..].trim().to_string(), |(_, v)| v.split([';', ',']).next().unwrap_or("").trim().to_string());
                (name.to_string(), if spec.is_empty() { "*".into() } else { spec })
            })
            .collect();
        judge("pyproject.toml", deps);
    }
    if let Some(j) = c.repo.json("composer.json")
        && let Some(d) = j.get("require").and_then(|d| d.as_object())
    {
        let deps = d
            .iter()
            .filter(|(n, _)| n.contains('/'))
            .filter_map(|(n, s)| Some((n.clone(), s.as_str()?.to_string())))
            .collect();
        judge("composer.json", deps);
    }
    v.outcome(Status::NotApplicable, "no manifest postmortem reads ranges from (package.json, Cargo.toml, pyproject.toml, composer.json)")
}

// ---------------------------------------------------------------- SRC ----

enum Reg {
    Set(String),
    Default,
    Unknown,
}

/// The registry each package manager is configured to use: `(pm, where, …)`.
fn registries(c: &Ctx) -> Vec<(Pm, String, Reg)> {
    let r = c.repo;
    let npmrc = r.npmrc();
    let reqs = r.requirements();
    pms(c)
        .into_iter()
        .map(|pm| {
            let set = |u: Option<String>, at: &str| match u {
                Some(u) => (pm, at.to_string(), Reg::Set(u)),
                None => (pm, String::new(), Reg::Default),
            };
            match pm {
                Pm::Npm | Pm::Pnpm | Pm::Yarn1 => set(npmrc.get("registry").cloned(), ".npmrc registry"),
                Pm::YarnBerry => set(
                    r.yaml(".yarnrc.yml").and_then(|y| y.get("npmRegistryServer").and_then(ystr)),
                    ".yarnrc.yml npmRegistryServer",
                ),
                Pm::Bun => set(
                    r.toml("bunfig.toml").and_then(|t| {
                        let reg = t.get("install")?.get("registry")?;
                        reg.as_str().map(str::to_string).or_else(|| reg.get("url")?.as_str().map(str::to_string))
                    }),
                    "bunfig.toml [install] registry",
                ),
                Pm::Uv => {
                    let found = r.uv_settings().and_then(|(t, at)| {
                        let idx = t.get("index").and_then(|i| i.as_array()).and_then(|a| {
                            a.iter()
                                .find(|i| i.get("default").and_then(|d| d.as_bool()) == Some(true))
                                .and_then(|i| i.get("url")?.as_str().map(str::to_string))
                        });
                        idx.or_else(|| t.get("index-url")?.as_str().map(str::to_string)).map(|u| (u, at))
                    });
                    match found {
                        Some((u, at)) => (pm, at.to_string(), Reg::Set(u)),
                        None => (pm, String::new(), Reg::Default),
                    }
                }
                Pm::Pip => {
                    let from_req = reqs.iter().find_map(|(n, t)| {
                        re!(r"(?m)^\s*(?:-i|--index-url)[=\s]+(\S+)").captures(t).map(|m| (m[1].to_string(), n.clone()))
                    });
                    let from_conf = r.pip_conf().and_then(|(m, at)| Some((m.get("index-url")?.clone(), at.to_string())));
                    match from_conf.or(from_req) {
                        Some((u, at)) => (pm, at, Reg::Set(u)),
                        None => (pm, String::new(), Reg::Default),
                    }
                }
                Pm::Poetry => set(
                    r.toml("pyproject.toml").and_then(|t| {
                        t.get("tool")?.get("poetry")?.get("source")?.as_array()?.iter()
                            .find(|s| matches!(s.get("priority").and_then(|p| p.as_str()), Some("primary") | Some("default")))
                            .and_then(|s| s.get("url")?.as_str().map(str::to_string))
                    }),
                    "pyproject.toml [[tool.poetry.source]]",
                ),
                Pm::Pipenv => set(
                    r.toml("Pipfile").and_then(|t| t.get("source")?.as_array()?.first()?.get("url")?.as_str().map(str::to_string)),
                    "Pipfile [[source]]",
                ),
                Pm::Cargo => {
                    let cfg = r.toml(".cargo/config.toml").or_else(|| r.toml(".cargo/config"));
                    let url = cfg.as_ref().and_then(|t| {
                        let src = t.get("source")?;
                        let to = src.get("crates-io")?.get("replace-with")?.as_str()?;
                        let target = src.get(to)?;
                        target.get("registry").or_else(|| target.get("local-registry")).or_else(|| target.get("directory"))
                            .and_then(|u| u.as_str()).map(str::to_string)
                            .or_else(|| t.get("registries")?.get(to)?.get("index")?.as_str().map(str::to_string))
                    });
                    set(url, ".cargo/config.toml [source.crates-io] replace-with")
                }
                Pm::Go => {
                    let found = build_files(r).find_map(|f| {
                        re!(r"GOPROXY\s*[=:]\s*['\x22]?([^\s'\x22,|]+)").captures(&f.text).map(|m| (m[1].to_string(), f.rel.clone()))
                    });
                    match found {
                        Some((u, _)) if u == "direct" || u == "off" => (pm, String::new(), Reg::Default),
                        Some((u, at)) => (pm, format!("{at} GOPROXY"), Reg::Set(u)),
                        None => (pm, String::new(), Reg::Default),
                    }
                }
                Pm::Bundler => set(
                    r.read("Gemfile").and_then(|t| re!(r#"(?m)^\s*source\s+['"]([^'"]+)['"]"#).captures(&t).map(|m| m[1].to_string())),
                    "Gemfile source",
                ),
                Pm::Composer => {
                    let j = r.json("composer.json");
                    let repos = j.as_ref().and_then(|j| j.get("repositories").cloned());
                    let packagist_off = repos.as_ref().is_some_and(|r| r.to_string().contains("\"packagist.org\":false"));
                    let url = repos.as_ref().and_then(|r| {
                        let items: Vec<&serde_json::Value> = match r {
                            serde_json::Value::Array(a) => a.iter().collect(),
                            serde_json::Value::Object(o) => o.values().collect(),
                            _ => Vec::new(),
                        };
                        items.into_iter().find(|i| i.get("type").and_then(|t| t.as_str()) == Some("composer"))
                            .and_then(|i| i.get("url")?.as_str().map(str::to_string))
                    });
                    if packagist_off && url.is_some() {
                        set(url, "composer.json repositories")
                    } else {
                        (pm, String::new(), Reg::Default)
                    }
                }
                Pm::Nuget => {
                    let cfg = ["nuget.config", "NuGet.Config", "NuGet.config"].iter().find_map(|f| r.read(f));
                    match cfg {
                        Some(t) if t.contains("<clear") => set(
                            re!(r#"<add\s+key="[^"]*"\s+value="(https?://[^"]+)""#).captures(&t).map(|m| m[1].to_string()),
                            "nuget.config packageSources",
                        ),
                        _ => (pm, String::new(), Reg::Default),
                    }
                }
                Pm::Maven | Pm::Gradle | Pm::Pdm => (pm, String::new(), Reg::Unknown),
            }
        })
        .collect()
}

fn src_001(c: &Ctx) -> Outcome {
    let mut v = V::default();
    for (pm, at, reg) in registries(c) {
        match reg {
            Reg::Set(u) => {
                let host = host_of(&u).unwrap_or_default();
                if !c.cfg.registries.is_empty() {
                    if c.cfg.registries.iter().any(|r| host_of(r).as_deref().unwrap_or(r) == host) {
                        v.pass(format!("{}: {at} → {host} (approved)", pm.name()));
                    } else {
                        v.fail(format!("{}: {at} → {host}, not in [harden] registries", pm.name()));
                    }
                } else if repo::is_public_registry(&host) {
                    v.fail(format!("{}: {at} points at the public registry {host}", pm.name()));
                } else {
                    v.pass(format!("{}: {at} → {host}", pm.name()));
                }
            }
            Reg::Default => v.fail(format!("{}: no registry configured in the repository — installs go to the public registry", pm.name())),
            Reg::Unknown => v.manual(format!("{}: registry mirrors live in settings outside the repository (settings.xml, init scripts)", pm.name())),
        }
    }
    if c.cfg.registries.is_empty() && !v.pass.is_empty() {
        v.info("set [harden] registries in postmortem.conf so postmortem can confirm these hosts are yours");
    }
    v.outcome(Status::NotApplicable, "no package manager detected")
}

fn src_002(c: &Ctx) -> Outcome {
    let mut v = V::default();
    let mut scopes: BTreeSet<String> = c
        .cfg
        .internal_scopes
        .iter()
        .map(|s| format!("@{}", s.trim_start_matches('@')))
        .collect();
    // A scope resolved from a private host is internal, declared or not.
    for d in c.deps.iter().filter(|d| d.ecosystem == Ecosystem::Node && d.name.starts_with('@')) {
        if let Some(h) = d.resolved_url.as_deref().filter(|u| u.contains("://")).and_then(host_of)
            && !repo::is_public_registry(&h)
            && let Some((scope, _)) = d.name.split_once('/')
        {
            scopes.insert(scope.to_string());
        }
    }
    let js = pms(c).iter().any(|p| p.is_js());
    if js && !scopes.is_empty() {
        let npmrc = c.repo.npmrc();
        let yarn = c.repo.yaml(".yarnrc.yml");
        let bun = c.repo.toml("bunfig.toml");
        for s in &scopes {
            let bare = s.trim_start_matches('@');
            let mapped = npmrc.get(&format!("{s}:registry")).map(|u| format!(".npmrc → {u}"))
                .or_else(|| yarn.as_ref().and_then(|y| y.get("npmScopes")?.get(bare)).map(|_| ".yarnrc.yml npmScopes".to_string()))
                .or_else(|| bun.as_ref().and_then(|t| {
                    let sc = t.get("install")?.get("scopes")?;
                    sc.get(s.as_str()).or_else(|| sc.get(bare)).map(|_| "bunfig.toml [install.scopes]".to_string())
                }));
            match mapped {
                Some(at) => v.pass(format!("{s} bound to the private registry ({at})")),
                None => v.fail(format!("{s} has no scope→registry mapping: a public package of that name would be resolved")),
            }
        }
    }
    let mut extra = Vec::new();
    if let Some((m, at)) = c.repo.pip_conf()
        && m.contains_key("extra-index-url")
    {
        extra.push(at.to_string());
    }
    for (n, t) in c.repo.requirements() {
        if t.contains("--extra-index-url") {
            extra.push(n);
        }
    }
    for f in build_files(c.repo) {
        if f.text.contains("--extra-index-url") || f.text.contains("PIP_EXTRA_INDEX_URL") {
            extra.push(f.rel.clone());
        }
    }
    if !extra.is_empty() {
        v.fail(format!(
            "pip --extra-index-url merges indexes, so an internal name can be served from PyPI ({}) — use uv's per-index pinning or a single proxy index",
            list(&extra, 4)
        ));
    }
    if let Some((t, at)) = c.repo.uv_settings()
        && let Some(s) = t.get("index-strategy").and_then(|s| s.as_str())
        && s.starts_with("unsafe")
    {
        v.fail(format!("uv: {at} index-strategy = {s} re-enables dependency confusion"));
    }
    if scopes.is_empty() && v.fail.is_empty() {
        v.info("no internal namespace declared or inferred — list yours in [harden] internal_scopes");
    }
    v.outcome(Status::NotApplicable, "")
}

fn src_003(c: &Ctx) -> Outcome {
    let scopes: Vec<String> = c.cfg.internal_scopes.iter().map(|s| format!("@{}", s.trim_start_matches('@'))).collect();
    let mut out = manual("ownership of names on public registries is checked on the registries themselves");
    if !scopes.is_empty() {
        out.evidence.push(format!("confirm you own on npmjs.com: {}", scopes.join(", ")));
    }
    out
}

fn src_004(c: &Ctx) -> Outcome {
    let mut found: BTreeMap<String, String> = BTreeMap::new();
    for d in c.deps.iter().filter(|d| d.scope == Scope::Prod) {
        let Some(u) = d.resolved_url.as_deref() else { continue };
        let bad = match d.ecosystem {
            Ecosystem::Node => non_registry(u),
            Ecosystem::Rust => u.starts_with("git+"),
            Ecosystem::Ruby => !u.starts_with("http"),
            _ => false,
        };
        if bad {
            found.entry(d.name.clone()).or_insert_with(|| u.to_string());
        }
    }
    if let Some(p) = c.repo.json("package.json")
        && let Some(d) = p.get("dependencies").and_then(|d| d.as_object())
    {
        for (n, s) in d {
            if let Some(s) = s.as_str()
                && re!(r"^(git|github:|gitlab:|bitbucket:|https?:|file:\.\.)").is_match(s)
            {
                found.entry(n.clone()).or_insert_with(|| s.to_string());
            }
        }
    }
    if let Some(t) = c.repo.toml("Cargo.toml")
        && let Some(d) = t.get("dependencies").and_then(|d| d.as_table())
    {
        for (n, s) in d {
            if let Some(g) = s.get("git").and_then(|g| g.as_str()) {
                found.entry(n.clone()).or_insert_with(|| format!("git {g}"));
            } else if let Some(p) = s.get("path").and_then(|p| p.as_str()).filter(|p| p.starts_with("..")) {
                found.entry(n.clone()).or_insert_with(|| format!("path {p}"));
            }
        }
    }
    for (file, t) in c.repo.requirements() {
        for l in t.lines().map(str::trim).filter(|l| re!(r"(git\+|https?://|^-e\s)").is_match(l) && !l.starts_with("--")) {
            found.entry(format!("{file}: {l}")).or_default();
        }
    }
    if let Some(t) = c.repo.read("Gemfile") {
        for m in re!(r#"(?m)^\s*gem\s+['"]([^'"]+)['"].*\b(git|github|path):"#).captures_iter(&t) {
            found.entry(m[1].to_string()).or_insert_with(|| format!("Gemfile {}:", &m[2]));
        }
    }
    if let Some(t) = c.repo.read("go.mod") {
        for m in re!(r"(?m)^\s*(?:replace\s+)?(\S+)(?:\s+\S+)?\s+=>\s+(\.\.?/\S*)").captures_iter(&t) {
            found.entry(m[1].to_string()).or_insert_with(|| format!("replace => {}", &m[2]));
        }
    }
    for (name, src) in python_sources(c.repo) {
        if let Err(u) = src {
            found.entry(name).or_insert(u);
        }
    }
    if found.is_empty() {
        Outcome::new(Status::Pass, vec!["✓ every production dependency is a named package from a registry".into()])
    } else {
        let items: Vec<String> = found.into_iter().map(|(n, s)| if s.is_empty() { n } else { format!("{n} ({s})") }).collect();
        Outcome::new(
            Status::Fail,
            vec![format!("✗ {} production dependency(ies) from a URL, repository or local path: {}", items.len(), list(&items, 6))],
        )
    }
}

fn src_005(c: &Ctx) -> Outcome {
    let mut hits = Vec::new();
    let mut texts: Vec<(String, String)> = [
        ".npmrc", ".yarnrc", ".yarnrc.yml", "bunfig.toml", "pip.conf", "pip.ini", "uv.toml", "pyproject.toml",
        ".cargo/config.toml", ".cargo/config", "composer.json", "nuget.config", "NuGet.Config", "Gemfile",
        ".bundle/config", "Pipfile",
    ]
    .iter()
    .filter_map(|f| c.repo.read(f).map(|t| (f.to_string(), t)))
    .collect();
    texts.extend(c.repo.requirements());
    texts.extend(build_files(c.repo).map(|f| (f.rel.clone(), f.text.clone())));
    let pat = re!(r#"(?ix)
        strict-ssl\s*[=\s]\s*false | enableStrictSsl:\s*false | unsafeHttpWhitelist
        | --trusted-host | ^\s*trusted-host\s*= | allow-insecure-host
        | NODE_TLS_REJECT_UNAUTHORIZED['"]?\s*[=:]\s*['"]?0 | PYTHONHTTPSVERIFY['"]?\s*[=:]\s*['"]?0
        | GIT_SSL_NO_VERIFY | "secure-http"\s*:\s*false | GOINSECURE | ssl_verify_mode\s*[:=]\s*0
        | BUNDLE_SSL_VERIFY_MODE\s*[:=]\s*['"]?0 | check-revoke\s*=\s*false
        | (?:registry|index-url|npmRegistryServer|url)\s*[=:]\s*['"]?http://([^/\s'":]+)"#);
    for (rel, text) in &texts {
        for (n, line) in text.lines().enumerate() {
            if let Some(m) = pat.captures(line)
                && !m.get(1).is_some_and(|h| matches!(h.as_str(), "localhost" | "127.0.0.1"))
            {
                hits.push(format!("{rel}:{}: {}", n + 1, m[0].trim()));
            }
        }
    }
    for d in c.deps {
        if let Some(u) = d.resolved_url.as_deref()
            && u.starts_with("http://")
            && !u.contains("://localhost")
            && !u.contains("://127.0.0.1")
        {
            hits.push(format!("lockfile: {} resolved over plain http", d.name));
        }
    }
    if hits.is_empty() {
        Outcome::new(Status::Pass, vec!["✓ no TLS bypass or plain-http registry in package-manager config, pipelines or Dockerfiles".into()])
    } else {
        Outcome::new(Status::Fail, hits.into_iter().take(10).map(|h| format!("✗ {h}")).collect())
    }
}

fn src_006(c: &Ctx) -> Outcome {
    let mut v = V::default();
    let need = |v: &mut V, pm: Pm, files: &[&str]| match files.iter().find(|f| c.repo.has(f)) {
        Some(f) => match c.repo.tracked(f) {
            Some(false) => v.fail(format!("{}: {f} exists but is not committed", pm.name())),
            _ => v.pass(format!("{}: {f}", pm.name())),
        },
        None => v.fail(format!("{}: no committed config ({}) — settings come from each machine", pm.name(), files.join(" / "))),
    };
    for pm in pms(c) {
        match pm {
            Pm::Npm => need(&mut v, pm, &[".npmrc"]),
            Pm::Yarn1 => need(&mut v, pm, &[".yarnrc", ".npmrc"]),
            Pm::Pnpm => need(&mut v, pm, &["pnpm-workspace.yaml", ".npmrc"]),
            Pm::YarnBerry => need(&mut v, pm, &[".yarnrc.yml"]),
            Pm::Bun => need(&mut v, pm, &["bunfig.toml"]),
            Pm::Uv => {
                if c.repo.uv_settings().is_some() {
                    v.pass("uv: settings in uv.toml / [tool.uv]");
                } else {
                    v.fail("uv: no [tool.uv] or uv.toml — release age and indexes come from each machine");
                }
            }
            Pm::Cargo if c.repo.has(".cargo/config.toml") => v.pass("cargo: .cargo/config.toml"),
            p if p.is_python() => v.manual(format!("{}: settings live in pip.conf or the environment — commit them and point the pipeline at them", p.name())),
            _ => {}
        }
    }
    // Security settings that exist only on this machine are the failure the
    // control describes, and the one a CI runner silently does not have.
    if pms(c).iter().any(|p| p.is_js())
        && let Some(home) = std::env::var_os("HOME")
        && let Ok(t) = std::fs::read_to_string(std::path::Path::new(&home).join(".npmrc"))
    {
        let user = repo::parse_ini(&t);
        let project = c.repo.npmrc();
        let only_here: Vec<&str> = ["min-release-age", "ignore-scripts", "registry", "strict-ssl"]
            .into_iter()
            .filter(|k| user.contains_key(*k) && !project.contains_key(*k))
            .collect();
        if !only_here.is_empty() {
            v.fail(format!("~/.npmrc sets {} on this machine only — move it to the project .npmrc", only_here.join(", ")));
        }
    }
    v.outcome(Status::NotApplicable, "no package manager with project-level security settings")
}

// ---------------------------------------------------------------- UPD ----

const RENOVATE: &[&str] = &[
    "renovate.json", "renovate.json5", ".renovaterc", ".renovaterc.json", ".renovaterc.json5",
    ".github/renovate.json", ".github/renovate.json5", ".gitlab/renovate.json", ".gitlab/renovate.json5",
];

fn renovate(r: &Repo) -> Option<(String, String)> {
    RENOVATE.iter().find_map(|f| r.read(f).map(|t| (f.to_string(), t))).or_else(|| {
        let p = r.json("package.json")?;
        Some(("package.json renovate".into(), p.get("renovate")?.to_string()))
    })
}

/// Renovate config as JSON. Renovate accepts JSON5, so comments, trailing
/// commas, unquoted keys and single-quoted strings are normalised first — a
/// best effort that gives up (`None`) rather than guess.
fn renovate_json(text: &str) -> Option<serde_json::Value> {
    if let Ok(j) = serde_json::from_str(text) {
        return Some(j);
    }
    let s = re!(r"(?m)^\s*//.*$").replace_all(text, "");
    let s = re!(r"(?s)/\*.*?\*/").replace_all(&s, "");
    let s = re!(r"'((?:[^'\\\x22]|\\.)*)'").replace_all(&s, "\"$1\"");
    let s = re!(r"([{,]\s*)([A-Za-z_$][\w$]*)\s*:").replace_all(&s, "$1\"$2\":");
    let s = re!(r",(\s*[}\]])").replace_all(&s, "$1");
    serde_json::from_str(&s).ok()
}

fn dependabot(r: &Repo) -> Option<(String, serde_yaml::Value)> {
    [".github/dependabot.yml", ".github/dependabot.yaml"].iter().find_map(|f| r.yaml(f).map(|y| (f.to_string(), y)))
}

fn dependabot_eco(pm: Pm) -> &'static [&'static str] {
    match pm {
        Pm::Npm | Pm::Pnpm | Pm::Yarn1 | Pm::YarnBerry => &["npm"],
        Pm::Bun => &["bun", "npm"],
        Pm::Uv => &["uv", "pip"],
        Pm::Poetry | Pm::Pdm | Pm::Pipenv | Pm::Pip => &["pip"],
        Pm::Cargo => &["cargo"],
        Pm::Go => &["gomod"],
        Pm::Bundler => &["bundler"],
        Pm::Composer => &["composer"],
        Pm::Maven => &["maven"],
        Pm::Gradle => &["gradle"],
        Pm::Nuget => &["nuget"],
    }
}

fn upd_001(c: &Ctx) -> Outcome {
    let need = c.param("min_release_age_hours") as f64;
    let mut v = V::default();
    let bot = dependabot(c.repo);
    let ren = renovate(c.repo);
    if bot.is_none() && ren.is_none() {
        return Outcome::new(Status::Fail, vec!["✗ no Dependabot or Renovate configuration".into()]);
    }
    if let Some((file, y)) = &bot {
        let updates = y.get("updates").and_then(|u| u.as_sequence()).cloned().unwrap_or_default();
        let ecos: Vec<String> = updates.iter().filter_map(|u| u.get("package-ecosystem").and_then(ystr)).collect();
        for pm in pms(c) {
            if dependabot_eco(pm).iter().any(|e| ecos.iter().any(|x| x == e)) {
                v.pass(format!("{file}: covers {}", pm.name()));
            } else if ren.is_none() {
                v.fail(format!("{file}: no `{}` entry for {}", dependabot_eco(pm)[0], pm.name()));
            }
        }
        for u in &updates {
            let eco = u.get("package-ecosystem").and_then(ystr).unwrap_or_default();
            if eco == "github-actions" || eco == "docker" {
                continue;
            }
            let days = u.get("cooldown").and_then(|cd| cd.get("default-days")).and_then(ystr).and_then(|d| d.parse::<f64>().ok());
            match days {
                Some(d) if d * 24.0 >= need => v.pass(format!("{file} `{eco}`: cooldown {d} days")),
                Some(d) => v.fail(format!("{file} `{eco}`: cooldown {d} days is below {}", hours(need))),
                None => v.fail(format!(
                    "{file} `{eco}`: no cooldown — add `cooldown: {{ default-days: {} }}` so proposals respect CB-DEP-AGE-001",
                    (need / 24.0).ceil() as i64
                )),
            }
        }
    }
    if let Some((file, text)) = &ren {
        v.pass(format!("{file}: Renovate covers every manager it detects"));
        let age = re!(r#"minimumReleaseAge["']?\s*:\s*["']([^"']+)["']"#)
            .captures(text)
            .and_then(|m| duration_hours(&m[1], 1.0));
        match age {
            Some(h) if h >= need => v.pass(format!("{file}: minimumReleaseAge {}", hours(h))),
            Some(h) => v.fail(format!("{file}: minimumReleaseAge {} is below {}", hours(h), hours(need))),
            None if text.contains("config:best-practices") || text.contains("security:minimumReleaseAgeNpm") => {
                if 72.0 >= need {
                    v.pass(format!("{file}: preset minimumReleaseAgeNpm (3 days, npm only)"));
                } else {
                    v.fail(format!("{file}: preset minimumReleaseAgeNpm is 3 days, below {}", hours(need)));
                }
            }
            None => v.fail(format!("{file}: no minimumReleaseAge — proposals ignore the release-age rule")),
        }
    }
    v.outcome(Status::Fail, "")
}

fn upd_002(c: &Ctx) -> Outcome {
    let mut v = V::default();
    let ren = renovate(c.repo);
    let bot = dependabot(c.repo);
    if let Some((file, text)) = &ren {
        match renovate_json(text) {
            Some(j) => {
                let rules = j.get("packageRules").and_then(|r| r.as_array()).cloned().unwrap_or_default();
                let types = |r: &serde_json::Value| -> Vec<String> {
                    r.get("matchUpdateTypes").and_then(|t| t.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default()
                };
                let major_blocked = rules.iter().any(|r| r.get("automerge") == Some(&serde_json::Value::Bool(false)) && types(r).iter().any(|t| t == "major"));
                if j.get("automerge") == Some(&serde_json::Value::Bool(true)) && !major_blocked {
                    v.fail(format!("{file}: top-level automerge applies to major updates too"));
                }
                for r in &rules {
                    if r.get("automerge") == Some(&serde_json::Value::Bool(true)) {
                        let t = types(r);
                        if t.is_empty() || t.iter().any(|x| x == "major") {
                            v.fail(format!("{file}: a packageRule automerges {}", if t.is_empty() { "every update type".into() } else { t.join("/") }));
                        } else {
                            v.pass(format!("{file}: automerge limited to {}", t.join("/")));
                        }
                    }
                }
                if v.fail.is_empty() && v.pass.is_empty() {
                    v.pass(format!("{file}: no automerge — every update is reviewed"));
                }
            }
            None => v.manual(format!("{file}: JSON5 postmortem could not parse — check automerge rules by hand")),
        }
    }
    for f in c.repo.ci.iter().filter(|f| f.text.contains("dependabot") && re!(r"gh pr merge|enable-pull-request-automerge|auto-merge").is_match(&f.text)) {
        if f.text.contains("semver-patch") || f.text.contains("semver-minor") {
            v.pass(format!("{}: Dependabot auto-merge gated on update type", f.rel));
        } else {
            v.fail(format!("{}: auto-merges Dependabot PRs without checking for a major update", f.rel));
        }
    }
    if bot.is_some() && ren.is_none() && v.fail.is_empty() && v.pass.is_empty() {
        v.pass("Dependabot PRs are not auto-merged");
    }
    if !v.pass.is_empty() || !v.fail.is_empty() {
        v.info("maintainer changes and new install scripts need review too: `postmortem diff` on the PR shows both");
    }
    v.outcome(Status::NotApplicable, "no automated updates (see CB-DEP-UPD-001)")
}

// ---------------------------------------------------------------- VET ----

/// Does a CODEOWNERS pattern cover `path`?
fn codeowners_match(pattern: &str, path: &str) -> bool {
    if pattern == "*" || pattern == "**" || pattern == "/" {
        return true;
    }
    let anchored = pattern.starts_with('/');
    let p = pattern.trim_start_matches('/');
    if let Some(dir) = p.strip_suffix('/') {
        return path.starts_with(&format!("{dir}/")) || (!anchored && path.contains(&format!("/{dir}/")));
    }
    let Some(re) = crate::config::glob_regex(p) else { return false };
    let full = |s: &str| re.find(s).is_some_and(|m| m.start() == 0 && m.end() == s.len());
    full(path) || (!anchored && !p.contains('/') && full(path.rsplit('/').next().unwrap_or(path)))
}

fn vet_001(c: &Ctx) -> Outcome {
    let Some((file, text)) = [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS", ".gitlab/CODEOWNERS"]
        .iter()
        .find_map(|f| c.repo.read(f).map(|t| (f.to_string(), t)))
    else {
        return Outcome::new(
            Status::Fail,
            vec!["✗ no CODEOWNERS file — nothing makes dependency changes need a responsible reviewer".into()],
        );
    };
    let rules: Vec<(&str, Vec<&str>)> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('['))
        .map(|l| {
            let mut it = l.split_whitespace();
            (it.next().unwrap_or(""), it.collect())
        })
        .collect();
    let mut v = V::default();
    let files: BTreeSet<&str> = c.pms.iter().flat_map(|p| std::iter::once(p.manifest.as_str()).chain(p.lockfile.as_deref())).collect();
    for f in files {
        // Last match wins; a match without owners unsets ownership.
        match rules.iter().rev().find(|(p, _)| codeowners_match(p, f)) {
            Some((_, owners)) if !owners.is_empty() => v.pass(format!("{f} → {}", owners.join(" "))),
            _ => v.fail(format!("{f} has no code owner in {file}")),
        }
    }
    v.info("branch protection must require code-owner review — a repository setting postmortem cannot read");
    v.outcome(Status::NotApplicable, "")
}

/// Development tools that do not belong in production `dependencies`.
const NODE_DEV_TOOLS: &[&str] = &[
    "eslint", "prettier", "jest", "mocha", "vitest", "nodemon", "husky", "lint-staged", "ts-node", "chai",
    "sinon", "nyc", "c8", "cypress", "playwright", "@playwright/test", "webpack-dev-server", "ava", "tap",
];
const PY_DEV_TOOLS: &[&str] = &["pytest", "black", "ruff", "mypy", "flake8", "pylint", "isort", "tox", "coverage", "pre-commit", "nox"];

fn vet_004(c: &Ctx) -> Outcome {
    let mut v = V::default();
    if let Some(d) = c.repo.json("package.json").and_then(|p| p.get("dependencies")?.as_object().cloned()) {
        let misplaced: Vec<String> = d
            .keys()
            .filter(|n| NODE_DEV_TOOLS.contains(&n.as_str()) || n.starts_with("@types/") || n.starts_with("@testing-library/"))
            .cloned()
            .collect();
        if misplaced.is_empty() {
            v.pass("package.json: no test or lint tool among production dependencies");
        } else {
            v.fail(format!("package.json: development tools in `dependencies`: {}", list(&misplaced, 6)));
        }
    }
    if let Some(d) = c.repo.toml("pyproject.toml").and_then(|t| t.get("project")?.get("dependencies")?.as_array().cloned()) {
        let misplaced: Vec<String> = d
            .iter()
            .filter_map(|s| s.as_str())
            .map(|s| s.split(|ch: char| !(ch.is_alphanumeric() || ch == '-' || ch == '_')).next().unwrap_or(s).to_ascii_lowercase())
            .filter(|n| PY_DEV_TOOLS.contains(&n.as_str()))
            .collect();
        if misplaced.is_empty() {
            v.pass("pyproject.toml: no test or lint tool among [project] dependencies");
        } else {
            v.fail(format!("pyproject.toml: development tools in [project] dependencies: {}", list(&misplaced, 6)));
        }
    }
    let pms = pms(c);
    for f in &c.repo.dockerfiles {
        // Only the last stage ships; a build stage legitimately installs dev tools.
        let last = f.text.rsplit_once("\nFROM ").map_or(f.text.as_str(), |(_, s)| s);
        let prod_env = re!(r"NODE_ENV[=\s]+['\x22]?production|BUNDLE_WITHOUT|POETRY_WITHOUT|UV_NO_DEV").is_match(last);
        for line in last.lines().filter(|l| is_install_command(l)) {
            let has = |s: &str| line.contains(s);
            let problem = if re!(r"\bnpm\s+(ci|install|i)\b").is_match(line) && !prod_env && !has("--omit=dev") && !has("--only=prod") && !has("--production") {
                Some("npm installs devDependencies — add --omit=dev")
            } else if re!(r"\bpnpm\s+(install|i)\b").is_match(line) && !prod_env && !has("--prod") && !has(" -P") {
                Some("pnpm installs devDependencies — add --prod")
            } else if re!(r"\bbun\s+(install|i|ci)\b").is_match(line) && !prod_env && !has("--production") {
                Some("bun installs devDependencies — add --production")
            } else if pms.contains(&Pm::Yarn1) && re!(r"\byarn(\s+install)?\b").is_match(line) && !prod_env && !has("--production") {
                Some("yarn installs devDependencies — add --production")
            } else if re!(r"\bpoetry\s+install\b").is_match(line) && !prod_env && !re!(r"--only[=\s]+main|--without[=\s]+\S*dev|--no-dev").is_match(line) {
                Some("poetry installs the dev group — add --only main")
            } else if re!(r"\buv\s+sync\b").is_match(line) && !prod_env && !has("--no-dev") && !has("--only-group") && !has("--no-default-groups") {
                Some("uv sync installs the dev group — add --no-dev")
            } else if re!(r"requirements[-_](dev|test)").is_match(line) || re!(r"\bpipenv\s+install\b.*--dev").is_match(line) {
                Some("installs development requirements")
            } else if re!(r"\bbundle\s+install\b").is_match(line) && !prod_env && !has("--without") {
                Some("bundler installs every group — set BUNDLE_WITHOUT=development:test")
            } else if re!(r"\bcomposer\s+install\b").is_match(line) && !has("--no-dev") {
                Some("composer installs require-dev — add --no-dev")
            } else {
                None
            };
            match problem {
                Some(p) => v.fail(format!("{}: `{}` — {p}", f.rel, snippet(line))),
                None => v.pass(format!("{}: `{}` installs runtime dependencies only", f.rel, snippet(line))),
            }
        }
    }
    if c.repo.dockerfiles.is_empty() {
        v.info("no Dockerfile: check that the shipped artifact excludes dev dependencies");
    }
    v.outcome(Status::Manual, "? nothing postmortem can read says how the artifact is built")
}

// --------------------------------------------------------------- VULN ----

const SCANNERS: &str = r"(?i)\b(postmortem\s+(tree|audit|scan)|mlab-sh/postmortem|osv-scanner|npm\s+audit|pnpm\s+audit|yarn\s+(npm\s+)?audit|pip-audit|cargo[\s-]audit|cargo[\s-]deny|trivy|grype|snyk|dependency-check|govulncheck|bundle(r)?[\s-]audit|composer\s+audit|safety\s+(check|scan)|--vulnerable)\b";

fn vuln_001(c: &Ctx) -> Outcome {
    let interval = c.param("scan_interval_hours");
    let mut v = V::default();
    let scanner = regex::Regex::new(SCANNERS).unwrap();
    let mut on_change = Vec::new();
    let mut scheduled = Vec::new();
    for f in &c.repo.ci {
        let Some(m) = scanner.find(&f.text) else { continue };
        let tool = m.as_str().to_string();
        if f.rel.starts_with(".github/") {
            if re!(r"(?m)^\s*-?\s*cron:").is_match(&f.text) {
                scheduled.push(format!("{} ({tool})", f.rel));
            }
            if re!(r"\b(push|pull_request|pull_request_target|merge_group)\b").is_match(&f.text) {
                on_change.push(format!("{} ({tool})", f.rel));
            }
        } else {
            on_change.push(format!("{} ({tool})", f.rel));
            v.info(format!("{}: pipeline schedules are configured in the CI server, not visible here", f.rel));
        }
    }
    if c.repo.ci.is_empty() {
        v.manual("no pipeline definition found — scanning may run on a platform (Dependabot alerts, an SCA app)");
    } else if on_change.is_empty() && scheduled.is_empty() {
        v.fail("no pipeline runs a vulnerability scanner (`postmortem tree --vulns --fail-on-vuln high`)");
    } else {
        if on_change.is_empty() {
            v.fail("no scan on each change (push / pull request)");
        } else {
            v.pass(format!("scan on change: {}", list(&on_change, 3)));
        }
        let has_gha_scanner = c.repo.ci.iter().any(|f| f.rel.starts_with(".github/") && scanner.is_match(&f.text));
        if !scheduled.is_empty() {
            v.pass(format!("scheduled scan: {}", list(&scheduled, 3)));
            v.info(format!("check the schedule runs at least every {interval}h"));
        } else if has_gha_scanner {
            v.fail(format!("no scheduled scan — add a `schedule:` cron so the default branch is rescanned every {interval}h"));
        }
    }
    if let Some(vulns) = c.vulns {
        v.info(format!("right now: {} vulnerable package(s) in the lockfiles (see CB-DEP-VULN-003)", vulns.len()));
    }
    v.outcome(Status::Manual, "")
}

fn vuln_002(c: &Ctx) -> Outcome {
    let mut v = V::default();
    if let Some(vulns) = c.vulns {
        let mal: Vec<String> = vulns
            .iter()
            .filter(|p| p.vulns.iter().any(|x| x.id.starts_with("MAL-")))
            .map(|p| format!("{}@{}", p.name, p.version))
            .collect();
        if mal.is_empty() {
            v.info("no installed package matches a malicious-package advisory (OSV MAL-)");
        } else {
            v.fail(format!("{} installed package(s) listed as malicious: {}", mal.len(), list(&mal, 8)));
        }
    } else {
        v.info("installed packages not checked against malicious-package advisories (needs --vulns)");
    }
    let gate: Vec<&str> = c
        .repo
        .ci
        .iter()
        .filter(|f| re!(r"(?i)\bpostmortem\b|mlab-sh/postmortem|socket\s+ci|socketdev").is_match(&f.text))
        .map(|f| f.rel.as_str())
        .collect();
    if gate.is_empty() {
        v.fail("no pipeline step fails the build on a malicious package (`postmortem audit` exits 1 on CRITICAL)");
    } else {
        v.pass(format!("malware gate in {}", gate.join(", ")));
    }
    v.outcome(Status::Fail, "")
}

fn vuln_003(c: &Ctx) -> Outcome {
    let mut out = manual(&format!(
        "deadlines ({}d critical, {}d high, {}d medium) are tracked in your ticketing, not the repository",
        c.param("sla_critical_days"),
        c.param("sla_high_days"),
        c.param("sla_medium_days"),
    ));
    match c.vulns {
        Some(vulns) => {
            let mut by: BTreeMap<String, usize> = BTreeMap::new();
            let mut fixable = 0;
            for x in vulns.iter().flat_map(|p| &p.vulns) {
                *by.entry(format!("{:?}", x.severity).to_lowercase()).or_default() += 1;
                fixable += usize::from(x.fixed.is_some());
            }
            let total: usize = by.values().sum();
            out.evidence.push(format!(
                "open now: {total} advisory(ies){}, {fixable} with a fixed version (`postmortem fix`)",
                if by.is_empty() { String::new() } else { format!(" ({})", by.iter().map(|(k, n)| format!("{n} {k}")).collect::<Vec<_>>().join(", ")) }
            ));
        }
        None => out.evidence.push("run with --vulns for the open advisories".into()),
    }
    out
}

fn vuln_004(c: &Ctx) -> Outcome {
    let Some(_) = c.online else {
        return skipped("needs --online: archive and activity status come from each package's source repository");
    };
    let mut v = V::default();
    for (prefix, what) in [("archived", "archived repositories"), ("stale", "no activity in a long time"), ("no-repository", "no source repository")] {
        let hits = flagged(c, prefix).unwrap_or_default();
        if !hits.is_empty() {
            let line = format!("{} package(s) with {what}: {}", hits.len(), list(&hits, 6));
            if prefix == "archived" { v.fail(line) } else { v.info(line) }
        }
    }
    if v.fail.is_empty() {
        v.pass("no dependency's source repository is archived");
    }
    v.info("record a replacement plan or an acceptance for each one; runtimes past end-of-life are not checked");
    v.outcome(Status::Pass, "")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every check runs over a repository that exercises its parsers, so a
    /// regex that does not compile or a lookup that panics fails here rather
    /// than in a user's terminal.
    #[test]
    fn every_check_runs_on_a_fixture() {
        let dir = std::env::temp_dir().join(format!("pm-harden-{}", std::process::id()));
        let w = |rel: &str, body: &str| {
            let p = dir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        };
        w("package.json", r#"{"dependencies":{"left-pad":"^1.3.0","eslint":"9.0.0","x":"github:a/b"},"scripts":{"gen":"npx cowsay hi"}}"#);
        w("package-lock.json", r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/left-pad":{"version":"1.3.0","resolved":"http://evil.example/left-pad/-/left-pad-1.3.0.tgz"}}}"#);
        w(".npmrc", "registry=https://npm.corp.example/\nstrict-ssl=false\nmin-release-age=1\n");
        w("requirements.txt", "--extra-index-url https://pypi.corp.example/simple\nflask>=3\n");
        w(".github/workflows/ci.yml", "on: [push, pull_request_target]\nenv:\n  T: ${{ secrets.NPM_TOKEN }}\njobs:\n  b:\n    steps:\n      - uses: actions/cache@v4\n        with:\n          key: deps\n      - run: npm install\n      - run: cargo build\n");
        w(".github/dependabot.yml", "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n");
        w("renovate.json", r#"{"automerge": true, "minimumReleaseAge": "1 day"}"#);
        w("Dockerfile", "FROM node\nRUN npm ci\nRUN go run x/y@latest\n");
        w("CODEOWNERS", "/docs/ @team\n");
        w("Cargo.toml", "[package]\nname='a'\n[dependencies]\nserde = '1'\nfoo = { git = 'https://x' }\n");
        w("pyproject.toml", "[project]\ndependencies=['pytest>=8']\n[tool.uv]\nexclude-newer='3 days'\n");
        let repo = Repo::load(&dir);
        let pms = repo::detect_pms(&repo);
        let controls = super::super::controls();
        let params = super::super::resolve_params(&controls, super::super::Level::Hardened, &BTreeMap::new()).unwrap();
        let cfg = crate::config::HardenConfig { internal_scopes: vec!["acme".into()], ..Default::default() };
        let ctx = Ctx {
            repo: &repo,
            pms: &pms,
            level: super::super::Level::Hardened,
            params: &params,
            cfg: &cfg,
            gate_allow: &[],
            deps: &[],
            online: None,
            vulns: Some(&[]),
            today: chrono::NaiveDate::from_ymd_opt(2026, 10, 16).unwrap(),
        };
        let status = |id: &str| run(id, &ctx).status;
        for (id, ..) in SUPPORT {
            let _ = run(id, &ctx);
        }
        for id in ["CB-DEP-AGE-001", "CB-DEP-SRC-002", "CB-DEP-SRC-004", "CB-DEP-SRC-005", "CB-DEP-LOCK-002",
                   "CB-DEP-CI-001", "CB-DEP-CI-004", "CB-DEP-EXEC-003", "CB-DEP-UPD-001", "CB-DEP-UPD-002",
                   "CB-DEP-VET-001", "CB-DEP-VET-004", "CB-DEP-LOCK-005"] {
            assert_eq!(status(id), Status::Fail, "{id}: {:?}", run(id, &ctx).evidence);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pinned_tokens() {
        assert!(pinned_token("cowsay@1.6.0", false));
        assert!(pinned_token("@scope/tool@2.0.0", false));
        assert!(!pinned_token("@scope/tool", false));
        assert!(!pinned_token("create-react-app", false));
        assert!(!pinned_token("tool@latest", false));
        assert!(pinned_token("ruff==0.6.1", true));
        assert!(pinned_token("ruff@0.6.1", true));
        assert!(!pinned_token("ruff", true));
    }

    #[test]
    fn install_problems() {
        let p = |l: &str| install_problem(l, "", &[Pm::Npm], false);
        assert!(p("npm install").is_some());
        assert!(p("npm ci").is_none());
        assert!(p("npm install -g pnpm").is_none());
        assert!(p("cargo build --release").is_some());
        assert!(p("cargo build --locked").is_none());
        assert!(p("uv sync").is_some());
        assert!(p("uv sync --locked").is_none());
        assert!(p("composer update").is_some());
        assert!(install_problem("yarn install", "", &[Pm::Yarn1], false).is_some());
        assert!(install_problem("yarn install", "", &[Pm::YarnBerry], false).is_none());
        assert!(p("bundle install").is_some());
        assert!(install_problem("bundle install", "ENV BUNDLE_FROZEN=true", &[], false).is_none());
    }

    #[test]
    fn codeowners_patterns() {
        assert!(codeowners_match("*", "package.json"));
        assert!(codeowners_match("package.json", "package.json"));
        assert!(codeowners_match("/package-lock.json", "package-lock.json"));
        assert!(codeowners_match("*.lock", "Cargo.lock"));
        assert!(codeowners_match("**/package.json", "package.json") || codeowners_match("package.json", "package.json"));
        assert!(!codeowners_match("/docs/", "package.json"));
    }

    #[test]
    fn exact_specs_and_requirements() {
        assert!(exact_spec("1.2.3"));
        assert!(exact_spec("=1.2.3"));
        assert!(!exact_spec("^1.2.3"));
        assert!(!exact_spec("~1.2"));
        assert_eq!(unpinned_requirements("flask==3.0.0\nrequests>=2\n# c\n-r base.txt\n"), vec!["requests>=2"]);
    }
}
