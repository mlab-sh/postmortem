//! Pipelines, normalised across CI platforms: where dependencies are
//! installed and what secrets are in reach there (CB-DEP-CI-001), and which
//! dependency caches exist and what they are keyed on (CB-DEP-CI-004).
//!
//! Every platform distributes secrets differently, and that is the whole
//! question: GitHub, Azure and Drone/Woodpecker hand a secret only to the step
//! that maps it; CircleCI contexts and Bitbucket deployments reach every step of
//! a job; GitLab project variables reach every job unless scoped. Each parser
//! records *why* an install step can see a secret, in that platform's terms.

use serde_yaml::Value;

use super::repo::{Ci, Repo, TextFile, ci_platform, is_install_command};

/// A pipeline step that installs dependencies.
pub struct Install {
    pub ci: Ci,
    pub file: String,
    pub job: String,
    pub step: String,
    /// Why secrets are in reach of this step; `None` when nothing in the file
    /// gives it any.
    pub exposure: Option<String>,
}

/// A dependency cache a pipeline restores or saves.
pub struct Cache {
    pub ci: Ci,
    pub file: String,
    pub job: String,
    /// What is wrong with it; `None` when it is keyed on the lockfile.
    pub problem: Option<String>,
    pub detail: String,
}

/// A pipeline file of a platform no parser here understands.
pub struct Unparsed {
    pub ci: Ci,
    pub file: String,
    pub installs: bool,
    pub caches: bool,
    /// The platform has a parser here, but this file did not parse (CircleCI
    /// tolerates duplicate YAML anchors, strict YAML does not).
    pub broken: bool,
}

#[derive(Default)]
pub struct Pipelines {
    pub installs: Vec<Install>,
    pub caches: Vec<Cache>,
    pub unparsed: Vec<Unparsed>,
}

pub fn read(r: &Repo) -> Pipelines {
    let mut p = Pipelines::default();
    for f in &r.ci {
        let Some(ci) = ci_platform(&f.rel) else { continue };
        let parsed = match ci {
            Ci::GithubActions | Ci::Forgejo => Some(gha(ci, f, &mut p)),
            Ci::GitLab => Some(gitlab(f, &mut p)),
            Ci::Azure => Some(azure(f, &mut p)),
            Ci::Circle => Some(circle(f, &mut p)),
            Ci::Bitbucket => Some(bitbucket(f, &mut p)),
            Ci::Drone | Ci::Woodpecker => Some(drone(ci, f, &mut p)),
            Ci::Jenkins => {
                jenkins(f, &mut p);
                Some(true)
            }
            _ => None,
        };
        if parsed != Some(true) {
            p.unparsed.push(Unparsed {
                ci,
                file: f.rel.clone(),
                installs: f.text.lines().any(is_install_command),
                caches: re!(r"(?mi)^\s*-?\s*(cache|caches|save_cache|restore_cache)\b").is_match(&f.text),
                broken: parsed == Some(false),
            });
        }
    }
    p
}

/// Secrets that reach every job or step of a platform, set outside the
/// repository — the part of CB-DEP-CI-001 a human checks remotely.
pub fn global_secrets(ci: Ci) -> Option<&'static str> {
    match ci {
        Ci::GitLab => Some("project and group CI/CD variables reach every job unless protected or environment-scoped — check them remotely"),
        Ci::Bitbucket => Some("repository and workspace variables reach every step — keep publish credentials in deployment variables"),
        Ci::Circle => Some("project environment variables reach every job — keep publish credentials in a restricted context"),
        Ci::Travis | Ci::Buildkite | Ci::AppVeyor | Ci::Semaphore | Ci::Cirrus => Some("repository-level secrets reach every job — check them remotely"),
        _ => None,
    }
}

/// Whether untrusted builds can write the caches trusted builds read: a
/// platform setting, so a line to check remotely — except on GitHub, whose
/// branch scoping answers it.
pub fn cache_isolation(ci: Ci) -> Result<&'static str, &'static str> {
    match ci {
        Ci::GithubActions => Ok("GitHub scopes caches per branch: a fork's PR cannot write the default branch's cache"),
        Ci::GitLab => Err("check 'Use separate caches for protected branches' is on (Settings → CI/CD → General pipelines)"),
        _ => Err("check that fork and pull-request builds cannot save caches the default branch restores"),
    }
}

// ------------------------------------------------------------- helpers ----

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn dump(v: Option<&Value>) -> String {
    v.and_then(|v| serde_yaml::to_string(v).ok()).unwrap_or_default()
}

/// A script as lines, whether written as one block, a list, or nested lists
/// (GitLab `!reference` arrays).
fn script_lines(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => s.lines().map(str::to_string).collect(),
        Some(Value::Sequence(seq)) => seq.iter().flat_map(|x| script_lines(Some(x))).collect(),
        Some(Value::Mapping(m)) => m.get("command").map_or_else(Vec::new, |c| script_lines(Some(c))),
        _ => Vec::new(),
    }
}

fn first_install<'a>(lines: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    lines.into_iter().find(|l| is_install_command(l))
}

fn short(line: &str) -> String {
    let t = line.trim().trim_start_matches("- ").trim_start_matches("run:").trim();
    if t.chars().count() > 70 { format!("{}…", t.chars().take(69).collect::<String>()) } else { t.to_string() }
}

fn label(name: Option<String>, line: &str) -> String {
    name.filter(|n| !n.is_empty()).unwrap_or_else(|| short(line))
}

/// Variable references that name a secret: `$NPM_TOKEN`, `${DEPLOY_KEY}`,
/// `$(registryPassword)`.
fn secret_refs(text: &str) -> Vec<String> {
    let mut out: Vec<String> = re!(r"\$\(?\{?([A-Za-z_][A-Za-z0-9_.]*)")
        .captures_iter(text)
        .map(|m| m[1].to_string())
        .filter(|n| re!(r"(?i)token|secret|passw|api[_.]?key|private[_.]?key|credential|_key$|^key$|auth|_pat$").is_match(n))
        .collect();
    out.sort();
    out.dedup();
    out
}

fn yaml_docs(text: &str) -> Vec<Value> {
    serde_yaml::Deserializer::from_str(text)
        .filter_map(|d| serde::Deserialize::deserialize(d).ok())
        .collect()
}

/// A lockfile named in a cache key or its file list.
fn names_lockfile(text: &str) -> bool {
    re!(r"(?i)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|poetry\.lock|uv\.lock|pdm\.lock|Pipfile\.lock|requirements[^\s'\x22|]*\.txt|Cargo\.lock|go\.sum|Gemfile\.lock|composer\.lock|packages\.lock\.json|gradle\.lockfile|\*\.lock\b|\.lock['\x22]?$)")
        .is_match(text)
}

/// Is this cache a *dependency* cache? CB-DEP-CI-004 is about those; a
/// compiler cache (ccache), a dataset or a build output is not. Paths decide
/// when there are any; a key derived from a lockfile settles it too; with
/// neither, the cache is kept — better judged than silently skipped.
fn dependency_cache(paths: &str, key: &str) -> bool {
    paths.trim().is_empty()
        || names_lockfile(key)
        || re!(r"(?i)node_modules|\.npm\b|pnpm-store|\.yarn|yarn[-_]cache|\.cache/(pip|pypoetry|uv|yarn|pnpm|go-build|composer)|pip[-_]cache|\.venv|\bvenv\b|site-packages|\bvendor\b|\.m2\b|\.gradle\b|\.ivy2|\.sbt\b|\.cargo\b|\btarget\b|\.go\b|pkg/mod|\.nuget|\.bundle\b|\bgems\b|\.composer|\.pub-cache|\bdeps\b|_build\b|\.stack\b|\.cabal\b|\brenv\b|\.conan\b|vcpkg")
            .is_match(paths)
}

// ------------------------------------------------------ GitHub Actions ----

fn gha(ci: Ci, f: &TextFile, p: &mut Pipelines) -> bool {
    let Ok(doc) = serde_yaml::from_str::<Value>(&f.text) else { return false };
    let workflow_secret = dump(doc.get("env")).contains("secrets.");
    let pr_target = dump(doc.get("on")).contains("pull_request_target");
    let Some(jobs) = doc.get("jobs").and_then(Value::as_mapping) else { return true };
    for (name, job) in jobs {
        let job_name = scalar(name).unwrap_or_default();
        let job_secret = workflow_secret || dump(job.get("env")).contains("secrets.");
        for step in job.get("steps").and_then(Value::as_sequence).into_iter().flatten() {
            let run = step.get("run").and_then(scalar).unwrap_or_default();
            if let Some(line) = first_install(run.lines()) {
                let step_secret = dump(step.get("env")).contains("secrets.");
                p.installs.push(Install {
                    ci,
                    file: f.rel.clone(),
                    job: job_name.clone(),
                    step: label(step.get("name").and_then(scalar), line),
                    exposure: if step_secret {
                        Some("secrets in the step env".into())
                    } else if job_secret {
                        Some("secrets in the job/workflow env".into())
                    } else {
                        None
                    },
                });
            }
            let uses = step.get("uses").and_then(scalar).unwrap_or_default();
            let with = step.get("with");
            let untrusted = pr_target.then(|| {
                "restores a cache on pull_request_target — untrusted code shares the base branch's cache".to_string()
            });
            if uses.starts_with("actions/cache") {
                let key = with.and_then(|w| w.get("key")).and_then(scalar).unwrap_or_default();
                let paths = with.and_then(|w| w.get("path")).and_then(scalar).unwrap_or_default();
                if !dependency_cache(&paths, &key) {
                    continue;
                }
                let problem = untrusted.or_else(|| {
                    (!(key.contains("hashFiles(") && names_lockfile(&key)))
                        .then(|| format!("cache key `{}` is not a hash of the lockfile", short(&key)))
                });
                p.caches.push(Cache { ci, file: f.rel.clone(), job: job_name.clone(), problem, detail: format!("cache keyed on {}", short(&key)) });
            } else if uses.starts_with("actions/setup-") && with.and_then(|w| w.get("cache")).is_some() {
                p.caches.push(Cache {
                    ci,
                    file: f.rel.clone(),
                    job: job_name.clone(),
                    problem: untrusted,
                    detail: format!("uses {} cache (keyed on the lockfile)", uses.split('@').next().unwrap_or(&uses)),
                });
            }
        }
    }
    true
}

// ----------------------------------------------------------------- GitLab ----

const GITLAB_KEYWORDS: &[&str] = &[
    "stages", "variables", "default", "include", "workflow", "image", "services", "cache", "before_script",
    "after_script", "spec",
];

fn gitlab(f: &TextFile, p: &mut Pipelines) -> bool {
    let docs = yaml_docs(&f.text);
    if docs.is_empty() {
        return false;
    }
    for doc in &docs {
        let Some(map) = doc.as_mapping() else { continue };
        let default = map.get("default");
        let default_before = script_lines(default.and_then(|d| d.get("before_script")).or_else(|| map.get("before_script")));
        if let Some(c) = default.and_then(|d| d.get("cache")).or_else(|| map.get("cache")) {
            gitlab_cache(f, "default", c, p);
        }
        for (k, job) in map {
            let Some(name) = scalar(k) else { continue };
            if GITLAB_KEYWORDS.contains(&name.as_str()) || !job.is_mapping() {
                continue;
            }
            let before = job.get("before_script").map(|b| script_lines(Some(b))).unwrap_or_else(|| default_before.clone());
            let lines: Vec<String> = before.into_iter().chain(script_lines(job.get("script"))).collect();
            if let Some(line) = first_install(lines.iter().map(String::as_str)) {
                p.installs.push(Install {
                    ci: Ci::GitLab,
                    file: f.rel.clone(),
                    job: name.clone(),
                    step: short(line),
                    exposure: gitlab_exposure(job),
                });
            }
            if let Some(c) = job.get("cache") {
                gitlab_cache(f, &name, c, p);
            }
        }
    }
    true
}

fn gitlab_exposure(job: &Value) -> Option<String> {
    if job.get("secrets").is_some() {
        return Some("`secrets:` from an external secret manager".into());
    }
    if job.get("id_tokens").is_some() {
        return Some("OIDC `id_tokens`".into());
    }
    if let Some(env) = job.get("environment") {
        let name = scalar(env).or_else(|| env.get("name").and_then(scalar)).unwrap_or_default();
        return Some(format!("deployment environment `{name}` (its scoped variables)"));
    }
    let refs = secret_refs(&dump(job.get("variables")));
    (!refs.is_empty()).then(|| format!("job variables pulling in {}", refs.iter().map(|r| format!("${r}")).collect::<Vec<_>>().join(", ")))
}

fn gitlab_cache(f: &TextFile, job: &str, c: &Value, p: &mut Pipelines) {
    let entries: Vec<&Value> = match c {
        Value::Sequence(s) => s.iter().collect(),
        other => vec![other],
    };
    for e in entries {
        // `cache: {}` / `cache: []` turns caching off for the job.
        if e.as_mapping().is_some_and(|m| m.is_empty()) {
            continue;
        }
        let key = e.get("key");
        let key_text = dump(key);
        if !dependency_cache(&dump(e.get("paths")), &key_text) {
            continue;
        }
        let (problem, detail) = match key {
            Some(k) if k.get("files").is_some() => {
                let files = dump(k.get("files")).replace('\n', " ");
                if names_lockfile(&files) {
                    (None, format!("cache keyed on files {}", short(&files)))
                } else {
                    (Some(format!("cache key files {} name no lockfile", short(&files))), String::new())
                }
            }
            Some(k) => {
                let k = scalar(k).unwrap_or_default();
                (Some(format!("cache key `{k}` is not derived from the lockfile — use `key: files: [<lockfile>]`")), String::new())
            }
            None => (Some("cache has no key: one cache shared by every branch and job".into()), String::new()),
        };
        p.caches.push(Cache { ci: Ci::GitLab, file: f.rel.clone(), job: job.to_string(), problem, detail });
    }
}

// ----------------------------------------------------------- Azure Pipelines ----

fn azure(f: &TextFile, p: &mut Pipelines) -> bool {
    let Ok(doc) = serde_yaml::from_str::<Value>(&f.text) else { return false };
    azure_walk(&doc, "pipeline", f, p);
    true
}

fn azure_walk(v: &Value, job: &str, f: &TextFile, p: &mut Pipelines) {
    match v {
        Value::Mapping(m) => {
            let name = m
                .get("job")
                .or_else(|| m.get("deployment"))
                .and_then(scalar)
                .unwrap_or_else(|| job.to_string());
            if let Some(steps) = m.get("steps").and_then(Value::as_sequence) {
                for s in steps {
                    azure_step(s, &name, f, p);
                }
            }
            for (k, val) in m {
                if k.as_str() != Some("steps") {
                    azure_walk(val, &name, f, p);
                }
            }
        }
        Value::Sequence(seq) => seq.iter().for_each(|x| azure_walk(x, job, f, p)),
        _ => {}
    }
}

fn azure_step(s: &Value, job: &str, f: &TextFile, p: &mut Pipelines) {
    let task = s.get("task").and_then(scalar).unwrap_or_default();
    let inputs = s.get("inputs");
    let input = |k: &str| inputs.and_then(|i| i.get(k)).and_then(scalar).unwrap_or_default();
    let script = ["script", "bash", "pwsh", "powershell"].iter().find_map(|k| s.get(*k).and_then(scalar)).unwrap_or_default();
    let task_install = (task.starts_with("Npm@") && matches!(input("command").as_str(), "install" | "ci" | ""))
        || (task.starts_with("DotNetCoreCLI@") && input("command") == "restore")
        || task.starts_with("NuGetCommand@") && input("command") == "restore";
    let install = first_install(script.lines()).map(str::to_string).or_else(|| task_install.then(|| task.clone()));
    if let Some(line) = install {
        let refs = secret_refs(&dump(s.get("env")));
        p.installs.push(Install {
            ci: Ci::Azure,
            file: f.rel.clone(),
            job: job.to_string(),
            step: label(s.get("displayName").and_then(scalar), &line),
            exposure: (!refs.is_empty()).then(|| format!("secret {} mapped into the step env", refs.iter().map(|r| format!("$({r})")).collect::<Vec<_>>().join(", "))),
        });
    }
    if task.starts_with("Cache@") && dependency_cache(&input("path"), &input("key")) {
        let key = input("key");
        let problem = (!names_lockfile(&key)).then(|| format!("Cache task key `{key}` names no lockfile"));
        p.caches.push(Cache { ci: Ci::Azure, file: f.rel.clone(), job: job.to_string(), problem, detail: format!("Cache task keyed on {}", short(&key)) });
    }
}

// -------------------------------------------------------------- CircleCI ----

fn circle(f: &TextFile, p: &mut Pipelines) -> bool {
    let Ok(doc) = serde_yaml::from_str::<Value>(&f.text) else { return false };
    // Which jobs run with a context, from every workflow that schedules them.
    let mut contexts: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for wf in doc.get("workflows").and_then(Value::as_mapping).into_iter().flat_map(|m| m.values()) {
        for j in wf.get("jobs").and_then(Value::as_sequence).into_iter().flatten() {
            let Some((name, cfg)) = j.as_mapping().and_then(|m| m.iter().next()) else { continue };
            let ctx: Vec<String> = match cfg.get("context") {
                Some(Value::Sequence(s)) => s.iter().filter_map(scalar).collect(),
                Some(v) => scalar(v).into_iter().collect(),
                None => Vec::new(),
            };
            if !ctx.is_empty() {
                contexts.entry(scalar(name).unwrap_or_default()).or_default().extend(ctx);
            }
        }
    }
    for (name, job) in doc.get("jobs").and_then(Value::as_mapping).into_iter().flatten() {
        let name = scalar(name).unwrap_or_default();
        let exposure = contexts.get(&name).map(|c| format!("context {} (its variables reach every step of the job)", c.join(", ")));
        for step in job.get("steps").and_then(Value::as_sequence).into_iter().flatten() {
            // `- node/install-packages` or `- node/install-packages: {…}`.
            let orb = scalar(step).or_else(|| step.as_mapping().and_then(|m| m.keys().next()).and_then(scalar)).unwrap_or_default();
            let run = step.get("run");
            let install = first_install(script_lines(run).iter().map(String::as_str))
                .map(str::to_string)
                .or_else(|| orb.ends_with("/install-packages").then(|| orb.clone()));
            if let Some(line) = install {
                p.installs.push(Install {
                    ci: Ci::Circle,
                    file: f.rel.clone(),
                    job: name.clone(),
                    step: label(run.and_then(|r| r.get("name")).and_then(scalar), &line),
                    exposure: exposure.clone(),
                });
            }
            if let Some(sc) = step.get("save_cache")
                && dependency_cache(&dump(sc.get("paths")), &sc.get("key").and_then(scalar).unwrap_or_default())
            {
                let key = sc.get("key").and_then(scalar).unwrap_or_default();
                let problem = (!(key.contains("checksum") && names_lockfile(&key)))
                    .then(|| format!("save_cache key `{key}` is not a checksum of the lockfile"));
                p.caches.push(Cache { ci: Ci::Circle, file: f.rel.clone(), job: name.clone(), problem, detail: format!("save_cache keyed on {}", short(&key)) });
            }
        }
    }
    true
}

// --------------------------------------------------------- Bitbucket ----

const BITBUCKET_PREDEFINED: &[&str] = &["node", "pip", "composer", "maven", "gradle", "dotnetcore", "sbt", "ivy2", "yarn"];

fn bitbucket(f: &TextFile, p: &mut Pipelines) -> bool {
    let Ok(doc) = serde_yaml::from_str::<Value>(&f.text) else { return false };
    let custom = doc.get("definitions").and_then(|d| d.get("caches")).and_then(Value::as_mapping).cloned().unwrap_or_default();
    let mut steps = Vec::new();
    collect_key(doc.get("pipelines"), "step", &mut steps);
    for s in steps {
        let name = s.get("name").and_then(scalar).unwrap_or_else(|| "step".into());
        let lines = script_lines(s.get("script"));
        if let Some(line) = first_install(lines.iter().map(String::as_str)) {
            let exposure = s
                .get("deployment")
                .and_then(scalar)
                .map(|d| format!("deployment `{d}` (its variables)"))
                .or_else(|| (s.get("oidc").and_then(Value::as_bool) == Some(true)).then(|| "an OIDC token".to_string()));
            p.installs.push(Install { ci: Ci::Bitbucket, file: f.rel.clone(), job: name.clone(), step: short(line), exposure });
        }
        for c in s.get("caches").and_then(Value::as_sequence).into_iter().flatten().filter_map(scalar) {
            if c == "docker" {
                continue;
            }
            let def = custom.get(c.as_str());
            if let Some(d) = def {
                let path = d.get("path").and_then(scalar).or_else(|| scalar(d)).unwrap_or_default();
                if !dependency_cache(&path, &dump(d.get("key"))) {
                    continue;
                }
            }
            let problem = match def {
                Some(d) if d.get("key").and_then(|k| k.get("files")).is_some() => None,
                Some(_) => Some(format!("custom cache `{c}` has no `key: files:` — it is not keyed on the lockfile")),
                None if BITBUCKET_PREDEFINED.contains(&c.as_str()) => {
                    Some(format!("predefined `{c}` cache is not keyed on the lockfile — define one with `key: files: [<lockfile>]`"))
                }
                None => Some(format!("cache `{c}` is not defined with a lockfile key")),
            };
            p.caches.push(Cache { ci: Ci::Bitbucket, file: f.rel.clone(), job: name.clone(), problem, detail: format!("cache `{c}` keyed on the lockfile") });
        }
    }
    true
}

/// Every value under `key`, at any depth.
fn collect_key<'a>(v: Option<&'a Value>, key: &str, out: &mut Vec<&'a Value>) {
    match v {
        Some(Value::Mapping(m)) => {
            for (k, val) in m {
                if k.as_str() == Some(key) {
                    out.push(val);
                } else {
                    collect_key(Some(val), key, out);
                }
            }
        }
        Some(Value::Sequence(s)) => s.iter().for_each(|x| collect_key(Some(x), key, out)),
        _ => {}
    }
}

// ------------------------------------------------- Drone / Woodpecker ----

fn drone(ci: Ci, f: &TextFile, p: &mut Pipelines) -> bool {
    let docs = yaml_docs(&f.text);
    if docs.is_empty() {
        return false;
    }
    for doc in &docs {
        let pipeline = doc.get("name").and_then(scalar).unwrap_or_else(|| "pipeline".into());
        // A list of named steps (Drone, Woodpecker ≥ 2) or a map of them.
        let steps: Vec<(String, &Value)> = match doc.get("steps").or_else(|| doc.get("pipeline")) {
            Some(Value::Sequence(s)) => s.iter().map(|x| (x.get("name").and_then(scalar).unwrap_or_default(), x)).collect(),
            Some(Value::Mapping(m)) => m.iter().map(|(k, x)| (scalar(k).unwrap_or_default(), x)).collect(),
            _ => Vec::new(),
        };
        for (name, s) in steps {
            let lines = script_lines(s.get("commands"));
            if let Some(line) = first_install(lines.iter().map(String::as_str)) {
                let env = dump(s.get("environment"));
                let from_secret: Vec<String> = s
                    .get("environment")
                    .and_then(Value::as_mapping)
                    .map(|m| m.iter().filter(|(_, v)| v.get("from_secret").is_some()).filter_map(|(k, _)| scalar(k)).collect())
                    .unwrap_or_default();
                let exposure = if !from_secret.is_empty() {
                    Some(format!("from_secret {}", from_secret.join(", ")))
                } else if env.contains("from_secret") {
                    Some("from_secret in the step environment".into())
                } else {
                    s.get("secrets").map(|x| format!("secrets: {}", dump(Some(x)).trim().replace('\n', " ")))
                };
                p.installs.push(Install { ci, file: f.rel.clone(), job: pipeline.clone(), step: label(Some(name.clone()), line), exposure });
            }
            let image = s.get("image").and_then(scalar).unwrap_or_default();
            let mounts = dump(s.get("settings").and_then(|st| st.get("mount")));
            if image.contains("cache") && dependency_cache(&mounts, &dump(s.get("settings"))) {
                let key = s
                    .get("settings")
                    .and_then(|st| st.get("cache_key").or_else(|| st.get("key")))
                    .and_then(scalar)
                    .unwrap_or_default();
                let problem = (!(key.contains("checksum") && names_lockfile(&key)))
                    .then(|| format!("cache step `{name}` key `{key}` is not a checksum of the lockfile"));
                p.caches.push(Cache { ci, file: f.rel.clone(), job: pipeline.clone(), problem, detail: format!("cache step `{name}` keyed on {}", short(&key)) });
            }
        }
    }
    true
}

// --------------------------------------------------------------- Jenkins ----

/// The `{ … }` block opening at `open`, as a byte range. Strings are not
/// tracked: a brace inside a quoted string can shift it, which only widens or
/// narrows a heuristic.
fn brace_block(text: &str, open: usize) -> Option<(usize, usize)> {
    let mut depth = 0usize;
    for (i, ch) in text[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some((open, open + i));
                }
            }
            _ => {}
        }
    }
    None
}

/// Blocks introduced by `pattern` (`environment`, `withCredentials(…)`, `stage(…)`).
fn blocks(text: &str, pattern: &regex::Regex) -> Vec<(usize, usize)> {
    pattern
        .find_iter(text)
        .filter_map(|m| text[m.end()..].find('{').map(|i| m.end() + i))
        .filter_map(|open| brace_block(text, open))
        .collect()
}

fn jenkins(f: &TextFile, p: &mut Pipelines) {
    let text: String = f.text.lines().map(|l| if l.trim_start().starts_with("//") { "" } else { l }).collect::<Vec<_>>().join("\n");
    let stages_at = re!(r"\bstages\s*\{").find(&text).map_or(usize::MAX, |m| m.start());
    let global_creds = blocks(&text, re!(r"\benvironment\s*"))
        .into_iter()
        .any(|(a, b)| a < stages_at && text[a..b].contains("credentials("));
    let with_creds = blocks(&text, re!(r"\bwithCredentials\s*\("));
    let stages: Vec<(usize, usize, String)> = re!(r#"\bstage\s*\(\s*['"]([^'"]+)['"]\s*\)"#)
        .captures_iter(&text)
        .filter_map(|c| {
            let end = c.get(0)?.end();
            let open = end + text[end..].find('{')?;
            let (a, b) = brace_block(&text, open)?;
            Some((a, b, c[1].to_string()))
        })
        .collect();
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let at = offset;
        offset += line.len();
        if !is_install_command(line) {
            continue;
        }
        // The innermost stage holding the line.
        let stage = stages.iter().filter(|(a, b, _)| *a <= at && at <= *b).min_by_key(|(a, b, _)| b - a);
        let exposure = if with_creds.iter().any(|(a, b)| *a <= at && at <= *b) {
            Some("withCredentials around the install".to_string())
        } else if stage.is_some_and(|(a, b, _)| {
            let s = &text[*a..*b];
            re!(r"\benvironment\s*\{[^}]*credentials\(").is_match(s)
        }) {
            Some("credentials() in the stage environment".to_string())
        } else if global_creds {
            Some("credentials() in the pipeline-level environment, which every stage inherits".to_string())
        } else {
            None
        };
        p.installs.push(Install {
            ci: Ci::Jenkins,
            file: f.rel.clone(),
            job: stage.map_or_else(|| "pipeline".to_string(), |s| s.2.clone()),
            step: short(line.trim().trim_start_matches("sh").trim().trim_matches(['\'', '"', '(', ')'])),
            exposure,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_one(rel: &str, body: &str) -> Pipelines {
        let mut p = Pipelines::default();
        let f = TextFile { rel: rel.into(), text: body.into() };
        let ci = ci_platform(rel).unwrap();
        let parsed = match ci {
            Ci::GithubActions | Ci::Forgejo => gha(ci, &f, &mut p),
            Ci::GitLab => gitlab(&f, &mut p),
            Ci::Azure => azure(&f, &mut p),
            Ci::Circle => circle(&f, &mut p),
            Ci::Bitbucket => bitbucket(&f, &mut p),
            Ci::Drone | Ci::Woodpecker => drone(ci, &f, &mut p),
            Ci::Jenkins => {
                jenkins(&f, &mut p);
                true
            }
            _ => false,
        };
        assert!(parsed, "{rel} did not parse");
        p
    }

    fn exposures(p: &Pipelines) -> Vec<Option<String>> {
        p.installs.iter().map(|i| i.exposure.clone()).collect()
    }

    #[test]
    fn gitlab_jobs_secrets_and_caches() {
        let p = read_one(
            ".gitlab-ci.yml",
            "stages: [test, deploy]\n\
             test:\n  cache:\n    key:\n      files: [package-lock.json]\n    paths: [node_modules]\n  script:\n    - npm ci\n    - npm test\n\
             deploy:\n  environment: production\n  cache:\n    key: $CI_COMMIT_REF_SLUG\n  script:\n    - npm ci\n    - ./deploy.sh\n\
             vault:\n  secrets:\n    TOKEN:\n      vault: ci/token@kv\n  script: [pip install -r requirements.txt]\n",
        );
        let e = exposures(&p);
        assert_eq!(e.len(), 3);
        assert!(e[0].is_none());
        assert!(e[1].as_deref().unwrap().contains("production"));
        assert!(e[2].as_deref().unwrap().contains("secrets:"));
        assert_eq!(p.caches.len(), 2);
        assert!(p.caches[0].problem.is_none());
        assert!(p.caches[1].problem.is_some());
    }

    #[test]
    fn azure_steps_and_cache_task() {
        let p = read_one(
            "azure-pipelines.yml",
            "stages:\n- stage: build\n  jobs:\n  - job: deps\n    steps:\n    - task: Cache@2\n      inputs:\n        key: 'npm | \"$(Agent.OS)\" | package-lock.json'\n        path: $(npm_config_cache)\n    - script: npm ci\n      env:\n        NPM_TOKEN: $(npmToken)\n    - task: Npm@1\n      inputs:\n        command: ci\n",
        );
        let e = exposures(&p);
        assert_eq!(e.len(), 2, "script + Npm@1 task");
        assert!(e[0].as_deref().unwrap().contains("npmToken"));
        assert!(e[1].is_none());
        assert!(p.caches[0].problem.is_none(), "{:?}", p.caches[0].problem);
        assert_eq!(p.installs[0].job, "deps");
    }

    #[test]
    fn circleci_contexts_and_checksums() {
        let p = read_one(
            ".circleci/config.yml",
            "version: 2.1\njobs:\n  build:\n    steps:\n      - checkout\n      - restore_cache:\n          keys:\n            - deps-{{ checksum \"package-lock.json\" }}\n      - run: npm ci\n      - save_cache:\n          key: deps-{{ checksum \"package-lock.json\" }}\n          paths: [node_modules]\n  release:\n    steps:\n      - node/install-packages\n      - save_cache:\n          key: deps-v1\n          paths: [node_modules]\nworkflows:\n  main:\n    jobs:\n      - build\n      - release:\n          context: npm-publish\n",
        );
        let e = exposures(&p);
        assert!(e[0].is_none());
        assert!(e[1].as_deref().unwrap().contains("npm-publish"));
        assert!(p.caches[0].problem.is_none());
        assert!(p.caches[1].problem.is_some());
    }

    #[test]
    fn bitbucket_deployments_and_caches() {
        let p = read_one(
            "bitbucket-pipelines.yml",
            "definitions:\n  caches:\n    npm-lock:\n      key:\n        files: [package-lock.json]\n      path: node_modules\npipelines:\n  default:\n    - step:\n        name: test\n        caches: [npm-lock]\n        script: [npm ci, npm test]\n  branches:\n    main:\n      - step:\n          name: publish\n          deployment: production\n          caches: [node]\n          script: [npm ci, npm publish]\n",
        );
        let e = exposures(&p);
        assert!(e[0].is_none());
        assert!(e[1].as_deref().unwrap().contains("production"));
        assert!(p.caches[0].problem.is_none());
        assert!(p.caches[1].problem.as_deref().unwrap().contains("predefined"));
    }

    #[test]
    fn drone_and_woodpecker_from_secret() {
        let p = read_one(
            ".drone.yml",
            "kind: pipeline\nname: default\nsteps:\n- name: deps\n  image: node:20\n  commands: [npm ci]\n- name: publish\n  image: node:20\n  environment:\n    NPM_TOKEN:\n      from_secret: npm_token\n  commands: [npm ci, npm publish]\n- name: cache\n  image: meltwater/drone-cache\n  settings:\n    cache_key: '{{ checksum \"package-lock.json\" }}'\n",
        );
        let e = exposures(&p);
        assert!(e[0].is_none());
        assert!(e[1].as_deref().unwrap().contains("NPM_TOKEN"));
        assert!(p.caches[0].problem.is_none());
        let w = read_one(".woodpecker.yml", "steps:\n  build:\n    image: node\n    secrets: [npm_token]\n    commands:\n      - npm ci\n");
        assert!(exposures(&w)[0].as_deref().unwrap().contains("npm_token"));
    }

    #[test]
    fn jenkins_credentials_scopes() {
        let global = read_one(
            "Jenkinsfile",
            "pipeline {\n  agent any\n  environment {\n    NPM_TOKEN = credentials('npm')\n  }\n  stages {\n    stage('Install') {\n      steps { sh 'npm ci' }\n    }\n  }\n}\n",
        );
        assert!(exposures(&global)[0].as_deref().unwrap().contains("pipeline-level"));
        assert_eq!(global.installs[0].job, "Install");
        let scoped = read_one(
            "Jenkinsfile",
            "pipeline {\n  stages {\n    stage('Install') {\n      steps { sh 'npm ci' }\n    }\n    stage('Publish') {\n      steps {\n        withCredentials([string(credentialsId: 'npm', variable: 'T')]) {\n          sh 'npm ci && npm publish'\n        }\n      }\n    }\n  }\n}\n",
        );
        let e = exposures(&scoped);
        assert!(e[0].is_none(), "{e:?}");
        assert!(e[1].as_deref().unwrap().contains("withCredentials"));
    }

    #[test]
    fn only_dependency_caches_are_judged() {
        let p = read_one(
            ".github/workflows/ci.yml",
            "on: [push]\njobs:\n  t:\n    steps:\n      - uses: actions/cache@v4\n        with:\n          path: ~/.ccache\n          key: ccache-${{ hashFiles('**/*.pyx') }}\n      - uses: actions/cache@v4\n        with:\n          path: ~/.cache/pip\n          key: pip-${{ hashFiles('pyproject.toml') }}\n      - uses: actions/cache@v4\n        with:\n          path: node_modules\n          key: npm-${{ hashFiles('package-lock.json') }}\n",
        );
        assert_eq!(p.caches.len(), 2, "the ccache is not a dependency cache");
        assert!(p.caches[0].problem.as_deref().unwrap().contains("not a hash of the lockfile"));
        assert!(p.caches[1].problem.is_none());
        let g = read_one(".gitlab-ci.yml", "docs:\n  cache: {}\n  script: [make docs]\nbuild:\n  cache:\n    key: build-$CI_COMMIT_SHA\n    paths: [public/]\n  script: [make]\n");
        assert!(g.caches.is_empty(), "disabled cache and build output are not judged");
    }

    #[test]
    fn github_actions_still_reads_env_and_caches() {
        let p = read_one(
            ".github/workflows/ci.yml",
            "on: [push]\njobs:\n  t:\n    env:\n      TOKEN: ${{ secrets.NPM_TOKEN }}\n    steps:\n      - uses: actions/cache@v4\n        with:\n          key: deps\n      - run: npm ci\n",
        );
        assert!(exposures(&p)[0].as_deref().unwrap().contains("job/workflow"));
        assert!(p.caches[0].problem.is_some());
    }
}
