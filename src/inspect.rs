//! `postmortem system inspect <pkg>` — focus on one installed package.
//!
//! Basic mode renders just that package's dependency subtree (not the whole
//! machine). `--deep` is a heavyweight audit: it resolves every dependency to
//! its source repo, **git-clones the actual code**, runs the complete detection
//! suite (`scan` analyzers + `tree --online` reputation + `--vulns`) over it, and
//! writes a Markdown report — then deletes the cloned source. This reuses the
//! full static analysis on real upstream code rather than metadata alone.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Result, bail};
use owo_colors::OwoColorize;

use crate::model::{DepRef, Dependency, Severity};
use crate::resolve::{RepoRef, Resolution};
use crate::{analyze, detect, gochi, resolve, settings, system, tree, ui};

/// Cap on repos cloned in `--deep`, to bound time/disk on huge trees.
const MAX_CLONES: usize = 60;

pub fn run(args: &crate::cli::InspectArgs) -> Result<()> {
    let ui = ui::Ui::new(!args.no_progress);

    // Read the installed inventory once (via whichever backend is available).
    let Some(backend) =
        system::detect().into_iter().find(|m| m.available && m.implemented).map(|m| m.name)
    else {
        bail!("no supported system package manager found");
    };
    let loader = gochi::Loader::spinner("gochi reading installed packages", ui.animating());
    let inv = match system::inventory(backend, system::Opts::default()) {
        Ok(inv) => {
            loader.finish(gochi::Mood::Happy, format!("read {}", inv.summary));
            inv
        }
        Err(e) => {
            loader.finish(gochi::Mood::Bad, "couldn't read packages");
            return Err(e);
        }
    };

    // The package's dependency subtree (itself + everything it pulls in).
    let sub = subtree_deps(&args.package, &inv.deps);
    if sub.is_empty() {
        bail!("'{}' is not installed, or has no dependency record", args.package);
    }

    if !args.deep {
        return render_focused(&args.package, &sub, &inv);
    }
    deep(args, &sub, &ui)
}

/// Basic mode: the offline subtree with the same signals/scoring as `system`.
fn render_focused(pkg: &str, sub: &[Dependency], inv: &system::Inventory) -> Result<()> {
    let eco = sub.first().map(|d| d.ecosystem.as_str()).unwrap_or("system").to_string();
    let mut forest = tree::build_focused(pkg, &[eco], sub, None, pkg);
    system::annotate(&mut forest, &inv.signals);
    tree::score(&mut forest);
    tree::render(&forest);
    Ok(())
}

// --- deep inspection ----------------------------------------------------------

fn deep(args: &crate::cli::InspectArgs, sub: &[Dependency], ui: &ui::Ui) -> Result<()> {
    if !git_available() {
        bail!("`git` is required for --deep but was not found on PATH");
    }
    if !confirm(&args.package, sub.len(), args.yes)? {
        eprintln!("aborted, no changes made.");
        return Ok(());
    }

    // 1. Resolve every dependency to its source repo + reputation (online).
    let mut settings = settings::Settings::load_or_warn();
    let tokens = resolve::Tokens {
        github: settings.resolve_github_token()?,
        gitlab: settings.gitlab_token(),
        codeberg: settings.codeberg_token(),
    };
    let resolver = resolve::Resolver::with_network(tokens, settings.tree.clone(), &settings.network);
    let resolutions = resolver.resolve_all(sub, ui);

    // 2. Stage a temp workspace under ~/.postmortem/inspect/.
    let work = workspace(&args.package)?;
    ui.note(format!("cloning sources into {}", work.display()));

    // 3. Clone each distinct resolved repo (shallow), capped.
    let mut targets: Vec<(String, RepoRef)> = Vec::new();
    let mut seen_repos = HashSet::new();
    for dep in sub {
        let key = (dep.name.clone(), dep.version.clone());
        if let Some(repo) = resolutions.get(&key).and_then(|r| r.repo.clone())
            && seen_repos.insert(repo.slug())
        {
            targets.push((dep.name.clone(), repo));
        }
    }
    let truncated = targets.len().saturating_sub(MAX_CLONES);
    targets.truncate(MAX_CLONES);
    if truncated > 0 {
        ui.note(format!("capping at {MAX_CLONES} repos ({truncated} more not cloned)"));
    }

    let bar = gochi::Loader::start(targets.len() as u64, ui.animating());
    bar.step("cloning + analyzing sources");
    let mut analyzed: Vec<RepoAudit> = Vec::new();
    let vuln_ctx = (
        crate::vuln::agent(&settings.network),
        crate::cache::Cache::open(),
        settings.vuln_token(),
        crate::vuln::scan_url(&settings.network),
    );
    for (name, repo) in &targets {
        bar.step(format!("git clone {}", repo.slug()));
        let dest = work.join(sanitize(&repo.slug()));
        if git_clone(&clone_url(repo), &dest) {
            analyzed.push(audit_clone(name, repo, &dest, &vuln_ctx, args.allow_test_files));
        } else {
            analyzed.push(RepoAudit::clone_failed(name, repo));
        }
        bar.inc();
    }
    let findings_total: usize = analyzed.iter().map(|a| a.findings.len()).sum();
    bar.finish(
        if findings_total > 0 { gochi::Mood::Bad } else { gochi::Mood::Happy },
        format!("analyzed {} repo(s), {findings_total} finding(s)", analyzed.len()),
    );

    // 4. Write the Markdown report, then delete the cloned source.
    let report = render_report(&args.package, sub, &resolutions, &analyzed, truncated);
    let path = report_path(&args.package);
    std::fs::write(&path, report)?;
    let _ = std::fs::remove_dir_all(&work); // sources were transient

    println!(
        "\n{} deep report written to {}",
        "✓".green(),
        path.display().to_string().bold()
    );
    Ok(())
}

/// Per-repo audit result gathered during the deep pass.
struct RepoAudit {
    dep: String,
    slug: String,
    cloned: bool,
    findings: Vec<crate::model::Finding>,
    vulns: usize,
}

impl RepoAudit {
    fn clone_failed(dep: &str, repo: &RepoRef) -> Self {
        RepoAudit { dep: dep.into(), slug: repo.slug(), cloned: false, findings: vec![], vulns: 0 }
    }
}

/// Run the full content-analyzer suite over the cloned repo's **entire** source
/// tree (every language, not gated by ecosystem detection), plus a best-effort
/// vuln scan of any lockfile it commits.
fn audit_clone(
    dep: &str,
    repo: &RepoRef,
    dir: &Path,
    vuln_ctx: &(crate::settings::Agents, crate::cache::Cache, Option<String>, String),
    allow_test_files: bool,
) -> RepoAudit {
    // Rewrite finding locations relative to the clone (the absolute temp path is
    // meaningless once the workspace is deleted).
    let prefix = format!("{}/", dir.display());
    let findings: Vec<crate::model::Finding> = analyze::scan_source_tree(dir)
        .into_iter()
        .map(|mut f| {
            if let Some(loc) = &f.location {
                f.location = Some(loc.strip_prefix(&prefix).unwrap_or(loc).to_string());
            }
            f
        })
        .collect();
    // Drop IOC noise from test/fixture trees unless asked to keep it. Locations
    // are already relative to the clone, so the base is empty.
    let findings = analyze::drop_test_iocs(findings, allow_test_files, Path::new(""));

    // --vulns: scan any lockfile the upstream repo commits (best-effort).
    let (agent, cache, token, scan_url) = vuln_ctx;
    let mut vulns = 0;
    for d in &detect::detect(dir).unwrap_or_default() {
        if let Some((lock, fmt)) = crate::mlab_target(d)
            && let Ok(v) = crate::vuln::scan(agent, cache, token.as_deref(), lock, fmt, scan_url)
        {
            vulns += v.iter().map(|p| p.vulns.len()).sum::<usize>();
        }
    }
    RepoAudit { dep: dep.into(), slug: repo.slug(), cloned: true, findings, vulns }
}

// --- report -------------------------------------------------------------------

fn render_report(
    pkg: &str,
    sub: &[Dependency],
    resolutions: &HashMap<DepRef, Resolution>,
    audits: &[RepoAudit],
    truncated: usize,
) -> String {
    use std::fmt::Write;
    let mut md = String::new();
    let flagged = audits.iter().filter(|a| !a.findings.is_empty() || a.vulns > 0).count();

    let _ = writeln!(md, "# postmortem deep inspection of `{pkg}`\n");
    let _ = writeln!(
        md,
        "{} dependencies · {} repos analyzed · **{flagged} with findings**{}\n",
        sub.len(),
        audits.iter().filter(|a| a.cloned).count(),
        if truncated > 0 { format!(" · {truncated} repos not cloned (cap)") } else { String::new() },
    );

    // Reputation summary (tree --online).
    let _ = writeln!(md, "## Source-repo reputation\n");
    let _ = writeln!(md, "| package | repo | stars | risk | signals |");
    let _ = writeln!(md, "|---|---|---:|---:|---|");
    let mut rows: Vec<&Dependency> = sub.iter().collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    for d in rows {
        if let Some(r) = resolutions.get(&(d.name.clone(), d.version.clone())) {
            let repo = r.repo.as_ref().map(|x| x.slug()).unwrap_or_else(|| "-".into());
            let stars = r.stats.as_ref().map(|s| s.stars.to_string()).unwrap_or_else(|| "-".into());
            let sig = if r.signals.is_empty() { "-".into() } else { r.signals.join(", ") };
            let _ = writeln!(md, "| `{}` | {} | {} | {} | {} |", d.name, repo, stars, r.risk, sig);
        }
    }

    // Static analysis of the cloned source.
    let _ = writeln!(md, "\n## Static analysis (full source)\n");
    let mut with_findings: Vec<&RepoAudit> =
        audits.iter().filter(|a| !a.findings.is_empty() || a.vulns > 0).collect();
    with_findings.sort_by(|a, b| b.findings.len().cmp(&a.findings.len()));
    if with_findings.is_empty() {
        let _ = writeln!(md, "_No findings across the cloned sources._");
    }
    for a in with_findings {
        let _ = writeln!(md, "### `{}` ({})", a.dep, a.slug);
        if a.vulns > 0 {
            let _ = writeln!(md, "- **{} known vulnerabilit{}** (via vuln.mlab.sh)", a.vulns, if a.vulns == 1 { "y" } else { "ies" });
        }
        let mut fs: Vec<&crate::model::Finding> = a.findings.iter().collect();
        fs.sort_by(|x, y| y.severity.cmp(&x.severity));
        for f in fs.iter().take(50) {
            let loc = f.location.as_deref().map(|l| format!(" ({l})")).unwrap_or_default();
            // The matched value (IP / domain / URL / wallet), after the location.
            let val = f.evidence.as_deref().map(|e| format!(" [`{}`]", e.trim())).unwrap_or_default();
            let _ = writeln!(
                md,
                "- `{}` **{}**: {}{}{}",
                sev_label(f.severity),
                f.category.as_str(),
                f.detail,
                loc,
                val
            );
        }
        if a.findings.len() > 50 {
            let _ = writeln!(md, "- _…and {} more_", a.findings.len() - 50);
        }
        let _ = writeln!(md);
    }

    // Repos we couldn't clone.
    let failed: Vec<&RepoAudit> = audits.iter().filter(|a| !a.cloned).collect();
    if !failed.is_empty() {
        let _ = writeln!(md, "## Not analyzed (clone failed / private)\n");
        for a in failed {
            let _ = writeln!(md, "- `{}` ({})", a.dep, a.slug);
        }
    }
    md
}

fn sev_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

// --- helpers ------------------------------------------------------------------

/// The package + its full transitive dependency closure (BFS over child edges).
fn subtree_deps(pkg: &str, deps: &[Dependency]) -> Vec<Dependency> {
    let index: HashMap<DepRef, &Dependency> =
        deps.iter().map(|d| ((d.name.clone(), d.version.clone()), d)).collect();
    let mut children: HashMap<DepRef, Vec<DepRef>> = HashMap::new();
    for d in deps {
        for p in &d.parents {
            children.entry(p.clone()).or_default().push((d.name.clone(), d.version.clone()));
        }
    }
    let mut seen = HashSet::new();
    let mut queue: VecDeque<DepRef> = deps
        .iter()
        .filter(|d| d.name == pkg)
        .map(|d| (d.name.clone(), d.version.clone()))
        .collect();
    for k in &queue {
        seen.insert(k.clone());
    }
    let mut out = Vec::new();
    while let Some(k) = queue.pop_front() {
        if let Some(d) = index.get(&k) {
            out.push((*d).clone());
        }
        if let Some(kids) = children.get(&k) {
            for c in kids {
                if seen.insert(c.clone()) {
                    queue.push_back(c.clone());
                }
            }
        }
    }
    out
}

/// gochi warns that deep mode is heavy, and asks to proceed. `-y` bypasses; a
/// non-interactive run without `-y` declines (never blocks a script).
fn confirm(pkg: &str, deps: usize, yes: bool) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    eprintln!(
        "\n  {}  {}",
        gochi::Mood::Idle.paint(),
        format!("deep inspection of '{pkg}' ({deps} deps)").bold()
    );
    eprintln!(
        "      {}",
        "I'll clone every dependency's source and run the full detection suite over it."
            .dimmed()
    );
    eprintln!("      {}", "This can take a while and use network + disk.".dimmed());
    if !std::io::stdin().is_terminal() {
        eprintln!("      {}", "non-interactive, pass -y to proceed.".dimmed());
        return Ok(false);
    }
    eprint!("  proceed? [y/N]: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

/// `~/.postmortem/inspect/<pkg>-<pid>/` — a transient clone workspace.
fn workspace(pkg: &str) -> Result<PathBuf> {
    let base = settings::base_dir()
        .ok_or_else(|| anyhow::anyhow!("cannot determine $HOME for the workspace"))?;
    let dir = base.join("inspect").join(format!("{}-{}", sanitize(pkg), std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn report_path(pkg: &str) -> PathBuf {
    PathBuf::from(format!("postmortem-inspect-{}.md", sanitize(pkg)))
}

fn git_available() -> bool {
    Command::new("git").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
}

fn git_clone(url: &str, dest: &Path) -> bool {
    Command::new("git")
        .args(["clone", "--depth", "1", "--quiet", url])
        .arg(dest)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A clonable HTTPS URL for a resolved repo (`https://host/owner/repo.git`).
fn clone_url(repo: &RepoRef) -> String {
    format!("https://{}/{}.git", repo.host, repo.slug())
}

/// Collapse a slug/name into one filesystem-safe path segment.
fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Ecosystem;

    fn dep(name: &str, parents: &[&str]) -> Dependency {
        Dependency {
            name: name.into(),
            version: "1.0".into(),
            ecosystem: Ecosystem::Brew,
            scope: crate::model::Scope::Prod,
            licenses: Vec::new(),
            license_source: crate::model::LicenseSource::Unknown,
            direct: parents.is_empty(),
            resolved_url: None,
            integrity: None,
            parents: parents.iter().map(|p| (p.to_string(), "1.0".to_string())).collect(),
        }
    }

    #[test]
    fn subtree_is_the_transitive_closure() {
        // root → a → c ; root → b ; d is unrelated.
        let deps = vec![
            dep("root", &[]),
            dep("a", &["root"]),
            dep("b", &["root"]),
            dep("c", &["a"]),
            dep("d", &[]),
        ];
        let mut got: Vec<String> = subtree_deps("root", &deps).into_iter().map(|d| d.name).collect();
        got.sort();
        assert_eq!(got, vec!["a", "b", "c", "root"]);
        // A leaf's subtree is just itself.
        assert_eq!(subtree_deps("c", &deps).into_iter().map(|d| d.name).collect::<Vec<_>>(), vec!["c"]);
        // Unknown package → empty.
        assert!(subtree_deps("nope", &deps).is_empty());
    }

    #[test]
    fn clone_url_and_sanitize() {
        let repo = RepoRef { host: "github.com".into(), owner: "o".into(), name: "r".into() };
        assert_eq!(clone_url(&repo), "https://github.com/o/r.git");
        assert_eq!(sanitize("group/sub/proj"), "group_sub_proj");
    }
}
