mod analyze;
mod archsec;
mod audit;
mod cache;
mod cli;
mod config;
mod detect;
mod diff;
mod enrich;
mod gate;
mod gochi;
mod inspect;
mod model;
mod osv;
mod parsers;
mod report;
mod resolve;
mod sbom;
mod scope;
mod settings;
mod system;
mod tree;
mod typosquat;
mod why;
mod ui;
mod vuln;

use std::path::Path;

use anyhow::{Context, Result};
use clap::Parser;

fn main() -> Result<()> {
    match cli::Cli::parse().command {
        cli::Command::Scan(args) => run_scan(args),
        cli::Command::Tree(args) => run_tree(args),
        cli::Command::Diff(args) => run_diff(args),
        cli::Command::Sbom(args) => run_sbom(args),
        cli::Command::Why(args) => run_why(args),
        cli::Command::Audit(args) => run_audit(args),
        cli::Command::Cache(args) => run_cache(args),
        cli::Command::System(args) => run_system(args),
        cli::Command::Help => {
            print_overview();
            Ok(())
        }
    }
}

/// `postmortem cache <action>` — manage the `tree --online` cache.
fn run_cache(args: cli::CacheArgs) -> Result<()> {
    let cache = cache::Cache::open();
    match args.action {
        cli::CacheAction::Prune(p) => {
            let opts = cache::PruneOpts {
                older_than_days: p.older_than,
                stale_only: p.stale,
                dry_run: p.dry_run,
            };
            let report = cache.prune(opts);
            let where_ = cache
                .root()
                .map(|r| r.display().to_string())
                .unwrap_or_else(|| "(no cache)".into());
            let verb = if p.dry_run { "would remove" } else { "removed" };
            // Describe what the filters actually selected, so the count is never
            // ambiguous: "removed 0 entries" reads very differently depending on
            // whether the filter matched nothing or the cache was empty.
            let mut scope = Vec::new();
            if p.stale {
                scope.push("stale format".to_string());
            }
            match p.older_than {
                Some(d) => scope.push(format!("older than {d}d")),
                None if !p.stale => scope.push("all".into()),
                None => {}
            }
            gochi::say(
                gochi::Mood::Happy,
                format!(
                    "{verb} {} entr{} ({}, {}), kept {} — {where_}",
                    report.removed,
                    if report.removed == 1 { "y" } else { "ies" },
                    scope.join(" + "),
                    human_bytes(report.freed),
                    report.kept,
                ),
            );
        }
        cli::CacheAction::Path => {
            let Some(root) = cache.root() else {
                eprintln!("no cache directory (no $HOME)");
                std::process::exit(2);
            };
            // Bare path on stdout, nothing else — this is meant to be captured.
            println!("{}", root.display());
        }
        cli::CacheAction::Info => render_cache_info(&cache.stats()),
    }
    Ok(())
}

/// The `cache info` view: one line per namespace, then the totals.
fn render_cache_info(stats: &cache::CacheStats) {
    use owo_colors::OwoColorize;

    let where_ = stats
        .root
        .as_ref()
        .map(|r| r.display().to_string())
        .unwrap_or_else(|| "(no cache directory)".into());
    println!("{}  {}", "cache".bold(), where_.dimmed());
    println!("{}", format!("record format v{}", cache::FORMAT_VERSION).dimmed());

    if stats.namespaces.is_empty() {
        println!("\n  {}", "empty".dimmed());
        return;
    }

    println!(
        "\n  {:<14} {:>8}  {:>9}  {:>8}  {}",
        "NAMESPACE".bold(),
        "ENTRIES".bold(),
        "SIZE".bold(),
        "STALE".bold(),
        "NEWEST".bold()
    );
    for ns in &stats.namespaces {
        // Pad before colouring: ANSI escapes count toward a format width, so
        // `{:>8}` on an already-coloured string misaligns the column.
        let stale = if ns.stale > 0 { ns.stale.to_string() } else { "-".to_string() };
        let stale = format!("{stale:>8}");
        let stale =
            if ns.stale > 0 { stale.truecolor(255, 165, 0).to_string() } else { stale.dimmed().to_string() };
        println!(
            "  {:<14} {:>8}  {:>9}  {}  {}",
            ns.name,
            ns.entries,
            human_bytes(ns.bytes),
            stale,
            ns.newest.map(age_label).unwrap_or_else(|| "-".into()).dimmed(),
        );
    }

    println!(
        "\n  {} entries · {} · oldest {} · newest {}",
        stats.entries().bold(),
        human_bytes(stats.bytes()).bold(),
        stats.oldest().map(age_label).unwrap_or_else(|| "-".into()),
        stats.newest().map(age_label).unwrap_or_else(|| "-".into()),
    );

    if stats.stale() > 0 {
        println!(
            "\n{}",
            format!(
                "⚠ {} entr{} predate record format v{} — they are refetched as they are \
                 touched, or run `postmortem cache prune --stale` to sweep them now",
                stats.stale(),
                if stats.stale() == 1 { "y" } else { "ies" },
                cache::FORMAT_VERSION
            )
            .truecolor(255, 165, 0)
        );
    }
}

/// A coarse "how long ago" label for a unix timestamp.
fn age_label(secs: u64) -> String {
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let d = now.saturating_sub(secs);
    match d {
        0..=59 => "just now".into(),
        60..=3599 => format!("{}m ago", d / 60),
        3600..=86_399 => format!("{}h ago", d / 3600),
        _ => format!("{}d ago", d / 86_400),
    }
}

/// `postmortem diff <old> <new>` — resolve both projects offline and report the
/// added / removed / version-changed dependencies.
fn run_diff(args: cli::DiffArgs) -> Result<()> {
    let ui = ui::Ui::new(!args.no_progress);
    // Both sides are filtered identically — a scope-filtered diff of an
    // unfiltered baseline would report every dev package as "removed".
    let omit = cli::OmitSet::scopes(&args.omit);
    let resolve_deps = |path: &Path| -> Result<Vec<model::Dependency>> {
        let root = path
            .canonicalize()
            .with_context(|| format!("cannot resolve path {}", path.display()))?;
        match detect_and_parse(&root, &ui, &omit)? {
            Some((_, deps, _)) => Ok(deps),
            None => anyhow::bail!("no supported ecosystem detected at {}", root.display()),
        }
    };
    let old = resolve_deps(&args.old)?;
    let new = resolve_deps(&args.new)?;
    let report = diff::diff(&old, &new);
    diff::render(&report, &args.old.display().to_string(), &args.new.display().to_string());
    Ok(())
}

/// `postmortem sbom <path>` — resolve the project and emit a CycloneDX 1.5 SBOM.
fn run_sbom(args: cli::SbomArgs) -> Result<()> {
    let ui = ui::Ui::new(!args.no_progress);
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("cannot resolve path {}", args.path.display()))?;
    let Some((_, deps, _)) = detect_and_parse(&root, &ui, &cli::OmitSet::scopes(&args.omit))? else {
        anyhow::bail!("no supported ecosystem detected at {}", root.display());
    };
    let name = root.file_name().and_then(|s| s.to_str()).unwrap_or("project");
    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let bom = sbom::cyclonedx(name, &deps, &timestamp);
    let out = serde_json::to_string_pretty(&bom)?;
    cli::OutputTarget::resolve_named(args.output.as_deref(), "sbom", "json").write(&out)?;
    Ok(())
}

/// `postmortem why <package> <path>` — show the dependency paths from a package
/// up to the direct dependencies.
fn run_why(args: cli::WhyArgs) -> Result<()> {
    let ui = ui::Ui::new(!args.no_progress);
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("cannot resolve path {}", args.path.display()))?;
    let Some((_, deps, _)) = detect_and_parse(&root, &ui, &cli::OmitSet::scopes(&args.omit))? else {
        anyhow::bail!("no supported ecosystem detected at {}", root.display());
    };
    why::render(&deps, &args.package, &args.path.display().to_string());
    Ok(())
}

/// `postmortem audit <path>` — unify the static scan, dependency inventory, and
/// (opt-in) online reputation + known vulns into one graded verdict.
fn run_audit(args: cli::AuditArgs) -> Result<()> {
    let ui = ui::Ui::new(!args.no_progress);
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("cannot resolve path {}", args.path.display()))?;
    let Some((detected, deps, diags)) = detect_and_parse(&root, &ui, &cli::OmitSet::scopes(&args.omit))? else {
        std::process::exit(2);
    };

    // Static malware scan (offline), tallied by severity.
    let findings = {
        let f = analyze::run_all(&detected, &deps, &ui);
        analyze::drop_test_iocs(f, args.allow_test_files, &root)
    };
    let count = |sev: model::Severity| findings.iter().filter(|f| f.severity == sev).count();

    let mut summary = audit::AuditSummary {
        ecosystems: detected.iter().map(|e| e.name().to_string()).collect(),
        total_deps: deps.len(),
        direct_deps: deps.iter().filter(|d| d.direct).count(),
        critical: count(model::Severity::Critical),
        high_findings: count(model::Severity::High),
        medium: count(model::Severity::Medium),
        low: count(model::Severity::Low),
        // Only unintended incompleteness counts against the verdict; a
        // deliberate `--omit` must not turn a clean project into a WARN.
        diagnostics: diags.iter().filter(|d| d.is_incompleteness()).count(),
        ..Default::default()
    };

    // Dependency forest — for the online risk + vuln layers.
    let ecosystems: Vec<String> = detected.iter().map(|e| e.name().to_string()).collect();
    let mut forest = tree::build(&root.display().to_string(), &ecosystems, &deps, None);
    forest.diagnostics = diags;

    let mut settings = settings::Settings::load().unwrap_or_default();
    if args.online {
        let tokens = resolve::Tokens {
            github: settings.resolve_github_token()?,
            gitlab: settings.gitlab_token(),
            codeberg: settings.codeberg_token(),
        };
        let resolver =
            resolve::Resolver::new(tokens, settings.tree.clone()).with_languages(args.languages);
        let resolutions = resolver.resolve_all(&deps, &ui);
        tree::enrich(&mut forest, &resolutions);
        tree::score(&mut forest);
    }
    if args.vulns {
        let (agent, cache, token) = (vuln::agent(), cache::Cache::open(), settings.vuln_token());
        for d in &detected {
            if let Some((lock, fmt)) = mlab_target(d)
                && let Ok(mut v) = vuln::scan(&agent, &cache, token.as_deref(), lock, fmt)
            {
                forest.vulnerabilities.append(&mut v);
            }
        }
    }

    // Reduce the forest to the summary metrics via an empty (no-threshold) gate.
    let today = chrono::Local::now().date_naive();
    let m = gate::evaluate(&gate::Policy::default(), &forest, today, None).metrics;
    if args.online {
        summary.risk = Some(m.risk);
        summary.high_deps = m.high;
        summary.sus_deps = m.sus;
    }
    if args.vulns {
        summary.vulns = Some(m.vulns);
        summary.worst_vuln = m.worst_vuln;
    }

    audit::render(&summary, &args.path.display().to_string());
    // Non-zero exit on a CRITICAL verdict, so `audit` is CI-usable.
    if audit::grade(&summary) == audit::Grade::Critical {
        std::process::exit(1);
    }
    Ok(())
}

/// `postmortem system` — detect OS package managers, list their source repos,
/// and tree the installed forest with risk scoring. Homebrew only today. Exit 2
/// if no supported manager is present.
fn run_system(args: cli::SystemArgs) -> Result<()> {
    // `system inspect <pkg>` focuses on a single package (its own flow).
    if let Some(cli::SystemCommand::Inspect(i)) = &args.command {
        return inspect::run(i);
    }

    let ui = ui::Ui::new(!args.no_progress);
    let managers = system::detect();

    system::render_detected(&managers);

    // Use the first available manager we have a backend for (Homebrew, pacman).
    let Some(backend) =
        managers.iter().find(|m| m.available && m.implemented).map(|m| m.name)
    else {
        eprintln!("no supported system package manager found.");
        std::process::exit(2);
    };

    // gochi rides the (indeterminate) load while the manager is read.
    let opts = system::Opts { online: args.online, force_aur: args.force_aur };
    let loader = gochi::Loader::spinner("gochi reading installed packages", ui.animating());
    let inv = match system::inventory(backend, opts) {
        Ok(inv) => {
            loader.finish(gochi::Mood::Happy, format!("read {}", inv.summary));
            inv
        }
        Err(e) => {
            loader.finish(gochi::Mood::Bad, "couldn't read packages");
            return Err(e);
        }
    };
    // Surface backend caveats (weakened signing trust, tampered files, un-synced
    // DB, …) as a gochi alert followed by one bullet per caveat, so a system with
    // many caveats stays readable instead of collapsing into one run-on line.
    if !inv.notes.is_empty() {
        use owo_colors::OwoColorize;
        let header = format!("{} trust caveat(s) — review before trusting this inventory", inv.notes.len());
        eprintln!("  {}  {}", gochi::Mood::Alert.paint(), header.yellow());
        for note in &inv.notes {
            eprintln!("         {} {}", "-".dimmed(), note.yellow());
        }
    }

    // `--repos`: just the source-repo view.
    if args.repos {
        system::render_repos(&inv);
        return Ok(());
    }

    let eco = inv.deps.first().map(|d| d.ecosystem.as_str()).unwrap_or(backend).to_string();
    let mut forest = tree::build(inv.manager, &[eco], &inv.deps, args.depth);

    // `--online`: resolve each formula's repo reputation through the shared
    // resolver (same token/cache/scoring path as `tree --online`).
    if args.online {
        gochi::greet(ui.animating());
        let mut settings = settings::Settings::load().unwrap_or_default();
        let github = settings.resolve_github_token()?;
        if github.is_none() {
            eprintln!(
                "note: no GitHub token — using the anonymous GitHub API (60 req/h). \
                 Set GITHUB_TOKEN or add it to ~/.postmortem/config.yml to raise the limit."
            );
        }
        let tokens = resolve::Tokens {
            github,
            gitlab: settings.gitlab_token(),
            codeberg: settings.codeberg_token(),
        };
        let resolver =
            resolve::Resolver::new(tokens, settings.tree.clone()).with_languages(args.languages);
        let resolutions = resolver.resolve_all(&inv.deps, &ui);
        tree::enrich(&mut forest, &resolutions);
    }

    // Offline system risk: third-party taps + cask download/artifact surface.
    // Merges with any online signals, then score so `risk:dep` reflects both.
    system::annotate(&mut forest, &inv.signals);
    tree::score(&mut forest);

    // `--vulns`: known-vulnerability intel via OSV.dev. The whole inventory is
    // one backend, so one ecosystem string covers it — or `None` when OSV
    // doesn't index this manager, in which case we record a diagnostic instead
    // of letting a silent zero read as "clean".
    if args.vulns {
        scan_system_vulns(&mut forest, &inv, args.release.as_deref(), &ui);
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&forest)?);
    } else {
        tree::render(&forest);
    }

    // CI gate: turn the machine's risk scores / vuln scan into an exit code.
    // Summary goes to stderr so it never corrupts `--json` on stdout.
    run_system_gate(&args, &forest);
    Ok(())
}

/// Apply the CI gate to a scanned system inventory and exit accordingly: 0 clean,
/// 1 tripped, 2 inconclusive/misconfigured. A vuln gate is **fail-closed** — if
/// OSV couldn't scan this backend (or the scan errored), the gate can't be
/// answered, so it exits 2 rather than silently passing ("not scanned" ≠ "clean").
fn run_system_gate(args: &cli::SystemArgs, forest: &tree::Tree) {
    let gc = match &args.config {
        Some(p) => match config::Config::load(p) {
            Ok(c) => c.gate,
            Err(e) => {
                eprintln!("warn: failed to load gate config {}: {e:#}", p.display());
                config::GateConfig::default()
            }
        },
        None => config::GateConfig::default(),
    };
    let policy = build_gate_policy(
        gc,
        args.max_risk,
        args.max_dep,
        args.max_high,
        args.max_sus,
        args.max_vulns,
        args.fail_on_vuln,
        &args.allow,
    );
    if !policy.is_active() {
        return; // no gate requested → normal exit 0
    }

    if policy.needs_vulns() && !args.vulns {
        eprintln!("error: --max-vulns/--fail-on-vuln require --vulns");
        std::process::exit(2);
    }
    // Fail-closed: an active vuln gate over an un-scannable backend (brew/nix,
    // Fedora/RHEL) or a scan that errored is INCONCLUSIVE, not clean.
    if policy.needs_vulns() {
        if let Some(d) = forest
            .diagnostics
            .iter()
            .find(|d| d.kind == "vuln_source_unavailable" || d.kind == "vuln_scan_failed")
        {
            eprintln!(
                "error: vuln gate cannot be evaluated — {} ({}); \
                 an un-scanned backend is not the same as clean",
                d.message, d.kind
            );
            std::process::exit(2);
        }
    }

    let today = chrono::Local::now().date_naive();
    let outcome = gate::evaluate(&policy, forest, today, None);
    gate::report(&outcome, &policy);
    std::process::exit(if outcome.tripped() { 1 } else { 0 });
}

/// Populate `forest.vulnerabilities` from OSV.dev for the installed inventory,
/// or push a `vuln_source_unavailable` diagnostic when the release can't be
/// resolved or OSV doesn't cover this backend.
fn scan_system_vulns(
    forest: &mut tree::Tree,
    inv: &system::Inventory,
    release_override: Option<&str>,
    ui: &ui::Ui,
) {
    let Some(eco) = inv.deps.first().map(|d| d.ecosystem) else {
        return; // nothing installed to scan
    };

    // Arch isn't in OSV — pacman uses its own source (the Arch Security Tracker),
    // no release needed (Arch is rolling).
    if eco == model::Ecosystem::Pacman {
        let loader = gochi::Loader::spinner(
            format!("gochi querying the Arch Security Tracker for {} packages", inv.deps.len()),
            ui.animating(),
        );
        match archsec::scan(&vuln::agent(), &inv.deps) {
            Ok(mut v) => {
                forest.vulnerabilities.append(&mut v);
                loader.finish(gochi::Mood::from_risk(0, 0, vuln_count(forest)), vuln_summary(forest));
            }
            Err(e) => {
                loader.finish(gochi::Mood::Alert, "vuln scan failed");
                forest.diagnostics.push(model::Diagnostic {
                    ecosystem: eco.as_str().into(),
                    kind: "vuln_scan_failed".into(),
                    message: format!("Arch Security Tracker scan failed: {e:#}"),
                });
            }
        }
        return;
    }

    let release = match release_override {
        Some(s) => osv::Release::parse_override(s),
        None => match osv::Release::detect() {
            Some(r) => r,
            None => {
                forest.diagnostics.push(model::Diagnostic {
                    ecosystem: eco.as_str().into(),
                    kind: "vuln_source_unavailable".into(),
                    message: "cannot read /etc/os-release; pass --release id:version to scan"
                        .into(),
                });
                return;
            }
        },
    };

    let Some(osv_eco) = osv::osv_ecosystem(eco, &release) else {
        // Actionable guidance for the dnf backends OSV doesn't index directly.
        let hint = match (eco, release.id.as_str()) {
            (model::Ecosystem::Dnf, "rhel" | "redhat" | "centos") => {
                " — RHEL isn't in OSV; retry with `--release almalinux:<N>` or `rocky:<N>` \
                 (binary-compatible) for approximate coverage"
            }
            (model::Ecosystem::Dnf, "fedora") => {
                " — Fedora isn't in OSV; `dnf updateinfo --security` lists advisories for \
                 available updates"
            }
            _ => "",
        };
        forest.diagnostics.push(model::Diagnostic {
            ecosystem: eco.as_str().into(),
            kind: "vuln_source_unavailable".into(),
            message: format!(
                "OSV has no vulnerability feed for {} ({}); packages were not scanned{hint}",
                eco.as_str(),
                release.id
            ),
        });
        return;
    };

    let settings = settings::Settings::load().unwrap_or_default();
    let token = settings.vuln_token();
    if token.is_none() {
        eprintln!(
            "note: no mlab token — vuln scans use the anonymous limit. \
             Set VULN_MLAB_TOKEN or vuln_token in ~/.postmortem/config.yml."
        );
    }
    let loader = gochi::Loader::spinner(
        format!("gochi querying vuln.mlab.sh for {} {osv_eco} packages", inv.deps.len()),
        ui.animating(),
    );
    match osv::scan(&vuln::agent(), &cache::Cache::open(), token.as_deref(), &inv.deps, &osv_eco) {
        Ok(mut v) => {
            forest.vulnerabilities.append(&mut v);
            loader.finish(
                gochi::Mood::from_risk(0, 0, vuln_count(forest)),
                vuln_summary(forest),
            );
        }
        Err(e) => {
            loader.finish(gochi::Mood::Alert, "vuln scan failed");
            forest.diagnostics.push(model::Diagnostic {
                ecosystem: eco.as_str().into(),
                kind: "vuln_scan_failed".into(),
                message: format!("vuln scan failed: {e:#}"),
            });
        }
    }
}

/// Total known-vulnerability count across a forest's vulnerable packages.
fn vuln_count(forest: &tree::Tree) -> usize {
    forest.vulnerabilities.iter().map(|p| p.vulns.len()).sum()
}

/// A one-line gochi summary of a forest's vuln scan: `N known vulnerabilities in
/// M package(s)`, or an all-clear.
fn vuln_summary(forest: &tree::Tree) -> String {
    let n = vuln_count(forest);
    if n == 0 {
        return "no known vulnerabilities".into();
    }
    let pkgs = forest.vulnerabilities.len();
    format!("{n} known vulnerabilit{} in {pkgs} package(s)", if n == 1 { "y" } else { "ies" })
}

/// gochi's closing verdict for a static scan: a mood + a severity breakdown, or
/// an all-clear. Bad on any critical/high, alert on softer findings.
fn scan_verdict(findings: &[model::Finding]) -> (gochi::Mood, String) {
    use model::Severity::*;
    let (mut crit, mut high, mut med, mut low) = (0, 0, 0, 0);
    for f in findings {
        match f.severity {
            Critical => crit += 1,
            High => high += 1,
            Medium => med += 1,
            Low => low += 1,
            Info => {}
        }
    }
    let total = crit + high + med + low;
    if total == 0 {
        return (gochi::Mood::Happy, "clean — no malicious patterns found".into());
    }
    let mood = if crit + high > 0 { gochi::Mood::Bad } else { gochi::Mood::Alert };
    (mood, format!("{total} finding(s): {crit} critical · {high} high · {med} medium · {low} low"))
}

/// Compact byte count: `0 B`, `4.2 KB`, `1.3 MB`.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// A branded, at-a-glance overview. This is intentionally a *start* — richer,
/// per-command help still lives behind `--help` / `<command> --help`.
fn print_overview() {
    use owo_colors::OwoColorize;
    println!("{} {}", "postmortem".bold(), env!("CARGO_PKG_VERSION").dimmed());
    println!("{}", "Supply-chain security scanner for the code you depend on.".dimmed());
    println!();
    println!("{}", "USAGE".bold());
    println!("  postmortem <command> [options]");
    println!();
    println!("{}", "COMMANDS".bold());
    println!("  {}   Scan one or more project directories for malicious dependencies", "scan".cyan());
    println!("  {}   Resolve the dependency tree from the lockfiles ({} for repo stats)", "tree".cyan(), "--online".dimmed());
    println!("  {}  One-shot graded health check ({}/{} deepen it)", "audit".cyan(), "--online".dimmed(), "--vulns".dimmed());
    println!("  {}    Explain why a package is installed (its dependency paths)", "why".cyan());
    println!("  {}   Compare two project states: added / removed / changed dependencies", "diff".cyan());
    println!("  {}   Export the dependency graph as a CycloneDX SBOM", "sbom".cyan());
    println!("  {}  Manage the on-disk cache used by {}", "cache".cyan(), "tree --online".dimmed());
    println!("  {} Audit OS package managers ({} for repo stats)", "system".cyan(), "--online".dimmed());
    println!("  {}   Show this overview", "help".cyan());
    println!();
    println!("{}", "ECOSYSTEMS".bold());
    println!("  {}", "node · python · rust · ruby · php · go · java".dimmed());
    println!();
    println!("{}", "EXAMPLES".bold());
    println!("  postmortem scan .");
    println!("  postmortem scan ./service-a ./service-b");
    println!("  postmortem scan . --json -o report.json");
    println!("  postmortem scan . --sarif        {}", "# GitHub Code Scanning".dimmed());
    println!("  postmortem tree . --depth 2      {}", "# dependency forest".dimmed());
    println!("  postmortem tree . --online --vulns {}", "# reputation + CVEs".dimmed());
    println!();
    println!(
        "Run {} for the full flag reference.",
        "postmortem scan --help".cyan()
    );
}

/// `postmortem scan <paths>...` — scan each path in sequence. Exit code: 2 if no
/// supported ecosystem was found at any path, 1 if any scan tripped the severity
/// gate, else 0.
fn run_scan(args: cli::ScanArgs) -> Result<()> {
    if args.paths.len() > 1 && !matches!(args.format(), cli::Format::Terminal) {
        anyhow::bail!(
            "machine formats (--json/--html/--sarif) support a single path; got {}",
            args.paths.len()
        );
    }

    let ui = ui::Ui::new(!args.no_progress);

    let mut any_detected = false;
    let mut gate_tripped = false;
    for path in &args.paths {
        let root = match path.canonicalize() {
            Ok(r) => r,
            Err(e) => {
                ui.note(format!("cannot resolve path {}: {e}", path.display()));
                continue;
            }
        };
        match scan_path(&root, &args, &ui)? {
            Some(tripped) => {
                any_detected = true;
                gate_tripped |= tripped;
            }
            None => ui.note(format!("no supported ecosystem detected at {}", root.display())),
        }
    }

    if !any_detected {
        std::process::exit(2);
    }
    std::process::exit(if gate_tripped { 1 } else { 0 });
}

/// `postmortem tree <paths>...` — resolve and render the dependency forest from
/// the lockfiles. Offline today; `--online` is reserved for repository-reputation
/// resolution (see [`resolve`]). Exit 2 if no supported ecosystem was found.
fn run_tree(args: cli::TreeArgs) -> Result<()> {
    let machine = args.json || args.sarif;
    if args.paths.len() > 1 && machine && !args.allow_multiple {
        anyhow::bail!(
            "machine formats (--json/--sarif) support a single target; got {}. \
             Pass --allow-multiple to emit them all — note the shape changes: \
             --json becomes an array of trees, --sarif one runs[] entry per target.",
            args.paths.len()
        );
    }
    if args.allow_multiple && !machine {
        eprintln!("note: --allow-multiple only affects --json/--sarif; the terminal view already renders every target");
    }

    let ui = ui::Ui::new(!args.no_progress);

    // Online resolution shares one resolver (and its cache/token) across paths.
    let mut settings = settings::Settings::load().unwrap_or_default();

    let resolver = if args.online {
        gochi::greet(ui.animating()); // gochi says hi before the token prompt
        let github = settings.resolve_github_token()?;
        if github.is_none() {
            eprintln!(
                "note: no GitHub token — using the anonymous GitHub API (60 req/h). \
                 Set GITHUB_TOKEN or add it to ~/.postmortem/config.yml to raise the limit."
            );
        }
        // GitLab/Codeberg stats resolve anonymously; a token only lifts the
        // rate limit, so these are quiet (env/config only, no prompt).
        let tokens = resolve::Tokens {
            github,
            gitlab: settings.gitlab_token(),
            codeberg: settings.codeberg_token(),
        };
        Some(resolve::Resolver::new(tokens, settings.tree.clone()).with_languages(args.languages))
    } else {
        None
    };

    // mlab vuln-scan context (agent + cache + token), independent of --online.
    let vuln_ctx = if args.vulns {
        if settings.vuln_token().is_none() {
            eprintln!(
                "note: no mlab token — vuln scans use the anonymous 8/h limit. \
                 Set VULN_MLAB_TOKEN or vuln_token in ~/.postmortem/config.yml."
            );
        }
        Some((vuln::agent(), cache::Cache::open(), settings.vuln_token()))
    } else {
        None
    };

    let today = chrono::Local::now().date_naive();
    let mut any_detected = false;
    let mut gate_tripped = false;
    let mut gate_misconfig = false;
    let mut machine_trees: Vec<tree::Tree> = Vec::new();
    for path in &args.paths {
        let target = match path.canonicalize() {
            Ok(r) => r,
            // A target that isn't there at all is a configuration error: with
            // several targets, skipping it silently would green-light the run.
            Err(e) => {
                ui.note(format!("cannot resolve path {}: {e}", path.display()));
                gate_misconfig = true;
                continue;
            }
        };
        // A pinned manifest/lockfile still belongs to its parent project: that
        // directory is the tree root and where `postmortem.conf` is looked up.
        let root = match target.is_file() {
            true => target.parent().unwrap_or(&target).to_path_buf(),
            false => target.clone(),
        };
        let parsed = match detect_and_parse(&target, &ui, &cli::OmitSet::scopes(&args.omit)) {
            Ok(Some(p)) => p,
            Ok(None) => {
                ui.note(format!("no supported ecosystem detected at {}", target.display()));
                continue;
            }
            // An explicit file target that can't be resolved is a configuration
            // error, not an empty result — never let it pass as a clean run.
            Err(e) => {
                ui.note(format!("{e:#}"));
                gate_misconfig = true;
                continue;
            }
        };
        let (detected, deps, diags) = parsed;
        any_detected = true;

        let ecosystems: Vec<String> = detected.iter().map(|e| e.name().to_string()).collect();
        let mut forest = tree::build(&root.display().to_string(), &ecosystems, &deps, args.depth);
        forest.diagnostics = diags;

        if let Some(resolver) = &resolver {
            let resolutions = resolver.resolve_all(&deps, &ui);
            tree::enrich(&mut forest, &resolutions);
            tree::score(&mut forest);
        }

        if let Some((agent, cache, token)) = &vuln_ctx {
            let loader =
                gochi::Loader::spinner("gochi querying vuln.mlab.sh for advisories", ui.animating());
            for d in &detected {
                loader.step(format!("gochi checking {} advisories", d.name()));
                match mlab_target(d) {
                    Some((lock, fmt)) => match vuln::scan(agent, cache, token.as_deref(), lock, fmt)
                    {
                        Ok(mut v) => forest.vulnerabilities.append(&mut v),
                        Err(e) => forest.diagnostics.push(model::Diagnostic {
                            ecosystem: d.name().into(),
                            kind: "vuln_scan_failed".into(),
                            message: format!("vuln scan failed: {e:#}"),
                        }),
                    },
                    None => forest.diagnostics.push(model::Diagnostic {
                        ecosystem: d.name().into(),
                        kind: "vuln_unsupported".into(),
                        message: "mlab vuln scan does not support this lockfile format".into(),
                    }),
                }
            }
            loader.finish(gochi::Mood::from_risk(0, 0, vuln_count(&forest)), vuln_summary(&forest));
        }

        // Machine formats are written once, after every target is resolved, so
        // several targets land in a single document. The terminal view streams.
        if !machine {
            tree::render(&forest);
        }

        // CI gate: turn the online scores / vuln scan into a pass/fail exit code.
        // The gate summary goes to stderr so it never corrupts `--json` on stdout.
        let policy = resolve_gate_policy(&root, &args);
        if policy.is_active() {
            if policy.needs_scores() && !forest.scored {
                eprintln!(
                    "error: gate thresholds (--max-risk/--max-dep/--max-high/--max-sus) require \
                     --online; no scores were computed for {}",
                    root.display()
                );
                gate_misconfig = true;
            } else if policy.needs_vulns() && !args.vulns {
                eprintln!(
                    "error: gate thresholds (--max-vulns/--fail-on-vuln) require --vulns; no vuln \
                     scan was run for {}",
                    root.display()
                );
                gate_misconfig = true;
            } else {
                if !forest.diagnostics.is_empty() {
                    eprintln!(
                        "  ⚠ {} graph diagnostic(s) present — gate metrics may be incomplete",
                        forest.diagnostics.len()
                    );
                }
                let baseline = match args.baseline.as_deref() {
                    Some(p) => match gate::Baseline::load(p) {
                        Ok(b) => Some(b),
                        Err(e) => {
                            eprintln!("error: {e:#}");
                            gate_misconfig = true;
                            continue;
                        }
                    },
                    None => None,
                };
                let outcome = gate::evaluate(&policy, &forest, today, baseline.as_ref());
                gate::report(&outcome, &policy);
                gate_tripped |= outcome.tripped();
            }
        }

        if machine {
            machine_trees.push(forest);
        }
    }

    // One document for every target: a bare object for a single tree (the
    // long-standing shape), an array / multi-run SARIF under --allow-multiple.
    if machine && !machine_trees.is_empty() {
        if args.json {
            let out = match args.allow_multiple {
                true => serde_json::to_string_pretty(&machine_trees)?,
                false => serde_json::to_string_pretty(&machine_trees[0])?,
            };
            cli::OutputTarget::resolve_named(args.output.as_deref(), "tree", "json").write(&out)?;
        } else {
            let out = match args.allow_multiple {
                true => report::sarif::render_trees(&machine_trees)?,
                false => report::sarif::render_tree(&machine_trees[0])?,
            };
            cli::OutputTarget::resolve_named(args.output.as_deref(), "tree", "sarif").write(&out)?;
        }
    }

    if !any_detected {
        std::process::exit(2);
    }
    if gate_misconfig {
        std::process::exit(2);
    }
    std::process::exit(if gate_tripped { 1 } else { 0 });
}

/// Build the effective gate policy for `root`: the `[gate]` table from
/// `--config` (or an auto-loaded `postmortem.conf`) with CLI flags layered on
/// top (CLI wins on each threshold; allowlists are unioned).
fn resolve_gate_policy(root: &Path, args: &cli::TreeArgs) -> gate::Policy {
    let cfg_path = args.config.clone().or_else(|| {
        let c = root.join(config::DEFAULT_FILENAME);
        c.is_file().then_some(c)
    });
    let gc = match cfg_path {
        Some(p) => match config::Config::load(&p) {
            Ok(c) => c.gate,
            Err(e) => {
                eprintln!("warn: failed to load gate config {}: {e:#}", p.display());
                config::GateConfig::default()
            }
        },
        None => config::GateConfig::default(),
    };
    build_gate_policy(
        gc,
        args.max_risk,
        args.max_dep,
        args.max_high,
        args.max_sus,
        args.max_vulns,
        args.fail_on_vuln,
        &args.allow,
    )
}

/// Layer CLI gate thresholds over a `[gate]` config table into an effective
/// [`gate::Policy`] (CLI wins per-threshold; the config allowlist is unioned
/// with `--allow`). Shared by `tree` and `system`.
#[allow(clippy::too_many_arguments)]
fn build_gate_policy(
    gc: config::GateConfig,
    max_risk: Option<u8>,
    max_dep: Option<u8>,
    max_high: Option<usize>,
    max_sus: Option<usize>,
    max_vulns: Option<usize>,
    fail_on_vuln: Option<model::Severity>,
    cli_allow: &[String],
) -> gate::Policy {
    gate::Policy {
        max_risk: max_risk.or(gc.max_risk),
        max_dep: max_dep.or(gc.max_dep),
        max_high: max_high.or(gc.max_high),
        max_sus: max_sus.or(gc.max_sus),
        max_vulns: max_vulns.or(gc.max_vulns),
        fail_on_vuln: fail_on_vuln.or(gc.fail_on_vuln),
        allow: gc
            .allow
            .iter()
            .map(|e| gate::Allow {
                package: e.package.clone(),
                reason: e.reason.clone(),
                expires: e.expires.clone(),
            })
            .chain(cli_allow.iter().map(|p| gate::Allow {
                package: p.clone(),
                reason: None,
                expires: None,
            }))
            .collect(),
    }
}

/// Detected ecosystems, parsed dependencies, and any diagnostics.
type ParsedProject = (Vec<detect::Detected>, Vec<model::Dependency>, Vec<model::Diagnostic>);

/// Map a detected ecosystem to the lockfile + mlab `format` its vuln API
/// accepts, or `None` when mlab doesn't support that format (pnpm/yarn, poetry/
/// Pipfile, Java).
pub(crate) fn mlab_target(d: &detect::Detected) -> Option<(&Path, &'static str)> {
    let base = |p: &Path| p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
    match d {
        detect::Detected::Node { lockfile, .. } => {
            matches!(base(lockfile).as_str(), "package-lock.json" | "npm-shrinkwrap.json")
                .then_some((lockfile.as_path(), "npm"))
        }
        detect::Detected::Rust { lockfile, .. } => Some((lockfile.as_path(), "cargo")),
        detect::Detected::Php { lockfile, .. } => Some((lockfile.as_path(), "composer")),
        detect::Detected::Ruby { lockfile, .. } => Some((lockfile.as_path(), "gem")),
        detect::Detected::Go { lockfile: Some(go_sum), .. } => Some((go_sum.as_path(), "go")),
        detect::Detected::Python { lockfile, manifest, .. } => {
            if lockfile.as_ref().is_some_and(|p| base(p) == "requirements.txt") {
                lockfile.as_deref().map(|p| (p, "pip"))
            } else if base(manifest) == "requirements.txt" {
                Some((manifest.as_path(), "pip"))
            } else {
                None
            }
        }
        detect::Detected::Go { .. } | detect::Detected::Java { .. } => None,
    }
}

/// Detect ecosystems and parse every lockfile at `target` — a project directory,
/// or a manifest/lockfile pinning one ecosystem (see [`detect::detect_target`]).
/// Shared by every project-level command. Returns `None` when no supported
/// ecosystem is present, else the detected ecosystems, the parsed dependencies,
/// and any diagnostics (parse failures / incomplete graphs) so a `0` result is
/// never mistaken for "clean". Errors when an explicitly pinned file can't be
/// used.
///
/// `omit` drops whole dependency sets (`--omit dev`). It is applied here, at the
/// single point every command funnels through, so the filter cannot drift
/// between `scan`, `tree`, `audit`, `sbom`, `why` and `diff` — and so scope
/// propagation runs exactly once, over the merged multi-ecosystem graph.
fn detect_and_parse(
    target: &Path,
    ui: &ui::Ui,
    omit: &[model::Scope],
) -> Result<Option<ParsedProject>> {
    let detect_phase = ui.phase("detecting ecosystems");
    let detected = match detect::detect_target(target) {
        Ok(d) => d,
        Err(e) => {
            detect_phase.abandon();
            return Err(e);
        }
    };
    if detected.is_empty() {
        detect_phase.abandon();
        return Ok(None);
    }
    detect_phase.done(format!(
        "detected {}: {}",
        detected.len(),
        detected
            .iter()
            .map(|e| e.name())
            .collect::<Vec<_>>()
            .join(", ")
    ));

    let parse_phase = ui.phase("parsing dependencies");
    let mut deps = Vec::new();
    let mut diags: Vec<model::Diagnostic> = Vec::new();
    let mut diag = |eco: &str, kind: &str, message: String| {
        parse_phase.note(format!("warn: {message}"));
        diags.push(model::Diagnostic { ecosystem: eco.into(), kind: kind.into(), message });
    };

    for eco in &detected {
        parse_phase.set(format!("parsing {} manifest", eco.name()));
        match eco {
            // Dispatch Node by lockfile flavor: npm (JSON), pnpm (YAML), yarn (v1/berry).
            detect::Detected::Node { manifest, lockfile, .. } => {
                let fname = lockfile.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let parsed = match fname {
                    "pnpm-lock.yaml" => parsers::pnpm::parse(lockfile),
                    "yarn.lock" => parsers::yarn::parse(manifest, lockfile),
                    _ => parsers::node::parse_lockfile(lockfile),
                };
                match parsed {
                    Ok(mut d) => deps.append(&mut d),
                    Err(e) => diag("node", "parse_failed", format!("{fname} parse failed: {e:#}")),
                }
            }
            detect::Detected::Python { manifest, lockfile, .. } => {
                match parsers::python::parse_any(manifest, lockfile.as_deref()) {
                    Ok(mut d) => deps.append(&mut d),
                    Err(e) => diag("python", "parse_failed", format!("python parse failed: {e:#}")),
                }
            }
            detect::Detected::Rust { manifest, lockfile, .. } => {
                match parsers::rust::parse_lockfile(lockfile, Some(manifest)) {
                    Ok(mut d) => deps.append(&mut d),
                    Err(e) => diag("rust", "parse_failed", format!("Cargo.lock parse failed: {e:#}")),
                }
            }
            detect::Detected::Ruby { manifest, lockfile, .. } => {
                match parsers::ruby::parse_lockfile(lockfile, manifest.as_deref()) {
                    Ok(mut d) => deps.append(&mut d),
                    Err(e) => diag("ruby", "parse_failed", format!("Gemfile.lock parse failed: {e:#}")),
                }
            }
            detect::Detected::Php { manifest, lockfile, .. } => {
                match parsers::php::parse_lockfile(lockfile, manifest.as_deref()) {
                    Ok(mut d) => deps.append(&mut d),
                    Err(e) => diag("php", "parse_failed", format!("composer.lock parse failed: {e:#}")),
                }
            }
            detect::Detected::Go { manifest, lockfile, .. } => {
                match parsers::go::parse(manifest, lockfile.as_deref()) {
                    Ok(mut d) => deps.append(&mut d),
                    Err(e) => diag("go", "parse_failed", format!("go.mod parse failed: {e:#}")),
                }
                // go.mod carries no edge data — the graph is a flat classified list.
                diag(
                    "go",
                    "flat_graph",
                    "go graph is flat — transitive parent edges are not reconstructed offline (needs `go mod graph`)".into(),
                );
                for (from, to) in parsers::go::replaces(manifest) {
                    diag(
                        "go",
                        "replace_directive",
                        format!("go.mod replaces {from} => {to} (module redirected — verify the target)"),
                    );
                }
            }
            detect::Detected::Java { manifest, lockfile, .. } => {
                match parsers::java::parse(manifest.as_deref(), lockfile.as_deref()) {
                    Ok(mut d) => deps.append(&mut d),
                    Err(e) => diag("java", "parse_failed", format!("JVM manifest/lockfile parse failed: {e:#}")),
                }
                diag(
                    "java",
                    "flat_graph",
                    "JVM graph is flat — Maven lists direct deps only and Gradle locks carry no edges (no transitive closure offline)".into(),
                );
            }
        }
    }
    // Parsers only classify the *direct* deps a manifest names; resolve the rest
    // of the graph before any filtering, so `--omit dev` acts on real reachability
    // rather than on what happened to be listed under devDependencies.
    scope::propagate(&mut deps);

    if omit.is_empty() {
        parse_phase.done(format!("parsed {} dependencies", deps.len()));
    } else {
        let before = deps.len();
        let dropped: Vec<String> = omit
            .iter()
            .map(|s| format!("{} {}", scope::count(&deps, *s), s.as_str()))
            .collect();
        deps = scope::apply_omit(deps, omit);
        let removed = before - deps.len();
        let detail = format!("{removed} of {before} dependencies omitted ({})", dropped.join(", "));
        parse_phase.done(format!("parsed {} dependencies — {detail}", deps.len()));
        // Also record it as a diagnostic. The progress UI is suppressed when
        // stderr isn't a TTY, so in CI the summary above never prints — and a
        // silently smaller dependency set is exactly what this project refuses
        // to ship. As a diagnostic the fact reaches --json and --sarif too.
        if removed > 0 {
            diags.push(model::Diagnostic {
                ecosystem: "*".into(),
                kind: model::DIAG_SCOPE_OMITTED.into(),
                message: detail,
            });
        }
    }

    Ok(Some((detected, deps, diags)))
}

/// Scan a single already-canonicalized project root. Returns `None` when no
/// supported ecosystem is present, otherwise `Some(gate_tripped)` where
/// `gate_tripped` is true if any finding meets or exceeds `--severity`.
fn scan_path(target: &Path, args: &cli::ScanArgs, ui: &ui::Ui) -> Result<Option<bool>> {
    let Some((detected, deps, diagnostics)) =
        detect_and_parse(target, ui, &cli::OmitSet::scopes(&args.omit))?
    else {
        return Ok(None);
    };
    // A pinned manifest/lockfile target belongs to its parent project: that
    // directory is what `postmortem.conf` autoload and test-path filtering use.
    let owned_root;
    let root = if target.is_file() {
        owned_root = target.parent().unwrap_or(target).to_path_buf();
        owned_root.as_path()
    } else {
        target
    };

    // Resolve the config: explicit --config wins; otherwise auto-load <root>/postmortem.conf
    // unless --no-config is set.
    let cfg_path = if args.no_config {
        None
    } else if let Some(p) = &args.config {
        Some(p.clone())
    } else {
        let candidate = root.join(config::DEFAULT_FILENAME);
        candidate.is_file().then_some(candidate)
    };
    let config = match cfg_path {
        Some(p) => match config::Config::load(&p) {
            Ok(c) => {
                ui.note(format!("loaded config from {}", p.display()));
                c
            }
            Err(e) => {
                ui.note(format!("warn: failed to load config {}: {e:#}", p.display()));
                config::Config::default()
            }
        },
        None => config::Config::default(),
    };
    let config = config.merge_cli(&args.skip_category, args.min_severity);

    let raw_findings = if args.skip_analyze {
        Vec::new()
    } else {
        let f = analyze::run_all(&detected, &deps, ui);
        analyze::drop_test_iocs(f, args.allow_test_files, root)
    };

    let (mut findings, suppressed) = config.apply(raw_findings);
    if suppressed > 0 {
        ui.note(format!("config suppressed {suppressed} finding(s)"));
    }
    if args.enrich {
        let enrich_phase = ui.phase("enriching findings");
        enrich::annotate(&mut findings);
        let n = findings.iter().filter(|f| f.enrich_url.is_some()).count();
        enrich_phase.done(format!("enriched {n} finding(s)"));
    }

    let report = model::Report {
        // 3: every dependency carries a `scope` (prod / dev / optional).
        schema_version: 3,
        root: root.display().to_string(),
        ecosystems: detected.iter().map(|e| e.name().to_string()).collect(),
        diagnostics,
        dependencies: deps,
        findings,
    };

    match args.format() {
        cli::Format::Terminal => {
            report::terminal::render(&report, !args.no_deps);
            let (mood, msg) = scan_verdict(&report.findings);
            gochi::say(mood, msg);
        }
        cli::Format::Json => {
            let out = report::json::render(&report)?;
            cli::OutputTarget::resolve(args.output.as_deref(), "json").write(&out)?;
        }
        cli::Format::Html => {
            let out = report::html::render(&report);
            cli::OutputTarget::resolve(args.output.as_deref(), "html").write(&out)?;
        }
        cli::Format::Sarif => {
            let out = report::sarif::render(&report)?;
            cli::OutputTarget::resolve(args.output.as_deref(), "sarif").write(&out)?;
        }
    }

    let gate_tripped = report.findings.iter().any(|f| f.severity >= args.severity);
    Ok(Some(gate_tripped))
}
