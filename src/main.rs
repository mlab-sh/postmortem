mod analyze;
mod cache;
mod cli;
mod config;
mod detect;
mod enrich;
mod gate;
mod gochi;
mod inspect;
mod model;
mod parsers;
mod report;
mod resolve;
mod settings;
mod system;
mod tree;
mod typosquat;
mod ui;
mod vuln;

use std::path::Path;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    match cli::Cli::parse().command {
        cli::Command::Scan(args) => run_scan(args),
        cli::Command::Tree(args) => run_tree(args),
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
            let report = cache.prune(p.older_than, p.dry_run);
            let where_ = cache
                .root()
                .map(|r| r.display().to_string())
                .unwrap_or_else(|| "(no cache)".into());
            let verb = if p.dry_run { "would remove" } else { "removed" };
            let scope = match p.older_than {
                Some(d) => format!("older than {d}d"),
                None => "all".into(),
            };
            println!(
                "{verb} {} entr{} ({scope}, {}), kept {} — {where_}",
                report.removed,
                if report.removed == 1 { "y" } else { "ies" },
                human_bytes(report.freed),
                report.kept,
            );
        }
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
            loader.finish(gochi::HAPPY, &format!("read {}", inv.summary));
            inv
        }
        Err(e) => {
            loader.finish(gochi::ALERT, "couldn't read packages");
            return Err(e);
        }
    };
    // Surface any backend caveat (e.g. an un-synced pacman DB) as a gochi alert.
    if let Some(note) = &inv.note {
        use owo_colors::OwoColorize;
        eprintln!("  {}  {}", gochi::ALERT.cyan(), note.yellow());
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

    if args.json {
        println!("{}", serde_json::to_string_pretty(&forest)?);
    } else {
        tree::render(&forest);
    }
    Ok(())
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
    println!("{}", "Static supply-chain scanner — no network by default.".dimmed());
    println!();
    println!("{}", "USAGE".bold());
    println!("  postmortem <command> [options]");
    println!();
    println!("{}", "COMMANDS".bold());
    println!("  {}   Scan one or more project directories for malicious dependencies", "scan".cyan());
    println!("  {}   Resolve the dependency tree from the lockfiles ({} for repo stats)", "tree".cyan(), "--online".dimmed());
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
    if args.paths.len() > 1 && (args.json || args.sarif) {
        anyhow::bail!(
            "machine formats (--json/--sarif) support a single path; got {}",
            args.paths.len()
        );
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
    for path in &args.paths {
        let root = match path.canonicalize() {
            Ok(r) => r,
            Err(e) => {
                ui.note(format!("cannot resolve path {}: {e}", path.display()));
                continue;
            }
        };
        let Some((detected, deps, diags)) = detect_and_parse(&root, &ui)? else {
            ui.note(format!("no supported ecosystem detected at {}", root.display()));
            continue;
        };
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
            ui.note("scanning known vulnerabilities via vuln.mlab.sh…");
            for d in &detected {
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
        }

        if args.json {
            let out = serde_json::to_string_pretty(&forest)?;
            cli::OutputTarget::resolve_named(args.output.as_deref(), "tree", "json").write(&out)?;
        } else if args.sarif {
            let out = report::sarif::render_tree(&forest)?;
            cli::OutputTarget::resolve_named(args.output.as_deref(), "tree", "sarif").write(&out)?;
        } else {
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
    gate::Policy {
        max_risk: args.max_risk.or(gc.max_risk),
        max_dep: args.max_dep.or(gc.max_dep),
        max_high: args.max_high.or(gc.max_high),
        max_sus: args.max_sus.or(gc.max_sus),
        max_vulns: args.max_vulns.or(gc.max_vulns),
        fail_on_vuln: args.fail_on_vuln.or(gc.fail_on_vuln),
        allow: gc
            .allow
            .iter()
            .map(|e| gate::Allow {
                package: e.package.clone(),
                reason: e.reason.clone(),
                expires: e.expires.clone(),
            })
            .chain(args.allow.iter().map(|p| gate::Allow {
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

/// Detect ecosystems and parse every lockfile at `root`. Shared by `scan` and
/// `tree`. Returns `None` when no supported ecosystem is present, else the
/// detected ecosystems, the parsed dependencies, and any diagnostics (parse
/// failures / incomplete graphs) so a `0` result is never mistaken for "clean".
fn detect_and_parse(root: &Path, ui: &ui::Ui) -> Result<Option<ParsedProject>> {
    let detect_phase = ui.phase("detecting ecosystems");
    let detected = detect::detect(root)?;
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
    parse_phase.done(format!("parsed {} dependencies", deps.len()));

    Ok(Some((detected, deps, diags)))
}

/// Scan a single already-canonicalized project root. Returns `None` when no
/// supported ecosystem is present, otherwise `Some(gate_tripped)` where
/// `gate_tripped` is true if any finding meets or exceeds `--severity`.
fn scan_path(root: &Path, args: &cli::ScanArgs, ui: &ui::Ui) -> Result<Option<bool>> {
    let Some((detected, deps, diagnostics)) = detect_and_parse(root, ui)? else {
        return Ok(None);
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
        schema_version: 2,
        root: root.display().to_string(),
        ecosystems: detected.iter().map(|e| e.name().to_string()).collect(),
        diagnostics,
        dependencies: deps,
        findings,
    };

    match args.format() {
        cli::Format::Terminal => report::terminal::render(&report, !args.no_deps),
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
