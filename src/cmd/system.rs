//! `postmortem system` — the machine's OS package managers.

use crate::cmd::common::{vuln_count, vuln_summary};
use crate::cmd::gate_policy::build_gate_policy;
use crate::{
    archsec, cache, cli, config, gate, gochi, inspect, model, osv, resolve, settings, system, tree,
    ui, vuln,
};
use anyhow::Result;

/// `postmortem system` — detect OS package managers, list their source repos,
/// and tree the installed forest with risk scoring. Six backends today
/// (Homebrew, pacman, apt, dnf, Nix, apk); MacPorts is detected but unsupported.
/// Exit 2 if no supported manager is present.
pub(crate) fn run_system(args: cli::SystemArgs) -> Result<()> {
    // `system inspect <pkg>` focuses on a single package (its own flow).
    if let Some(cli::SystemCommand::Inspect(i)) = &args.command {
        return inspect::run(i);
    }

    let ui = ui::Ui::new(!args.no_progress);
    let managers = system::detect();
    system::render_detected(&managers);

    // Use the first available manager we have a backend for. On a machine with
    // several (Homebrew alongside apt, say) the detection order in
    // `system::KNOWN` decides; `--repos` and the tree then describe that one.
    let Some(backend) = managers
        .iter()
        .find(|m| m.available && m.implemented)
        .map(|m| m.name)
    else {
        eprintln!("no supported system package manager found.");
        std::process::exit(2);
    };

    // gochi rides the (indeterminate) load while the manager is read.
    let opts = system::Opts {
        online: args.online,
        force_aur: args.force_aur,
    };
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
        let header = format!(
            "{} trust caveat(s) — review before trusting this inventory",
            inv.notes.len()
        );
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

    let eco = inv
        .deps
        .first()
        .map(|d| d.ecosystem.as_str())
        .unwrap_or(backend)
        .to_string();
    let mut forest = tree::build(inv.manager, &[eco], &inv.deps, args.depth);

    // `--online`: resolve each formula's repo reputation through the shared
    // resolver (same token/cache/scoring path as `tree --online`).
    if args.online {
        gochi::greet(ui.animating());
        let mut settings = settings::Settings::load_or_warn();
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
            resolve::Resolver::with_network(tokens, settings.tree.clone(), &settings.network)
                .with_languages(args.languages)
                .with_licenses(true);
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
    if policy.needs_vulns()
        && let Some(d) = forest
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
    // One load for both branches: the proxy and endpoint overrides apply to the
    // Arch tracker and the OSV route alike.
    let settings = settings::Settings::load_or_warn();
    let net = &settings.network;

    // Arch isn't in OSV — pacman uses its own source (the Arch Security Tracker),
    // no release needed (Arch is rolling).
    if eco == model::Ecosystem::Pacman {
        let loader = gochi::Loader::spinner(
            format!(
                "gochi querying the Arch Security Tracker for {} packages",
                inv.deps.len()
            ),
            ui.animating(),
        );
        match archsec::scan(&vuln::agent(net), &inv.deps, &net.endpoints.arch_security()) {
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
    let token = settings.vuln_token();
    if token.is_none() {
        eprintln!(
            "note: no mlab token — vuln scans use the anonymous limit. \
             Set VULN_MLAB_TOKEN or vuln_token in ~/.postmortem/config.yml."
        );
    }
    let loader = gochi::Loader::spinner(
        format!(
            "gochi querying vuln.mlab.sh for {} {osv_eco} packages",
            inv.deps.len()
        ),
        ui.animating(),
    );
    match osv::scan(
        &vuln::agent(net),
        &cache::Cache::open(),
        token.as_deref(),
        &inv.deps,
        &osv_eco,
        &vuln::scan_url(net),
    ) {
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
