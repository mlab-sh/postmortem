//! `postmortem harden` — the CIRSEC dependency baseline, evaluated.

use crate::cmd::common::{detect_and_parse, mlab_target};
use crate::harden::{self, Level, Status, repo};
use crate::{cache, cli, config, resolve, settings, ui, vuln};

use anyhow::{Context, Result};

/// `postmortem harden <path>` — evaluate every control of the chosen profile.
///
/// Exits 1 when a control fails and 2 when the project's `[harden]` settings
/// cannot be used: a broken policy must never read as a passing one.
pub(crate) fn run_harden(args: cli::HardenArgs) -> Result<()> {
    if let Some(cli::HardenAction::Info(info)) = &args.action {
        let controls = harden::controls();
        if info.json {
            println!("{}", serde_json::to_string_pretty(&harden::info_json(&controls, info.level))?);
        } else {
            harden::render_info(&controls, info.level);
        }
        return Ok(());
    }
    let ui = ui::Ui::new(!args.no_progress);
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("cannot resolve path {}", args.path.display()))?;

    let cfg_path = args.config.clone().or_else(|| {
        let c = root.join(config::DEFAULT_FILENAME);
        c.is_file().then_some(c)
    });
    let cfg = match cfg_path.as_deref().map(config::Config::load).transpose() {
        Ok(c) => c.unwrap_or_default(),
        Err(e) => fail_config(format!("{e:#}")),
    };
    let level = match (args.level, cfg.harden.level.as_deref()) {
        (Some(l), _) => l,
        (None, Some(s)) => Level::parse(s)
            .unwrap_or_else(|| fail_config(format!("[harden] level = {s:?}: expected baseline or hardened"))),
        (None, None) => Level::Baseline,
    };
    let controls = harden::controls();
    let params = harden::resolve_params(&controls, level, &cfg.harden.params)
        .unwrap_or_else(|e| fail_config(format!("{e:#}")));

    let repo = repo::Repo::load(&root);
    let pms = repo::detect_pms(&repo);
    // The graph feeds the lockfile-level controls; a project with only
    // manifests (no lockfile yet) still gets every configuration check.
    let (detected, deps) = match detect_and_parse(&root, &ui, &[]) {
        Ok(Some((d, deps, _))) => (d, deps),
        Ok(None) => (Vec::new(), Vec::new()),
        Err(e) => {
            eprintln!("warn: dependency graph unavailable: {e:#}");
            (Vec::new(), Vec::new())
        }
    };

    let mut settings = settings::Settings::load_or_warn();
    // The release-age and package-age windows are the baseline's, not the
    // `tree` defaults: `--level hardened` checks 72h, not 48h.
    settings.tree.fresh_hours = params["min_release_age_hours"];
    settings.tree.newborn_days = params["min_package_age_days"];
    let resolutions = if args.online {
        let tokens = resolve::Tokens {
            github: settings.resolve_github_token()?,
            gitlab: settings.gitlab_token(),
            codeberg: settings.codeberg_token(),
        };
        let resolver = resolve::Resolver::with_network(tokens, settings.tree.clone(), &settings.network);
        Some(resolver.resolve_all(&deps, &ui))
    } else {
        None
    };
    let vulns = args.vulns.then(|| {
        let net = settings.network.clone();
        let targets: Vec<_> = detected.iter().filter_map(mlab_target).collect();
        let mut all = Vec::new();
        for r in vuln::scan_many(
            &vuln::agent(&net),
            &cache::Cache::open(),
            settings.vuln_token().as_deref(),
            &targets,
            &vuln::scan_url(&net),
        ) {
            match r {
                Ok(v) => vuln::merge(&mut all, v),
                Err(e) => eprintln!("warn: vulnerability scan failed: {e:#}"),
            }
        }
        all
    });

    let ctx = harden::Ctx {
        repo: &repo,
        pms: &pms,
        level,
        params: &params,
        cfg: &cfg.harden,
        gate_allow: &cfg.gate.allow,
        deps: &deps,
        online: resolutions.as_ref(),
        vulns: vulns.as_deref(),
        today: chrono::Local::now().date_naive(),
    };
    let rows = harden::evaluate(&controls, &ctx);
    let label = args.path.display().to_string();
    if args.json || args.webhook.is_some() {
        let out = serde_json::to_string_pretty(&harden::to_json(&rows, &root.display().to_string(), level, &params))?;
        cli::OutputTarget::emit(args.json, args.webhook.as_deref(), args.output.as_deref(), "harden", &out)?;
    } else {
        harden::render(&rows, &controls, &label, level, &pms);
    }
    if harden::count(&rows, Status::Fail) > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn fail_config(msg: String) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(2);
}
