//! `postmortem audit` — one graded verdict over scan + inventory.

use crate::cmd::common::{self, detect_and_parse, mlab_target};
use crate::cmd::gate_policy::{build_gate_policy, load_gate_config};
use crate::{
    analyze, audit, cache, cli, config, detect, fix, gate, image, model, report, resolve,
    settings, system, tree, ui, vuln,
};
use anyhow::{Context, Result};
use std::path::PathBuf;

/// `postmortem audit <path>` — unify the static scan, dependency inventory, and
/// (opt-in) online reputation + known vulns into one graded verdict.
pub(crate) fn run_audit(args: cli::AuditArgs) -> Result<()> {
    let started = chrono::Utc::now();
    let ui = ui::Ui::new(!args.no_progress);
    // `content_root` is where the code being analyzed lives; `config_root` is
    // where this project's own policy is read from. They are the same directory
    // for a path target and deliberately different for an image: a
    // `postmortem.conf` shipped inside someone else's image must never be able
    // to relax the verdict on that image.
    let Prepared {
        content_root,
        config_root,
        label,
        ecosystems,
        detected,
        mut deps,
        diags,
        inventory,
        release,
        _image,
    } = match prepare(&args, &ui) {
        Ok(p) => p,
        // A target that cannot be read is a configuration error, not a clean
        // audit — the same exit code the gate checks below use.
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(2);
        }
    };

    // Static malware scan (offline), tallied by severity.
    // The project's own suppressions apply here too. `audit` previously ignored
    // them entirely, so a `postmortem.conf` that quieted `scan` had no effect on
    // the command sold as the one-shot verdict.
    let findings = {
        let f = analyze::run_all(&detected, &deps, &ui);
        let f = analyze::drop_test_iocs(f, args.allow_test_files, &content_root);
        let cfg = match args.config.as_deref() {
            Some(p) => config::Config::load(p)?,
            None => {
                let c = config_root.join(config::DEFAULT_FILENAME);
                if c.is_file() {
                    config::Config::load(&c)?
                } else {
                    config::Config::default()
                }
            }
        };
        let applied = cfg.apply(f, chrono::Local::now().date_naive());
        for e in &applied.expired {
            eprintln!("warn: ignore rule no longer applies — {e}");
        }
        applied.findings
    };
    let count = |sev: model::Severity| findings.iter().filter(|f| f.severity == sev).count();
    let mut summary = audit::AuditSummary {
        // Includes the image's OS backend, not just the application ecosystems:
        // a verdict that named only `node` for an image would hide the layer
        // most of its packages actually came from.
        ecosystems: ecosystems.clone(),
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
    let mut forest = tree::build(&label, &ecosystems, &deps, None);
    forest.diagnostics = diags;
    // An image's OS provenance signals join the same forest the parsers filled.
    if let Some(inv) = &inventory {
        system::annotate(&mut forest, &inv.signals);
        if !args.online {
            tree::score(&mut forest);
        }
    }
    let mut settings = settings::Settings::load_or_warn();
    if args.online {
        let tokens = resolve::Tokens {
            github: settings.resolve_github_token()?,
            gitlab: settings.gitlab_token(),
            codeberg: settings.codeberg_token(),
        };
        let resolver =
            resolve::Resolver::with_network(tokens, settings.tree.clone(), &settings.network)
                .with_languages(args.languages)
                .with_licenses(true);
        let resolutions = resolver.resolve_all(&deps, &ui);
        resolve::apply_licenses(&mut deps, &resolutions);
        tree::enrich(&mut forest, &resolutions);
        tree::score(&mut forest);
    }
    if args.vulns {
        let net = settings.network.clone();
        let (agent, cache, token) = (
            vuln::agent(&net),
            cache::Cache::open(),
            settings.vuln_token(),
        );
        let scan_url = vuln::scan_url(&net);
        for d in &detected {
            if let Some((lock, fmt)) = mlab_target(d)
                && let Ok(mut v) =
                    vuln::scan(&agent, &cache, token.as_deref(), lock, fmt, &scan_url)
            {
                forest.vulnerabilities.append(&mut v);
            }
        }
        // The OS layer of an image, pinned to the release read from the image
        // rather than from this machine.
        if let (Some(inv), Some(rel)) = (&inventory, &release) {
            common::scan_os_vulns(&mut forest, inv, Some(rel.as_str()), &ui);
        }
    }

    // The CI gate, sharing `tree`'s policy: the `[gate]` table plus CLI flags.
    let today = chrono::Local::now().date_naive();
    let policy = build_gate_policy(
        load_gate_config(&config_root, args.config.as_deref()),
        args.max_risk,
        args.max_dep,
        args.max_high,
        args.max_sus,
        args.max_vulns,
        args.fail_on_vuln,
        &args.allow,
    );

    // A threshold over data this run never collected is a misconfiguration, not
    // a pass — the same fail-closed rule `tree` applies. Checked before the
    // report so the user is not shown a green verdict they cannot trust.
    if policy.needs_scores() && !args.online {
        eprintln!(
            "error: gate thresholds (--max-risk/--max-dep/--max-high/--max-sus) require --online; \
             no scores were computed"
        );
        std::process::exit(2);
    }
    if policy.needs_vulns() && !args.vulns {
        eprintln!(
            "error: gate thresholds (--max-vulns/--fail-on-vuln) require --vulns; no vuln scan \
             was run"
        );
        std::process::exit(2);
    }

    let baseline = match args.baseline.as_deref() {
        Some(p) => match gate::Baseline::load(p) {
            Ok(b) => Some(b),
            Err(e) => {
                eprintln!("error: {e:#}");
                std::process::exit(2);
            }
        },
        None => None,
    };

    // One evaluation serves both purposes: its metrics feed the graded verdict,
    // and its outcome drives the gate.
    let outcome = gate::evaluate(&policy, &forest, today, baseline.as_ref());
    let m = &outcome.metrics;
    if args.online {
        summary.risk = Some(m.risk);
        summary.high_deps = m.high;
        summary.sus_deps = m.sus;
    }
    if args.vulns {
        summary.vulns = Some(m.vulns);
        summary.worst_vuln = m.worst_vuln;
    }

    let gate_tripped = policy.is_active().then(|| outcome.tripped());
    if args.gitlab {
        let plan = fix::plan(&deps, &forest.vulnerabilities);
        let out = report::gitlab::render_tree(
            &forest,
            &started.to_rfc3339(),
            &chrono::Utc::now().to_rfc3339(),
            Some(&plan),
        )?;
        cli::OutputTarget::emit(
            args.json,
            args.webhook.as_deref(),
            args.output.as_deref(),
            "audit",
            &out,
        )?;
    } else if args.json || args.webhook.is_some() {
        let doc = audit::to_json(&summary, &label, gate_tripped);
        let out = serde_json::to_string_pretty(&doc)?;
        cli::OutputTarget::emit(
            args.json,
            args.webhook.as_deref(),
            args.output.as_deref(),
            "audit",
            &out,
        )?;
    } else {
        audit::render(&summary, &label);
        if policy.is_active() {
            gate::report(&outcome, &policy);
        }
    }

    // Non-zero exit on a CRITICAL verdict *or* a tripped threshold. The grade is
    // the built-in floor; the gate is the policy the project layered on top, and
    // either one failing must fail the build.
    let critical = audit::grade(&summary) == audit::Grade::Critical;
    if critical || outcome.tripped() {
        std::process::exit(1);
    }
    Ok(())
}

/// A target resolved into everything `audit` needs, whether it was a directory
/// or a container image.
struct Prepared {
    content_root: PathBuf,
    config_root: PathBuf,
    label: String,
    ecosystems: Vec<String>,
    detected: Vec<detect::Detected>,
    deps: Vec<model::Dependency>,
    diags: Vec<model::Diagnostic>,
    inventory: Option<system::Inventory>,
    /// The image's own release, formatted the way `--release` accepts it.
    release: Option<String>,
    /// Holds the extracted image alive for as long as its files are read.
    _image: Option<image::Image>,
}

/// Resolve `--image` or the positional path into a [`Prepared`].
fn prepare(args: &cli::AuditArgs, ui: &ui::Ui) -> Result<Prepared> {
    let omit = cli::OmitSet::scopes(&args.omit);
    if let Some(reference) = &args.image {
        let scan = common::open_image(reference, false, ui, &omit)?;
        let content_root = scan.image.root().to_path_buf();
        let ecosystems = scan.ecosystems();
        let common::ImageScan {
            image,
            detected,
            deps,
            diags,
            inventory,
            release,
            files: _,
        } = scan;
        return Ok(Prepared {
            content_root,
            config_root: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            label: format!("image {reference}"),
            ecosystems,
            detected,
            deps,
            diags,
            inventory,
            release: release.map(|r| format!("{}:{}", r.id, r.version_id)),
            _image: Some(image),
        });
    }

    // clap guarantees one of the two is present.
    let path = args.path.as_ref().expect("a path or --image");
    let root = path
        .canonicalize()
        .with_context(|| format!("cannot resolve path {}", path.display()))?;
    let Some((detected, deps, diags)) = detect_and_parse(&root, ui, &omit)? else {
        std::process::exit(2);
    };
    Ok(Prepared {
        label: root.display().to_string(),
        content_root: root.clone(),
        config_root: root,
        ecosystems: detected.iter().map(|e| e.name().to_string()).collect(),
        detected,
        deps,
        diags,
        inventory: None,
        release: None,
        _image: None,
    })
}
