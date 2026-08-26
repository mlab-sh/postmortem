//! `postmortem audit` — one graded verdict over scan + inventory.

use crate::cmd::common::{detect_and_parse, mlab_target};
use crate::cmd::gate_policy::{build_gate_policy, load_gate_config};
use crate::{
    analyze, audit, cache, cli, config, fix, gate, model, report, resolve, settings, tree, ui, vuln,
};
use anyhow::{Context, Result};

/// `postmortem audit <path>` — unify the static scan, dependency inventory, and
/// (opt-in) online reputation + known vulns into one graded verdict.
pub(crate) fn run_audit(args: cli::AuditArgs) -> Result<()> {
    let started = chrono::Utc::now();
    let ui = ui::Ui::new(!args.no_progress);
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("cannot resolve path {}", args.path.display()))?;
    let Some((detected, mut deps, diags)) =
        detect_and_parse(&root, &ui, &cli::OmitSet::scopes(&args.omit))?
    else {
        std::process::exit(2);
    };

    // Static malware scan (offline), tallied by severity.
    // The project's own suppressions apply here too. `audit` previously ignored
    // them entirely, so a `postmortem.conf` that quieted `scan` had no effect on
    // the command sold as the one-shot verdict.
    let findings = {
        let f = analyze::run_all(&detected, &deps, &ui);
        let f = analyze::drop_test_iocs(f, args.allow_test_files, &root);
        let cfg = match args.config.as_deref() {
            Some(p) => config::Config::load(p)?,
            None => {
                let c = root.join(config::DEFAULT_FILENAME);
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
    }

    // The CI gate, sharing `tree`'s policy: the `[gate]` table plus CLI flags.
    let today = chrono::Local::now().date_naive();
    let policy = build_gate_policy(
        load_gate_config(&root, args.config.as_deref()),
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
        cli::OutputTarget::resolve_named(args.output.as_deref(), "audit", "json").write(&out)?;
    } else if args.json {
        let doc = audit::to_json(&summary, &args.path.display().to_string(), gate_tripped);
        let out = serde_json::to_string_pretty(&doc)?;
        cli::OutputTarget::resolve_named(args.output.as_deref(), "audit", "json").write(&out)?;
    } else {
        audit::render(&summary, &args.path.display().to_string());
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
