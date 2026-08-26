//! `postmortem tree` — the resolved dependency graph, with the online
//! reputation, vulnerability and gate passes layered on top.

use crate::cmd::common::{detect_and_parse, mlab_target, vuln_count, vuln_summary};
use crate::cmd::gate_policy::resolve_gate_policy;
use crate::{
    cache, cli, fix, gate, gochi, human, model, report, resolve, settings, tree, ui, vuln,
};
use anyhow::Result;

pub(crate) fn run_tree(args: cli::TreeArgs) -> Result<()> {
    let started = chrono::Utc::now();
    let machine = args.json || args.sarif || args.html || args.gitlab;
    if args.paths.len() > 1 && machine && !args.allow_multiple {
        anyhow::bail!(
            "machine formats (--json/--sarif/--html/--gitlab) support a single target; got {}. \
             Pass --allow-multiple to emit them all — note the shape changes: \
             --json becomes an array of trees, --sarif one runs[] entry per target, \
             and --html one page per target concatenated.",
            args.paths.len()
        );
    }
    if args.human && !args.online {
        anyhow::bail!(
            "--human needs --online: maintainer sets come from the package registry, and \
             nothing in a lockfile names who can publish"
        );
    }
    if args.allow_multiple && !machine {
        eprintln!(
            "note: --allow-multiple only affects --json/--sarif/--html; the terminal view already renders every target"
        );
    }

    let ui = ui::Ui::new(!args.no_progress);

    // Online resolution shares one resolver (and its cache/token) across paths.
    let mut settings = settings::Settings::load_or_warn();
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
        Some(
            resolve::Resolver::with_network(tokens, settings.tree.clone(), &settings.network)
                .with_languages(args.languages)
                .with_licenses(true),
        )
    } else {
        None
    };

    // mlab vuln-scan context (agent + cache + token + endpoint), independent of --online.
    let vuln_ctx = if args.vulns {
        if settings.vuln_token().is_none() {
            eprintln!(
                "note: no mlab token — vuln scans use the anonymous 8/h limit. \
                 Set VULN_MLAB_TOKEN or vuln_token in ~/.postmortem/config.yml."
            );
        }
        Some((
            vuln::agent(&settings.network),
            cache::Cache::open(),
            settings.vuln_token(),
            vuln::scan_url(&settings.network),
        ))
    } else {
        None
    };
    let today = chrono::Local::now().date_naive();
    let mut any_detected = false;
    let mut gate_tripped = false;
    let mut gate_misconfig = false;
    let mut machine_trees: Vec<tree::Tree> = Vec::new();
    // Kept alongside the trees purely so --gitlab can run `fix` over them: the
    // GitLab report's `solution` is the upgrade target, and computing it needs
    // the dependency graph the tree alone does not carry.
    let mut machine_deps: Vec<Vec<model::Dependency>> = Vec::new();
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
                ui.note(format!(
                    "no supported ecosystem detected at {}",
                    target.display()
                ));
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
        let (detected, mut deps, diags) = parsed;
        any_detected = true;
        let ecosystems: Vec<String> = detected.iter().map(|e| e.name().to_string()).collect();
        let mut forest = tree::build(&root.display().to_string(), &ecosystems, &deps, args.depth);
        forest.diagnostics = diags;
        if let Some(resolver) = &resolver {
            let resolutions = resolver.resolve_all(&deps, &ui);
            resolve::apply_licenses(&mut deps, &resolutions);

            // The maintainer graph replaces the tree view rather than adding to
            // it: it answers a different question over the same resolution.
            if args.human {
                let g = human::graph(&deps, &resolutions);
                if args.json {
                    let out = serde_json::to_string_pretty(&human::to_json(
                        &g,
                        &deps,
                        &root.display().to_string(),
                    ))?;
                    cli::OutputTarget::resolve_named(args.output.as_deref(), "human", "json")
                        .write(&out)?;
                } else {
                    human::render(&g, &deps, &root.display().to_string());
                }
                continue;
            }

            tree::enrich(&mut forest, &resolutions);
            tree::score(&mut forest);
        }

        if let Some((agent, cache, token, scan_url)) = &vuln_ctx {
            let loader = gochi::Loader::spinner(
                "gochi querying vuln.mlab.sh for advisories",
                ui.animating(),
            );
            for d in &detected {
                loader.step(format!("gochi checking {} advisories", d.name()));
                match mlab_target(d) {
                    Some((lock, fmt)) => {
                        match vuln::scan(agent, cache, token.as_deref(), lock, fmt, scan_url) {
                            Ok(mut v) => forest.vulnerabilities.append(&mut v),
                            Err(e) => forest.diagnostics.push(model::Diagnostic {
                                ecosystem: d.name().into(),
                                kind: "vuln_scan_failed".into(),
                                message: format!("vuln scan failed: {e:#}"),
                            }),
                        }
                    }
                    None => forest.diagnostics.push(model::Diagnostic {
                        ecosystem: d.name().into(),
                        kind: "vuln_unsupported".into(),
                        message: "mlab vuln scan does not support this lockfile format".into(),
                    }),
                }
            }
            loader.finish(
                gochi::Mood::from_risk(0, 0, vuln_count(&forest)),
                vuln_summary(&forest),
            );
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
            if args.gitlab {
                machine_deps.push(deps);
            }
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
        } else if args.html {
            // One document per target: HTML has no multi-run container the way
            // SARIF does, so several targets are concatenated as separate pages.
            let out = machine_trees
                .iter()
                .map(report::html::render_tree)
                .collect::<Vec<_>>()
                .join("\n");
            cli::OutputTarget::resolve_named(args.output.as_deref(), "tree", "html").write(&out)?;
        } else if args.gitlab {
            // GitLab reads one report per job artifact, so --allow-multiple has
            // nothing to widen here: the first target is the one reported.
            let plan = fix::plan(
                machine_deps.first().map(Vec::as_slice).unwrap_or(&[]),
                &machine_trees[0].vulnerabilities,
            );
            let out = report::gitlab::render_tree(
                &machine_trees[0],
                &started.to_rfc3339(),
                &chrono::Utc::now().to_rfc3339(),
                Some(&plan),
            )?;
            cli::OutputTarget::resolve_named(args.output.as_deref(), "tree", "json").write(&out)?;
        } else {
            let out = match args.allow_multiple {
                true => report::sarif::render_trees(&machine_trees)?,
                false => report::sarif::render_tree(&machine_trees[0])?,
            };
            cli::OutputTarget::resolve_named(args.output.as_deref(), "tree", "sarif")
                .write(&out)?;
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
