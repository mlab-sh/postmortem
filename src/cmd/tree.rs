//! `postmortem tree` — the resolved dependency graph, with the online
//! reputation, vulnerability and gate passes layered on top.

use crate::cmd::common::{self, detect_and_parse, mlab_target, vuln_count, vuln_summary};
use crate::cmd::gate_policy::resolve_gate_policy;
use crate::{
    cache, cli, detect, fix, gate, gochi, human, image, model, report, resolve, settings, system,
    tree, ui, vuln,
};
use anyhow::Result;
use std::path::PathBuf;

/// One target of a `tree` run: a path on disk, or the single container image
/// `--image` names.
enum Job<'a> {
    Path(&'a PathBuf),
    Image(&'a str),
}

/// A target resolved into everything the rendering pass needs, whichever kind of
/// target it was.
struct Prepared {
    /// Where `postmortem.conf` and the gate policy are looked up. For an image
    /// this is the working directory: the project's policy governs the run, and
    /// a config file that happens to sit inside someone else's image must never
    /// be allowed to relax it.
    root: PathBuf,
    /// What the report calls this target.
    label: String,
    ecosystems: Vec<String>,
    detected: Vec<detect::Detected>,
    deps: Vec<model::Dependency>,
    diags: Vec<model::Diagnostic>,
    /// The image's OS packages, when the target was an image whose database
    /// could be read.
    inventory: Option<system::Inventory>,
    /// The image's own OS release, pinned so the OS vuln scan can never fall
    /// through to this machine's.
    release: Option<osv_release::Pinned>,
    /// Holds the extracted image alive: the lockfiles the vuln scan uploads live
    /// inside it, so it must outlive the whole iteration.
    _image: Option<image::Image>,
}

/// A release formatted the way `--release` accepts it, so the shared OS vuln
/// scan can be pinned to the image rather than to this machine.
mod osv_release {
    pub struct Pinned(pub String);
    impl Pinned {
        pub fn of(r: &crate::osv::Release) -> Pinned {
            Pinned(format!("{}:{}", r.id, r.version_id))
        }
    }
}

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
    // One job per target. `--image` names exactly one and conflicts with paths,
    // so the two never mix and the loop below stays a single code path.
    let jobs: Vec<Job> = match &args.image {
        Some(reference) => vec![Job::Image(reference.as_str())],
        None => args.paths.iter().map(Job::Path).collect(),
    };
    for job in jobs {
        let Prepared {
            root,
            label,
            ecosystems,
            detected,
            mut deps,
            diags,
            inventory,
            release,
            _image,
        } = match job {
            Job::Path(path) => {
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
                let parsed = match detect_and_parse(&target, &ui, &cli::OmitSet::scopes(&args.omit))
                {
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
                let (detected, deps, diags) = parsed;
                Prepared {
                    label: root.display().to_string(),
                    root,
                    ecosystems: detected.iter().map(|e| e.name().to_string()).collect(),
                    detected,
                    deps,
                    diags,
                    inventory: None,
                    release: None,
                    _image: None,
                }
            }
            // An image that cannot be acquired is a configuration error for the
            // same reason a missing path is: an empty tree would read as clean.
            Job::Image(reference) => {
                match common::open_image(reference, &ui, &cli::OmitSet::scopes(&args.omit)) {
                    Ok(scan) => {
                        let ecosystems = scan.ecosystems();
                        let common::ImageScan {
                            image,
                            detected,
                            deps,
                            diags,
                            inventory,
                            release,
                        } = scan;
                        Prepared {
                            root: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
                            label: format!("image {reference}"),
                            ecosystems,
                            detected,
                            deps,
                            diags,
                            inventory,
                            release: release.as_ref().map(osv_release::Pinned::of),
                            _image: Some(image),
                        }
                    }
                    Err(e) => {
                        ui.note(format!("{e:#}"));
                        gate_misconfig = true;
                        continue;
                    }
                }
            }
        };
        any_detected = true;
        let mut forest = tree::build(&label, &ecosystems, &deps, args.depth);
        forest.diagnostics = diags;
        // An image's OS provenance signals (install scripts, third-party
        // repositories) land on the same nodes the parsers produced, so one tree
        // carries both layers.
        if let Some(inv) = &inventory {
            system::annotate(&mut forest, &inv.signals);
            if resolver.is_none() {
                // Online runs score after enrichment. Offline, this is the only
                // pass that can turn those signals into a `risk:dep` figure.
                tree::score(&mut forest);
            }
        }
        if let Some(resolver) = &resolver {
            let resolutions = resolver.resolve_all(&deps, &ui);
            resolve::apply_licenses(&mut deps, &resolutions);

            // The maintainer graph replaces the tree view rather than adding to
            // it: it answers a different question over the same resolution.
            if args.human {
                let g = human::graph(&deps, &resolutions);
                if args.json || args.webhook.is_some() {
                    let out = serde_json::to_string_pretty(&human::to_json(
                        &g,
                        &deps,
                        &label,
                    ))?;
                    cli::OutputTarget::emit(
            args.json,
            args.webhook.as_deref(),
            args.output.as_deref(),
            "human",
            &out,
        )?;
                } else {
                    human::render(&g, &deps, &label);
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

        // An image's OS packages take the same OSV route `system` uses, pinned
        // to the release read out of the image. Without that pin the shared
        // helper would fall back to this machine's `/etc/os-release` and match
        // an Alpine image against the host distribution's advisories.
        if args.vulns
            && let (Some(inv), Some(rel)) = (&inventory, &release)
        {
            common::scan_os_vulns(&mut forest, inv, Some(rel.0.as_str()), &ui);
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
                     --online; no scores were computed for {label}"
                );
                gate_misconfig = true;
            } else if policy.needs_vulns() && !args.vulns {
                eprintln!(
                    "error: gate thresholds (--max-vulns/--fail-on-vuln) require --vulns; no vuln \
                     scan was run for {label}"
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
        if args.json || args.webhook.is_some() {
            let out = match args.allow_multiple {
                true => serde_json::to_string_pretty(&machine_trees)?,
                false => serde_json::to_string_pretty(&machine_trees[0])?,
            };
            cli::OutputTarget::emit(
            args.json,
            args.webhook.as_deref(),
            args.output.as_deref(),
            "tree",
            &out,
        )?;
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
            cli::OutputTarget::emit(
            args.json,
            args.webhook.as_deref(),
            args.output.as_deref(),
            "tree",
            &out,
        )?;
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
