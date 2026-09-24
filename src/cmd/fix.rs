//! `postmortem fix` — the change that clears the vulnerability report.

use crate::cmd::common::{detect_and_parse, mlab_target};
use crate::{cache, cli, fix, gochi, settings, ui, vuln};

use anyhow::{Context, Result};

/// `postmortem fix <path>` — plan the upgrade that clears the known advisories.
///
/// Always scans vulnerabilities: a fix plan without them would have nothing to
/// plan. Exits 1 while anything is outstanding so it works as a CI step, unless
/// `--no-fail` says otherwise.
pub(crate) fn run_fix(args: cli::FixArgs) -> Result<()> {
    let ui = ui::Ui::new(!args.no_progress);
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("cannot resolve path {}", args.path.display()))?;
    let Some((detected, deps, _)) =
        detect_and_parse(&root, &ui, &cli::OmitSet::scopes(&args.omit))?
    else {
        anyhow::bail!("no supported ecosystem detected at {}", root.display());
    };
    let settings = settings::Settings::load_or_warn();
    let net = settings.network.clone();
    let (agent, cache, token) = (
        vuln::agent(&net),
        cache::Cache::open(),
        settings.vuln_token(),
    );
    let scan_url = vuln::scan_url(&net);
    let loader = gochi::Loader::spinner("gochi looking up advisories", ui.animating());
    let mut vulns = Vec::new();
    // An ecosystem the advisory API cannot read is not a clean one, and a plan
    // that silently omitted it would read as "nothing to fix".
    let unscannable: Vec<String> = detected
        .iter()
        .filter(|d| mlab_target(d).is_none())
        .map(|d| d.name().to_string())
        .collect();
    // Every lockfile at once; the first failure, in detection order, aborts.
    let (scanned, targets): (Vec<_>, Vec<_>) = detected
        .iter()
        .filter_map(|d| mlab_target(d).map(|t| (d, t)))
        .unzip();
    let scans = vuln::scan_many(&agent, &cache, token.as_deref(), &targets, &scan_url);
    for (d, scan) in scanned.into_iter().zip(scans) {
        match scan {
            Ok(mut v) => vulns.append(&mut v),
            Err(e) => {
                loader.finish(gochi::Mood::Bad, "advisory lookup failed");
                return Err(e).with_context(|| format!("scanning {}", d.name()));
            }
        }
    }
    let plan = fix::plan(&deps, &vulns);
    loader.finish(
        if plan.is_empty() {
            gochi::Mood::Happy
        } else {
            gochi::Mood::Alert
        },
        format!("{} package(s) to fix", plan.remedies.len()),
    );
    if args.json || args.webhook.is_some() {
        let out = serde_json::to_string_pretty(&fix::to_json(&plan, &root.display().to_string()))?;
        cli::OutputTarget::emit(
            args.json,
            args.webhook.as_deref(),
            args.output.as_deref(),
            "fix",
            &out,
        )?;
    } else {
        fix::render(&plan, &args.path.display().to_string());
        if !unscannable.is_empty() {
            eprintln!(
                "\nwarn: {} not covered by the advisory API — those dependencies are unassessed, \
                 not clean",
                unscannable.join(", ")
            );
        }
    }

    if !args.no_fail && !plan.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}
