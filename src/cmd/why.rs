//! `postmortem why` — why a package is installed, and what a compromise
//! of it would reach.

use crate::cmd::common::detect_and_parse;
use crate::{analyze, blast, cli, ui, why};

use anyhow::{Context, Result};

/// `postmortem why <package> <path>` — show the dependency paths from a package
/// up to the direct dependencies.
pub(crate) fn run_why(args: cli::WhyArgs) -> Result<()> {
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
    let label = args.path.display().to_string();
    if args.blast {
        // The behavioural half needs the offline analyzers; the positional half
        // does not, so a failure there would still leave a useful answer — but
        // running them is cheap and local, so they always run.
        let findings = {
            let f = analyze::run_all(&detected, &deps, &ui);
            analyze::drop_test_iocs(f, false, &root)
        };
        // Whether the dependencies' own code was on disk decides between "no
        // install hook" and "could not check" — see `blast::Trigger::Unknown`.
        let code_scanned = analyze::scans_dependency_code(&detected);
        let Some(b) = blast::analyze(&deps, &findings, &args.package, code_scanned) else {
            anyhow::bail!("{} is not in the dependency graph", args.package);
        };
        if args.json || args.webhook.is_some() {
            let out = serde_json::to_string_pretty(&blast::to_json(&b, &label))?;
            cli::OutputTarget::emit(
            args.json,
            args.webhook.as_deref(),
            args.output.as_deref(),
            "blast",
            &out,
        )?;
        } else {
            blast::render(&b, &label);
        }
        return Ok(());
    }

    if args.json || args.webhook.is_some() {
        let doc = why::to_json(&deps, &args.package, &label);
        let out = serde_json::to_string_pretty(&doc)?;
        cli::OutputTarget::emit(
            args.json,
            args.webhook.as_deref(),
            args.output.as_deref(),
            "why",
            &out,
        )?;
    } else {
        why::render(&deps, &args.package, &label);
    }
    Ok(())
}
