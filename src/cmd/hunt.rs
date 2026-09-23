//! `postmortem hunt` — incident response: which projects pinned a compromised
//! package, and when.

use std::time::Instant;

use crate::{cli, hunt};

use anyhow::{Context, Result};

pub(crate) fn run_hunt(args: cli::HuntArgs) -> Result<()> {
    let mut targets: Vec<hunt::Target> = args.targets.iter().filter_map(|s| hunt::Target::parse(s)).collect();
    if let Some(feed) = &args.feed {
        let text = std::fs::read_to_string(feed)
            .with_context(|| format!("cannot read feed {}", feed.display()))?;
        targets.extend(text.lines().filter_map(hunt::Target::parse));
    }
    targets.dedup();
    if targets.is_empty() {
        anyhow::bail!("nothing to hunt: pass name@version targets or --feed <file>");
    }
    let roots: Vec<_> = args
        .within
        .iter()
        .map(|p| p.canonicalize().with_context(|| format!("cannot resolve {}", p.display())))
        .collect::<Result<_>>()?;

    let ui = crate::ui::Ui::new(!args.no_progress);
    let started = Instant::now();
    let phase = ui.phase("discovering projects");
    let (projects, dirs) = hunt::discover(&roots);
    let discovery_ms = started.elapsed().as_millis();
    phase.done(format!("{} project(s) in {dirs} dirs", projects.len()));

    let outcome = hunt::hunt(&projects, &targets, !args.no_history, ui.animating());
    let elapsed = started.elapsed().as_millis();

    if args.json || args.webhook.is_some() {
        let out = serde_json::to_string_pretty(&hunt::to_json(&outcome, &targets, &roots, elapsed))?;
        cli::OutputTarget::emit(
            args.json,
            args.webhook.as_deref(),
            args.output.as_deref(),
            "hunt",
            &out,
        )?;
    } else {
        hunt::render(&outcome, &targets, (dirs, discovery_ms), elapsed);
    }

    // Any exposure, past or present, fails: a package removed last week still
    // ran its install scripts on every machine that installed it meanwhile.
    if hunt::exposed(&outcome) > 0 {
        std::process::exit(1);
    }
    Ok(())
}
