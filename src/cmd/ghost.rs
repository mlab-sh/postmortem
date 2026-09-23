//! `postmortem ghost` — does each npm dependency's tarball match its source?

use crate::cmd::common::detect_and_parse;
use crate::model::Ecosystem;
use crate::{cli, ghost, resolve, settings, ui};

use anyhow::{Context, Result};

pub(crate) fn run_ghost(args: cli::GhostArgs) -> Result<()> {
    if !ghost::git_available() {
        anyhow::bail!("`git` is required for ghost but was not found on PATH");
    }
    let ui = ui::Ui::new(!args.no_progress);
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("cannot resolve path {}", args.path.display()))?;
    let Some((_, deps, _)) = detect_and_parse(&root, &ui, &cli::OmitSet::scopes(&args.omit))?
    else {
        anyhow::bail!("no supported ecosystem detected at {}", root.display());
    };

    // npm only, registry versions only: a git/file/link dependency has no
    // tarball on the registry to compare.
    let mut skipped = 0;
    let mut targets: Vec<_> = deps
        .into_iter()
        .filter(|d| {
            let npm = d.ecosystem == Ecosystem::Node
                && d.resolved_url.as_deref().is_none_or(|u| u.starts_with("http"));
            skipped += usize::from(!npm);
            npm
        })
        .filter(|d| {
            if args.package.is_empty() {
                args.all || d.direct
            } else {
                args.package.contains(&d.name)
            }
        })
        .collect();
    targets.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    targets.dedup_by(|a, b| a.name == b.name && a.version == b.version);
    if targets.is_empty() {
        anyhow::bail!("no npm dependency to compare (--all includes transitive ones)");
    }

    let mut settings = settings::Settings::load_or_warn();
    let tokens = resolve::Tokens {
        github: settings.resolve_github_token()?,
        gitlab: settings.gitlab_token(),
        codeberg: settings.codeberg_token(),
    };
    let resolver =
        resolve::Resolver::with_network(tokens, settings.tree.clone(), &settings.network);
    let reports = ghost::check_all(&resolver, &targets, ui.animating())?;

    let label = args.path.display().to_string();
    if args.json || args.webhook.is_some() {
        let out = serde_json::to_string_pretty(&ghost::to_json(&reports, &label, skipped))?;
        cli::OutputTarget::emit(
            args.json,
            args.webhook.as_deref(),
            args.output.as_deref(),
            "ghost",
            &out,
        )?;
    } else {
        ghost::render(&reports, &label, skipped);
    }

    // A ghost always fails. Unverifiable is reported, not failed: most of it
    // is repos that simply do not tag releases.
    if ghost::count(&reports, ghost::Verdict::Ghost) > 0 {
        std::process::exit(1);
    }
    Ok(())
}
