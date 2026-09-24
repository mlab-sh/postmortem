//! `postmortem timeline` — a package's release history, in order.

use crate::cmd::common::parse_detected;
use crate::{cli, detect, model, resolve, settings, timeline, ui};

use anyhow::Result;

/// `postmortem timeline <package>` — the package's release history, in order.
///
/// Fetches the npm packument and lays out what changed at each release. The
/// project path is used only to mark which version is installed; a project that
/// does not have the package still gets the history.
pub(crate) fn run_timeline(args: cli::TimelineArgs) -> Result<()> {
    let ui = ui::Ui::new(!args.no_progress);
    let mut settings = settings::Settings::load_or_warn();
    let tokens = resolve::Tokens {
        github: settings.resolve_github_token()?,
        gitlab: settings.gitlab_token(),
        codeberg: settings.codeberg_token(),
    };
    let resolver =
        resolve::Resolver::with_network(tokens, settings.tree.clone(), &settings.network);
    let phase = ui.phase(format!("fetching {} history", args.package));
    let (doc, installed) = std::thread::scope(|s| {
        // The installed version, found while the packument downloads. Only the
        // Node lockfiles are parsed — nothing else can hold an npm version — and
        // quietly, under the fetch's progress line. Best-effort: the history
        // stands on its own, so a project that fails to resolve costs the "you
        // are here" marker and nothing else.
        let installed = s.spawn(|| {
            let root = args.path.canonicalize().ok()?;
            let node: Vec<_> = detect::detect_target(&root)
                .ok()?
                .into_iter()
                .filter(|d| matches!(d, detect::Detected::Node { .. }))
                .collect();
            if node.is_empty() {
                return None;
            }
            let (_, deps, _) = parse_detected(node, &ui::Ui::new(false), &[]).ok()?;
            deps.into_iter()
                .find(|d| d.name == args.package && d.ecosystem == model::Ecosystem::Node)
                .map(|d| d.version)
        });
        let doc = resolver.packument(&args.package);
        (doc, installed.join().ok().flatten())
    });
    let Some(doc) = doc? else {
        phase.abandon();
        anyhow::bail!("{} is not on the npm registry", args.package);
    };
    let t = timeline::build(&doc, &args.package, installed.as_deref());
    phase.done(format!("{} release(s)", t.releases.len()));
    if args.json || args.webhook.is_some() {
        let out = serde_json::to_string_pretty(&timeline::to_json(&t))?;
        cli::OutputTarget::emit(
            args.json,
            args.webhook.as_deref(),
            args.output.as_deref(),
            "timeline",
            &out,
        )?;
    } else {
        timeline::render(&t, args.all);
    }
    Ok(())
}
