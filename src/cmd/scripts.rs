//! `postmortem scripts` — what runs at install time.

use crate::cmd::common::detect_and_parse;
use crate::{analyze, cli, detect, scripts, ui};

use anyhow::{Context, Result};

/// `postmortem scripts <path>` — which dependencies execute code at install
/// time, whether each is approved, and what its script does.
///
/// Fully offline: which packages run code comes from the lockfile, and what the
/// scripts do comes from the analyzers reading whatever is on disk.
pub(crate) fn run_scripts(args: cli::ScriptsArgs) -> Result<()> {
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

    // Which packages run code: from the lockfile, so this works uninstalled.
    let mut with_scripts = std::collections::BTreeSet::new();
    for d in &detected {
        if let detect::Detected::Node { lockfile, .. } = d {
            with_scripts.extend(scripts::lockfile_install_scripts(lockfile));
        }
    }
    // What those scripts do: needs the code, which may not be there.
    let findings = analyze::run_all(&detected, &deps, &ui);
    let code_scanned = analyze::scans_dependency_code(&detected);
    let approvals = scripts::read_approvals(&root);
    let report = scripts::build(&deps, &with_scripts, &approvals, &findings, code_scanned);
    if args.json {
        let out =
            serde_json::to_string_pretty(&scripts::to_json(&report, &root.display().to_string()))?;
        cli::OutputTarget::resolve_named(args.output.as_deref(), "scripts", "json").write(&out)?;
    } else {
        scripts::render(&report, &args.path.display().to_string());
    }

    // A flagged script always fails; merely-pending only when asked, since a
    // fresh project has everything pending and that is not a finding.
    if report.flagged() > 0 || (args.fail_on_pending && report.pending() > 0) {
        std::process::exit(1);
    }
    Ok(())
}
