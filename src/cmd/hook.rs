//! `postmortem hook` — the git pre-commit hook.

use crate::{cli, gochi, hook};

use anyhow::{Context, Result};

/// `postmortem hook <action>` — manage the git pre-commit hook.
pub(crate) fn run_hook(args: cli::HookArgs) -> Result<()> {
    use owo_colors::OwoColorize;
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("cannot resolve path {}", args.path.display()))?;
    match args.action {
        cli::HookAction::Status => {
            let st = hook::state(&root)?;
            hook::render_status(&root, &st);
        }
        cli::HookAction::Install(i) => {
            let p = hook::install(&root, &i.run, i.force)?;
            gochi::say(
                gochi::Mood::Happy,
                format!("pre-commit hook written to {}", p.display()),
            );
            println!(
                "  {}",
                format!("it runs `postmortem {}` when a lockfile is staged", i.run).dimmed()
            );
            // Said at install time, not buried in docs: this is the moment
            // somebody forms an expectation about what they are protected from.
            println!(
                "  {}",
                "this does not stop a malicious install script — that already ran; it stops \
                 the bad lockfile reaching the rest of the team."
                    .dimmed()
            );
        }
        cli::HookAction::Uninstall => {
            if hook::uninstall(&root)? {
                gochi::say(gochi::Mood::Happy, "pre-commit hook removed");
            } else {
                gochi::say(gochi::Mood::Idle, "no postmortem hook was installed");
            }
        }
    }
    Ok(())
}
