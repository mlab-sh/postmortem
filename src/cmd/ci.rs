//! `postmortem ci` — ready-to-commit pipeline templates.

use crate::{ci, cli};

use anyhow::{Context, Result};

/// `postmortem tree <paths>...` — resolve and render the dependency forest from
/// the lockfiles. Offline today; `--online` is reserved for repository-reputation
/// resolution (see [`crate::resolve`]). Exit 2 if no supported ecosystem was found.
/// `postmortem ci <platform>` — print a pipeline for GitLab CI, Azure DevOps or
/// Jenkins (or the shell equivalent of the GitHub Action).
pub(crate) fn run_ci(args: cli::CiArgs) -> Result<()> {
    let version = args
        .version
        .unwrap_or_else(|| format!("v{}", env!("CARGO_PKG_VERSION")));
    let out = ci::render(args.platform, &version);
    match args.output.as_deref() {
        // Default to stdout: this is meant to be piped or reviewed before it is
        // committed, not silently dropped in the cwd like the report commands.
        None => print!("{out}"),
        Some(p) if p.as_os_str() == "-" => print!("{out}"),
        Some(p) => {
            std::fs::write(p, &out).with_context(|| format!("cannot write {}", p.display()))?
        }
    }
    Ok(())
}
