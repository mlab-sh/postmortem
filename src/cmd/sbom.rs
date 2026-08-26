//! `postmortem sbom` — CycloneDX export.

use crate::cmd::common::{detect_and_parse, license_resolver};
use crate::{cli, resolve, sbom, ui};

use anyhow::{Context, Result};

/// `postmortem sbom <path>` — resolve the project and emit a CycloneDX 1.5 SBOM.
pub(crate) fn run_sbom(args: cli::SbomArgs) -> Result<()> {
    let ui = ui::Ui::new(!args.no_progress);
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("cannot resolve path {}", args.path.display()))?;
    let Some((_, mut deps, _)) = detect_and_parse(&root, &ui, &cli::OmitSet::scopes(&args.omit))?
    else {
        anyhow::bail!("no supported ecosystem detected at {}", root.display());
    };
    if args.online {
        let resolutions = license_resolver(&ui)?.resolve_all(&deps, &ui);
        resolve::apply_licenses(&mut deps, &resolutions);
    }
    let name = root
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("project");
    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let bom = sbom::cyclonedx(name, &deps, &timestamp);
    let out = serde_json::to_string_pretty(&bom)?;
    cli::OutputTarget::emit(
            true,
            args.webhook.as_deref(),
            args.output.as_deref(),
            "sbom",
            &out,
        )?;
    Ok(())
}
