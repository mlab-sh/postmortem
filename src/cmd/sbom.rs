//! `postmortem sbom` — CycloneDX export.

use crate::cmd::common::{self, detect_and_parse, license_resolver};
use crate::{cli, resolve, sbom, ui};

use anyhow::{Context, Result};

/// `postmortem sbom <path>` — resolve the project and emit a CycloneDX 1.5 SBOM.
///
/// With `--image` the component is the image reference and the inventory spans
/// both of its layers: the applications inside it and the OS packages beneath
/// them. An image SBOM that listed only one of the two would understate what is
/// actually shipped.
pub(crate) fn run_sbom(args: cli::SbomArgs) -> Result<()> {
    let ui = ui::Ui::new(!args.no_progress);
    let omit = cli::OmitSet::scopes(&args.omit);
    // The image is bound for the whole function: its extracted filesystem has to
    // outlive the license resolution that reads out of it.
    let image = match &args.image {
        Some(reference) => Some(common::open_image(reference, false, &ui, &omit)?),
        None => None,
    };
    let (name, mut deps) = match (&image, &args.path) {
        (Some(scan), _) => (
            args.image.clone().unwrap_or_default(),
            scan.deps.clone(),
        ),
        (None, Some(path)) => {
            let root = path
                .canonicalize()
                .with_context(|| format!("cannot resolve path {}", path.display()))?;
            let Some((_, deps, _)) = detect_and_parse(&root, &ui, &omit)? else {
                anyhow::bail!("no supported ecosystem detected at {}", root.display());
            };
            let name = root
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("project")
                .to_string();
            (name, deps)
        }
        // clap guarantees one of the two is present.
        (None, None) => unreachable!("clap requires a path or --image"),
    };
    if args.online {
        let resolutions = license_resolver(&ui)?.resolve_all(&deps, &ui);
        resolve::apply_licenses(&mut deps, &resolutions);
    }
    let name = name.as_str();
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
