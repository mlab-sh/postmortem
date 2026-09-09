//! `postmortem diff` — what a change does to the dependency set.

use crate::cmd::common::{self, detect_and_parse, mlab_target};
use crate::{cache, cli, detect, diff, model, pr, resolve, settings, ui, vuln};

use anyhow::{Context, Result};

use std::path::{Path, PathBuf};

/// `postmortem diff <old> <new>` — resolve both projects offline and report the
/// added / removed / version-changed dependencies.
///
/// `<old>` may instead be a GitHub pull-request URL, in which case both sides
/// are fetched from it and `<new>` is omitted.
pub(crate) fn run_diff(args: cli::DiffArgs) -> Result<()> {
    let ui = ui::Ui::new(!args.no_progress);

    // Both sides are filtered identically — a scope-filtered diff of an
    // unfiltered baseline would report every dev package as "removed".
    let omit = cli::OmitSet::scopes(&args.omit);
    let resolve_deps = |path: &Path| -> Result<Vec<model::Dependency>> {
        let root = path
            .canonicalize()
            .with_context(|| format!("cannot resolve path {}", path.display()))?;
        match detect_and_parse(&root, &ui, &omit)? {
            // A PR side legitimately has no dependencies (the base predates the
            // lockfile, say), and that is a diff of "everything added", not an
            // error — so only a *path* the user typed is worth failing on.
            None => Ok(Vec::new()),
            Some((_, deps, _)) => Ok(deps),
        }
    };

    // A PR URL supplies both sides; two specs supply one each. Both guards are
    // held to the end of the function because dropping either deletes the files
    // the dependency lists were read from.
    let mut settings = settings::Settings::load_or_warn();
    let mut _images: Vec<common::ImageScan> = Vec::new();

    // `image://<ref>` on either side compares a built artifact instead of a
    // source tree. `diff image://app:1.2.0 image://app:1.2.1` is the review of a
    // version bump that no lockfile can give you, because the OS layer underneath
    // the application moves too — and it is where compromises actually land.
    if image_ref(&args.old).is_some() || args.new.as_deref().and_then(image_ref).is_some() {
        let Some(new_spec) = args.new.clone() else {
            anyhow::bail!("comparing an image needs two sides: an old one and a new one");
        };
        let mut side = |spec: &str| -> Result<(Vec<model::Dependency>, Vec<detect::Detected>)> {
            match image_ref(spec) {
                Some(reference) => {
                    let scan = common::open_image(reference, false, &ui, &omit)?;
                    let (deps, detected) = (scan.deps.clone(), scan.detected.clone());
                    _images.push(scan);
                    Ok((deps, detected))
                }
                None => {
                    let root = Path::new(spec);
                    let deps = resolve_deps(root)?;
                    let detected = root
                        .canonicalize()
                        .ok()
                        .and_then(|r| detect::detect_target(&r).ok())
                        .unwrap_or_default();
                    Ok((deps, detected))
                }
            }
        };
        let (old, _) = side(&args.old)?;
        let (new, new_detected) = side(&new_spec)?;
        if old.is_empty() && new.is_empty() {
            anyhow::bail!("no supported ecosystem detected on either side");
        }
        return finish_diff(
            &args,
            old,
            new,
            label(&args.old),
            label(&new_spec),
            new_detected,
            &ui,
        );
    }

    let (old_path, new_path, old_label, new_label, _sides) = match pr::parse_url(&args.old) {
        Some(reference) => {
            if args.new.is_some() {
                anyhow::bail!(
                    "a pull-request URL already names both sides — drop the second argument"
                );
            }
            let sides = pr::materialize(&reference, &mut settings, &ui)?;
            if sides.files == 0 {
                anyhow::bail!(
                    "no manifests or lockfiles found in {}/{} at either side of PR #{}",
                    reference.owner,
                    reference.repo,
                    reference.number
                );
            }
            let m = &sides.meta;
            let fork = m
                .head_repo
                .as_deref()
                .map(|r| format!(" [{r}]"))
                .unwrap_or_default();
            let (ol, nl) = (
                format!("{} ({})", m.base_ref, short(&m.base_sha)),
                format!("{}{fork} ({})", m.head_ref, short(&m.head_sha)),
            );
            (sides.base.clone(), sides.head.clone(), ol, nl, Some(sides))
        }
        None => {
            let Some(new) = args.new.clone() else {
                anyhow::bail!(
                    "expected two paths, or one GitHub pull-request URL \
                     (https://github.com/owner/repo/pull/42)"
                );
            };
            let (o, n) = (PathBuf::from(&args.old), PathBuf::from(&new));
            let (ol, nl) = (args.old.clone(), new);
            (o, n, ol, nl, None)
        }
    };

    let old = resolve_deps(&old_path)?;
    let new = resolve_deps(&new_path)?;
    if old.is_empty() && new.is_empty() {
        anyhow::bail!("no supported ecosystem detected on either side");
    }
    let new_root = new_path.canonicalize().unwrap_or_else(|_| new_path.clone());
    let new_detected = detect::detect_target(&new_root).unwrap_or_default();
    finish_diff(&args, old, new, old_label, new_label, new_detected, &ui)
}

/// Assess and render a diff, whatever the two sides were.
///
/// `new_detected` is the *new* side's manifests: advisories are looked up per
/// lockfile, and those files live wherever that side was materialised — a
/// directory, a fetched PR, or an extracted image.
#[allow(clippy::too_many_arguments)]
fn finish_diff(
    args: &cli::DiffArgs,
    old: Vec<model::Dependency>,
    new: Vec<model::Dependency>,
    old_label: String,
    new_label: String,
    new_detected: Vec<detect::Detected>,
    ui: &ui::Ui,
) -> Result<()> {
    let mut report = diff::diff(&old, &new);

    // Assess only what the change introduces. The added/changed packages are
    // looked up in the *new* set to get their real `Dependency` (with the
    // resolved URL and integrity the resolver needs) rather than reconstructed.
    if args.online || args.vulns {
        let introduced = report.introduced();
        let subject: Vec<model::Dependency> = new
            .iter()
            .filter(|d| {
                introduced
                    .iter()
                    .any(|(e, n, v)| *e == d.ecosystem && *n == d.name && *v == d.version)
            })
            .cloned()
            .collect();
        let mut settings = settings::Settings::load_or_warn();
        let resolutions = if args.online && !subject.is_empty() {
            let tokens = resolve::Tokens {
                github: settings.resolve_github_token()?,
                gitlab: settings.gitlab_token(),
                codeberg: settings.codeberg_token(),
            };
            resolve::Resolver::with_network(tokens, settings.tree.clone(), &settings.network)
                .resolve_all(&subject, ui)
        } else {
            Default::default()
        };

        // Advisories are looked up per lockfile, so the new project is scanned
        // whole and the results filtered — `assess` keeps only the introduced
        // packages, which is what a reviewer is being asked to approve.
        let mut vulns = Vec::new();
        if args.vulns {
            let net = settings.network.clone();
            let (agent, cache, token) = (
                vuln::agent(&net),
                cache::Cache::open(),
                settings.vuln_token(),
            );
            let scan_url = vuln::scan_url(&net);
            for d in &new_detected {
                if let Some((lock, fmt)) = mlab_target(d)
                    && let Ok(mut v) =
                        vuln::scan(&agent, &cache, token.as_deref(), lock, fmt, &scan_url)
                {
                    vulns.append(&mut v);
                }
            }
        }
        diff::assess(&mut report, &resolutions, &vulns);
    }

    let (ol, nl) = (old_label, new_label);
    if args.json || args.webhook.is_some() {
        let doc = diff::to_json(&report, &ol, &nl);
        let out = serde_json::to_string_pretty(&doc)?;
        cli::OutputTarget::emit(
            args.json,
            args.webhook.as_deref(),
            args.output.as_deref(),
            "diff",
            &out,
        )?;
    } else {
        diff::render(&report, &ol, &nl);
    }
    Ok(())
}

/// An abbreviated commit SHA, for labelling the two sides of a PR diff.
fn short(sha: &str) -> &str {
    &sha[..sha.len().min(8)]
}


/// The scheme that names a container image as a diff side.
const IMAGE_PREFIX: &str = "image://";

/// The reference behind an `image://` spec, or `None` for anything else.
fn image_ref(spec: &str) -> Option<&str> {
    spec.strip_prefix(IMAGE_PREFIX)
        .map(str::trim)
        .filter(|r| !r.is_empty())
}

/// How a side is labelled in the report: an image by its reference, anything
/// else by what the user typed.
fn label(spec: &str) -> String {
    match image_ref(spec) {
        Some(reference) => format!("image {reference}"),
        None => spec.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_sides_are_recognised_and_labelled() {
        assert_eq!(image_ref("image://alpine:3.19"), Some("alpine:3.19"));
        assert_eq!(image_ref("image:// ghcr.io/o/r:1 "), Some("ghcr.io/o/r:1"));
        // A path is a path, and an empty reference is not a side.
        assert_eq!(image_ref("./app"), None);
        assert_eq!(image_ref("image://"), None);
        assert_eq!(image_ref("https://github.com/o/r/pull/42"), None);

        assert_eq!(label("image://alpine:3.19"), "image alpine:3.19");
        assert_eq!(label("./app"), "./app");
    }
}
