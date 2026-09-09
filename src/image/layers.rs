//! Layer-by-layer acquisition: `<runtime> save`, then stack the layers by hand.
//!
//! The default acquisition path asks the runtime to flatten the image for us
//! (`export`). This one does the flattening itself, which costs more disk and
//! more time and buys two things nothing else can:
//!
//! - **attribution.** Every file remembers which layer last wrote it, and every
//!   layer remembers the build instruction that produced it. "This vulnerable
//!   package entered at `RUN apt-get install -y curl`" is a different sentence
//!   from "this image contains a vulnerable package", and only one of them tells
//!   you where to go and fix it.
//! - **a path that never creates a container.** `save` reads the image store
//!   directly, so unlike `export` there is no scratch container to create, leak
//!   or clean up.
//!
//! It is also the shape a registry client would produce, since a registry hands
//! out layer blobs rather than a flattened filesystem.
//!
//! ## Whiteouts
//!
//! A layer deletes a file from the layers below it by adding a marker instead of
//! removing anything: `.wh.<name>` deletes that sibling, and `.wh..wh..opq`
//! empties the directory it sits in. Applying these in order is what separates
//! stacking layers from concatenating them — get it wrong and a file the image
//! deleted, such as a credential or a build tool the author removed on purpose,
//! reappears in the report as if it shipped.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use serde::Deserialize;

/// Above this many recorded paths, attribution is dropped rather than allowed to
/// grow without bound. A very large image is exactly the case where the map costs
/// the most and the answer helps the least: the caller is told, and the rest of
/// the scan is unaffected.
const MAX_TRACKED_PATHS: usize = 400_000;

/// One layer of an image, and the build step that produced it.
#[derive(Clone, Debug)]
pub struct Layer {
    /// Position in the stack; 0 is the base.
    pub index: usize,
    /// The build instruction from the image config's history, cleaned of the
    /// shell wrapper buildkit adds. Empty when the image carries no history.
    pub created_by: String,
}

impl Layer {
    /// A short, single-line form for a report.
    ///
    /// A build instruction is recorded with its line continuations intact, so
    /// folding it onto one line leaves stray backslashes behind; they are
    /// dropped, because they were never part of the command.
    pub fn summary(&self) -> String {
        let one_line = self
            .created_by
            .split_whitespace()
            .filter(|t| *t != "\\")
            .collect::<Vec<_>>()
            .join(" ");
        let trimmed = match one_line.char_indices().nth(100) {
            Some((i, _)) => format!("{}…", &one_line[..i]),
            None => one_line,
        };
        match trimmed.is_empty() {
            true => format!("layer {}", self.index),
            false => format!("layer {}: {trimmed}", self.index),
        }
    }
}

/// What stacking an image produced.
pub struct Stacked {
    pub layers: Vec<Layer>,
    /// Path as the image sees it (`/usr/bin/curl`) → the layer that last wrote
    /// it. Empty when the image was too large to track.
    pub owner: HashMap<String, usize>,
    /// Acquisition facts worth reporting.
    pub notes: Vec<String>,
}

/// The docker-archive index `save` writes at the root of its tar.
#[derive(Deserialize)]
struct ArchiveManifest {
    #[serde(rename = "Config")]
    config: String,
    #[serde(rename = "Layers")]
    layers: Vec<String>,
}

/// The image config blob, reduced to the build history.
#[derive(Deserialize)]
struct ImageConfig {
    #[serde(default)]
    history: Vec<HistoryEntry>,
}

#[derive(Deserialize)]
struct HistoryEntry {
    #[serde(default)]
    created_by: String,
    /// A history entry that produced no filesystem layer (`ENV`, `CMD`, …).
    #[serde(default)]
    empty_layer: bool,
}

/// Save `reference` and stack its layers into `root`.
///
/// `archive` is a scratch directory for the saved blobs; the caller owns its
/// lifetime, because it can be as large as the image itself.
pub fn stack_into(
    rt: &str,
    reference: &str,
    root: &Path,
    archive: &Path,
    mut progress: impl FnMut(String),
) -> Result<Stacked> {
    progress(format!("saving {reference}"));
    save_into(rt, reference, archive)?;

    let manifest = read_manifest(archive)?;
    let history = read_history(archive, &manifest.config)?;
    let mut notes = Vec::new();

    // History lists every build instruction; only the non-empty ones consumed a
    // layer, and they line up with the layer list in order.
    let mut instructions = history
        .into_iter()
        .filter(|h| !h.empty_layer)
        .map(|h| clean_instruction(&h.created_by));
    let layers: Vec<Layer> = manifest
        .layers
        .iter()
        .enumerate()
        .map(|(index, _)| Layer {
            index,
            created_by: instructions.next().unwrap_or_default(),
        })
        .collect();

    let mut owner: HashMap<String, usize> = HashMap::new();
    let mut tracking = true;
    for (index, rel) in manifest.layers.iter().enumerate() {
        progress(format!(
            "stacking layer {}/{}",
            index + 1,
            manifest.layers.len()
        ));
        let blob = archive.join(rel);
        let entries =
            list_entries(&blob).with_context(|| format!("listing layer {index} of {reference}"))?;
        apply_whiteouts(root, &entries);
        extract_layer(&blob, root)
            .with_context(|| format!("extracting layer {index} of {reference}"))?;
        if tracking {
            for e in &entries {
                if e.ends_with('/') || basename(e).starts_with(".wh.") {
                    continue;
                }
                if owner.len() >= MAX_TRACKED_PATHS {
                    tracking = false;
                    owner.clear();
                    notes.push(format!(
                        "over {MAX_TRACKED_PATHS} files: per-file layer attribution was not recorded"
                    ));
                    break;
                }
                owner.insert(format!("/{}", e.trim_start_matches("./")), index);
            }
        }
    }

    Ok(Stacked {
        layers,
        owner,
        notes,
    })
}

/// `<rt> save <ref>` streamed straight into `tar -x` under `dest`.
fn save_into(rt: &str, reference: &str, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest).with_context(|| format!("creating {}", dest.display()))?;
    let mut save = Command::new(rt)
        .args(["save", reference])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("running `{rt} save`"))?;
    let stdout = save
        .stdout
        .take()
        .with_context(|| format!("`{rt} save` produced no stream"))?;
    let tar = Command::new("tar")
        .arg("-x")
        .arg("-f")
        .arg("-")
        .arg("-C")
        .arg(dest)
        .arg("--no-same-owner")
        .stdin(Stdio::from(stdout))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("running `tar` to unpack the saved image")?;
    let save = save
        .wait_with_output()
        .with_context(|| format!("waiting on `{rt} save`"))?;
    if !save.status.success() {
        anyhow::bail!(
            "`{rt} save {reference}` failed: {}",
            String::from_utf8_lossy(&save.stderr).trim()
        );
    }
    if !tar.status.success() {
        anyhow::bail!(
            "unpacking the saved image failed: {}",
            String::from_utf8_lossy(&tar.stderr).trim()
        );
    }
    Ok(())
}

/// The single-image entry of a saved archive's `manifest.json`.
fn read_manifest(archive: &Path) -> Result<ArchiveManifest> {
    let path = archive.join("manifest.json");
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "reading {} — the saved archive is not in the expected layout",
            path.display()
        )
    })?;
    let mut manifests: Vec<ArchiveManifest> =
        serde_json::from_str(&text).context("parsing the saved image manifest")?;
    if manifests.len() > 1 {
        anyhow::bail!(
            "the reference resolved to {} images; name one of them explicitly",
            manifests.len()
        );
    }
    manifests.pop().context("the saved archive lists no image")
}

/// The build history from the image's config blob. An image with no history is
/// not an error: layers still stack, they just carry no instruction.
fn read_history(archive: &Path, config: &str) -> Result<Vec<HistoryEntry>> {
    let path = archive.join(config);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading the image config {}", path.display()))?;
    let cfg: ImageConfig = serde_json::from_str(&text).context("parsing the image config")?;
    Ok(cfg.history)
}

/// Strip the wrappers a builder puts around the instruction it recorded, so what
/// is reported is what the Dockerfile said.
fn clean_instruction(raw: &str) -> String {
    let s = raw.trim();
    // buildkit: `RUN /bin/sh -c apt-get install … # buildkit`
    let s = s.strip_suffix("# buildkit").unwrap_or(s).trim();
    // classic builder: `/bin/sh -c #(nop)  ENV PATH=…`
    if let Some(rest) = s.split("#(nop)").nth(1) {
        return rest.trim().to_string();
    }
    if let Some(rest) = s.strip_prefix("/bin/sh -c ") {
        return format!("RUN {}", rest.trim());
    }
    s.to_string()
}

/// The member names of a layer blob.
fn list_entries(blob: &Path) -> Result<Vec<String>> {
    let out = Command::new("tar")
        .arg("-tf")
        .arg(blob)
        .output()
        .context("running `tar -tf` on a layer")?;
    if !out.status.success() {
        anyhow::bail!(
            "`tar -tf` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim_end().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// Apply this layer's deletions to what the layers below it already wrote.
///
/// Must run *before* the layer is extracted: an opaque marker clears a directory
/// that this same layer then refills, and clearing it afterwards would delete the
/// image's own content.
fn apply_whiteouts(root: &Path, entries: &[String]) {
    for e in entries {
        let name = basename(e);
        let Some(parent_rel) = e.strip_suffix(name) else {
            continue;
        };
        let parent = root.join(parent_rel.trim_start_matches("./"));
        if name == ".wh..wh..opq" {
            // Everything the lower layers put in this directory is hidden.
            if let Ok(dir) = std::fs::read_dir(&parent) {
                for entry in dir.flatten() {
                    remove_any(&entry.path());
                }
            }
        } else if let Some(target) = name.strip_prefix(".wh.") {
            remove_any(&parent.join(target));
        }
    }
}

/// Extract one layer over the accumulated root, dropping the whiteout markers
/// themselves — they are instructions, not files the image ships.
fn extract_layer(blob: &Path, root: &Path) -> Result<()> {
    let out = Command::new("tar")
        .arg("-x")
        .arg("-f")
        .arg(blob)
        .arg("-C")
        .arg(root)
        .arg("--no-same-owner")
        .arg("--exclude=.wh.*")
        .arg("--exclude=*/.wh.*")
        .arg("--exclude=dev/*")
        .arg("--exclude=proc/*")
        .arg("--exclude=sys/*")
        .output()
        .context("running `tar` to extract a layer")?;
    // As with the flat path, `tar` exits non-zero both for a handful of
    // unwritable special files and for a truncated archive. Only the second is
    // fatal, and the difference is whether anything landed.
    if !out.status.success() && is_empty_dir(root) {
        anyhow::bail!(
            "extracting a layer produced nothing: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Remove a path whatever it is, ignoring what is not there.
fn remove_any(p: &Path) {
    let Ok(md) = p.symlink_metadata() else { return };
    let _ = match md.is_dir() {
        true => std::fs::remove_dir_all(p),
        false => std::fs::remove_file(p),
    };
}

fn is_empty_dir(p: &Path) -> bool {
    std::fs::read_dir(p)
        .map(|mut d| d.next().is_none())
        .unwrap_or(true)
}

/// The last path segment of a tar member name, keeping a trailing `/` off.
fn basename(entry: &str) -> &str {
    let e = entry.trim_end_matches('/');
    match e.rsplit_once('/') {
        Some((_, name)) => name,
        None => e,
    }
}

/// A scratch directory for a saved archive, beside the extraction it feeds.
pub fn archive_dir(root: &Path) -> PathBuf {
    let mut name = root.file_name().unwrap_or_default().to_os_string();
    name.push("-archive");
    root.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basenames_of_tar_members() {
        assert_eq!(basename("usr/bin/curl"), "curl");
        assert_eq!(basename("usr/bin/"), "bin");
        assert_eq!(basename("curl"), "curl");
        assert_eq!(basename("./etc/.wh.passwd"), ".wh.passwd");
    }

    #[test]
    fn build_instructions_are_unwrapped() {
        assert_eq!(
            clean_instruction("RUN /bin/sh -c apt-get update # buildkit"),
            "RUN /bin/sh -c apt-get update"
        );
        assert_eq!(
            clean_instruction("/bin/sh -c #(nop)  ENV PATH=/usr/bin"),
            "ENV PATH=/usr/bin"
        );
        assert_eq!(
            clean_instruction("/bin/sh -c apt-get install -y curl"),
            "RUN apt-get install -y curl"
        );
        assert_eq!(clean_instruction("  COPY app /app  "), "COPY app /app");
    }

    #[test]
    fn a_layer_summary_stays_one_short_line() {
        let l = Layer {
            index: 3,
            created_by: "RUN apt-get update \\\n  && apt-get install -y curl".into(),
        };
        let s = l.summary();
        assert!(
            s.starts_with("layer 3: RUN apt-get update && apt-get"),
            "{s}"
        );
        assert!(!s.contains('\n'));

        let long = Layer {
            index: 1,
            created_by: "x".repeat(200),
        };
        assert!(long.summary().ends_with('…'));

        // An image with no history still names its layer.
        assert_eq!(
            Layer {
                index: 0,
                created_by: String::new()
            }
            .summary(),
            "layer 0"
        );
    }

    /// The rule that separates stacking from concatenating: a file the image
    /// deleted must not reappear, and an opaque marker empties a whole directory.
    #[test]
    fn whiteouts_delete_from_the_layers_below() {
        let root = std::env::temp_dir().join(format!("postmortem-wh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc")).expect("etc");
        std::fs::create_dir_all(root.join("opt/cache/sub")).expect("cache");
        std::fs::write(root.join("etc/secret"), b"x").expect("secret");
        std::fs::write(root.join("etc/keep"), b"x").expect("keep");
        std::fs::write(root.join("opt/cache/a"), b"x").expect("a");
        std::fs::write(root.join("opt/cache/sub/b"), b"x").expect("b");

        apply_whiteouts(
            &root,
            &[
                "etc/.wh.secret".to_string(),
                "opt/cache/.wh..wh..opq".to_string(),
            ],
        );

        assert!(!root.join("etc/secret").exists(), "the deletion applied");
        assert!(root.join("etc/keep").exists(), "its sibling survived");
        assert!(
            !root.join("opt/cache/a").exists() && !root.join("opt/cache/sub").exists(),
            "an opaque marker empties the directory, subdirectories included"
        );
        assert!(
            root.join("opt/cache").is_dir(),
            "the directory itself stays"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_archive_dir_sits_beside_the_extraction() {
        let d = archive_dir(Path::new("/tmp/postmortem-image-1-2"));
        assert_eq!(d, Path::new("/tmp/postmortem-image-1-2-archive"));
    }
}
