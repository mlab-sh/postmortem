//! `--image <ref>` — scan a container image the way a directory is scanned.
//!
//! An image is acquired by flattening it onto disk: `create` makes a container
//! without starting it, `export` streams that container's filesystem as a tar,
//! and the container is removed straight away. **Nothing from the image is ever
//! executed** — the whole point is to read an artifact whose code you do not
//! trust.
//!
//! Any Docker-compatible runtime can do this; see [`RUNTIMES`].
//!
//! The extracted root is deleted when the [`Image`] is dropped, the same
//! discipline `system inspect --deep` applies to the repositories it clones.
//!
//! Two things are deliberately reported rather than papered over: the platform
//! actually pulled (a multi-arch reference resolves to one of its manifests, and
//! which one is the daemon's choice, not postmortem's), and the archive entries
//! `tar` could not write (device nodes need root). Both reach the caller as
//! [`Image::notes`].

mod layers;

pub use layers::Layer;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use crate::analyze::{image_config, image_secrets};
use crate::ui::Ui;

/// Directory names never descended into when looking for a project.
///
/// The first three are kernel-virtual and empty in an image. The rest hold
/// *dependency* code: a `package.json` under `node_modules/` describes a
/// package the application installed, not the application, and treating it as a
/// project root would report one image as hundreds of projects.
const SKIP_DIRS: &[&str] = &[
    "proc",
    "sys",
    "dev",
    "node_modules",
    "vendor",
    "site-packages",
    "dist-packages",
    ".git",
    ".cache",
];

/// How deep below the image root to look for a project. Applications live near
/// the top (`/app`, `/srv`, `/usr/src/app`, `/home/<user>/<name>`); a manifest
/// deeper than this is vendored code, not the image's own project.
const MAX_DEPTH: usize = 8;

/// Files that mark a directory as a project root. This is the set
/// [`crate::detect`] keys on — kept here as names only, because the image walk
/// has to recognize a project *before* it can ask `detect` about it.
const MARKERS: &[&str] = &[
    "package.json",
    "pyproject.toml",
    "setup.py",
    "Pipfile",
    "requirements.txt",
    "Cargo.toml",
    "Gemfile.lock",
    "composer.lock",
    "go.mod",
    "pom.xml",
    "gradle.lockfile",
];

/// Extracted directories to keep looking through even after a marker is found
/// there. Only the image root qualifies: `/` holding a stray `requirements.txt`
/// must not stop the walk from reaching `/app`.
fn is_terminal_project(depth: usize) -> bool {
    depth > 0
}

/// The container runtimes postmortem can drive, in preference order.
///
/// All three speak the same four verbs with the same output shapes, so one code
/// path covers them and there is nothing to configure: whichever is installed is
/// used. podman matters because it is the default on Fedora and RHEL, where
/// Docker often is not present at all.
///
/// Apple's `container` is deliberately **not** here. Its `export` materialises a
/// container's root filesystem only once the container has been *started*, and
/// starting an image is exactly what a tool that reads untrusted artifacts must
/// never do. Supporting it means unpacking `container image save` layer by layer
/// instead, which is a different acquisition path rather than another name in
/// this list.
pub const RUNTIMES: &[&str] = &["docker", "podman", "nerdctl"];

/// The argv handed to `create`, never resolved and never run. See
/// [`create_container`].
const PLACEHOLDER_ARGV: &str = "/postmortem-never-runs-this";

/// The first runtime on `PATH`.
fn runtime() -> Result<&'static str> {
    RUNTIMES
        .iter()
        .copied()
        .find(|bin| {
            std::process::Command::new(bin)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        })
        .with_context(|| {
            format!(
                "no container runtime found on PATH (looked for {}) — one is needed to read an image",
                RUNTIMES.join(", ")
            )
        })
}

/// A container image flattened onto disk. The extracted root is removed on drop.
pub struct Image {
    /// Facts about the acquisition the report must carry: the platform the
    /// reference resolved to, and anything `tar` could not write.
    pub notes: Vec<String>,
    /// What the image *declares*: the user it runs as, its environment, labels
    /// and start command. Read for every acquisition, because it is one cheap
    /// call and it is the only part of an image that describes intent.
    pub config: image_config::Config,
    /// The layer stack, base first. Empty unless the image was acquired layer by
    /// layer, which only the `--layers` path does.
    pub layers: Vec<Layer>,
    /// Credential files a later layer hid or replaced, which therefore still ship
    /// in an earlier one. Only knowable while stacking, so only ever populated by
    /// the layer-by-layer path.
    pub removed_secrets: Vec<image_secrets::Removed>,
    /// Path as the image sees it (`/usr/bin/curl`) → the layer that last wrote it.
    owner: HashMap<String, usize>,
    root: PathBuf,
    /// Scratch directory holding the saved archive, when there was one. As large
    /// as the image, so it is deleted with the extraction.
    archive: Option<PathBuf>,
}

impl Image {
    /// The extracted filesystem root. Every backend reading an image is handed
    /// this path instead of `/`.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// How many tracked files each layer contributed, indexed like [`Self::layers`].
    pub fn files_per_layer(&self) -> Vec<usize> {
        let mut counts = vec![0usize; self.layers.len()];
        for idx in self.owner.values() {
            if let Some(c) = counts.get_mut(*idx) {
                *c += 1;
            }
        }
        counts
    }

    /// The layer a set of files belongs to.
    ///
    /// The **last** layer to write any of them, because that is the build step
    /// that put the thing in its shipped state: a package installed in one layer
    /// and patched in a later one belongs to the patch, which is the step whose
    /// author has to act.
    pub fn layer_for_files<'a>(&self, files: impl IntoIterator<Item = &'a str>) -> Option<&Layer> {
        let idx = files.into_iter().filter_map(|f| self.owner.get(f)).max()?;
        self.layers.get(*idx)
    }
}

impl Drop for Image {
    fn drop(&mut self) {
        purge(&self.root);
        if let Some(a) = &self.archive {
            purge(a);
        }
    }
}

/// Flatten `reference` into a temporary directory.
///
/// Errors when the daemon is unreachable or the reference cannot be resolved:
/// an image that could not be read must never come back as an empty scan.
pub fn acquire(reference: &str, layered: bool, ui: &Ui) -> Result<Image> {
    let phase = ui.phase(format!("acquiring image {reference}"));

    let rt = match runtime() {
        Ok(r) => r,
        Err(e) => {
            phase.abandon();
            return Err(e);
        }
    };
    let platform = match inspect_platform(rt, reference) {
        Ok(p) => p,
        Err(e) => {
            phase.abandon();
            return Err(e);
        }
    };
    let config = inspect_config(rt, reference).unwrap_or_default();
    let root = temp_root();
    let mut notes = vec![format!("platform {platform} (resolved by {rt})")];

    if layered {
        let archive = layers::archive_dir(&root);
        let stacked = (|| -> Result<layers::Stacked> {
            std::fs::create_dir_all(&root)
                .with_context(|| format!("creating {}", root.display()))?;
            layers::stack_into(rt, reference, &root, &archive, |m| phase.set(m))
        })();
        // The archive is the size of the image; it has served its purpose the
        // moment the layers are stacked.
        purge(&archive);
        let stacked = match stacked {
            Ok(s) => s,
            Err(e) => {
                purge(&root);
                phase.abandon();
                return Err(e);
            }
        };
        notes.extend(stacked.notes);
        phase.done(format!(
            "stacked {reference} ({platform}, {} layer(s))",
            stacked.layers.len()
        ));
        return Ok(Image {
            notes,
            config,
            layers: stacked.layers,
            removed_secrets: stacked.removed_secrets,
            owner: stacked.owner,
            root,
            archive: None,
        });
    }

    phase.set(format!("creating container from {reference} ({platform})"));
    let container = match create_container(rt, reference) {
        Ok(c) => c,
        Err(e) => {
            phase.abandon();
            return Err(e);
        }
    };

    // From here on the container exists, so every exit path has to remove it.
    let result = (|| -> Result<Vec<String>> {
        std::fs::create_dir_all(&root).with_context(|| format!("creating {}", root.display()))?;
        phase.set(format!("exporting {reference} filesystem"));
        export_into(rt, &container, &root)
    })();
    remove_container(rt, &container);

    let skipped = match result {
        Ok(s) => s,
        Err(e) => {
            purge(&root);
            phase.abandon();
            return Err(e);
        }
    };

    if !skipped.is_empty() {
        notes.push(format!(
            "{} archive entry/entries not extracted (device nodes and special files need root): {}",
            skipped.len(),
            preview(&skipped)
        ));
    }

    phase.done(format!("extracted {reference} ({platform})"));
    Ok(Image {
        notes,
        config,
        layers: Vec::new(),
        removed_secrets: Vec::new(),
        owner: HashMap::new(),
        root,
        archive: None,
    })
}

/// The image's declared runtime configuration.
///
/// Best-effort: a runtime that reports an unfamiliar shape costs the config
/// checks, not the scan. Every runtime in [`RUNTIMES`] exposes it under the same
/// `Config` key, so in practice this is one small call that always answers.
fn inspect_config(rt: &str, reference: &str) -> Option<image_config::Config> {
    let out = Command::new(rt)
        .args(["image", "inspect", "--format", "{{json .Config}}", reference])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    serde_json::from_slice(&out.stdout).ok()
}

/// Every project root inside an extracted image.
///
/// A directory qualifies when it holds one of [`MARKERS`]; the walk does not
/// descend past a project it has found, and never enters [`SKIP_DIRS`]. Returns
/// the roots in walk order, deepest-first ties broken by path, so a report lists
/// them deterministically.
pub fn projects(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            continue;
        }
        if has_marker(&dir) {
            out.push(dir.clone());
            if is_terminal_project(depth) {
                continue;
            }
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.filter_map(Result::ok) {
            // `is_dir` follows symlinks; an image is full of them (`/bin` →
            // `/usr/bin`) and following them walks the same tree repeatedly.
            let Ok(md) = e.path().symlink_metadata() else {
                continue;
            };
            if !md.is_dir() {
                continue;
            }
            let name = e.file_name();
            let name = name.to_string_lossy();
            if SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            stack.push((e.path(), depth + 1));
        }
    }
    out.sort();
    out
}

/// True when `dir` holds any file that marks a project root.
fn has_marker(dir: &Path) -> bool {
    MARKERS.iter().any(|m| dir.join(m).is_file())
}

/// `os/arch` the reference resolves to on this daemon. Doubles as the check that
/// the daemon is reachable and the reference exists — `docker image inspect`
/// does not pull, so a missing image is reported here rather than halfway
/// through an export.
fn inspect_platform(rt: &str, reference: &str) -> Result<String> {
    let out = Command::new(rt)
        .args([
            "image",
            "inspect",
            "--format",
            "{{.Os}}/{{.Architecture}}",
            reference,
        ])
        .output()
        .with_context(|| format!("running `{rt} image inspect` — is the daemon running?"))?;
    if out.status.success() {
        let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !p.is_empty() {
            return Ok(p);
        }
    }
    // Not present locally: pull it, then ask again. Pulling is the one network
    // access this path makes, and it is the user's own reference.
    // Even `--quiet` echoes the resolved reference on stdout, and stdout is where
    // `--json` goes. A pull is progress, not output.
    let pull = Command::new(rt)
        .args(["pull", "--quiet", reference])
        .stdout(Stdio::null())
        .status()
        .with_context(|| format!("running `{rt} pull`"))?;
    if !pull.success() {
        anyhow::bail!(
            "cannot resolve image `{reference}`: not present locally and `{rt} pull` failed"
        );
    }
    let out = Command::new(rt)
        .args([
            "image",
            "inspect",
            "--format",
            "{{.Os}}/{{.Architecture}}",
            reference,
        ])
        .output()
        .with_context(|| format!("running `{rt} image inspect`"))?;
    if !out.status.success() {
        anyhow::bail!(
            "`{rt} image inspect {reference}` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Create a container from `reference` without starting it, returning its id.
fn create_container(rt: &str, reference: &str) -> Result<String> {
    // The placeholder argv matters: `create` refuses an image that declares
    // neither `Cmd` nor `Entrypoint`, which is exactly what a distroless or
    // scratch-derived base looks like — so without it the whole acquisition
    // failed on the images people choose *for* their small attack surface.
    // Nothing is ever started, so the value is never resolved or run; it is
    // spelled out so a leaked container says what made it.
    let out = Command::new(rt)
        .args(["create", reference, PLACEHOLDER_ARGV])
        .output()
        .with_context(|| format!("running `{rt} create`"))?;
    if !out.status.success() {
        anyhow::bail!(
            "`{rt} create {reference}` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    // podman echoes progress before the id; the id is always the last line.
    let id = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next_back()
        .unwrap_or_default()
        .trim()
        .to_string();
    if id.is_empty() {
        anyhow::bail!("`{rt} create {reference}` returned no container id");
    }
    Ok(id)
}

/// Best-effort removal of the scratch container. A failure here leaks a stopped
/// container, which is worth a warning and not worth failing a scan over.
fn remove_container(rt: &str, id: &str) {
    let done = Command::new(rt)
        .args(["rm", "--force", id])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !matches!(done, Ok(s) if s.success()) {
        eprintln!(
            "warn: could not remove scratch container {id} — remove it with `{rt} rm -f {id}`"
        );
    }
}

/// Stream `docker export <id>` straight into `tar -x` under `dest`.
///
/// The two processes are piped in-process rather than through a shell so that
/// both exit codes are seen: a shell pipeline reports only the last one, and a
/// failed export followed by a happy `tar` is exactly the silent-empty-scan
/// case this refuses to produce.
///
/// Returns the entries `tar` reported it could not write.
fn export_into(rt: &str, id: &str, dest: &Path) -> Result<Vec<String>> {
    let mut export = Command::new(rt)
        .args(["export", id])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("running `{rt} export`"))?;
    let stdout = export
        .stdout
        .take()
        .with_context(|| format!("`{rt} export` produced no stream"))?;

    let tar = Command::new("tar")
        .arg("-x")
        .arg("-f")
        .arg("-")
        .arg("-C")
        .arg(dest)
        .arg("--no-same-owner")
        // Kernel-virtual directories: empty in an image, and the only entries
        // that routinely need root to recreate.
        .arg("--exclude=dev/*")
        .arg("--exclude=proc/*")
        .arg("--exclude=sys/*")
        .stdin(Stdio::from(stdout))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("running `tar` to extract the image filesystem")?;

    let export = export
        .wait_with_output()
        .with_context(|| format!("waiting on `{rt} export`"))?;
    if !export.status.success() {
        anyhow::bail!(
            "`{rt} export` failed: {}",
            String::from_utf8_lossy(&export.stderr).trim()
        );
    }

    let warnings: Vec<String> = String::from_utf8_lossy(&tar.stderr)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    // `tar` exits non-zero both for "could not write two device nodes" and for
    // "the archive was truncated". Only the second invalidates the scan, and the
    // difference is whether anything landed at all.
    if !tar.status.success() && is_empty_dir(dest) {
        anyhow::bail!(
            "extracting the image filesystem failed and produced nothing: {}",
            preview(&warnings)
        );
    }
    Ok(warnings)
}

/// True when nothing was extracted — the signal that a `tar` failure was fatal
/// rather than a handful of unwritable special files.
fn is_empty_dir(p: &Path) -> bool {
    std::fs::read_dir(p)
        .map(|mut d| d.next().is_none())
        .unwrap_or(true)
}

/// The first few lines of a warning list, for a message that stays readable.
fn preview(lines: &[String]) -> String {
    let shown: Vec<&str> = lines.iter().take(3).map(|s| s.as_str()).collect();
    if lines.len() > shown.len() {
        format!(
            "{} … (+{} more)",
            shown.join("; "),
            lines.len() - shown.len()
        )
    } else {
        shown.join("; ")
    }
}

/// A unique scratch directory under the system temp dir.
fn temp_root() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("postmortem-image-{}-{nanos}", std::process::id()))
}

/// Delete an extracted root.
///
/// An image ships read-only directories, and `remove_dir_all` does not chmod its
/// way in — so a plain removal can leave gigabytes behind. The fallback shells
/// out, guarded on the path being one this module created under the temp dir:
/// an `rm -rf` is worth writing carefully.
fn purge(root: &Path) {
    if !root.exists() {
        return;
    }
    if std::fs::remove_dir_all(root).is_ok() {
        return;
    }
    let named_by_us = root
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with("postmortem-image-"));
    if !named_by_us || !root.starts_with(std::env::temp_dir()) {
        eprintln!("warn: left {} behind — remove it by hand", root.display());
        return;
    }
    let done = Command::new("rm")
        .arg("-rf")
        .arg(root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !matches!(done, Ok(s) if s.success()) {
        eprintln!("warn: left {} behind — remove it by hand", root.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch tree that cleans itself up, so the walk tests touch no fixture.
    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tmp(tag: &str) -> Tmp {
        let p =
            std::env::temp_dir().join(format!("postmortem-imgtest-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("scratch dir");
        Tmp(p)
    }
    fn touch(root: &Path, rel: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        std::fs::write(&p, b"").expect("write");
    }

    #[test]
    fn finds_an_application_below_the_root() {
        let t = tmp("app");
        touch(&t.0, "app/package.json");
        touch(&t.0, "app/package-lock.json");
        assert_eq!(projects(&t.0), vec![t.0.join("app")]);
    }

    /// The regression this walk exists to avoid: an image's `node_modules` holds
    /// one `package.json` per installed package, and each is a dependency's
    /// manifest rather than a project of the image.
    #[test]
    fn does_not_descend_into_vendored_trees() {
        let t = tmp("vendored");
        touch(&t.0, "srv/app/package.json");
        touch(&t.0, "srv/app/node_modules/lodash/package.json");
        touch(&t.0, "srv/app/node_modules/express/package.json");
        assert_eq!(projects(&t.0), vec![t.0.join("srv/app")]);
    }

    #[test]
    fn stops_at_the_project_it_found() {
        let t = tmp("nested");
        touch(&t.0, "app/go.mod");
        touch(&t.0, "app/internal/testdata/go.mod");
        assert_eq!(projects(&t.0), vec![t.0.join("app")]);
    }

    /// A marker at the image root must not swallow the walk: base images drop
    /// files in `/`, and the application still lives in `/app`.
    #[test]
    fn a_marker_at_the_root_does_not_stop_the_walk() {
        let t = tmp("rootmarker");
        touch(&t.0, "requirements.txt");
        touch(&t.0, "app/requirements.txt");
        assert_eq!(projects(&t.0), vec![t.0.clone(), t.0.join("app")]);
    }

    #[test]
    fn several_applications_are_all_reported() {
        let t = tmp("multi");
        touch(&t.0, "srv/api/Cargo.toml");
        touch(&t.0, "srv/web/package.json");
        assert_eq!(
            projects(&t.0),
            vec![t.0.join("srv/api"), t.0.join("srv/web")]
        );
    }

    #[test]
    fn kernel_virtual_directories_are_skipped() {
        let t = tmp("virt");
        touch(&t.0, "proc/1/package.json");
        touch(&t.0, "sys/kernel/go.mod");
        touch(&t.0, "app/Cargo.toml");
        assert_eq!(projects(&t.0), vec![t.0.join("app")]);
    }

    #[test]
    fn an_image_with_no_project_reports_none() {
        let t = tmp("bare");
        touch(&t.0, "etc/passwd");
        touch(&t.0, "usr/bin/sh");
        assert!(projects(&t.0).is_empty());
    }

    #[test]
    fn purge_only_shells_out_for_paths_it_created() {
        // The guard, not the removal: a path outside the temp dir must never
        // reach `rm -rf`, so purging a non-existent one is a no-op.
        let outside = Path::new("/definitely/not/ours");
        purge(outside);
        assert!(!outside.exists());
    }

    #[test]
    fn preview_caps_the_warning_list() {
        let many: Vec<String> = (0..7).map(|i| format!("line{i}")).collect();
        let s = preview(&many);
        assert!(s.contains("line0") && s.contains("(+4 more)"), "{s}");
        assert!(!s.contains("line5"));
    }
}
