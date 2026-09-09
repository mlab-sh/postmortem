//! Work every command shares: turning a path into a parsed dependency
//! graph, and the two summaries more than one command prints.

use crate::{
    analyze, archsec, cache, detect, gochi, image, model, osv, parsers, resolve, scope, settings,
    system, tree, ui, vuln,
};

use anyhow::Result;

use std::path::Path;

/// Detected ecosystems, parsed dependencies, and any diagnostics.
type ParsedProject = (
    Vec<detect::Detected>,
    Vec<model::Dependency>,
    Vec<model::Diagnostic>,
);

/// Map a detected ecosystem to the lockfile + mlab `format` its vuln API
/// accepts, or `None` when mlab doesn't support that format (pnpm/yarn, poetry/
/// Pipfile, Java).
pub(crate) fn mlab_target(d: &detect::Detected) -> Option<(&Path, &'static str)> {
    let base = |p: &Path| {
        p.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string()
    };
    match d {
        detect::Detected::Node { lockfile, .. } => matches!(
            base(lockfile).as_str(),
            "package-lock.json" | "npm-shrinkwrap.json"
        )
        .then_some((lockfile.as_path(), "npm")),
        detect::Detected::Rust { lockfile, .. } => Some((lockfile.as_path(), "cargo")),
        detect::Detected::Php { lockfile, .. } => Some((lockfile.as_path(), "composer")),
        detect::Detected::Ruby { lockfile, .. } => Some((lockfile.as_path(), "gem")),
        detect::Detected::Go {
            lockfile: Some(go_sum),
            ..
        } => Some((go_sum.as_path(), "go")),
        detect::Detected::Python {
            lockfile, manifest, ..
        } => {
            if lockfile
                .as_ref()
                .is_some_and(|p| base(p) == "requirements.txt")
            {
                lockfile.as_deref().map(|p| (p, "pip"))
            } else if base(manifest) == "requirements.txt" {
                Some((manifest.as_path(), "pip"))
            } else {
                None
            }
        }
        detect::Detected::Go { .. } | detect::Detected::Java { .. } => None,
    }
}

/// Detect ecosystems and parse every lockfile at `target` — a project directory,
/// or a manifest/lockfile pinning one ecosystem (see [`detect::detect_target`]).
/// Shared by every project-level command. Returns `None` when no supported
/// ecosystem is present, else the detected ecosystems, the parsed dependencies,
/// and any diagnostics (parse failures / incomplete graphs) so a `0` result is
/// never mistaken for "clean". Errors when an explicitly pinned file can't be
/// used.
///
/// `omit` drops whole dependency sets (`--omit dev`). It is applied here, at the
/// single point every command funnels through, so the filter cannot drift
/// between `scan`, `tree`, `audit`, `sbom`, `why` and `diff` — and so scope
/// propagation runs exactly once, over the merged multi-ecosystem graph.
pub(crate) fn detect_and_parse(
    target: &Path,
    ui: &ui::Ui,
    omit: &[model::Scope],
) -> Result<Option<ParsedProject>> {
    let detect_phase = ui.phase("detecting ecosystems");
    let detected = match detect::detect_target(target) {
        Ok(d) => d,
        Err(e) => {
            detect_phase.abandon();
            return Err(e);
        }
    };
    if detected.is_empty() {
        detect_phase.abandon();
        return Ok(None);
    }
    detect_phase.done(format!(
        "detected {}: {}",
        detected.len(),
        detected
            .iter()
            .map(|e| e.name())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    parse_detected(detected, ui, omit).map(Some)
}

/// Parse an already-detected set of ecosystems into one dependency graph.
///
/// Split out from [`detect_and_parse`] because detection is what varies: a
/// directory detects one project, and a container image detects one per
/// application found inside it. Everything after detection — the per-ecosystem
/// parsers, the diagnostics they raise, scope propagation and `--omit` — has to
/// behave identically whichever way the ecosystems were found, and the only way
/// to guarantee that is for there to be one copy of it.
pub(crate) fn parse_detected(
    detected: Vec<detect::Detected>,
    ui: &ui::Ui,
    omit: &[model::Scope],
) -> Result<ParsedProject> {
    let parse_phase = ui.phase("parsing dependencies");
    let mut deps = Vec::new();
    let mut diags: Vec<model::Diagnostic> = Vec::new();
    let mut diag = |eco: &str, kind: &str, message: String| {
        parse_phase.note(format!("warn: {message}"));
        diags.push(model::Diagnostic {
            ecosystem: eco.into(),
            kind: kind.into(),
            message,
        });
    };
    for eco in &detected {
        parse_phase.set(format!("parsing {} manifest", eco.name()));
        match eco {
            // Dispatch Node by lockfile flavor: npm (JSON), pnpm (YAML), yarn (v1/berry).
            detect::Detected::Node {
                manifest, lockfile, ..
            } => {
                let fname = lockfile.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let parsed = match fname {
                    "pnpm-lock.yaml" => parsers::pnpm::parse(lockfile),
                    "yarn.lock" => parsers::yarn::parse(manifest, lockfile),
                    _ => parsers::node::parse_lockfile(lockfile),
                };
                match parsed {
                    Ok(mut d) => deps.append(&mut d),
                    Err(e) => diag(
                        "node",
                        "parse_failed",
                        format!("{fname} parse failed: {e:#}"),
                    ),
                }
            }
            detect::Detected::Python {
                manifest, lockfile, ..
            } => match parsers::python::parse_any(manifest, lockfile.as_deref()) {
                Ok(mut d) => deps.append(&mut d),
                Err(e) => diag(
                    "python",
                    "parse_failed",
                    format!("python parse failed: {e:#}"),
                ),
            },
            detect::Detected::Rust {
                manifest, lockfile, ..
            } => match parsers::rust::parse_lockfile(lockfile, Some(manifest)) {
                Ok(mut d) => deps.append(&mut d),
                Err(e) => diag(
                    "rust",
                    "parse_failed",
                    format!("Cargo.lock parse failed: {e:#}"),
                ),
            },
            detect::Detected::Ruby {
                manifest, lockfile, ..
            } => match parsers::ruby::parse_lockfile(lockfile, manifest.as_deref()) {
                Ok(mut d) => deps.append(&mut d),
                Err(e) => diag(
                    "ruby",
                    "parse_failed",
                    format!("Gemfile.lock parse failed: {e:#}"),
                ),
            },
            detect::Detected::Php {
                manifest, lockfile, ..
            } => match parsers::php::parse_lockfile(lockfile, manifest.as_deref()) {
                Ok(mut d) => deps.append(&mut d),
                Err(e) => diag(
                    "php",
                    "parse_failed",
                    format!("composer.lock parse failed: {e:#}"),
                ),
            },
            detect::Detected::Go {
                manifest, lockfile, ..
            } => {
                match parsers::go::parse(manifest, lockfile.as_deref()) {
                    Ok(mut d) => deps.append(&mut d),
                    Err(e) => diag("go", "parse_failed", format!("go.mod parse failed: {e:#}")),
                }
                // go.mod carries no edge data — the graph is a flat classified list.
                diag(
                    "go",
                    "flat_graph",
                    "go graph is flat — transitive parent edges are not reconstructed offline (needs `go mod graph`)".into(),
                );
                for (from, to) in parsers::go::replaces(manifest) {
                    diag(
                        "go",
                        "replace_directive",
                        format!(
                            "go.mod replaces {from} => {to} (module redirected — verify the target)"
                        ),
                    );
                }
            }
            detect::Detected::Java {
                manifest, lockfile, ..
            } => {
                match parsers::java::parse(manifest.as_deref(), lockfile.as_deref()) {
                    Ok(mut d) => deps.append(&mut d),
                    Err(e) => diag(
                        "java",
                        "parse_failed",
                        format!("JVM manifest/lockfile parse failed: {e:#}"),
                    ),
                }
                diag(
                    "java",
                    "flat_graph",
                    "JVM graph is flat — Maven lists direct deps only and Gradle locks carry no edges (no transitive closure offline)".into(),
                );
            }
        }
    }
    // Parsers only classify the *direct* deps a manifest names; resolve the rest
    // of the graph before any filtering, so `--omit dev` acts on real reachability
    // rather than on what happened to be listed under devDependencies.
    scope::propagate(&mut deps);
    if omit.is_empty() {
        parse_phase.done(format!("parsed {} dependencies", deps.len()));
    } else {
        let before = deps.len();
        let dropped: Vec<String> = omit
            .iter()
            .map(|s| format!("{} {}", scope::count(&deps, *s), s.as_str()))
            .collect();
        deps = scope::apply_omit(deps, omit);
        let removed = before - deps.len();
        let detail = format!(
            "{removed} of {before} dependencies omitted ({})",
            dropped.join(", ")
        );
        parse_phase.done(format!("parsed {} dependencies — {detail}", deps.len()));
        // Also record it as a diagnostic. The progress UI is suppressed when
        // stderr isn't a TTY, so in CI the summary above never prints — and a
        // silently smaller dependency set is exactly what this project refuses
        // to ship. As a diagnostic the fact reaches --json and --sarif too.
        if removed > 0 {
            diags.push(model::Diagnostic {
                ecosystem: "*".into(),
                kind: model::DIAG_SCOPE_OMITTED.into(),
                message: detail,
            });
        }
    }

    Ok((detected, deps, diags))
}

/// A resolver configured only to fill in licenses.
///
/// Reputation scoring is not wanted here, but the registry document that carries
/// the license is the same one the repo lookup fetches — so this shares the
/// resolver, and the cache, without asking for language breakdowns.
pub(crate) fn license_resolver(_ui: &ui::Ui) -> Result<resolve::Resolver> {
    let mut settings = settings::Settings::load_or_warn();
    let tokens = resolve::Tokens {
        github: settings.resolve_github_token()?,
        gitlab: settings.gitlab_token(),
        codeberg: settings.codeberg_token(),
    };
    Ok(
        resolve::Resolver::with_network(tokens, settings.tree.clone(), &settings.network)
            .with_licenses(true),
    )
}

/// Total known-vulnerability count across a forest's vulnerable packages.
pub(crate) fn vuln_count(forest: &tree::Tree) -> usize {
    forest.vulnerabilities.iter().map(|p| p.vulns.len()).sum()
}

// --- container images --------------------------------------------------------

/// One container image, flattened and parsed: the applications found inside it,
/// the OS packages underneath them, and the facts about the acquisition itself.
pub(crate) struct ImageScan {
    /// Owns the extracted filesystem. Dropping it deletes the extraction, so it
    /// has to outlive every path derived from it — which is why the caller holds
    /// the whole [`ImageScan`] rather than pulling the pieces out of it.
    #[allow(dead_code)]
    pub image: image::Image,
    pub detected: Vec<detect::Detected>,
    pub deps: Vec<model::Dependency>,
    pub diags: Vec<model::Diagnostic>,
    /// The OS inventory, when a backend could read this image's root. `None`
    /// always comes with a diagnostic saying why.
    pub inventory: Option<system::Inventory>,
    /// The release the OS layer belongs to, for the OSV ecosystem string.
    pub release: Option<osv::Release>,
    /// `package name → the files it installed`, for layer attribution. Empty
    /// unless the image was acquired layer by layer and its backend indexes files.
    pub files: std::collections::HashMap<String, Vec<String>>,
    /// Findings from what the image *declares* — a credential in its environment,
    /// a start command that fetches code, a root main process. Separate from the
    /// dependency graph because they are properties of the artifact rather than
    /// of anything installed in it.
    pub findings: Vec<model::Finding>,
}

impl ImageScan {
    /// Ecosystem labels for the report header: the application ecosystems found
    /// inside the image, plus the OS backend when one answered.
    pub fn ecosystems(&self) -> Vec<String> {
        let mut out: Vec<String> = self.detected.iter().map(|e| e.name().to_string()).collect();
        out.dedup();
        if let Some(inv) = &self.inventory {
            out.push(inv.manager.to_string());
        }
        out
    }
}

/// Flatten `reference` and read both of its layers.
///
/// The application layer reuses detection and the parsers unchanged — the only
/// difference from a directory scan is that an image may hold several projects,
/// so detection runs once per project found and the results are parsed as one
/// set. The OS layer is read by whichever backend recognises the image's package
/// database.
///
/// Every way this can come back thin is recorded as a diagnostic: no project, no
/// package database, or a database whose backend cannot yet read an alternate
/// root. An image is a black box, and "postmortem found nothing" must never be
/// indistinguishable from "postmortem did not look".
pub(crate) fn open_image(
    reference: &str,
    layered: bool,
    ui: &ui::Ui,
    omit: &[model::Scope],
) -> Result<ImageScan> {
    let image = image::acquire(reference, layered, ui)?;
    let root = image.root().to_path_buf();

    let mut diags: Vec<model::Diagnostic> = image
        .notes
        .iter()
        .map(|n| model::Diagnostic {
            ecosystem: "image".into(),
            kind: model::DIAG_INFO.into(),
            message: n.clone(),
        })
        .collect();

    // --- application layer ---------------------------------------------------
    let find_phase = ui.phase("finding projects in the image");
    let projects = image::projects(&root);
    let mut detected = Vec::new();
    // Directories holding a manifest that resolves to nothing, almost always a
    // `package.json` whose lockfile was pruned out of the final stage. Common
    // enough in images to deserve a diagnostic rather than the stderr warning
    // `detect` prints: off a TTY that warning is invisible, and a consumer
    // reading `--json` would see an application layer that simply is not there.
    let mut unresolved: Vec<String> = Vec::new();
    for p in &projects {
        match detect::detect(p) {
            Ok(d) if d.is_empty() => unresolved.push(display_in(&root, p)),
            Ok(d) => detected.extend(d),
            Err(e) => diags.push(model::Diagnostic {
                ecosystem: "image".into(),
                kind: "detect_failed".into(),
                message: format!("{}: {e:#}", display_in(&root, p)),
            }),
        }
    }
    if !unresolved.is_empty() {
        let shown: Vec<&str> = unresolved.iter().take(5).map(|s| s.as_str()).collect();
        let more = unresolved.len() - shown.len();
        diags.push(model::Diagnostic {
            ecosystem: "image".into(),
            kind: "manifest_unresolved".into(),
            message: format!(
                "{} director(y/ies) hold a manifest with no lockfile beside it, so their dependencies were not resolved: {}{}",
                unresolved.len(),
                shown.join(", "),
                if more > 0 { format!(" (+{more} more)") } else { String::new() }
            ),
        });
    }
    if projects.is_empty() {
        find_phase.done("no project manifest found in the image".to_string());
        diags.push(model::Diagnostic {
            ecosystem: "image".into(),
            kind: "no_project".into(),
            message:
                "no application manifest found in the image — its dependency graph is the OS layer only"
                    .into(),
        });
    } else {
        find_phase.done(format!(
            "found {} project(s): {}",
            projects.len(),
            projects
                .iter()
                .map(|p| display_in(&root, p))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let (detected, mut deps, parse_diags) = parse_detected(detected, ui, omit)?;
    diags.extend(parse_diags);

    // --- OS layer ------------------------------------------------------------
    let os_phase = ui.phase("reading the image's OS packages");
    let mut inventory = None;
    let mut release = None;
    let mut files = std::collections::HashMap::new();
    match system::root_manager(&root) {
        Some(manager) => match system::inventory_at(manager, &root, system::Opts::default()) {
            Ok(inv) => {
                os_phase.done(format!("{manager}: {}", inv.summary));
                release = osv::Release::detect_in(&root);
                if release.is_none() {
                    diags.push(model::Diagnostic {
                        ecosystem: manager.into(),
                        kind: "no_release".into(),
                        message:
                            "the image carries no /etc/os-release — its OS packages cannot be matched to a vulnerability ecosystem"
                                .into(),
                    });
                }
                deps.extend(inv.deps.iter().cloned());
                // Only worth the directory walk when there are layers to
                // attribute packages to.
                if layered {
                    files = system::file_index_at(manager, &root);
                }
                for note in &inv.notes {
                    diags.push(model::Diagnostic {
                        ecosystem: manager.into(),
                        kind: model::DIAG_INFO.into(),
                        message: note.clone(),
                    });
                }
                inventory = Some(inv);
            }
            Err(e) => {
                os_phase.abandon();
                diags.push(model::Diagnostic {
                    ecosystem: manager.into(),
                    kind: "os_layer_unread".into(),
                    message: format!("{e:#}"),
                });
            }
        },
        None => {
            os_phase.done("no OS package database in the image".to_string());
            diags.push(model::Diagnostic {
                ecosystem: "image".into(),
                kind: "no_os_database".into(),
                message:
                    "no apk/dpkg/rpm database in the image (scratch or distroless?) — no OS packages were examined"
                        .into(),
            });
        }
    }

    let label = format!("image {reference}");
    let mut findings = analyze::image_config::scan(&image.config, &label);
    findings.extend(analyze::image_secrets::scan(&image.removed_secrets, &label));
    if !layered {
        // The check exists only while layers are being stacked, so a flat
        // acquisition cannot have run it. Saying so beats an image that looks
        // clean of a class of finding nobody looked for.
        diags.push(model::Diagnostic {
            ecosystem: "image".into(),
            kind: model::DIAG_INFO.into(),
            message: "credentials deleted in a later layer were not checked — pass --layers"
                .into(),
        });
    }

    Ok(ImageScan {
        image,
        detected,
        deps,
        diags,
        inventory,
        release,
        files,
        findings,
    })
}

/// A path inside the image, shown the way it exists *in the image* (`/app`)
/// rather than as the scratch directory it was extracted to.
fn display_in(root: &Path, p: &Path) -> String {
    match p.strip_prefix(root) {
        Ok(rel) if rel.as_os_str().is_empty() => "/".to_string(),
        Ok(rel) => format!("/{}", rel.display()),
        Err(_) => p.display().to_string(),
    }
}

/// A one-line gochi summary of a forest's vuln scan: `N known vulnerabilities in
/// M package(s)`, or an all-clear.
pub(crate) fn vuln_summary(forest: &tree::Tree) -> String {
    let n = vuln_count(forest);
    if n == 0 {
        return "no known vulnerabilities".into();
    }
    let pkgs = forest.vulnerabilities.len();
    format!(
        "{n} known vulnerabilit{} in {pkgs} package(s)",
        if n == 1 { "y" } else { "ies" }
    )
}

// --- OS vulnerability intelligence -------------------------------------------

/// Populate `forest.vulnerabilities` from OSV.dev for an OS inventory, or push a
/// `vuln_source_unavailable` diagnostic when the release can't be resolved or
/// OSV doesn't cover this backend.
///
/// Shared by `system` (this machine) and `--image` (an extracted image root).
/// `release_override` is what pins which of the two is being described: an image
/// MUST pass its own release, because falling through to this machine's
/// `/etc/os-release` would match an Alpine image's packages against the host's
/// Debian advisories.
pub(crate) fn scan_os_vulns(
    forest: &mut tree::Tree,
    inv: &system::Inventory,
    release_override: Option<&str>,
    ui: &ui::Ui,
) {
    let Some(eco) = inv.deps.first().map(|d| d.ecosystem) else {
        return; // nothing installed to scan
    };
    // One load for both branches: the proxy and endpoint overrides apply to the
    // Arch tracker and the OSV route alike.
    let settings = settings::Settings::load_or_warn();
    let net = &settings.network;

    // Arch isn't in OSV — pacman uses its own source (the Arch Security Tracker),
    // no release needed (Arch is rolling).
    if eco == model::Ecosystem::Pacman {
        let loader = gochi::Loader::spinner(
            format!(
                "gochi querying the Arch Security Tracker for {} packages",
                inv.deps.len()
            ),
            ui.animating(),
        );
        match archsec::scan(&vuln::agent(net), &inv.deps, &net.endpoints.arch_security()) {
            Ok(mut v) => {
                forest.vulnerabilities.append(&mut v);
                loader.finish(
                    gochi::Mood::from_risk(0, 0, vuln_count(forest)),
                    vuln_summary(forest),
                );
            }
            Err(e) => {
                loader.finish(gochi::Mood::Alert, "vuln scan failed");
                forest.diagnostics.push(model::Diagnostic {
                    ecosystem: eco.as_str().into(),
                    kind: "vuln_scan_failed".into(),
                    message: format!("Arch Security Tracker scan failed: {e:#}"),
                });
            }
        }
        return;
    }

    let release = match release_override {
        Some(s) => osv::Release::parse_override(s),
        None => match osv::Release::detect() {
            Some(r) => r,
            None => {
                forest.diagnostics.push(model::Diagnostic {
                    ecosystem: eco.as_str().into(),
                    kind: "vuln_source_unavailable".into(),
                    message: "cannot read /etc/os-release; pass --release id:version to scan"
                        .into(),
                });
                return;
            }
        },
    };
    let Some(osv_eco) = osv::osv_ecosystem(eco, &release) else {
        // Actionable guidance for the dnf backends OSV doesn't index directly.
        let hint = match (eco, release.id.as_str()) {
            (model::Ecosystem::Dnf, "rhel" | "redhat" | "centos") => {
                " — RHEL isn't in OSV; retry with `--release almalinux:<N>` or `rocky:<N>` \
                 (binary-compatible) for approximate coverage"
            }
            (model::Ecosystem::Dnf, "fedora") => {
                " — Fedora isn't in OSV; `dnf updateinfo --security` lists advisories for \
                 available updates"
            }
            _ => "",
        };
        forest.diagnostics.push(model::Diagnostic {
            ecosystem: eco.as_str().into(),
            kind: "vuln_source_unavailable".into(),
            message: format!(
                "OSV has no vulnerability feed for {} ({}); packages were not scanned{hint}",
                eco.as_str(),
                release.id
            ),
        });
        return;
    };
    let token = settings.vuln_token();
    if token.is_none() {
        eprintln!(
            "note: no mlab token — vuln scans use the anonymous limit. \
             Set VULN_MLAB_TOKEN or vuln_token in ~/.postmortem/config.yml."
        );
    }
    let loader = gochi::Loader::spinner(
        format!(
            "gochi querying vuln.mlab.sh for {} {osv_eco} packages",
            inv.deps.len()
        ),
        ui.animating(),
    );
    match osv::scan(
        &vuln::agent(net),
        &cache::Cache::open(),
        token.as_deref(),
        &inv.deps,
        &osv_eco,
        &vuln::scan_url(net),
    ) {
        Ok(mut v) => {
            forest.vulnerabilities.append(&mut v);
            loader.finish(
                gochi::Mood::from_risk(0, 0, vuln_count(forest)),
                vuln_summary(forest),
            );
        }
        Err(e) => {
            loader.finish(gochi::Mood::Alert, "vuln scan failed");
            forest.diagnostics.push(model::Diagnostic {
                ecosystem: eco.as_str().into(),
                kind: "vuln_scan_failed".into(),
                message: format!("vuln scan failed: {e:#}"),
            });
        }
    }
}
