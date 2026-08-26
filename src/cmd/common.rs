//! Work every command shares: turning a path into a parsed dependency
//! graph, and the two summaries more than one command prints.

use crate::{detect, model, parsers, resolve, scope, settings, tree, ui};

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

    Ok(Some((detected, deps, diags)))
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
