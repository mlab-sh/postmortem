//! `postmortem system` — the machine's OS package managers.

use crate::cmd::common::{vuln_count, vuln_summary};
use crate::cmd::gate_policy::build_gate_policy;
use crate::{
    archsec, cache, cli, config, gate, gochi, inspect, model, osv, resolve, settings, system, tree,
    ui, vuln,
};
use anyhow::Result;

/// `postmortem system` — detect OS package managers, list their source repos,
/// and tree the installed forest with risk scoring. Six backends today
/// (Homebrew, pacman, apt, dnf, Nix, apk); MacPorts is detected but unsupported.
/// Exit 2 if no supported manager is present.
pub(crate) fn run_system(args: cli::SystemArgs) -> Result<()> {
    // `system inspect <pkg>` focuses on a single package (its own flow).
    if let Some(cli::SystemCommand::Inspect(i)) = &args.command {
        return inspect::run(i);
    }

    let ui = ui::Ui::new(!args.no_progress);
    let managers = system::detect();
    system::render_detected(&managers);

    // Which backends to read. `--manager` pins one; otherwise Windows reads
    // every layer it can, because winget, MSIX and the registry all describe
    // the same machine and picking one would be exactly the partial scan this
    // command exists to avoid. A Linux box has a single distro manager, so the
    // first match there is the whole story.
    let backends: Vec<&'static str> = if let Some(want) = &args.manager {
        match managers.iter().find(|m| m.name.eq_ignore_ascii_case(want)) {
            Some(m) if m.available && m.implemented => vec![m.name],
            Some(m) if !m.implemented => {
                eprintln!("'{}' is detected but has no backend yet.", m.name);
                std::process::exit(2);
            }
            Some(m) => {
                eprintln!("'{}' has a backend but is not installed here.", m.name);
                std::process::exit(2);
            }
            None => {
                let known: Vec<&str> = managers.iter().map(|m| m.name).collect();
                eprintln!("unknown manager '{want}'. known: {}", known.join(", "));
                std::process::exit(2);
            }
        }
    } else {
        let usable = managers.iter().filter(|m| m.available && m.implemented);
        let picked: Vec<&'static str> = if cfg!(windows) {
            // The network layer is incident-response material and is only read
            // when asked for.
            usable
                .filter(|m| m.name != "network" || args.deep)
                .map(|m| m.name)
                .collect()
        } else {
            usable.take(1).map(|m| m.name).collect()
        };
        if picked.is_empty() {
            eprintln!("no supported system package manager found.");
            std::process::exit(2);
        }
        picked
    };

    // gochi rides the (indeterminate) load while the manager is read.
    let opts = system::Opts {
        online: args.online,
        force_aur: args.force_aur,
        signatures: !args.no_signatures,
        deep: args.deep,
    };
    let mut read = Vec::new();
    let mut unread = Vec::new();
    for backend in &backends {
        let loader = gochi::Loader::spinner(
            &format!("gochi reading {backend} packages"),
            ui.animating(),
        );
        match system::inventory(backend, opts) {
            Ok(inv) => {
                loader.finish(gochi::Mood::Happy, format!("read {}", inv.summary));
                read.push(inv);
            }
            // With one backend asked for, its failure is the command's failure.
            // With several, one unreadable layer must not abort the others —
            // but it must not vanish either, or a partial scan reads as a
            // complete one.
            Err(e) if backends.len() == 1 => {
                loader.finish(gochi::Mood::Bad, "couldn't read packages");
                return Err(e);
            }
            Err(e) => {
                loader.finish(gochi::Mood::Bad, format!("couldn't read {backend}"));
                unread.push(format!("{backend} could not be read: {e}"));
            }
        }
    }
    if read.is_empty() {
        anyhow::bail!("none of the detected managers could be read: {}", unread.join("; "));
    }
    let mut inv = merge_inventories(read, unread);
    // Only meaningful once every layer has been read: an Add/Remove entry is
    // orphaned relative to what the *other* managers claim.
    system::flag_unclaimed(&mut inv);
    // Test signing and a third-party driver are each unremarkable; together
    // they mean the machine loads kernel code nobody vouched for.
    system::flag_unsigned_driver_risk(&mut inv);
    // Surface backend caveats (weakened signing trust, tampered files, un-synced
    // DB, …) as a gochi alert followed by one bullet per caveat, so a system with
    // many caveats stays readable instead of collapsing into one run-on line.
    if !inv.notes.is_empty() {
        use owo_colors::OwoColorize;
        let header = format!(
            "{} trust caveat(s) — review before trusting this inventory",
            inv.notes.len()
        );
        eprintln!("  {}  {}", gochi::Mood::Alert.paint(), header.yellow());
        for note in &inv.notes {
            eprintln!("         {} {}", "-".dimmed(), note.yellow());
        }
    }

    // `--repos`: just the source-repo view.
    if args.repos {
        system::render_repos(&inv);
        return Ok(());
    }

    let mut ecos: Vec<String> = Vec::new();
    for d in &inv.deps {
        let e = d.ecosystem.as_str().to_string();
        if !ecos.contains(&e) {
            ecos.push(e);
        }
    }
    if ecos.is_empty() {
        ecos.push(inv.manager.to_string());
    }
    let mut forest = tree::build(inv.manager, &ecos, &inv.deps, args.depth);

    // `--online`: resolve each formula's repo reputation through the shared
    // resolver (same token/cache/scoring path as `tree --online`).
    if args.online {
        gochi::greet(ui.animating());
        let mut settings = settings::Settings::load_or_warn();
        let github = settings.resolve_github_token()?;
        if github.is_none() {
            eprintln!(
                "note: no GitHub token — using the anonymous GitHub API (60 req/h). \
                 Set GITHUB_TOKEN or add it to ~/.postmortem/config.yml to raise the limit."
            );
        }
        let tokens = resolve::Tokens {
            github,
            gitlab: settings.gitlab_token(),
            codeberg: settings.codeberg_token(),
        };
        let resolver =
            resolve::Resolver::with_network(tokens, settings.tree.clone(), &settings.network)
                .with_languages(args.languages)
                .with_licenses(true);
        let resolutions = resolver.resolve_all(&inv.deps, &ui);
        tree::enrich(&mut forest, &resolutions);
    }

    // Offline system risk: third-party taps + cask download/artifact surface.
    // Merges with any online signals, then score so `risk:dep` reflects both.
    system::annotate(&mut forest, &inv.signals);
    tree::score(&mut forest);

    // `--vulns`: known-vulnerability intel via OSV.dev. The whole inventory is
    // one backend, so one ecosystem string covers it — or `None` when OSV
    // doesn't index this manager, in which case we record a diagnostic instead
    // of letting a silent zero read as "clean".
    if args.vulns {
        scan_system_vulns(&mut forest, &inv, args.release.as_deref(), &ui);
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&forest)?);
    } else {
        tree::render(&forest);
    }

    // CI gate: turn the machine's risk scores / vuln scan into an exit code.
    // Summary goes to stderr so it never corrupts `--json` on stdout.
    run_system_gate(&args, &forest);
    Ok(())
}

/// Apply the CI gate to a scanned system inventory and exit accordingly: 0 clean,
/// 1 tripped, 2 inconclusive/misconfigured. A vuln gate is **fail-closed** — if
/// OSV couldn't scan this backend (or the scan errored), the gate can't be
/// answered, so it exits 2 rather than silently passing ("not scanned" ≠ "clean").
fn run_system_gate(args: &cli::SystemArgs, forest: &tree::Tree) {
    let gc = match &args.config {
        Some(p) => match config::Config::load(p) {
            Ok(c) => c.gate,
            Err(e) => {
                eprintln!("warn: failed to load gate config {}: {e:#}", p.display());
                config::GateConfig::default()
            }
        },
        None => config::GateConfig::default(),
    };
    let policy = build_gate_policy(
        gc,
        args.max_risk,
        args.max_dep,
        args.max_high,
        args.max_sus,
        args.max_vulns,
        args.fail_on_vuln,
        &args.allow,
    );
    if !policy.is_active() {
        return; // no gate requested → normal exit 0
    }

    if policy.needs_vulns() && !args.vulns {
        eprintln!("error: --max-vulns/--fail-on-vuln require --vulns");
        std::process::exit(2);
    }
    // Fail-closed: an active vuln gate over an un-scannable backend (brew/nix,
    // Fedora/RHEL) or a scan that errored is INCONCLUSIVE, not clean.
    if policy.needs_vulns()
        && let Some(d) = forest
            .diagnostics
            .iter()
            .find(|d| d.kind == "vuln_source_unavailable" || d.kind == "vuln_scan_failed")
    {
        eprintln!(
            "error: vuln gate cannot be evaluated — {} ({}); \
             an un-scanned backend is not the same as clean",
            d.message, d.kind
        );
        std::process::exit(2);
    }

    let today = chrono::Local::now().date_naive();
    let outcome = gate::evaluate(&policy, forest, today, None);
    gate::report(&outcome, &policy);
    std::process::exit(if outcome.tripped() { 1 } else { 0 });
}

/// Populate `forest.vulnerabilities` from OSV.dev for the installed inventory,
/// or push a `vuln_source_unavailable` diagnostic when the release can't be
/// resolved or OSV doesn't cover this backend.
fn scan_system_vulns(
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

/// Fold the inventories of several coexisting layers into one, so everything
/// downstream — tree, annotate, score, vulns, gate — stays a single path.
///
/// `unread` carries the layers that failed: they are appended to the caveats so
/// an incomplete machine view is stated rather than implied.
fn merge_inventories(mut invs: Vec<system::Inventory>, unread: Vec<String>) -> system::Inventory {
    if invs.len() == 1 && unread.is_empty() {
        return invs.remove(0);
    }
    let summary = invs
        .iter()
        .map(|i| format!("{}: {}", i.manager, i.summary))
        .collect::<Vec<_>>()
        .join(" · ");
    let mut merged = system::Inventory {
        // A name for the combined view; the per-layer names survive in the
        // summary and in each package's ecosystem.
        manager: "system",
        deps: Vec::new(),
        repos: Vec::new(),
        signals: std::collections::HashMap::new(),
        claims: Vec::new(),
        summary,
        notes: Vec::new(),
    };
    for inv in invs {
        let eco = inv
            .deps
            .first()
            .map(|d| d.ecosystem.as_str().to_string())
            .unwrap_or_default();
        merged.deps.extend(inv.deps);
        merged.repos.extend(inv.repos);
        merged.notes.extend(inv.notes);
        merged.claims.extend(inv.claims);
        // Signal keys are package names, which stop being unique the moment
        // layers are merged: `jq` exists in both Chocolatey and Scoop, and an
        // unqualified key hands each layer's findings to the other's package —
        // doubling both scores. Qualify by ecosystem on the way in.
        for (name, sigs) in inv.signals {
            merged
                .signals
                .entry(system::qualify(&eco, &name))
                .or_default()
                .extend(sigs);
        }
    }
    merged.notes.extend(unread);
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, Ecosystem, LicenseSource, Scope, Severity};

    fn inv(manager: &'static str, eco: Ecosystem, names: &[&str]) -> system::Inventory {
        let deps = names
            .iter()
            .map(|n| crate::model::Dependency {
                name: (*n).into(),
                version: "1.0".into(),
                ecosystem: eco,
                direct: true,
                scope: Scope::Prod,
                licenses: Vec::new(),
                license_source: LicenseSource::Unknown,
                resolved_url: None,
                integrity: None,
                parents: Vec::new(),
            })
            .collect();
        system::Inventory {
            manager,
            deps,
            repos: Vec::new(),
            signals: std::collections::HashMap::new(),
            claims: Vec::new(),
            summary: format!("{} package(s)", names.len()),
            notes: Vec::new(),
        }
    }

    /// A single healthy layer must come through untouched — merging is only for
    /// the coexisting case.
    #[test]
    fn one_layer_passes_through_unchanged() {
        let merged = merge_inventories(vec![inv("winget", Ecosystem::Winget, &["a"])], vec![]);
        assert_eq!(merged.manager, "winget");
        assert_eq!(merged.deps.len(), 1);
    }

    /// Windows layers coexist, so their packages land in one forest and each
    /// keeps its own ecosystem.
    #[test]
    fn coexisting_layers_are_folded_into_one_view() {
        let merged = merge_inventories(
            vec![
                inv("winget", Ecosystem::Winget, &["a", "b"]),
                inv("msix", Ecosystem::Msix, &["c"]),
            ],
            vec![],
        );
        assert_eq!(merged.manager, "system");
        assert_eq!(merged.deps.len(), 3);
        assert!(merged.summary.contains("winget:"));
        assert!(merged.summary.contains("msix:"));
        assert_eq!(
            merged.deps.iter().filter(|d| d.ecosystem == Ecosystem::Msix).count(),
            1
        );
    }

    /// Two layers can carry the same package name — `jq` exists in both
    /// Chocolatey and Scoop. Merging their signals under a bare name handed
    /// each layer's findings to the other's package and doubled both scores.
    /// They must stay attributed to the layer that raised them.
    #[test]
    fn same_named_packages_in_two_layers_do_not_inherit_each_others_signals() {
        let mut choco = inv("choco", Ecosystem::Choco, &["jq"]);
        choco.signals.insert(
            "jq".into(),
            vec![system::SysSignal {
                label: "from-choco".into(),
                category: Category::Unsigned,
                severity: Severity::Low,
                points: 40,
            }],
        );
        let mut scoop = inv("scoop", Ecosystem::Scoop, &["jq"]);
        scoop.signals.insert(
            "jq".into(),
            vec![system::SysSignal {
                label: "from-scoop".into(),
                category: Category::Tamper,
                severity: Severity::High,
                points: 40,
            }],
        );

        let merged = merge_inventories(vec![choco, scoop], vec![]);
        let choco_key = system::qualify(Ecosystem::Choco.as_str(), "jq");
        let scoop_key = system::qualify(Ecosystem::Scoop.as_str(), "jq");

        assert_eq!(merged.signals[&choco_key].len(), 1);
        assert_eq!(merged.signals[&choco_key][0].label, "from-choco");
        assert_eq!(merged.signals[&scoop_key].len(), 1);
        assert_eq!(merged.signals[&scoop_key][0].label, "from-scoop");
        assert!(
            !merged.signals.contains_key("jq"),
            "nothing may remain under the ambiguous bare name"
        );
    }

    /// A layer that could not be read is stated as a caveat. Staying silent
    /// would let a partial machine view read as a complete one.
    #[test]
    fn an_unreadable_layer_is_surfaced_not_swallowed() {
        let merged = merge_inventories(
            vec![inv("winget", Ecosystem::Winget, &["a"])],
            vec!["msix could not be read: powershell failed".into()],
        );
        assert!(merged.notes.iter().any(|n| n.contains("msix could not be read")));
    }
}
