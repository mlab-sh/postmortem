//! `postmortem scan` — static analysis of dependency code.

use crate::cmd::common::detect_and_parse;
use crate::{analyze, cli, config, enrich, gochi, model, report, ui};

use anyhow::Result;

use std::path::Path;

/// `postmortem scan <paths>...` — scan each path in sequence. Exit code: 2 if no
/// supported ecosystem was found at any path, 1 if any scan tripped the severity
/// gate, else 0.
pub(crate) fn run_scan(args: cli::ScanArgs) -> Result<()> {
    if args.paths.len() > 1 && !matches!(args.format(), cli::Format::Terminal) {
        anyhow::bail!(
            "machine formats (--json/--html/--sarif) support a single path; got {}",
            args.paths.len()
        );
    }

    let ui = ui::Ui::new(!args.no_progress);
    let mut any_detected = false;
    let mut gate_tripped = false;
    for path in &args.paths {
        let root = match path.canonicalize() {
            Ok(r) => r,
            Err(e) => {
                ui.note(format!("cannot resolve path {}: {e}", path.display()));
                continue;
            }
        };
        match scan_path(&root, &args, &ui)? {
            Some(tripped) => {
                any_detected = true;
                gate_tripped |= tripped;
            }
            None => ui.note(format!(
                "no supported ecosystem detected at {}",
                root.display()
            )),
        }
    }

    if !any_detected {
        std::process::exit(2);
    }
    std::process::exit(if gate_tripped { 1 } else { 0 });
}

/// Scan a single already-canonicalized project root. Returns `None` when no
/// supported ecosystem is present, otherwise `Some(gate_tripped)` where
/// `gate_tripped` is true if any finding meets or exceeds `--severity`.
fn scan_path(target: &Path, args: &cli::ScanArgs, ui: &ui::Ui) -> Result<Option<bool>> {
    let Some((detected, deps, diagnostics)) =
        detect_and_parse(target, ui, &cli::OmitSet::scopes(&args.omit))?
    else {
        return Ok(None);
    };
    // A pinned manifest/lockfile target belongs to its parent project: that
    // directory is what `postmortem.conf` autoload and test-path filtering use.
    let owned_root;
    let root = if target.is_file() {
        owned_root = target.parent().unwrap_or(target).to_path_buf();
        owned_root.as_path()
    } else {
        target
    };

    // Resolve the config: explicit --config wins; otherwise auto-load <root>/postmortem.conf
    // unless --no-config is set.
    let cfg_path = if args.no_config {
        None
    } else if let Some(p) = &args.config {
        Some(p.clone())
    } else {
        let candidate = root.join(config::DEFAULT_FILENAME);
        candidate.is_file().then_some(candidate)
    };
    let config = match cfg_path {
        Some(p) => match config::Config::load(&p) {
            Ok(c) => {
                ui.note(format!("loaded config from {}", p.display()));
                c
            }
            Err(e) => {
                ui.note(format!(
                    "warn: failed to load config {}: {e:#}",
                    p.display()
                ));
                config::Config::default()
            }
        },
        None => config::Config::default(),
    };
    let config = config.merge_cli(&args.skip_category, args.min_severity);
    let raw_findings = if args.skip_analyze {
        Vec::new()
    } else {
        let f = analyze::run_all(&detected, &deps, ui);
        analyze::drop_test_iocs(f, args.allow_test_files, root)
    };
    let applied = config.apply(raw_findings, chrono::Local::now().date_naive());
    let mut findings = applied.findings;
    if applied.suppressed > 0 {
        ui.note(format!(
            "config suppressed {} finding(s)",
            applied.suppressed
        ));
    }
    // Lapsed rules go to stderr unconditionally — the progress UI is suppressed
    // off-TTY, and an exception nobody renewed must be visible in CI too.
    for e in &applied.expired {
        eprintln!("warn: ignore rule no longer applies — {e}");
    }
    if args.enrich {
        let enrich_phase = ui.phase("enriching findings");
        enrich::annotate(&mut findings);
        let n = findings.iter().filter(|f| f.enrich_url.is_some()).count();
        enrich_phase.done(format!("enriched {n} finding(s)"));
    }

    let report = model::Report {
        // 3: every dependency carries a `scope` (prod / dev / optional).
        schema_version: 3,
        root: root.display().to_string(),
        ecosystems: detected.iter().map(|e| e.name().to_string()).collect(),
        diagnostics,
        dependencies: deps,
        findings,
    };
    match args.format() {
        cli::Format::Terminal => {
            report::terminal::render(&report, !args.no_deps);
            let (mood, msg) = scan_verdict(&report.findings);
            gochi::say(mood, msg);
        }
        cli::Format::Json => {
            let out = report::json::render(&report)?;
            cli::OutputTarget::resolve(args.output.as_deref(), "json").write(&out)?;
        }
        cli::Format::Html => {
            let out = report::html::render(&report);
            cli::OutputTarget::resolve(args.output.as_deref(), "html").write(&out)?;
        }
        cli::Format::Sarif => {
            let out = report::sarif::render(&report)?;
            cli::OutputTarget::resolve(args.output.as_deref(), "sarif").write(&out)?;
        }
    }

    let gate_tripped = report.findings.iter().any(|f| f.severity >= args.severity);
    Ok(Some(gate_tripped))
}

/// gochi's closing verdict for a static scan: a mood + a severity breakdown, or
/// an all-clear. Bad on any critical/high, alert on softer findings.
fn scan_verdict(findings: &[model::Finding]) -> (gochi::Mood, String) {
    use model::Severity::*;
    let (mut crit, mut high, mut med, mut low) = (0, 0, 0, 0);
    for f in findings {
        match f.severity {
            Critical => crit += 1,
            High => high += 1,
            Medium => med += 1,
            Low => low += 1,
            Info => {}
        }
    }
    let total = crit + high + med + low;
    if total == 0 {
        return (
            gochi::Mood::Happy,
            "clean — no malicious patterns found".into(),
        );
    }
    let mood = if crit + high > 0 {
        gochi::Mood::Bad
    } else {
        gochi::Mood::Alert
    };
    (
        mood,
        format!("{total} finding(s): {crit} critical · {high} high · {med} medium · {low} low"),
    )
}
