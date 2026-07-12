mod analyze;
mod cli;
mod config;
mod detect;
mod enrich;
mod model;
mod parsers;
mod report;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let args = cli::Cli::parse();
    let root = args
        .path
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("cannot resolve path {}: {e}", args.path.display()))?;

    let detected = detect::detect(&root)?;
    if detected.is_empty() {
        eprintln!("no supported ecosystem detected at {}", root.display());
        std::process::exit(2);
    }

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
                eprintln!("loaded config from {}", p.display());
                c
            }
            Err(e) => {
                eprintln!("warn: failed to load config {}: {e:#}", p.display());
                config::Config::default()
            }
        },
        None => config::Config::default(),
    };
    let config = config.merge_cli(&args.skip_category, args.min_severity);

    let mut deps = Vec::new();
    for eco in &detected {
        match eco {
            detect::Detected::Node { lockfile, .. } => match parsers::node::parse_lockfile(lockfile) {
                Ok(mut d) => deps.append(&mut d),
                Err(e) => eprintln!("warn: node lockfile parse failed: {e:#}"),
            },
            detect::Detected::Python { manifest, lockfile, .. } => {
                match parsers::python::parse_any(manifest, lockfile.as_deref()) {
                    Ok(mut d) => deps.append(&mut d),
                    Err(e) => eprintln!("warn: python parse failed: {e:#}"),
                }
            }
            detect::Detected::Rust { manifest, lockfile, .. } => {
                match parsers::rust::parse_lockfile(lockfile, Some(manifest)) {
                    Ok(mut d) => deps.append(&mut d),
                    Err(e) => eprintln!("warn: cargo lockfile parse failed: {e:#}"),
                }
            }
            detect::Detected::Ruby { manifest, lockfile, .. } => {
                match parsers::ruby::parse_lockfile(lockfile, manifest.as_deref()) {
                    Ok(mut d) => deps.append(&mut d),
                    Err(e) => eprintln!("warn: Gemfile.lock parse failed: {e:#}"),
                }
            }
            detect::Detected::Php { manifest, lockfile, .. } => {
                match parsers::php::parse_lockfile(lockfile, manifest.as_deref()) {
                    Ok(mut d) => deps.append(&mut d),
                    Err(e) => eprintln!("warn: composer.lock parse failed: {e:#}"),
                }
            }
            detect::Detected::Go { manifest, lockfile, .. } => {
                match parsers::go::parse(manifest, lockfile.as_deref()) {
                    Ok(mut d) => deps.append(&mut d),
                    Err(e) => eprintln!("warn: go.mod parse failed: {e:#}"),
                }
            }
        }
    }

    let raw_findings = if args.skip_analyze {
        Vec::new()
    } else {
        analyze::run_all(&detected, &deps)
    };

    let (mut findings, suppressed) = config.apply(raw_findings);
    if suppressed > 0 {
        eprintln!("config suppressed {suppressed} finding(s)");
    }
    if args.enrich {
        enrich::annotate(&mut findings);
    }

    let report = model::Report {
        schema_version: 1,
        root: root.display().to_string(),
        ecosystems: detected.iter().map(|e| e.name().to_string()).collect(),
        dependencies: deps,
        findings,
    };

    match args.format() {
        cli::Format::Terminal => report::terminal::render(&report, !args.no_deps),
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

    let exit = if report
        .findings
        .iter()
        .any(|f| f.severity >= args.severity)
    {
        1
    } else {
        0
    };
    std::process::exit(exit);
}
