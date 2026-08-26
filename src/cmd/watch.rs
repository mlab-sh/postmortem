//! `postmortem watch` — re-scan when a lockfile changes.

use crate::{cli, watch};

use anyhow::{Context, Result};

use std::path::PathBuf;

/// `postmortem watch <path>` — re-run a scan whenever a lockfile changes.
///
/// A feedback loop, not a gate: it reacts after an install has finished. Runs
/// until interrupted, or until `--max-runs`.
pub(crate) fn run_watch(args: cli::WatchArgs) -> Result<()> {
    use owo_colors::OwoColorize;
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("cannot resolve path {}", args.path.display()))?;
    let present = watch::present(&root);
    println!(
        "{}  {}",
        "watch".bold(),
        root.display().to_string().dimmed()
    );
    if present.is_empty() {
        println!(
            "
  {}",
            "no lockfile or manifest here — nothing to react to".yellow()
        );
    } else {
        println!(
            "
  {} {}",
            "watching".dimmed(),
            present.join(", ")
        );
    }
    println!(
        "  {}
",
        "reacts after an install finishes — it does not withhold anything (see `postmortem scripts`)"
            .dimmed()
    );
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("postmortem"));
    let argv: Vec<String> = args.run.split_whitespace().map(str::to_string).collect();
    let mut prev = watch::fingerprint(&root);
    let mut runs = 0u32;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(args.interval.max(1)));
        let now = watch::fingerprint(&root);
        let changed = watch::changed(&prev, &now);
        prev = now;
        if changed.is_empty() {
            continue;
        }

        let names: Vec<String> = changed
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        println!("{}", format!("── {} changed", names.join(", ")).bold());

        // The child inherits stdout/stderr, so its output lands inline. Its exit
        // status is reported rather than acted on: a watch that stopped on the
        // first finding would be useless for the loop it exists to serve.
        let status = std::process::Command::new(&exe)
            .args(&argv)
            .current_dir(&root)
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => println!(
                "{}",
                format!("── exited {}", s.code().unwrap_or(-1)).yellow()
            ),
            Err(e) => println!("{}", format!("── could not run: {e}").red()),
        }
        println!();
        runs += 1;
        if args.max_runs.is_some_and(|m| runs >= m) {
            return Ok(());
        }
    }
}
