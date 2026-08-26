//! `postmortem cache` — inspecting and pruning the on-disk cache.

use crate::{cache, cli, gochi};

use anyhow::Result;

/// `postmortem cache <action>` — manage the `tree --online` cache.
pub(crate) fn run_cache(args: cli::CacheArgs) -> Result<()> {
    let cache = cache::Cache::open();
    match args.action {
        cli::CacheAction::Prune(p) => {
            let opts = cache::PruneOpts {
                older_than_days: p.older_than,
                stale_only: p.stale,
                dry_run: p.dry_run,
            };
            let report = cache.prune(opts);
            let where_ = cache
                .root()
                .map(|r| r.display().to_string())
                .unwrap_or_else(|| "(no cache)".into());
            let verb = if p.dry_run { "would remove" } else { "removed" };
            // Describe what the filters actually selected, so the count is never
            // ambiguous: "removed 0 entries" reads very differently depending on
            // whether the filter matched nothing or the cache was empty.
            let mut scope = Vec::new();
            if p.stale {
                scope.push("stale format".to_string());
            }
            match p.older_than {
                Some(d) => scope.push(format!("older than {d}d")),
                None if !p.stale => scope.push("all".into()),
                None => {}
            }
            gochi::say(
                gochi::Mood::Happy,
                format!(
                    "{verb} {} entr{} ({}, {}), kept {} — {where_}",
                    report.removed,
                    if report.removed == 1 { "y" } else { "ies" },
                    scope.join(" + "),
                    human_bytes(report.freed),
                    report.kept,
                ),
            );
        }
        cli::CacheAction::Path => {
            let Some(root) = cache.root() else {
                eprintln!("no cache directory (no $HOME)");
                std::process::exit(2);
            };
            // Bare path on stdout, nothing else — this is meant to be captured.
            println!("{}", root.display());
        }
        cli::CacheAction::Info => render_cache_info(&cache.stats()),
    }
    Ok(())
}

/// The `cache info` view: one line per namespace, then the totals.
fn render_cache_info(stats: &cache::CacheStats) {
    use owo_colors::OwoColorize;
    let where_ = stats
        .root
        .as_ref()
        .map(|r| r.display().to_string())
        .unwrap_or_else(|| "(no cache directory)".into());
    println!("{}  {}", "cache".bold(), where_.dimmed());
    println!(
        "{}",
        format!("record format v{}", cache::FORMAT_VERSION).dimmed()
    );
    if stats.namespaces.is_empty() {
        println!("\n  {}", "empty".dimmed());
        return;
    }

    println!(
        "\n  {:<14} {:>8}  {:>9}  {:>8}  {}",
        "NAMESPACE".bold(),
        "ENTRIES".bold(),
        "SIZE".bold(),
        "STALE".bold(),
        "NEWEST".bold()
    );
    for ns in &stats.namespaces {
        // Pad before colouring: ANSI escapes count toward a format width, so
        // `{:>8}` on an already-coloured string misaligns the column.
        let stale = if ns.stale > 0 {
            ns.stale.to_string()
        } else {
            "-".to_string()
        };
        let stale = format!("{stale:>8}");
        let stale = if ns.stale > 0 {
            stale.truecolor(255, 165, 0).to_string()
        } else {
            stale.dimmed().to_string()
        };
        println!(
            "  {:<14} {:>8}  {:>9}  {}  {}",
            ns.name,
            ns.entries,
            human_bytes(ns.bytes),
            stale,
            ns.newest
                .map(age_label)
                .unwrap_or_else(|| "-".into())
                .dimmed(),
        );
    }

    println!(
        "\n  {} entries · {} · oldest {} · newest {}",
        stats.entries().bold(),
        human_bytes(stats.bytes()).bold(),
        stats.oldest().map(age_label).unwrap_or_else(|| "-".into()),
        stats.newest().map(age_label).unwrap_or_else(|| "-".into()),
    );
    if stats.stale() > 0 {
        println!(
            "\n{}",
            format!(
                "⚠ {} entr{} predate record format v{} — they are refetched as they are \
                 touched, or run `postmortem cache prune --stale` to sweep them now",
                stats.stale(),
                if stats.stale() == 1 { "y" } else { "ies" },
                cache::FORMAT_VERSION
            )
            .truecolor(255, 165, 0)
        );
    }
}

/// A coarse "how long ago" label for a unix timestamp.
fn age_label(secs: u64) -> String {
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let d = now.saturating_sub(secs);
    match d {
        0..=59 => "just now".into(),
        60..=3599 => format!("{}m ago", d / 60),
        3600..=86_399 => format!("{}h ago", d / 3600),
        _ => format!("{}d ago", d / 86_400),
    }
}

/// Compact byte count: `0 B`, `4.2 KB`, `1.3 MB`.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}
