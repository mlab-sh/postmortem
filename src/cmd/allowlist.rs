//! `postmortem allowlist` — every suppression the project declares.

use crate::{cli, config, gochi};

use anyhow::{Context, Result};

/// `postmortem allowlist <path>` — every suppression the project declares, and
/// how long each has left to run.
///
/// Suppressions are technical debt with a due date. Scattered across three
/// tables they are easy to accumulate and impossible to review, so this is the
/// one place that shows all of them together.
pub(crate) fn run_allowlist(args: cli::AllowlistArgs) -> Result<()> {
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("cannot resolve path {}", args.path.display()))?;
    let cfg_path = args.config.clone().or_else(|| {
        let c = root.join(config::DEFAULT_FILENAME);
        c.is_file().then_some(c)
    });
    let cfg = match &cfg_path {
        Some(p) => config::Config::load(p)?,
        None => config::Config::default(),
    };
    let today = chrono::Local::now().date_naive();
    let mut items = config::suppressions(&cfg, today);
    // npm's script approvals live in package.json, not in postmortem.conf, but
    // they suppress the same way — omitting them would understate what the
    // project has waved through.
    items.extend(config::script_approvals(&root));
    if args.expired {
        items.retain(|s| s.status.is_lapsed());
    }
    // Worst first: lapsed, then soonest to lapse, then permanent.
    items.sort_by_key(|s| match &s.status {
        config::Status::Invalid(_) => (0, 0),
        config::Status::Expired(_) => (1, 0),
        config::Status::Active(d) => (2, *d),
        config::Status::Permanent => (3, 0),
    });
    let lapsed = items.iter().filter(|s| s.status.is_lapsed()).count();
    let soon = args.expiring_in.map(|w| {
        items
            .iter()
            .filter(|s| matches!(s.status, config::Status::Active(d) if d <= w))
            .count()
    });
    let where_ = cfg_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| format!("{} (no postmortem.conf)", root.display()));
    if args.json {
        let doc = serde_json::json!({
            "schema_version": 1,
            "config": where_,
            "summary": {
                "total": items.len(),
                "lapsed": lapsed,
                "expiring_soon": soon,
            },
            "suppressions": items.iter().map(|s| serde_json::json!({
                "source": s.source,
                "target": s.target,
                "reason": s.reason,
                "expires": s.expires,
                "status": match &s.status {
                    config::Status::Permanent => "permanent".to_string(), config::Status::Active(_) => "active".to_string(), config::Status::Expired(_) => "expired".to_string(), config::Status::Invalid(_) => "invalid".to_string(),
                },
                "days_left": match &s.status {
                    config::Status::Active(d) => Some(*d),
                    _ => None,
                },
            })).collect::<Vec<_>>(),
        });
        let out = serde_json::to_string_pretty(&doc)?;
        cli::OutputTarget::resolve_named(args.output.as_deref(), "allowlist", "json")
            .write(&out)?;
    } else {
        render_allowlist(&items, &where_, lapsed, soon, args.expiring_in);
    }

    // Only `--expired` gates: a plain listing is a report, not a check.
    if args.expired && lapsed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn render_allowlist(
    items: &[config::Suppression],
    where_: &str,
    lapsed: usize,
    soon: Option<usize>,
    window: Option<i64>,
) {
    use owo_colors::OwoColorize;
    println!("{}  {}", "allowlist".bold(), where_.dimmed());
    if items.is_empty() {
        println!();
        gochi::say(gochi::Mood::Happy, "no suppressions declared");
        return;
    }

    println!();
    for s in items {
        let (mark, state) = match &s.status {
            config::Status::Invalid(raw) => (
                "✗".red().to_string(),
                format!("invalid date {raw:?}").red().to_string(),
            ),
            config::Status::Expired(d) => (
                "✗".red().to_string(),
                format!("expired {d}").red().to_string(),
            ),
            config::Status::Active(d) if window.is_some_and(|w| *d <= w) => (
                "!".truecolor(255, 165, 0).to_string(),
                format!("{d}d left").truecolor(255, 165, 0).to_string(),
            ),
            config::Status::Active(d) => (
                "·".dimmed().to_string(),
                format!("{d}d left").dimmed().to_string(),
            ),
            config::Status::Permanent => {
                ("·".dimmed().to_string(), "no expiry".dimmed().to_string())
            }
        };
        println!(
            "  {mark} {:<18} {:<40} {state}",
            s.source.dimmed(),
            s.target
        );
        if let Some(r) = &s.reason {
            println!("      {}", r.dimmed());
        }
    }

    println!();
    if lapsed > 0 {
        println!(
            "{}",
            format!(
                "⚠ {lapsed} suppression(s) have lapsed — they no longer hide anything, so \
                 whatever they covered is being reported again"
            )
            .truecolor(255, 165, 0)
        );
    }
    if let (Some(n), Some(w)) = (soon, window)
        && n > 0
    {
        println!("{}", format!("· {n} more lapse within {w} days").dimmed());
    }
    let permanent = items
        .iter()
        .filter(|s| s.status == config::Status::Permanent)
        .count();
    if permanent > 0 {
        println!(
            "{}",
            format!("· {permanent} have no expiry — those never come back for review").dimmed()
        );
    }
}
