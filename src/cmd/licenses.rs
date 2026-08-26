//! `postmortem licenses` — the license inventory and its policy.

use crate::cmd::common::{detect_and_parse, license_resolver};
use crate::{cli, config, license, model, resolve, ui};

use anyhow::{Context, Result};

/// `postmortem licenses <path>` — group the dependency graph by license, and
/// enforce a policy over it.
///
/// Exits 1 on a policy violation, so it drops into CI as its own step. The
/// policy comes from `postmortem.conf`'s `[license]` table, with CLI flags added
/// on top rather than replacing it.
pub(crate) fn run_licenses(args: cli::LicensesArgs) -> Result<()> {
    let ui = ui::Ui::new(!args.no_progress);
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("cannot resolve path {}", args.path.display()))?;
    let Some((_, mut deps, _)) = detect_and_parse(&root, &ui, &cli::OmitSet::scopes(&args.omit))?
    else {
        anyhow::bail!("no supported ecosystem detected at {}", root.display());
    };
    if args.online {
        let resolutions = license_resolver(&ui)?.resolve_all(&deps, &ui);
        resolve::apply_licenses(&mut deps, &resolutions);
    }

    // Policy: config first, CLI flags additive on top.
    let cfg_path = args.config.clone().or_else(|| {
        let c = root.join(config::DEFAULT_FILENAME);
        c.is_file().then_some(c)
    });
    let file_policy = match &cfg_path {
        Some(p) => config::Config::load(p)?.license,
        None => config::LicenseConfig::default(),
    };
    let policy = license::Policy {
        deny: [file_policy.deny, args.deny.clone()].concat(),
        allow: [file_policy.allow, args.allow.clone()].concat(),
        fail_on_unknown: file_policy.fail_on_unknown || args.fail_on_unknown,
    };
    let inventory = license::inventory(&deps);
    let violations = license::evaluate(&deps, &policy);
    if args.json || args.webhook.is_some() {
        let doc = license::inventory_json(&inventory, &violations, &deps);
        let out = serde_json::to_string_pretty(&doc)?;
        cli::OutputTarget::emit(
            args.json,
            args.webhook.as_deref(),
            args.output.as_deref(),
            "licenses",
            &out,
        )?;
    } else {
        render_licenses(
            &inventory,
            &violations,
            &deps,
            args.unknown_only,
            args.packages,
        );
    }

    if !violations.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

/// The `licenses` terminal view.
fn render_licenses(
    inventory: &[license::Bucket],
    violations: &[license::Violation],
    deps: &[model::Dependency],
    unknown_only: bool,
    show_packages: bool,
) {
    use owo_colors::OwoColorize;
    const ORANGE: (u8, u8, u8) = (255, 165, 0);
    let unknown = inventory
        .iter()
        .find(|b| b.label == "(unknown)")
        .map_or(0, |b| b.packages.len());
    println!(
        "{}  {}",
        "licenses".bold(),
        format!("({} deps, {} unresolved)", deps.len(), unknown).dimmed()
    );

    // Which labels the policy rejected, so they can be marked in the listing.
    let denied: std::collections::HashSet<&str> = violations
        .iter()
        .filter_map(|v| v.license.as_deref())
        .collect();
    let shown: Vec<&license::Bucket> = if unknown_only {
        inventory
            .iter()
            .filter(|b| b.label == "(unknown)")
            .collect()
    } else {
        inventory.iter().collect()
    };
    if shown.is_empty() {
        println!("\n  {}", "nothing to report".dimmed());
        return;
    }

    println!();
    let width = shown
        .iter()
        .map(|b| b.label.chars().count())
        .max()
        .unwrap_or(10)
        .clamp(10, 40);
    for b in &shown {
        let count = b.packages.len();
        let label = if b.label == "(unknown)" {
            b.label.truecolor(ORANGE.0, ORANGE.1, ORANGE.2).to_string()
        } else if denied.contains(b.label.as_str()) {
            b.label.red().to_string()
        } else if b.spdx {
            b.label.green().to_string()
        } else {
            // Resolved to something, but not to an SPDX identifier.
            b.label.yellow().to_string()
        };
        // Pad on the plain text: ANSI escapes count toward a format width.
        let pad = width.saturating_sub(b.label.chars().count());
        let mark = if denied.contains(b.label.as_str()) {
            format!("  {}", "⚠ denied".red())
        } else if !b.spdx && b.label != "(unknown)" {
            format!("  {}", "non-SPDX".dimmed())
        } else {
            String::new()
        };
        println!("  {label}{:pad$}  {count:>4}{mark}", "", pad = pad);
        if show_packages || unknown_only {
            for p in &b.packages {
                println!("      {}", p.dimmed());
            }
        }
    }

    if violations.is_empty() {
        return;
    }
    println!();
    let by_reason = |r: license::Reason| violations.iter().filter(|v| v.reason == r).count();
    let mut parts = Vec::new();
    for (r, word) in [
        (license::Reason::Denied, "denied"),
        (license::Reason::NotAllowed, "not allowed"),
        (license::Reason::Unknown, "unresolved"),
    ] {
        let n = by_reason(r);
        if n > 0 {
            parts.push(format!("{n} {word}"));
        }
    }
    println!("{}", format!("⚠ policy: {}", parts.join(", ")).red().bold());
    for v in violations.iter().take(20) {
        println!(
            "  {} {}  {}",
            format!("{}@{}", v.package, v.version).red(),
            v.license.as_deref().unwrap_or("(no license)").dimmed(),
            v.reason.as_str().dimmed()
        );
    }
    if violations.len() > 20 {
        println!(
            "  {}",
            format!("… and {} more", violations.len() - 20).dimmed()
        );
    }
}
