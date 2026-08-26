//! Building a [`crate::gate::Policy`] out of CLI flags and a project's
//! `postmortem.conf` — shared by `tree`, `audit` and `system`.

use crate::{cli, config, gate, model};

use std::path::Path;

/// Build the effective gate policy for `root`: the `[gate]` table from
/// `--config` (or an auto-loaded `postmortem.conf`) with CLI flags layered on
/// top (CLI wins on each threshold; allowlists are unioned).
pub(crate) fn resolve_gate_policy(root: &Path, args: &cli::TreeArgs) -> gate::Policy {
    build_gate_policy(
        load_gate_config(root, args.config.as_deref()),
        args.max_risk,
        args.max_dep,
        args.max_high,
        args.max_sus,
        args.max_vulns,
        args.fail_on_vuln,
        &args.allow,
    )
}

/// The `[gate]` table for `root`: an explicit `--config`, else an auto-loaded
/// `postmortem.conf`, else empty. A config that fails to parse warns and yields
/// an empty table rather than aborting — a broken policy file must not look like
/// a passing gate, and the caller's own thresholds still apply.
pub(crate) fn load_gate_config(root: &Path, explicit: Option<&Path>) -> config::GateConfig {
    let cfg_path = explicit.map(Path::to_path_buf).or_else(|| {
        let c = root.join(config::DEFAULT_FILENAME);
        c.is_file().then_some(c)
    });
    match cfg_path {
        Some(p) => match config::Config::load(&p) {
            Ok(c) => c.gate,
            Err(e) => {
                eprintln!("warn: failed to load gate config {}: {e:#}", p.display());
                config::GateConfig::default()
            }
        },
        None => config::GateConfig::default(),
    }
}

/// Layer CLI gate thresholds over a `[gate]` config table into an effective
/// [`gate::Policy`] (CLI wins per-threshold; the config allowlist is unioned
/// with `--allow`). Shared by `tree` and `system`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_gate_policy(
    gc: config::GateConfig,
    max_risk: Option<u8>,
    max_dep: Option<u8>,
    max_high: Option<usize>,
    max_sus: Option<usize>,
    max_vulns: Option<usize>,
    fail_on_vuln: Option<model::Severity>,
    cli_allow: &[String],
) -> gate::Policy {
    gate::Policy {
        max_risk: max_risk.or(gc.max_risk),
        max_dep: max_dep.or(gc.max_dep),
        max_high: max_high.or(gc.max_high),
        max_sus: max_sus.or(gc.max_sus),
        max_vulns: max_vulns.or(gc.max_vulns),
        fail_on_vuln: fail_on_vuln.or(gc.fail_on_vuln),
        allow: gc
            .allow
            .iter()
            .map(|e| gate::Allow {
                package: e.package.clone(),
                reason: e.reason.clone(),
                expires: e.expires.clone(),
            })
            .chain(cli_allow.iter().map(|p| gate::Allow {
                package: p.clone(),
                reason: None,
                expires: None,
            }))
            .collect(),
    }
}
