//! postmortem — supply-chain auditing for a project's dependencies, and for
//! the machine's own packages.
//!
//! This file is dispatch and nothing else. Every command lives in its own
//! module under `cmd`, over a shared core: `detect` + `parsers` build the
//! graph, `analyze` reads the code, `resolve` is the only networked part, and
//! `report` renders. Work that more than one command needs sits in
//! `cmd::common` and `cmd::gate_policy`.

mod analyze;
mod archsec;
mod audit;
mod blast;
mod cache;
mod ci;
mod cli;
mod cmd;
mod config;
mod detect;
mod diff;
mod enrich;
mod fix;
mod gate;
mod gochi;
mod hook;
mod human;
mod inspect;
mod license;
mod lifecycle;
mod model;
mod osv;
mod parsers;
mod pr;
mod report;
mod resolve;
mod sbom;
mod scope;
mod scripts;
mod semver;
mod settings;
mod system;
mod timeline;
mod tree;
mod typosquat;
mod ui;
mod vuln;
mod watch;
mod webhook;
mod why;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    match cli::Cli::parse().command {
        cli::Command::Scan(args) => cmd::scan::run_scan(args),
        cli::Command::Tree(args) => cmd::tree::run_tree(args),
        cli::Command::Diff(args) => cmd::diff::run_diff(args),
        cli::Command::Sbom(args) => cmd::sbom::run_sbom(args),
        cli::Command::Why(args) => cmd::why::run_why(args),
        cli::Command::Audit(args) => cmd::audit::run_audit(args),
        cli::Command::Licenses(args) => cmd::licenses::run_licenses(args),
        cli::Command::Fix(args) => cmd::fix::run_fix(args),
        cli::Command::Scripts(args) => cmd::scripts::run_scripts(args),
        cli::Command::Hook(args) => cmd::hook::run_hook(args),
        cli::Command::Watch(args) => cmd::watch::run_watch(args),
        cli::Command::Timeline(args) => cmd::timeline::run_timeline(args),
        cli::Command::Allowlist(args) => cmd::allowlist::run_allowlist(args),
        cli::Command::Ci(a) => cmd::ci::run_ci(a),
        cli::Command::Cache(args) => cmd::cache::run_cache(args),
        cli::Command::System(args) => cmd::system::run_system(args),
        cli::Command::Help => {
            cmd::overview::print_overview();
            Ok(())
        }
    }
}
