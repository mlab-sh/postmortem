use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};

use crate::model::{Category, Severity};

#[derive(Parser, Debug)]
#[command(
    name = "postmortem",
    version,
    about = "Dependency scanner (Node / Python / Rust). Static analysis, no network by default.",
    subcommand_required = true,
    arg_required_else_help = true,
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Scan one or more project directories for malicious dependencies.
    Scan(ScanArgs),

    /// Resolve the dependency tree from the lockfiles. Offline today; `--online`
    /// (coming soon) will walk each node out to its source repository and pull
    /// reputation stats to flag suspicious supply-chain updates.
    Tree(TreeArgs),

    /// Manage the on-disk cache (~/.postmortem/cache) used by `tree --online`.
    Cache(CacheArgs),

    /// Audit the machine's OS-level package managers (Homebrew today): detect
    /// them, list their source repos, and tree the installed forest with the
    /// same risk scoring as `tree`. `--online` adds repo reputation.
    System(SystemArgs),

    /// Show an overview of postmortem: what it does and the available commands.
    Help,
}

/// Arguments for `postmortem system`.
#[derive(Args, Debug)]
pub struct SystemArgs {
    /// Focus on one installed package instead of the whole machine.
    #[command(subcommand)]
    pub command: Option<SystemCommand>,

    /// List the configured source repos (Homebrew taps) and exit, flagging
    /// third-party taps that bypass core review.
    #[arg(long)]
    pub repos: bool,

    /// Limit the tree to this many levels below each root.
    #[arg(long)]
    pub depth: Option<usize>,

    /// Emit the resolved forest as JSON instead of the terminal view.
    #[arg(long)]
    pub json: bool,

    /// Go ONLINE: resolve each package to its source repo and fetch reputation
    /// stats (Homebrew `homepage` → GitHub). Touches the network.
    #[arg(long)]
    pub online: bool,

    /// With --online, also fetch each repo's language breakdown (one extra,
    /// cached, call per repo).
    #[arg(long)]
    pub languages: bool,

    /// Disable the animated progress UI.
    #[arg(long)]
    pub no_progress: bool,
}

#[derive(Subcommand, Debug)]
pub enum SystemCommand {
    /// Inspect one installed package: show only its dependency subtree. With
    /// `--deep`, clone every dependency's source and run the full detection
    /// suite (scan + tree --online + --vulns) over it, into a Markdown report.
    Inspect(InspectArgs),
}

#[derive(Args, Debug)]
pub struct InspectArgs {
    /// The installed package to inspect.
    pub package: String,

    /// Deep mode: clone every dependency's source repo and run the complete
    /// analysis over the actual code. Touches the network and disk.
    #[arg(long)]
    pub deep: bool,

    /// Assume "yes" to the deep-analysis confirmation prompt.
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// Disable the animated progress UI.
    #[arg(long)]
    pub no_progress: bool,
}

/// `postmortem cache <action>`.
#[derive(Args, Debug)]
pub struct CacheArgs {
    #[command(subcommand)]
    pub action: CacheAction,
}

#[derive(Subcommand, Debug)]
pub enum CacheAction {
    /// Remove cached entries. With no filter, prunes everything; more actions
    /// (path, info, …) will land here later.
    Prune(PruneArgs),
}

#[derive(Args, Debug)]
pub struct PruneArgs {
    /// Only remove entries older than this many days (default: remove all).
    #[arg(long)]
    pub older_than: Option<u64>,

    /// Show what would be removed without deleting anything.
    #[arg(long)]
    pub dry_run: bool,
}

/// Arguments for `postmortem tree <paths>...`.
#[derive(Args, Debug)]
pub struct TreeArgs {
    /// One or more project directories to resolve. Machine format (--json)
    /// requires a single path.
    #[arg(required = true, num_args = 1..)]
    pub paths: Vec<PathBuf>,

    /// Limit the tree to this many levels below each root.
    #[arg(long)]
    pub depth: Option<usize>,

    /// Emit the resolved tree as JSON instead of the terminal view.
    #[arg(long)]
    pub json: bool,

    /// Emit SARIF 2.1.0 — risk signals + known vulns as GitHub Code Scanning
    /// alerts. Combine with --online / --vulns for content.
    #[arg(long, conflicts_with = "json")]
    pub sarif: bool,

    /// Write output to file. Pass `-` to force stdout. When omitted for --json a
    /// file named `postmortem-tree-[MM.DD.YYYY::HH:MM].json` is written in the cwd.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Go ONLINE: resolve each dependency to its source repository and fetch
    /// reputation stats + identity/provenance signals. Touches the network.
    #[arg(long)]
    pub online: bool,

    /// With --online, also fetch each repo's language breakdown (one extra,
    /// cached, call per repo). Without it, only GitHub's free primary language
    /// is shown.
    #[arg(long)]
    pub languages: bool,

    /// Query known vulnerabilities via the mlab SBOM scan API (vuln.mlab.sh):
    /// the lockfile is scanned recursively and OSV/GHSA/CVE advisories are
    /// reported per package. Independent of --online.
    #[arg(long)]
    pub vulns: bool,

    /// Disable the animated progress UI (also auto-off when stderr isn't a TTY,
    /// or NO_COLOR / CI is set).
    #[arg(long)]
    pub no_progress: bool,

    // --- CI gate (see `crate::gate`). Each threshold is a ceiling: the gate
    // trips (exit 1) when the measured value is strictly greater. Score/count
    // gates require --online; vuln gates require --vulns. ---
    /// GATE: fail if the worst risk score exceeds this (0–100). Needs --online.
    #[arg(long, value_name = "N")]
    pub max_risk: Option<u8>,

    /// GATE: fail if any dependency's subtree (dep) score exceeds this (0–100). Needs --online.
    #[arg(long, value_name = "N")]
    pub max_dep: Option<u8>,

    /// GATE: fail if more than N high-risk deps are present. Needs --online.
    #[arg(long, value_name = "N")]
    pub max_high: Option<usize>,

    /// GATE: fail if more than N suspicious deps are present. Needs --online.
    #[arg(long, value_name = "N")]
    pub max_sus: Option<usize>,

    /// GATE: fail if more than N known vulnerabilities are present. Needs --vulns.
    #[arg(long, value_name = "N")]
    pub max_vulns: Option<usize>,

    /// GATE: fail if any known vulnerability is at least this severe. Needs --vulns.
    #[arg(long, value_enum, value_name = "SEV")]
    pub fail_on_vuln: Option<Severity>,

    /// GATE: allowlist a package (name or name@version) from every gate count.
    /// Repeatable. For a reason/expiry, use a [[gate.allow]] block in postmortem.conf.
    #[arg(long = "allow", value_name = "PKG")]
    pub allow: Vec<String>,

    /// GATE: diff mode — only count risk absent from this baseline (a prior
    /// `tree --json` file), so the build fails on newly-introduced risk only.
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<PathBuf>,

    /// Path to a postmortem.conf supplying a [gate] policy. Defaults to
    /// auto-loading postmortem.conf from the scanned directory when present.
    #[arg(long)]
    pub config: Option<PathBuf>,
}

/// Arguments for `postmortem scan <paths>...`.
#[derive(Args, Debug)]
pub struct ScanArgs {
    /// One or more project directories to scan. Multiple paths are scanned in
    /// sequence; machine formats (--json/--html/--sarif) require a single path.
    #[arg(required = true, num_args = 1..)]
    pub paths: Vec<PathBuf>,

    /// Emit JSON
    #[arg(long, conflicts_with_all = ["html", "sarif"])]
    pub json: bool,

    /// Emit a self-contained HTML report
    #[arg(long, conflicts_with_all = ["json", "sarif"])]
    pub html: bool,

    /// Emit SARIF 2.1.0 — consumable by GitHub Code Scanning and other
    /// SARIF-aware tools.
    #[arg(long, conflicts_with_all = ["json", "html"])]
    pub sarif: bool,

    /// Write output to file. Pass `-` to force stdout. When omitted for
    /// `--json` / `--html` / `--sarif`, a file named
    /// `postmortem-report-[MM.DD.YYYY::HH:MM].<ext>` is written in the cwd.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Minimum severity that causes a non-zero exit code (CI gate)
    #[arg(long, value_enum, default_value_t = Severity::High)]
    pub severity: Severity,

    /// Skip every analyzer — only emit the SBOM
    #[arg(long)]
    pub skip_analyze: bool,

    /// Attach an mlab.sh deep-link to every IOC finding so you can click
    /// through to enrichment (WHOIS / passive DNS / abuse). No HTTP is made
    /// — links only.
    #[arg(long)]
    pub enrich: bool,

    /// Hide entire finding categories. Repeatable: `--skip-category ioc --skip-category obfuscation`,
    /// or comma-separated: `--skip-category ioc,obfuscation`.
    #[arg(long, value_enum, value_delimiter = ',', num_args = 1..)]
    pub skip_category: Vec<Category>,

    /// Path to a postmortem.conf file. If omitted, postmortem.conf is auto-loaded
    /// from the scanned directory when present.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Disable auto-loading of postmortem.conf from the scanned directory
    #[arg(long, conflicts_with = "config")]
    pub no_config: bool,

    /// Skip the dependency table in terminal output (findings only)
    #[arg(long)]
    pub no_deps: bool,

    /// Hide findings whose severity is below this threshold from the report
    #[arg(long, value_enum)]
    pub min_severity: Option<Severity>,

    /// Disable the animated progress UI. Progress is also auto-disabled when
    /// stderr is not a TTY, or when NO_COLOR / CI is set.
    #[arg(long)]
    pub no_progress: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Format {
    Terminal,
    Json,
    Html,
    Sarif,
}

impl ScanArgs {
    pub fn format(&self) -> Format {
        if self.json {
            Format::Json
        } else if self.html {
            Format::Html
        } else if self.sarif {
            Format::Sarif
        } else {
            Format::Terminal
        }
    }
}

/// Target for a machine-format output (json/html/sarif). Terminal format
/// always writes to stdout via println! directly.
pub enum OutputTarget {
    Stdout,
    File(PathBuf),
}

impl OutputTarget {
    pub fn resolve(user_choice: Option<&Path>, ext: &str) -> Self {
        Self::resolve_named(user_choice, "report", ext)
    }

    /// Like [`resolve`](Self::resolve) but with a custom default-filename stem
    /// (e.g. `tree` → `postmortem-tree-[…].json`).
    pub fn resolve_named(user_choice: Option<&Path>, stem: &str, ext: &str) -> Self {
        match user_choice {
            Some(p) if p.as_os_str() == "-" => OutputTarget::Stdout,
            Some(p) => OutputTarget::File(p.to_path_buf()),
            None => OutputTarget::File(default_named(stem, ext)),
        }
    }

    pub fn write(&self, data: &str) -> Result<()> {
        match self {
            OutputTarget::Stdout => {
                print!("{data}");
                Ok(())
            }
            OutputTarget::File(p) => {
                std::fs::write(p, data)?;
                eprintln!("wrote {} bytes to {}", data.len(), p.display());
                Ok(())
            }
        }
    }
}

/// `postmortem-<stem>-[MM.DD.YYYY::HH:MM].<ext>` in the current working dir.
pub fn default_named(stem: &str, ext: &str) -> PathBuf {
    let stamp = chrono::Local::now().format("%m.%d.%Y::%H:%M");
    PathBuf::from(format!("postmortem-{stem}-[{stamp}].{ext}"))
}
