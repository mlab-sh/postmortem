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

    /// Show an overview of postmortem: what it does and the available commands.
    Help,
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

    /// Write output to file. Pass `-` to force stdout. When omitted for --json a
    /// file named `postmortem-tree-[MM.DD.YYYY::HH:MM].json` is written in the cwd.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Go ONLINE: resolve each dependency to its source repository and fetch
    /// reputation stats + identity/provenance signals. Touches the network.
    #[arg(long)]
    pub online: bool,

    /// Query known vulnerabilities via the mlab SBOM scan API (vuln.mlab.sh):
    /// the lockfile is scanned recursively and OSV/GHSA/CVE advisories are
    /// reported per package. Independent of --online.
    #[arg(long)]
    pub vulns: bool,

    /// Disable the animated progress UI (also auto-off when stderr isn't a TTY,
    /// or NO_COLOR / CI is set).
    #[arg(long)]
    pub no_progress: bool,
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
