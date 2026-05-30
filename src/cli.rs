use anyhow::Result;
use clap::{Parser, ValueEnum};
use std::path::{Path, PathBuf};

use crate::model::{Category, Severity};

#[derive(Parser, Debug)]
#[command(
    name = "postmortem",
    version,
    about = "Dependency scanner (Node / Python / Rust). Static analysis, no network by default."
)]
pub struct Cli {
    /// Path to the project to scan
    pub path: PathBuf,

    /// Emit JSON
    #[arg(long, conflicts_with_all = ["html"])]
    pub json: bool,

    /// Emit a self-contained HTML report
    #[arg(long, conflicts_with_all = ["json"])]
    pub html: bool,

    /// Write output to file instead of stdout
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
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Format {
    Terminal,
    Json,
    Html,
}

impl Cli {
    pub fn format(&self) -> Format {
        if self.json {
            Format::Json
        } else if self.html {
            Format::Html
        } else {
            Format::Terminal
        }
    }
}

pub fn write_output(path: Option<&Path>, data: &str) -> Result<()> {
    match path {
        Some(p) => std::fs::write(p, data)?,
        None => print!("{data}"),
    }
    Ok(())
}
