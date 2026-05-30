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
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Format {
    Terminal,
    Json,
    Html,
    Sarif,
}

impl Cli {
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
        match user_choice {
            Some(p) if p.as_os_str() == "-" => OutputTarget::Stdout,
            Some(p) => OutputTarget::File(p.to_path_buf()),
            None => OutputTarget::File(default_filename(ext)),
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

/// `postmortem-report-[MM.DD.YYYY::HH:MM].<ext>` in the current working dir.
pub fn default_filename(ext: &str) -> PathBuf {
    let stamp = chrono::Local::now().format("%m.%d.%Y::%H:%M");
    PathBuf::from(format!("postmortem-report-[{stamp}].{ext}"))
}
