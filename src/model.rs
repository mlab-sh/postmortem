use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Node,
    Python,
    Rust,
    Ruby,
    Php,
    Go,
    Java,
    /// Homebrew (macOS/Linux) — an OS-level package manager, surfaced by the
    /// `system` command rather than the project-lockfile parsers.
    Brew,
    /// Arch Linux `pacman` — an OS-level package manager (`system` command).
    Pacman,
    /// Debian/Ubuntu `apt`/`dpkg` — an OS-level package manager (`system` command).
    Apt,
    /// Fedora/RHEL `dnf`/`rpm` — an OS-level package manager (`system` command).
    Dnf,
}

impl Ecosystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Ecosystem::Node => "node",
            Ecosystem::Python => "python",
            Ecosystem::Rust => "rust",
            Ecosystem::Ruby => "ruby",
            Ecosystem::Php => "php",
            Ecosystem::Go => "go",
            Ecosystem::Java => "java",
            Ecosystem::Brew => "brew",
            Ecosystem::Pacman => "pacman",
            Ecosystem::Apt => "apt",
            Ecosystem::Dnf => "dnf",
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
#[clap(rename_all = "snake_case")]
pub enum Category {
    Ioc,
    Obfuscation,
    InstallHook,
    SensitiveApi,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Ioc => "ioc",
            Category::Obfuscation => "obfuscation",
            Category::InstallHook => "install_hook",
            Category::SensitiveApi => "sensitive_api",
        }
    }
}

/// (name, version) — disambiguates same-name-different-version in transitive graphs.
pub type DepRef = (String, String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub direct: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,
    pub parents: Vec<DepRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub dependency: String,
    pub severity: Severity,
    pub category: Category,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// External-investigation URL populated when `--enrich` is set. Today this
    /// is a deep-link into mlab.sh; future versions may also include CVE / OSV
    /// links per dependency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrich_url: Option<String>,
}

/// A first-class signal that the dependency graph is incomplete — so a `0`
/// result is never silently mistaken for "clean". Emitted when a lockfile fails
/// to parse, or when an ecosystem's transitive edges can't be reconstructed
/// offline (Go, Java).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub ecosystem: String,
    /// `parse_failed` | `flat_graph` | `replace_directive`
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub root: String,
    pub ecosystems: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
    pub dependencies: Vec<Dependency>,
    pub findings: Vec<Finding>,
}
