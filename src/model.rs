use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
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
    /// Nix (the store / profiles) — an OS-level package manager (`system` command).
    Nix,
    /// Alpine `apk` — an OS-level package manager (`system` command).
    Apk,
    /// Windows `winget` — an OS-level package manager (`system` command).
    Winget,
    /// Windows MSIX/AppX packages (Store and sideloaded) — `system` command.
    Msix,
    /// Windows `chocolatey` — an OS-level package manager (`system` command).
    Choco,
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
            Ecosystem::Nix => "nix",
            Ecosystem::Apk => "apk",
            Ecosystem::Winget => "winget",
            Ecosystem::Msix => "msix",
            Ecosystem::Choco => "choco",
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
    /// The artefact carries no valid signature, or its download was never
    /// verified against one (Authenticode, a repo key, a checksum).
    Unsigned,
    /// It came from a source outside the curated/official set — a Homebrew tap,
    /// the AUR, a PPA, a custom winget source, a scoop bucket.
    ThirdPartySource,
    /// It installs something that runs on its own afterwards: a boot service, a
    /// scheduled task, an autorun entry.
    Persistence,
    /// The permissions on what it installed are wider than they need to be
    /// (setuid, a world-writable path on an execution surface).
    WeakAcl,
    /// What is on disk no longer matches what the package database says should
    /// be there — modified files, a diversion.
    Tamper,
    /// The machine's own trust configuration is weakened or unverifiable: an
    /// un-synced package DB, relaxed signature checking.
    Policy,
    /// A version behind the current one. Not provenance and not persistence —
    /// running old code simply means missing upstream fixes.
    Outdated,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Ioc => "ioc",
            Category::Obfuscation => "obfuscation",
            Category::InstallHook => "install_hook",
            Category::SensitiveApi => "sensitive_api",
            Category::Unsigned => "unsigned",
            Category::ThirdPartySource => "third_party_source",
            Category::Persistence => "persistence",
            Category::WeakAcl => "weak_acl",
            Category::Tamper => "tamper",
            Category::Policy => "policy",
            Category::Outdated => "outdated",
        }
    }
}

/// Which dependency set a package belongs to, **after** propagation through the
/// graph ([`crate::scope::propagate`]).
///
/// A package is only `Dev` when *every* path from a root reaches it through a
/// development edge — anything also reachable from a production root is `Prod`,
/// because it ships. That ordering is what makes `--omit dev` safe: it can never
/// hide a package that ends up in the shipped artifact.
///
/// The variant order is the precedence order (`Dev < Optional < Prod`), so
/// merging two reachability paths is just [`Ord::max`].
#[derive(
    Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Reachable only through a dev/test edge (`devDependencies`,
    /// `[dev-dependencies]`, `require-dev`, Bundler's `:development`/`:test`
    /// groups, Maven `<scope>test</scope>`, Gradle `test*` configurations).
    Dev,
    /// Reachable only through an optional edge (`optionalDependencies`). Ships
    /// when it installs, so it outranks `Dev`.
    Optional,
    /// Ships with the application — the safe default for anything we cannot
    /// classify, so an unknown package is never silently omitted.
    #[default]
    Prod,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Dev => "dev",
            Scope::Optional => "optional",
            Scope::Prod => "prod",
        }
    }
}

fn is_unknown_source(s: &LicenseSource) -> bool {
    *s == LicenseSource::Unknown
}

/// One license claim about a package.
///
/// The three shapes are the ones CycloneDX distinguishes, and conflating them is
/// what gets a document rejected by SBOM consumers:
///
/// * `Id` — a valid SPDX short identifier (`MIT`). Emitted as `license.id`.
/// * `Expression` — a compound SPDX expression (`MIT OR Apache-2.0`). Emitted as
///   `expression`, which is a *sibling* of `license`, never a field inside it.
/// * `Name` — free text we could not map to SPDX (`"see LICENSE file"`).
///   Emitted as `license.name`. Never as an id: an invalid `id` fails schema
///   validation, so guessing here is worse than admitting ignorance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum License {
    Id { value: String },
    Expression { value: String },
    Name { value: String },
}

impl License {
    /// The text to show a human, whichever shape it is.
    pub fn label(&self) -> &str {
        match self {
            License::Id { value } | License::Expression { value } | License::Name { value } => {
                value
            }
        }
    }

    /// Did we manage to tie this to SPDX at all? Drives the "unknown license"
    /// count, which is the actionable number: an unidentifiable license is a
    /// legal unknown, not a permissive default.
    pub fn is_spdx(&self) -> bool {
        matches!(self, License::Id { .. } | License::Expression { .. })
    }
}

/// Where a license claim came from — a fact read from a lockfile is worth more
/// than one fetched from a registry describing a possibly different version.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LicenseSource {
    /// Declared in the project's own lockfile (npm, composer).
    Lockfile,
    /// Fetched from the package registry (`--online`).
    Registry,
    #[default]
    Unknown,
}

/// (name, version) — disambiguates same-name-different-version in transitive graphs.
pub type DepRef = (String, String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub direct: bool,
    /// Which dependency set this package belongs to. Parsers seed it for the
    /// *direct* deps they can classify; [`crate::scope::propagate`] then resolves
    /// it for the whole graph. Defaults to [`Scope::Prod`] so a report written by
    /// an older postmortem still deserializes.
    #[serde(default)]
    pub scope: Scope,
    /// Declared license(s). Populated offline where the lockfile records them
    /// (npm, composer) and by `--online` elsewhere. Empty means *unknown*, which
    /// is a finding in its own right — never assume permissive.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub licenses: Vec<License>,
    /// Where [`Self::licenses`] came from.
    #[serde(default, skip_serializing_if = "is_unknown_source")]
    pub license_source: LicenseSource,
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
    /// `parse_failed` | `flat_graph` | `replace_directive` | `scope_omitted`
    pub kind: String,
    pub message: String,
}

/// The `kind` recording a deliberate `--omit`, as opposed to an incompleteness
/// we suffered rather than chose.
pub const DIAG_SCOPE_OMITTED: &str = "scope_omitted";

impl Diagnostic {
    /// Does this diagnostic mean the graph is *unintentionally* incomplete?
    ///
    /// `--omit` also shrinks the graph, and that fact is worth carrying into the
    /// JSON/SARIF output so a CI consumer can see it — but it was asked for, so
    /// it must not read as a defect or drag a verdict down.
    pub fn is_incompleteness(&self) -> bool {
        self.kind != DIAG_SCOPE_OMITTED
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// 1: initial. 2: added `diagnostics`. 3: every dependency carries a
    /// [`Scope`]. Each bump is additive, so a consumer written against an older
    /// version keeps working — it just ignores the new field.
    pub schema_version: u32,
    pub root: String,
    pub ecosystems: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
    pub dependencies: Vec<Dependency>,
    pub findings: Vec<Finding>,
}
