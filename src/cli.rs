use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};

use crate::model::{Category, Scope, Severity};

/// A dependency set `--omit` can drop.
///
/// Deliberately *not* [`Scope`] itself: production is not omittable, and letting
/// `--omit prod` parse would offer a flag whose only effect is to hide the code
/// that actually ships.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
#[clap(rename_all = "lowercase")]
pub enum OmitSet {
    /// Packages reachable only through a dev/test dependency edge.
    Dev,
    /// Packages reachable only through an optional dependency edge.
    Optional,
}

impl OmitSet {
    pub fn scope(self) -> Scope {
        match self {
            OmitSet::Dev => Scope::Dev,
            OmitSet::Optional => Scope::Optional,
        }
    }

    /// The scopes to drop for a given `--omit` selection.
    pub fn scopes(sets: &[OmitSet]) -> Vec<Scope> {
        sets.iter().map(|s| s.scope()).collect()
    }
}

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

    /// Resolve the dependency tree from the lockfiles. Offline by default;
    /// `--online` walks each node out to its source repository and pulls
    /// reputation and provenance stats to flag suspicious supply-chain updates,
    /// and `--vulns` adds known advisories.
    Tree(TreeArgs),

    /// Compare two project states and report added / removed / version-changed
    /// dependencies. Offline set-diff (the companion to the gate's `--baseline`).
    Diff(DiffArgs),

    /// Export the resolved dependency graph as a CycloneDX 1.5 SBOM (JSON).
    Sbom(SbomArgs),

    /// Explain why a package is installed: the dependency paths from it up to the
    /// direct dependencies (like `npm why` / `cargo tree -i`).
    Why(WhyArgs),

    /// One-shot graded health check: static malware scan + dependency inventory,
    /// plus optional online reputation (`--online`) and known vulns (`--vulns`).
    Audit(AuditArgs),

    /// Inventory the licenses of the dependency graph, and enforce a policy over
    /// them. Grouped by license, with the unresolved ones called out.
    Licenses(LicensesArgs),

    /// Turn the vulnerability report into the change that clears it: the
    /// minimum upgrade per package, and where to make it.
    Fix(FixArgs),

    /// Lay a package's release history out in order: when it changed hands,
    /// when an install script appeared, when its repository moved.
    Timeline(TimelineArgs),

    /// List every suppression the project declares — gate allowlist, ignore
    /// rules, skips — with how long each has left to run.
    Allowlist(AllowlistArgs),

    /// Manage the on-disk cache (~/.postmortem/cache) used by `tree --online`.
    Cache(CacheArgs),

    /// Audit the machine's OS-level package managers (Homebrew, pacman/AUR,
    /// apt/dpkg, dnf/rpm, Nix, apk): detect them, list their source repos, and
    /// tree the installed forest with the same risk scoring as `tree`.
    /// `--online` adds repo reputation, `--vulns` known CVEs.
    System(SystemArgs),

    /// Show an overview of postmortem: what it does and the available commands.
    Help,
}

/// Arguments for `postmortem timeline <package>`.
#[derive(Args, Debug)]
pub struct TimelineArgs {
    /// The package whose history to lay out. npm only — it is the one registry
    /// publishing a per-version history rather than a current view.
    pub package: String,

    /// Project directory used to mark which version you have installed.
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// List every release, including those that changed nothing.
    #[arg(long)]
    pub all: bool,

    /// Emit the history as JSON instead of the terminal view.
    #[arg(long)]
    pub json: bool,

    /// Write output to file. Pass `-` to force stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Disable the animated progress UI.
    #[arg(long)]
    pub no_progress: bool,
}

/// Arguments for `postmortem allowlist <path>`.
#[derive(Args, Debug)]
pub struct AllowlistArgs {
    /// Project directory whose `postmortem.conf` to read.
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Only show suppressions that have lapsed, and exit 1 if any have — so a
    /// scheduled job can surface the debt nobody renewed.
    #[arg(long)]
    pub expired: bool,

    /// Also flag entries lapsing within this many days.
    #[arg(long, value_name = "DAYS")]
    pub expiring_in: Option<i64>,

    /// Emit the listing as JSON instead of the terminal view.
    #[arg(long)]
    pub json: bool,

    /// Write output to file. Pass `-` to force stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Path to a postmortem.conf. Defaults to the one in <PATH>.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Accepted for symmetry with the other commands; this one reads a config
    /// file and has nothing to animate.
    #[arg(long)]
    pub no_progress: bool,
}

/// Arguments for `postmortem fix <path>`.
#[derive(Args, Debug)]
pub struct FixArgs {
    /// Project directory to plan a fix for.
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Omit a dependency set from the plan. Repeatable: `--omit dev --omit
    /// optional`. A package reachable from production is always kept — see
    /// the dependency-scopes documentation.
    #[arg(long, value_enum)]
    pub omit: Vec<OmitSet>,

    /// Emit the plan as JSON instead of the terminal view.
    #[arg(long)]
    pub json: bool,

    /// Write output to file. Pass `-` to force stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Exit 0 even when advisories remain. By default the command exits 1 while
    /// anything is still outstanding, so it drops into CI as a blocking step.
    #[arg(long)]
    pub no_fail: bool,

    /// Disable the animated progress UI.
    #[arg(long)]
    pub no_progress: bool,
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

    /// Force foreign/AUR detection even when the package DB looks un-synced
    /// (pacman): normally that state is skipped to avoid flagging everything.
    #[arg(long)]
    pub force_aur: bool,

    /// Scan installed packages for known vulnerabilities. Covers apt
    /// (Debian/Ubuntu), apk (Alpine) and dnf (Rocky/AlmaLinux) via OSV, and
    /// pacman via the Arch Security Tracker; other backends report as un-scanned
    /// rather than clean. Touches the network.
    #[arg(long)]
    pub vulns: bool,

    /// Override the detected OS release used for the OSV lookup, as `id:version`
    /// (e.g. `debian:12`, `alpine:3.19`). Defaults to `/etc/os-release`. Useful
    /// when scanning an image whose os-release isn't this machine's.
    #[arg(long)]
    pub release: Option<String>,

    /// Disable the animated progress UI.
    #[arg(long)]
    pub no_progress: bool,

    // --- CI gate (see `crate::gate`), mirroring `tree`. Each threshold is a
    // ceiling: the gate trips (exit 1) when the measured value is strictly
    // greater. A vuln gate over an un-scannable backend (brew/nix, Fedora/RHEL)
    // is INCONCLUSIVE and exits 2 — never a silent pass. ---
    /// GATE: fail if the machine's worst risk score exceeds this (0–100).
    #[arg(long, value_name = "N")]
    pub max_risk: Option<u8>,

    /// GATE: fail if any package's subtree (dep) score exceeds this (0–100).
    #[arg(long, value_name = "N")]
    pub max_dep: Option<u8>,

    /// GATE: fail if more than N high-risk packages are present.
    #[arg(long, value_name = "N")]
    pub max_high: Option<usize>,

    /// GATE: fail if more than N suspicious packages are present.
    #[arg(long, value_name = "N")]
    pub max_sus: Option<usize>,

    /// GATE: fail if more than N known vulnerabilities are present. Needs --vulns.
    #[arg(long, value_name = "N")]
    pub max_vulns: Option<usize>,

    /// GATE: fail if any known vulnerability is at least this severe. Needs --vulns.
    #[arg(long, value_enum, value_name = "SEV")]
    pub fail_on_vuln: Option<Severity>,

    /// GATE: allowlist a package (name or name@version) from every gate count.
    /// Repeatable. For a reason/expiry, use a [[gate.allow]] block in a config.
    #[arg(long = "allow", value_name = "PKG")]
    pub allow: Vec<String>,

    /// Path to a postmortem.conf supplying a [gate] policy.
    #[arg(long)]
    pub config: Option<PathBuf>,
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

    /// Report IOC findings inside test/fixture directories too (off by default).
    #[arg(long)]
    pub allow_test_files: bool,

    /// Disable the animated progress UI.
    #[arg(long)]
    pub no_progress: bool,
}

/// Arguments for `postmortem diff <old> <new>`.
#[derive(Args, Debug)]
pub struct DiffArgs {
    /// The baseline project directory (the "before" state), **or** a GitHub
    /// pull-request URL — `https://github.com/owner/repo/pull/42` — in which
    /// case both sides come from the PR and `<NEW>` is omitted.
    pub old: String,

    /// The project directory to compare against it (the "after" state). Omit
    /// when `<OLD>` is a pull-request URL.
    pub new: Option<String>,

    /// Go ONLINE and assess what the change *introduces*: source-repo
    /// reputation and provenance signals for the added and version-changed
    /// packages. Only those are resolved, so the cost scales with the diff, not
    /// with the tree.
    #[arg(long)]
    pub online: bool,

    /// Report known vulnerabilities against the packages the change introduces.
    #[arg(long)]
    pub vulns: bool,

    /// Emit the result as JSON instead of the terminal view.
    #[arg(long)]
    pub json: bool,

    /// Write output to file. Pass `-` to force stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Omit a dependency set from the analysis. Repeatable: `--omit dev --omit
    /// optional`. A package is dropped only when *every* path to it from a root
    /// goes through an omitted edge, so anything that also ships in production
    /// stays. Ecosystems that do not record the distinction (Go) are unaffected.
    #[arg(long, value_enum)]
    pub omit: Vec<OmitSet>,

    /// Disable the animated progress UI.
    #[arg(long)]
    pub no_progress: bool,
}

/// Arguments for `postmortem sbom <path>`.
#[derive(Args, Debug)]
pub struct SbomArgs {
    /// The project directory to resolve and export.
    pub path: PathBuf,

    /// Write output to file. Pass `-` for stdout. When omitted, a file named
    /// `postmortem-sbom-[MM.DD.YYYY::HH:MM].json` is written in the cwd.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Go ONLINE to fill in licenses the lockfile does not record. npm and
    /// composer declare them offline; every other ecosystem needs its registry.
    /// Reuses the `tree --online` cache, and adds no request beyond the ones
    /// repo resolution already makes.
    #[arg(long)]
    pub online: bool,

    /// Omit a dependency set from the analysis. Repeatable: `--omit dev --omit
    /// optional`. A package is dropped only when *every* path to it from a root
    /// goes through an omitted edge, so anything that also ships in production
    /// stays. Ecosystems that do not record the distinction (Go) are unaffected.
    #[arg(long, value_enum)]
    pub omit: Vec<OmitSet>,

    /// Disable the animated progress UI.
    #[arg(long)]
    pub no_progress: bool,
}

/// Arguments for `postmortem why <package> <path>`.
#[derive(Args, Debug)]
pub struct WhyArgs {
    /// The package name to explain.
    pub package: String,

    /// The project directory to resolve.
    pub path: PathBuf,

    /// Blast radius instead of the paths: what a compromise of this package
    /// would reach — how much of the tree depends on it, whether it ships,
    /// whether it runs at install time, and what that position exposes.
    #[arg(long)]
    pub blast: bool,

    /// Emit the result as JSON instead of the terminal view.
    #[arg(long)]
    pub json: bool,

    /// Write output to file. Pass `-` to force stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Omit a dependency set from the analysis. Repeatable: `--omit dev --omit
    /// optional`. A package is dropped only when *every* path to it from a root
    /// goes through an omitted edge, so anything that also ships in production
    /// stays. Ecosystems that do not record the distinction (Go) are unaffected.
    #[arg(long, value_enum)]
    pub omit: Vec<OmitSet>,

    /// Disable the animated progress UI.
    #[arg(long)]
    pub no_progress: bool,
}

/// Arguments for `postmortem audit <path>`.
#[derive(Args, Debug)]
pub struct AuditArgs {
    /// The project directory to audit.
    pub path: PathBuf,

    /// Go ONLINE: add source-repo reputation risk scoring. Touches the network.
    #[arg(long)]
    pub online: bool,

    /// With --online, also fetch each repo's language breakdown.
    #[arg(long)]
    pub languages: bool,

    /// Add known-vulnerability intelligence via the mlab SBOM scan (vuln.mlab.sh).
    #[arg(long)]
    pub vulns: bool,

    /// Report IOC findings inside test/fixture directories too (off by default).
    #[arg(long)]
    pub allow_test_files: bool,

    /// Emit the result as JSON instead of the terminal view.
    #[arg(long)]
    pub json: bool,

    /// Write output to file. Pass `-` to force stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Omit a dependency set from the analysis. Repeatable: `--omit dev --omit
    /// optional`. A package is dropped only when *every* path to it from a root
    /// goes through an omitted edge, so anything that also ships in production
    /// stays. Ecosystems that do not record the distinction (Go) are unaffected.
    #[arg(long, value_enum)]
    pub omit: Vec<OmitSet>,

    // --- CI gate (see `crate::gate`), mirroring `tree`. Each threshold is a
    // ceiling: the gate trips (exit 1) when the measured value is strictly
    // greater. Thresholds needing data the run did not collect are a
    // misconfiguration (exit 2), never a silent pass. ---
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
    /// Repeatable. For a reason/expiry, use a [[gate.allow]] block in a config.
    #[arg(long = "allow", value_name = "PKG")]
    pub allow: Vec<String>,

    /// GATE: diff mode — only count risk absent from this baseline (a prior
    /// `tree --json`), so an existing problem does not fail every build.
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<PathBuf>,

    /// Path to a postmortem.conf supplying a [gate] policy.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Disable the animated progress UI.
    #[arg(long)]
    pub no_progress: bool,
}

/// Arguments for `postmortem licenses <path>`.
#[derive(Args, Debug)]
pub struct LicensesArgs {
    /// The project directory to inventory.
    pub path: PathBuf,

    /// Go ONLINE to resolve licenses the lockfile does not record. npm and
    /// composer declare them offline; every other ecosystem needs its registry.
    /// Adds no request beyond the ones repo resolution already makes.
    #[arg(long)]
    pub online: bool,

    /// Show only the packages whose license could not be resolved — the set
    /// worth acting on.
    #[arg(long)]
    pub unknown_only: bool,

    /// List the packages under each license instead of just counting them.
    #[arg(long)]
    pub packages: bool,

    /// Emit the inventory as JSON.
    #[arg(long)]
    pub json: bool,

    /// Write output to file. Pass `-` to force stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// POLICY: fail if this SPDX id is present. Repeatable. A dual-licensed
    /// package is only flagged when *every* alternative it offers is denied.
    #[arg(long = "deny", value_name = "SPDX")]
    pub deny: Vec<String>,

    /// POLICY: permit only these SPDX ids; anything else fails. Repeatable.
    #[arg(long = "allow", value_name = "SPDX")]
    pub allow: Vec<String>,

    /// POLICY: fail if any package has no resolvable license. Off by default,
    /// since coverage depends on the ecosystem — pair it with `--online`.
    #[arg(long)]
    pub fail_on_unknown: bool,

    /// Path to a postmortem.conf supplying a [license] policy. Otherwise
    /// postmortem.conf is auto-loaded from the project directory.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Omit a dependency set from the analysis. Repeatable: `--omit dev --omit
    /// optional`. A package is dropped only when *every* path to it from a root
    /// goes through an omitted edge, so anything that also ships in production
    /// stays. Ecosystems that do not record the distinction (Go) are unaffected.
    #[arg(long, value_enum)]
    pub omit: Vec<OmitSet>,

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
    /// Remove cached entries. With no filter, prunes everything.
    Prune(PruneArgs),

    /// Summarize the cache: entries, size and age per namespace, plus how many
    /// entries were written by an older record format and will be refetched.
    Info,

    /// Print the cache directory, and nothing else — so it composes:
    /// `du -sh "$(postmortem cache path)"`.
    Path,
}

#[derive(Args, Debug)]
pub struct PruneArgs {
    /// Only remove entries older than this many days (default: remove all).
    #[arg(long)]
    pub older_than: Option<u64>,

    /// Only remove entries written by an older record format — the ones a
    /// postmortem upgrade has already invalidated. They are dropped lazily as
    /// they are touched anyway; this sweeps them all in one pass.
    #[arg(long)]
    pub stale: bool,

    /// Show what would be removed without deleting anything.
    #[arg(long)]
    pub dry_run: bool,
}

/// Arguments for `postmortem tree <paths>...`.
#[derive(Args, Debug)]
pub struct TreeArgs {
    /// One or more targets to resolve: a project directory, or an explicit
    /// manifest/lockfile (e.g. `packages/api/yarn.lock`) to pin one ecosystem
    /// and one lockfile flavor. Machine formats (--json/--sarif) require a
    /// single target unless --allow-multiple is given.
    #[arg(required = true, num_args = 1..)]
    pub paths: Vec<PathBuf>,

    /// Allow --json/--sarif with several targets. THE OUTPUT SHAPE CHANGES:
    /// --json emits an ARRAY of trees instead of one object, and --sarif emits
    /// one `runs[]` entry per target. Consumers that assume a single tree will
    /// break — that's why it is opt-in.
    #[arg(long)]
    pub allow_multiple: bool,

    /// Limit the tree to this many levels below each root.
    #[arg(long)]
    pub depth: Option<usize>,

    /// Show the **maintainer graph** instead of the tree: which accounts control
    /// the largest share of it, measured by what a compromise of each would
    /// reach. Requires --online (the maintainer sets come from the registry).
    #[arg(long)]
    pub human: bool,

    /// Emit the resolved tree as JSON instead of the terminal view.
    #[arg(long)]
    pub json: bool,

    /// Emit SARIF 2.1.0 — risk signals + known vulns as GitHub Code Scanning
    /// alerts. Combine with --online / --vulns for content.
    #[arg(long, conflicts_with_all = ["json", "html"])]
    pub sarif: bool,

    /// Emit a self-contained HTML report: the flagged packages worst-first with
    /// their source repos and signals, known vulnerabilities, and the full
    /// forest. Combine with --online / --vulns for content. One target only,
    /// unless --allow-multiple.
    #[arg(long, conflicts_with = "json")]
    pub html: bool,

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

    /// Omit a dependency set from the analysis. Repeatable: `--omit dev --omit
    /// optional`. A package is dropped only when *every* path to it from a root
    /// goes through an omitted edge, so anything that also ships in production
    /// stays. Ecosystems that do not record the distinction (Go) are unaffected.
    #[arg(long, value_enum)]
    pub omit: Vec<OmitSet>,

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

    /// Report IOC findings inside test/fixture directories too. Off by default:
    /// test code routinely embeds fake IPs/URLs/domains (pure noise).
    #[arg(long)]
    pub allow_test_files: bool,

    /// Omit a dependency set from the analysis. Repeatable: `--omit dev --omit
    /// optional`. A package is dropped only when *every* path to it from a root
    /// goes through an omitted edge, so anything that also ships in production
    /// stays. Ecosystems that do not record the distinction (Go) are unaffected.
    #[arg(long, value_enum)]
    pub omit: Vec<OmitSet>,

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
