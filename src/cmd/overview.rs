//! `postmortem help` — the overview, grouped by the question each
//! command answers.

/// A branded, at-a-glance overview. This is intentionally a *start* — richer,
/// per-command help still lives behind `--help` / `<command> --help`.
/// `postmortem help` — the overview a newcomer reads first.
///
/// Grouped by the question each command answers rather than listed flat: at
/// sixteen commands an alphabetical list tells you nothing about where to start.
pub(crate) fn print_overview() {
    use owo_colors::OwoColorize;

    /// One command row, padded before colouring — ANSI escapes count toward a
    /// format width, so `{:<9}` on a coloured string misaligns the column.
    fn cmd(name: &str, what: &str) {
        println!("  {} {what}", format!("{name:<9}").cyan());
    }

    println!(
        "{} {}",
        "postmortem".bold(),
        env!("CARGO_PKG_VERSION").dimmed()
    );
    println!(
        "{}",
        "Supply-chain security scanner for the code you depend on.".dimmed()
    );
    println!(
        "{}",
        "No telemetry. Offline unless you pass --online or --vulns.".dimmed()
    );
    println!();
    println!("{}", "USAGE".bold());
    println!("  postmortem <command> [options]");

    println!("\n{}", "LOOK FOR PROBLEMS".bold());
    cmd("scan", "malicious code in your dependencies' source");
    cmd(
        "tree",
        &format!(
            "the dependency graph {}",
            "(--online, --vulns, --human)".dimmed()
        ),
    );
    cmd("audit", "one graded verdict: malware + risk + CVEs");
    cmd(
        "system",
        "your machine's OS packages (brew, apt, dnf, pacman, nix, apk)",
    );

    println!("\n{}", "UNDERSTAND ONE THING".bold());
    cmd(
        "why",
        &format!(
            "why a package is here {}",
            "(--blast: what a compromise reaches)".dimmed()
        ),
    );
    cmd(
        "timeline",
        "a package's history: handovers, install scripts, repo moves",
    );
    cmd(
        "diff",
        &format!(
            "what a change pulls in {}",
            "(also takes a GitHub PR URL)".dimmed()
        ),
    );
    cmd("scripts", "which dependencies execute code at install time");

    println!("\n{}", "DECIDE AND ACT".bold());
    cmd("fix", "the minimum upgrade that clears the known CVEs");
    cmd("licenses", "license inventory, with a deny / allow policy");
    cmd(
        "allowlist",
        "every suppression you have, and what has lapsed",
    );

    println!("\n{}", "PUT IT IN YOUR WORKFLOW".bold());
    cmd("sbom", "export the graph as a CycloneDX 1.5 SBOM");
    cmd(
        "ci",
        &format!(
            "a ready-made pipeline {}",
            "(gitlab · azure · jenkins · github)".dimmed()
        ),
    );
    cmd(
        "hook",
        "the git pre-commit hook for staged dependency changes",
    );
    cmd("watch", "re-scan whenever a lockfile changes");
    cmd("cache", "inspect and clear the cache the online paths use");
    cmd("help", "show this overview");

    println!("\n{}", "ECOSYSTEMS".bold());
    println!(
        "  {}",
        "node · python · rust · ruby · php · go · java".dimmed()
    );
    println!(
        "  {}",
        "and your machine: brew · pacman · apt · dnf · nix · apk".dimmed()
    );

    println!("\n{}", "EXAMPLES".bold());
    let ex = |c: &str, note: &str| println!("  {c:<44}{}", note.dimmed());
    ex("postmortem scan .", "# malicious code, offline");
    ex("postmortem audit . --online --vulns", "# one verdict");
    ex("postmortem tree . --omit dev", "# only what ships");
    ex(
        "postmortem tree . --online --human",
        "# who controls your tree",
    );
    ex("postmortem fix .", "# how to clear the CVEs");
    ex("postmortem scripts .", "# what runs on install");
    ex(
        "postmortem diff <github-pr-url> --online",
        "# what does this PR pull in",
    );
    ex(
        "postmortem timeline event-stream",
        "# when did it change hands",
    );
    ex(
        "postmortem ci gitlab > .gitlab-ci.yml",
        "# wire it into your pipeline",
    );

    println!(
        "\nRun {} for a command's flags, or read the manual at {}",
        "postmortem <command> --help".cyan(),
        "github.com/mlab-sh/postmortem/wiki".cyan()
    );
}
