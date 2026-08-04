//! `postmortem tree` — resolve and render the dependency graph.
//!
//! Today this is fully **offline**: it reuses the same lockfile parsers as
//! `scan` and renders the recursive dependency forest. It is also the home of
//! the forthcoming **online** step (see [`crate::resolve`]): walking each node
//! out to its source repository and pulling reputation stats (stars, age, last
//! push) to surface suspicious supply-chain updates — a fresh package version
//! that now points at a 1-star, days-old, or freshly-transferred repo. That
//! resolution is the only part of postmortem that touches the network, and it
//! stays behind the explicit `--online` opt-in.

use std::collections::{BTreeMap, HashMap, HashSet};

use owo_colors::OwoColorize;
use serde::Serialize;

use crate::model::{Dependency, DepRef, Severity};
use crate::resolve::Resolution;

/// Amber/orange for the "inactive"/suspicious tier (true-color; degrades gracefully).
const ORANGE: (u8, u8, u8) = (255, 165, 0);
/// A clearer yellow for the informational "services" line — deliberately pulled
/// away from the amber warning above so the two don't read alike.
const YELLOW: (u8, u8, u8) = (232, 218, 92);

/// A resolved dependency forest, serializable for `--json` so downstream tooling
/// can consume the graph (the "use this data later" foundation).
#[derive(Debug, Serialize)]
pub struct Tree {
    pub root: String,
    pub ecosystems: Vec<String>,
    pub stats: Stats,
    /// Incomplete-graph / parse signals (see [`crate::model::Diagnostic`]).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<crate::model::Diagnostic>,
    /// Known vulnerabilities from the mlab SBOM scan (`--vulns`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vulnerabilities: Vec<crate::vuln::VulnPackage>,
    /// True once [`score`] has run (online mode) — gates score display.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub scored: bool,
    pub roots: Vec<Node>,
}

#[derive(Debug, Serialize)]
pub struct Node {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub direct: bool,
    /// True when this node was already expanded elsewhere in the forest and is
    /// shown collapsed to keep the output finite (diamond deps / cycles).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub deduped: bool,
    /// True when children exist but were hidden by `--depth`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,

    // --- online enrichment (populated only by `tree --online`) ---
    /// Resolved source repo, `owner/repo`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// Repository star count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stars: Option<u64>,
    /// Risk signals raised for this node.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<String>,
    /// Worst signal severity — drives the node's color.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// The package's own risk score, 0–100.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<u8>,
    /// Its dependency-subtree risk score, 0–100.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dep: Option<u8>,
    /// Source-repo primary language (online; free on GitHub).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// Source-repo language breakdown `(name, percent)` (online, `--languages`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub languages: Option<Vec<(String, f64)>>,

    pub children: Vec<Node>,
}

#[derive(Debug, Serialize, Clone, Copy)]
pub struct Stats {
    pub total: usize,
    pub direct: usize,
    pub transitive: usize,
    pub max_depth: usize,
    /// Nodes collapsed as duplicates (diamond deps / cycles).
    pub deduped: usize,
}

/// Build the dependency forest for one project.
pub fn build(root: &str, ecosystems: &[String], deps: &[Dependency], depth: Option<usize>) -> Tree {
    // Roots: the direct dependencies. Fall back to parent-less nodes if a
    // lockfile marks nothing direct.
    let mut roots: Vec<DepRef> = deps
        .iter()
        .filter(|d| d.direct)
        .map(|d| (d.name.clone(), d.version.clone()))
        .collect();
    if roots.is_empty() {
        roots = deps
            .iter()
            .filter(|d| d.parents.is_empty())
            .map(|d| (d.name.clone(), d.version.clone()))
            .collect();
    }
    build_with_roots(root, ecosystems, deps, depth, roots)
}

/// Build a forest rooted at a single package `name` (all its installed versions)
/// — its dependency subtree only, for `system inspect`.
pub fn build_focused(
    root: &str,
    ecosystems: &[String],
    deps: &[Dependency],
    depth: Option<usize>,
    name: &str,
) -> Tree {
    let roots: Vec<DepRef> = deps
        .iter()
        .filter(|d| d.name == name)
        .map(|d| (d.name.clone(), d.version.clone()))
        .collect();
    build_with_roots(root, ecosystems, deps, depth, roots)
}

/// Shared forest builder given an explicit set of roots.
fn build_with_roots(
    root: &str,
    ecosystems: &[String],
    deps: &[Dependency],
    depth: Option<usize>,
    mut roots: Vec<DepRef>,
) -> Tree {
    let index: BTreeMap<DepRef, &Dependency> = deps
        .iter()
        .map(|d| ((d.name.clone(), d.version.clone()), d))
        .collect();

    // Invert the parent edges into a child adjacency map (sorted for stable output).
    let mut children: BTreeMap<DepRef, Vec<DepRef>> = BTreeMap::new();
    for d in deps {
        let child = (d.name.clone(), d.version.clone());
        for parent in &d.parents {
            children.entry(parent.clone()).or_default().push(child.clone());
        }
    }
    for kids in children.values_mut() {
        kids.sort();
        kids.dedup();
    }

    roots.sort();
    roots.dedup();

    let mut expanded: HashSet<DepRef> = HashSet::new();
    let mut stats = Stats {
        total: deps.len(),
        direct: deps.iter().filter(|d| d.direct).count(),
        transitive: deps.iter().filter(|d| !d.direct).count(),
        max_depth: 0,
        deduped: 0,
    };

    let root_nodes = roots
        .iter()
        .map(|k| build_node(k, &index, &children, &mut expanded, &mut stats, depth, 1))
        .collect();

    Tree {
        root: root.to_string(),
        ecosystems: ecosystems.to_vec(),
        stats,
        diagnostics: Vec::new(),
        vulnerabilities: Vec::new(),
        scored: false,
        roots: root_nodes,
    }
}

fn build_node(
    key: &DepRef,
    index: &BTreeMap<DepRef, &Dependency>,
    children: &BTreeMap<DepRef, Vec<DepRef>>,
    expanded: &mut HashSet<DepRef>,
    stats: &mut Stats,
    depth: Option<usize>,
    level: usize,
) -> Node {
    stats.max_depth = stats.max_depth.max(level);
    let (name, version) = key;
    let ecosystem = index
        .get(key)
        .map(|d| d.ecosystem.as_str().to_string())
        .unwrap_or_default();
    let direct = index.get(key).map(|d| d.direct).unwrap_or(false);
    let has_children = children.get(key).is_some_and(|c| !c.is_empty());

    // Collapse a node we've already fully expanded (diamond deps / cycles):
    // marking on first visit also breaks cycles, since the back-edge sees it here.
    if has_children && !expanded.insert(key.clone()) {
        stats.deduped += 1;
        return Node {
            name: name.clone(),
            version: version.clone(),
            ecosystem,
            direct,
            deduped: true,
            truncated: false,
            repo: None,
            stars: None,
            signals: Vec::new(),
            severity: None,
            risk: None,
            dep: None,
            language: None,
            languages: None,
            children: Vec::new(),
        };
    }

    // Depth gate: stop descending but flag that children were hidden.
    if depth.is_some_and(|max| level >= max) && has_children {
        return Node {
            name: name.clone(),
            version: version.clone(),
            ecosystem,
            direct,
            deduped: false,
            truncated: true,
            repo: None,
            stars: None,
            signals: Vec::new(),
            severity: None,
            risk: None,
            dep: None,
            language: None,
            languages: None,
            children: Vec::new(),
        };
    }

    let child_nodes = children
        .get(key)
        .map(|kids| {
            kids.iter()
                .map(|k| build_node(k, index, children, expanded, stats, depth, level + 1))
                .collect()
        })
        .unwrap_or_default();

    Node {
        name: name.clone(),
        version: version.clone(),
        ecosystem,
        direct,
        deduped: false,
        truncated: false,
        repo: None,
        stars: None,
        signals: Vec::new(),
        severity: None,
        risk: None,
        dep: None,
        language: None,
        languages: None,
        children: child_nodes,
    }
}

/// Attach online resolution (repo / stars / risk signals) to matching nodes.
/// Keyed by `(name, version)`, so every occurrence of a package in the forest
/// — including deduped copies — carries the same annotation.
pub fn enrich(tree: &mut Tree, resolutions: &HashMap<DepRef, Resolution>) {
    fn walk(node: &mut Node, resolutions: &HashMap<DepRef, Resolution>) {
        if let Some(r) = resolutions.get(&(node.name.clone(), node.version.clone())) {
            node.repo = r.repo.as_ref().map(|x| x.slug());
            node.stars = r.stats.as_ref().map(|s| s.stars);
            node.signals = r.signals.clone();
            node.severity = r.worst;
            node.risk = Some(r.risk);
            node.language = r.language.clone();
            node.languages = r.languages.clone();
        }
        for child in &mut node.children {
            walk(child, resolutions);
        }
    }
    for root in &mut tree.roots {
        walk(root, resolutions);
    }
}

// --- scoring ------------------------------------------------------------------

/// Dependency-subtree points per flagged dep, by severity. Tuned so a couple of
/// flagged deps stay low, while a rotten tree (many low-star/stale packages)
/// saturates toward 100.
const DEP_HIGH: u32 = 10;
const DEP_MEDIUM: u32 = 5;
const DEP_LOW: u32 = 3;

/// A clean package whose `dep` score reaches this is painted blue — the code is
/// fine but it drags in a suspicious tree (the `qs` case).
const BLUE_DEP_THRESHOLD: u8 = 50;

/// Compute the `risk`/`dep` scores for every node (online mode only). Own `risk`
/// is already set by [`enrich`]; here we fill `dep` from each node's subtree.
pub fn score(tree: &mut Tree) {
    for root in &mut tree.roots {
        score_node(root);
    }
    tree.scored = true;
}

fn score_node(node: &mut Node) {
    for child in &mut node.children {
        score_node(child);
    }
    let dep = {
        let mut seen = HashSet::new();
        let mut sevs = Vec::new();
        for child in &node.children {
            collect_flagged(child, node, &mut seen, &mut sevs);
        }
        dep_score(&sevs)
    };
    node.dep = Some(dep);
    node.risk.get_or_insert(0);
}

/// Walk a subtree gathering the severities of *distinct, external* flagged deps.
/// "External" excludes same-module splits (the `@napi-rs/nice-*` case): a child
/// that is a family member of its parent isn't a real added dependency, so it
/// doesn't inflate the score — though we still recurse past it to reach any
/// genuine deps underneath.
fn collect_flagged(
    node: &Node,
    parent: &Node,
    seen: &mut HashSet<DepRef>,
    out: &mut Vec<Severity>,
) {
    if !is_family(parent, node)
        && let Some(sev) = node.severity
        && seen.insert((node.name.clone(), node.version.clone()))
    {
        out.push(sev);
    }
    for child in &node.children {
        collect_flagged(child, node, seen, out);
    }
}

/// Is `child` the same module as `parent` — a platform/scope split rather than a
/// distinct dependency? True when the name is prefixed (`@napi-rs/nice` →
/// `@napi-rs/nice-*`) or both resolve to the same repository.
fn is_family(parent: &Node, child: &Node) -> bool {
    child.name.starts_with(&format!("{}-", parent.name))
        || child.name.starts_with(&format!("{}/", parent.name))
        || matches!((&parent.repo, &child.repo), (Some(a), Some(b)) if a == b)
}

fn dep_score(sevs: &[Severity]) -> u8 {
    let sum: u32 = sevs
        .iter()
        .map(|s| match s {
            Severity::Critical | Severity::High => DEP_HIGH,
            Severity::Medium => DEP_MEDIUM,
            Severity::Low => DEP_LOW,
            Severity::Info => 0,
        })
        .sum();
    sum.min(100) as u8
}

/// The overall project scores: the worst own-risk in the forest, and the dep
/// score of the whole thing (every top-level tree, deduped).
fn project_scores(tree: &Tree) -> (u8, u8) {
    fn max_risk(node: &Node, acc: &mut u8) {
        *acc = (*acc).max(node.risk.unwrap_or(0));
        for c in &node.children {
            max_risk(c, acc);
        }
    }
    let mut risk = 0u8;
    let mut seen = HashSet::new();
    let mut sevs = Vec::new();
    for root in &tree.roots {
        max_risk(root, &mut risk);
        // A synthetic project parent never matches a family prefix, so all
        // top-level deps count.
        let project = Node {
            name: String::new(),
            version: String::new(),
            ecosystem: String::new(),
            direct: false,
            deduped: false,
            truncated: false,
            repo: None,
            stars: None,
            signals: Vec::new(),
            severity: None,
            risk: None,
            dep: None,
            language: None,
            languages: None,
            children: Vec::new(),
        };
        collect_flagged(root, &project, &mut seen, &mut sevs);
    }
    (risk, dep_score(&sevs))
}

/// Render the forest to stdout as a classic `tree(1)`-style view.
pub fn render(tree: &Tree) {
    let eco = if tree.ecosystems.is_empty() {
        String::new()
    } else {
        format!(" ({})", tree.ecosystems.join(", "))
    };
    println!("{}{}", tree.root.bold(), eco.dimmed());

    let last = tree.roots.len().saturating_sub(1);
    for (i, node) in tree.roots.iter().enumerate() {
        render_node(node, "", i == last, tree.scored);
    }

    let s = &tree.stats;
    println!(
        "\n{}",
        format!(
            "{} nodes · {} direct · {} transitive · depth {}{}",
            s.total,
            s.direct,
            s.transitive,
            s.max_depth,
            if s.deduped > 0 {
                format!(" · {} deduped", s.deduped)
            } else {
                String::new()
            }
        )
        .dimmed()
    );

    render_diagnostics(&tree.diagnostics);
    render_vulns(&tree.vulnerabilities);
    render_flagged(tree);

    if tree.scored {
        render_recap(tree);
    }
}

/// List known vulnerabilities (from `--vulns`) — package → advisories, worst
/// severity first.
fn render_vulns(packages: &[crate::vuln::VulnPackage]) {
    if packages.is_empty() {
        return;
    }
    let total: usize = packages.iter().map(|p| p.vulns.len()).sum();
    println!(
        "\n{}  {}",
        format!("🛡 {total} known vulnerabilit{}", if total == 1 { "y" } else { "ies" })
            .bold(),
        "via vuln.mlab.sh".dimmed()
    );

    let mut pkgs: Vec<&crate::vuln::VulnPackage> = packages.iter().collect();
    pkgs.sort_by(|a, b| worst(b).cmp(&worst(a)).then_with(|| a.name.cmp(&b.name)));
    for p in pkgs {
        let ids: Vec<String> = p
            .vulns
            .iter()
            .map(|v| colorize(&v.id, Some(v.severity)))
            .collect();
        println!(
            "  {}{} {}",
            p.name,
            format!("@{}", p.version).dimmed(),
            ids.join(", ")
        );
    }
}

fn worst(p: &crate::vuln::VulnPackage) -> Option<Severity> {
    p.vulns.iter().map(|v| v.severity).max()
}

/// Surface incompleteness so a small/empty graph is never read as "clean".
pub fn render_diagnostics(diags: &[crate::model::Diagnostic]) {
    if diags.is_empty() {
        return;
    }
    println!(
        "\n{}",
        format!("⚠ {} graph diagnostic(s) — results may be incomplete", diags.len())
            .yellow()
            .bold()
    );
    for d in diags {
        let tag = match d.kind.as_str() {
            "parse_failed" => "parse-failed".red().bold().to_string(),
            "replace_directive" => "replace".truecolor(ORANGE.0, ORANGE.1, ORANGE.2).to_string(),
            _ => d.kind.replace('_', "-").dimmed().to_string(),
        };
        println!("  {} {}  {}", format!("[{}]", d.ecosystem).dimmed(), tag, d.message);
    }
}

/// gochi's closing recap: the overall scores and a per-category headcount,
/// deduped by name@version. Packages flagged only by **soft** signals (version
/// drift / persistence) get their own yellow lines instead of the amber
/// "suspicious" bucket. gochi's face reacts to the worst *real* tier present.
fn render_recap(tree: &Tree) {
    #[derive(Default)]
    struct Counts {
        high: usize,
        suspicious: usize,
        unchecked: usize,
        outdated: usize,
        services: usize,
    }
    let mut seen = HashSet::new();
    let mut c = Counts::default();
    fn walk(node: &Node, seen: &mut HashSet<DepRef>, c: &mut Counts) {
        if node.severity.is_some() && seen.insert((node.name.clone(), node.version.clone())) {
            if soft_tint(&node.signals) {
                // Soft-only: count under the yellow lines (a package can be both).
                if node.signals.iter().any(|s| s.starts_with("outdated")) {
                    c.outdated += 1;
                }
                if node.signals.iter().any(|s| s.starts_with("installs-service")) {
                    c.services += 1;
                }
            } else {
                match node.severity {
                    Some(Severity::Critical | Severity::High) => c.high += 1,
                    Some(Severity::Medium | Severity::Low) => c.suspicious += 1,
                    _ => c.unchecked += 1,
                }
            }
        }
        for child in &node.children {
            walk(child, seen, c);
        }
    }
    for r in &tree.roots {
        walk(r, &mut seen, &mut c);
    }

    // Soft-only packages don't alarm gochi — only real risk tiers do.
    let face = if c.high > 0 {
        crate::gochi::ALERT
    } else if c.suspicious > 0 {
        crate::gochi::IDLE
    } else {
        crate::gochi::HAPPY
    };
    let (risk, dep) = project_scores(tree);
    let pad = |n: usize| format!("{n:>3}");
    let orange = |s: String| s.truecolor(ORANGE.0, ORANGE.1, ORANGE.2).to_string();
    let yellow = |s: String| s.truecolor(YELLOW.0, YELLOW.1, YELLOW.2).to_string();

    println!("\n  {}  {}", face.cyan(), "gochi's recap".bold());
    println!(
        "    {}  risk {}/100 · dep {}/100",
        "overall".dimmed(),
        paint_score(risk, risk_color(risk)),
        paint_score(dep, dep_color(dep)),
    );
    println!(
        "    {}  {}   {}",
        pad(c.high).red().bold(),
        "high-risk".red(),
        "typosquat / install-hook / low stars / fresh repo".dimmed()
    );
    println!(
        "    {}  {}  {}",
        orange(pad(c.suspicious)),
        orange("suspicious".into()),
        "new maintainer / dormant / stale / archived".dimmed()
    );
    println!(
        "    {}  {}   {}",
        pad(c.unchecked).dimmed(),
        "unchecked".dimmed(),
        "no repo / informational / couldn't verify".dimmed()
    );
    // Soft categories — noted, not scored. Same yellow for both.
    if c.outdated > 0 {
        println!(
            "    {}  {}    {}",
            yellow(pad(c.outdated)),
            yellow("outdated".into()),
            "behind current version".dimmed()
        );
    }
    if c.services > 0 {
        println!(
            "    {}  {}    {}",
            yellow(pad(c.services)),
            yellow("services".into()),
            "runs at boot/login".dimmed()
        );
    }
    let vulns: usize = tree.vulnerabilities.iter().map(|p| p.vulns.len()).sum();
    if vulns > 0 {
        println!(
            "    {}  {}   {}",
            pad(vulns).red().bold(),
            "known-vulns".red(),
            "OSV / GHSA / CVE".dimmed()
        );
    }
}

/// A "soft" signal — version drift or persistence. Noted, but not a security
/// risk that meaningfully touches the score.
fn is_soft_signal(s: &str) -> bool {
    s.starts_with("outdated") || s.starts_with("installs-service")
}

/// A node flagged ONLY by soft signals (`outdated` and/or `installs-service`),
/// nothing more severe. Painted with the recap's soft yellow — the same for
/// both — rather than the amber "suspicious" tint or the default dim.
fn soft_tint(signals: &[String]) -> bool {
    !signals.is_empty() && signals.iter().all(|s| is_soft_signal(s))
}

/// Color `text` for a node: the soft yellow when [`soft_tint`] applies,
/// otherwise by severity ([`colorize`]).
fn tint(text: &str, severity: Option<Severity>, signals: &[String]) -> String {
    if soft_tint(signals) {
        text.truecolor(YELLOW.0, YELLOW.1, YELLOW.2).to_string()
    } else {
        colorize(text, severity)
    }
}

/// Color a package by its own risk (red/orange/yellow/dimmed) if it's flagged;
/// else blue when its dependency tree is bad (clean code, rotten deps); else plain.
fn paint(text: &str, node: &Node) -> String {
    if node.severity.is_some() {
        tint(text, node.severity, &node.signals)
    } else if node.dep.is_some_and(|d| d >= BLUE_DEP_THRESHOLD) {
        text.blue().to_string()
    } else {
        text.to_string()
    }
}

fn risk_color(risk: u8) -> Option<Severity> {
    match risk {
        0 => None,
        1..=39 => Some(Severity::Medium),
        _ => Some(Severity::High),
    }
}

fn dep_color(dep: u8) -> Option<Severity> {
    // dep uses blue for "bad tree"; reuse Low as a marker the painter maps.
    if dep >= BLUE_DEP_THRESHOLD { Some(Severity::Low) } else { None }
}

fn paint_score(n: u8, sev: Option<Severity>) -> String {
    match sev {
        Some(Severity::Critical) | Some(Severity::High) => n.to_string().red().bold().to_string(),
        Some(Severity::Medium) => n.to_string().truecolor(ORANGE.0, ORANGE.1, ORANGE.2).to_string(),
        Some(Severity::Low) => n.to_string().blue().to_string(),
        _ => n.to_string().dimmed().to_string(),
    }
}

/// Color `text` by risk severity: red for the reputation red flags, orange for
/// inactivity, dimmed for operational noise, plain when healthy.
fn colorize(text: &str, severity: Option<Severity>) -> String {
    match severity {
        Some(Severity::Critical) | Some(Severity::High) => text.red().bold().to_string(),
        Some(Severity::Medium) => text.truecolor(ORANGE.0, ORANGE.1, ORANGE.2).to_string(),
        Some(Severity::Low) => text.yellow().to_string(),
        Some(Severity::Info) => text.dimmed().to_string(),
        None => text.to_string(),
    }
}

/// The parenthesized language group shown after `(risk:dep)`. `None` for nodes
/// that weren't resolved to a repo (offline, or `no-repository`) — so it isn't
/// noise on every line. A resolved repo with no reported language shows `(?)`.
fn language_tag(node: &Node) -> Option<String> {
    if let Some(bk) = &node.languages {
        // Full breakdown (`--languages`): `Rust:96.9|Shell:1.9|Other:1.2`.
        let parts: Vec<String> = bk.iter().map(|(n, p)| format!("{n}:{p:.1}")).collect();
        Some(format!("({})", parts.join("|")))
    } else if let Some(lang) = &node.language {
        Some(format!("({lang})"))
    } else if node.repo.is_some() {
        Some("(?)".to_string())
    } else {
        None
    }
}

fn render_node(node: &Node, prefix: &str, is_last: bool, scored: bool) {
    let connector = if is_last { "└── " } else { "├── " };
    // The name takes the node's color: red/orange if it's itself risky, blue if
    // it's clean but drags in a bad tree — so problem nodes pop out.
    let mut label = format!("{}{}", paint(&node.name, node), format!("@{}", node.version).dimmed());
    if let Some(stars) = node.stars {
        label.push_str(&format!(" {}", format!("★{stars}").dimmed()));
    }
    if node.deduped {
        label.push_str(&" (*)".dimmed().to_string());
    } else if node.truncated {
        label.push_str(&" …".dimmed().to_string());
    }
    if !node.signals.is_empty() {
        let tag = format!("⚠ {}", node.signals.join(", "));
        label.push_str(&format!(" {}", tint(&tag, node.severity, &node.signals)));
    }
    if scored {
        let scores = format!("({}:{})", node.risk.unwrap_or(0), node.dep.unwrap_or(0));
        label.push_str(&format!(" {}", paint(&scores, node)));
        // Repo language, after the scores: `(Rust)`, a breakdown
        // `(Rust:96.9|Shell:1.9|Other:1.2)`, or `(?)` when we resolved a repo but
        // the host reported no language. Only shown for online-resolved nodes.
        if let Some(tag) = language_tag(node) {
            label.push_str(&format!(" {}", tag.dimmed()));
        }
    }
    println!("{prefix}{connector}{label}");

    let child_prefix = format!("{prefix}{}", if is_last { "    " } else { "│   " });
    let last = node.children.len().saturating_sub(1);
    for (i, child) in node.children.iter().enumerate() {
        render_node(child, &child_prefix, i == last, scored);
    }
}

/// One flagged package: repo slug, worst severity, and signal labels.
struct Flag {
    repo: Option<String>,
    severity: Option<Severity>,
    signals: Vec<String>,
}
type Flagged = BTreeMap<(String, String), Flag>;

/// After the tree, list the flagged packages once each (deduped by name@version),
/// worst-severity first, so a big forest's warnings are easy to eyeball. Only
/// **Medium+** nodes are listed — the real flags; "couldn't verify" nodes (Info,
/// e.g. a curated OS package with no GitHub repo) are summarized in the recap's
/// `unchecked` count instead of drowning the list. No-op offline (no signals).
fn render_flagged(tree: &Tree) {
    let mut flagged: Flagged = BTreeMap::new();
    fn collect(node: &Node, out: &mut Flagged) {
        // The flagged list is Medium+ only; low-severity/informational signals
        // (installs-service, setuid, component, held, …) stay inline on the tree
        // and are summarized in the recap, so they don't drown the real flags.
        let surface = node.severity.is_some_and(|s| s >= Severity::Medium);
        if surface && !node.signals.is_empty() {
            out.insert(
                (node.name.clone(), node.version.clone()),
                Flag {
                    repo: node.repo.clone(),
                    severity: node.severity,
                    signals: node.signals.clone(),
                },
            );
        }
        for child in &node.children {
            collect(child, out);
        }
    }
    for root in &tree.roots {
        collect(root, &mut flagged);
    }

    if flagged.is_empty() {
        return;
    }

    // Worst first, then by name.
    let mut rows: Vec<(&(String, String), &Flag)> = flagged.iter().collect();
    rows.sort_by(|(ka, a), (kb, b)| b.severity.cmp(&a.severity).then_with(|| ka.cmp(kb)));

    println!("\n{}", format!("⚠ {} flagged package(s)", flagged.len()).bold());
    for ((name, version), flag) in rows {
        let repo = flag.repo.as_deref().unwrap_or("—");
        println!(
            "  {}{} {} {}",
            tint(name, flag.severity, &flag.signals),
            format!("@{version}").dimmed(),
            format!("[{repo}]").dimmed(),
            tint(&flag.signals.join(", "), flag.severity, &flag.signals)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    /// Build a test node. `sev` present => flagged with that severity.
    fn n(name: &str, sev: Option<Severity>, children: Vec<Node>) -> Node {
        Node {
            name: name.into(),
            version: "1.0.0".into(),
            ecosystem: "node".into(),
            direct: false,
            deduped: false,
            truncated: false,
            repo: None,
            stars: None,
            signals: if sev.is_some() { vec!["low-stars".into()] } else { vec![] },
            severity: sev,
            risk: sev.map(|_| 30),
            dep: None,
            language: None,
            languages: None,
            children,
        }
    }

    fn tree_of(roots: Vec<Node>) -> Tree {
        Tree {
            root: "proj".into(),
            ecosystems: vec!["node".into()],
            stats: Stats { total: 0, direct: 0, transitive: 0, max_depth: 0, deduped: 0 },
            diagnostics: Vec::new(),
            vulnerabilities: Vec::new(),
            scored: false,
            roots,
        }
    }

    #[test]
    fn dep_score_aggregates_and_dedups() {
        // clean root -> 3 distinct flagged deps (High, High, Medium) = 10+10+5
        let a = n("a", Some(Severity::High), vec![]);
        let b = n("b", Some(Severity::High), vec![n("a", Some(Severity::High), vec![])]); // dup a
        let c = n("c", Some(Severity::Medium), vec![]);
        let root = n("root", None, vec![a, b, c]);
        let mut t = tree_of(vec![root]);
        score(&mut t);
        // a counted once despite appearing twice: 10(a)+10(b)+5(c) = 25
        assert_eq!(t.roots[0].dep, Some(25));
        assert_eq!(t.roots[0].risk, Some(0)); // clean itself
    }

    #[test]
    fn napi_family_is_collapsed() {
        // @napi-rs/nice is itself flagged, but its @napi-rs/nice-* platform
        // splits must NOT inflate its dep score.
        let kids = vec![
            n("@napi-rs/nice-linux-x64-gnu", Some(Severity::High), vec![]),
            n("@napi-rs/nice-darwin-arm64", Some(Severity::High), vec![]),
            n("@napi-rs/nice-win32-x64-msvc", Some(Severity::High), vec![]),
        ];
        let nice = n("@napi-rs/nice", Some(Severity::High), kids);
        let mut t = tree_of(vec![nice]);
        score(&mut t);
        assert_eq!(t.roots[0].dep, Some(0), "family splits should not count as deps");
    }

    #[test]
    fn same_repo_counts_as_family() {
        let mut child = n("totally-different-name", Some(Severity::High), vec![]);
        child.repo = Some("acme/mono".into());
        let mut parent = n("parent", None, vec![child]);
        parent.repo = Some("acme/mono".into());
        let mut t = tree_of(vec![parent]);
        score(&mut t);
        assert_eq!(t.roots[0].dep, Some(0), "same repo => same module => not a dep");
    }

    #[test]
    fn clean_pkg_with_rotten_tree_scores_blue() {
        // 6 distinct High-flagged deps => dep 60 >= blue threshold
        let kids: Vec<Node> = (0..6)
            .map(|i| n(&format!("bad{i}"), Some(Severity::High), vec![]))
            .collect();
        let qs = n("qs", None, kids); // clean itself
        let mut t = tree_of(vec![qs]);
        score(&mut t);
        assert!(t.roots[0].dep.unwrap() >= BLUE_DEP_THRESHOLD);
        assert_eq!(t.roots[0].severity, None); // stays clean -> painter picks blue
    }

    #[test]
    fn soft_tint_only_for_outdated_and_service() {
        // Either soft signal alone, or both together → soft.
        assert!(soft_tint(&["installs-service (runs at boot/login)".into()]));
        assert!(soft_tint(&["outdated (1.0 → 1.1)".into()]));
        assert!(soft_tint(&["outdated (a → b)".into(), "installs-service (x)".into()]));
        // Any non-soft signal alongside disqualifies it.
        assert!(!soft_tint(&["installs-service (x)".into(), "stale (100d idle)".into()]));
        assert!(!soft_tint(&["no-repository".into()]));
        assert!(!soft_tint(&[]));
    }

    #[test]
    fn project_scores_aggregate_over_all_roots() {
        let r1 = n("r1", Some(Severity::High), vec![n("x", Some(Severity::Medium), vec![])]);
        let r2 = n("r2", None, vec![n("y", Some(Severity::High), vec![])]);
        let mut t = tree_of(vec![r1, r2]);
        score(&mut t);
        let (risk, dep) = project_scores(&t);
        assert_eq!(risk, 30, "worst own-risk in the forest");
        // the project's deps include the direct ones: r1(High=10) + x(Med=5) + y(High=10)
        assert_eq!(dep, 25);
    }
}
