//! Self-contained HTML report: single file, no external assets, no JS dependencies.

use crate::model::{Report, Severity};

/// The shared stylesheet. Both renderers embed it verbatim — the report must be
/// a single file with no external asset, so there is nothing to link to.
const STYLE: &str = r##"<style>
  :root { color-scheme: light dark; }
  body { font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; margin: 2rem; max-width: 1200px; }
  h1 { font-size: 1.5rem; margin-bottom: 0; }
  .root { color: #888; font-family: ui-monospace, monospace; font-size: 0.9rem; }
  .summary { display: flex; gap: 1rem; margin: 1rem 0; flex-wrap: wrap; }
  .card { padding: 0.6rem 1rem; border: 1px solid #ccc4; border-radius: 6px; }
  .card b { display: block; font-size: 1.4rem; }
  table { border-collapse: collapse; width: 100%; margin-top: 1rem; font-size: 0.9rem; }
  th, td { text-align: left; padding: 0.35rem 0.6rem; border-bottom: 1px solid #ccc4; }
  th { background: #8881; }
  .loc { font-family: ui-monospace, monospace; font-size: 0.8rem; color: #888; }
  .enrich a { font-size: 0.85rem; text-decoration: none; }
  .badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
  .badge-critical { background: #b00020; color: white; }
  .badge-high     { background: #e53935; color: white; }
  .badge-medium   { background: #fb8c00; color: white; }
  .badge-low      { background: #1e88e5; color: white; }
  .badge-info     { background: #757575; color: white; }
  details { margin-top: 2rem; }
  details summary { cursor: pointer; font-weight: 600; }
</style>
"##;

pub fn render(report: &Report) -> String {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut info = 0;
    for f in &report.findings {
        match f.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
            Severity::Info => info += 1,
        }
    }

    let direct = report.dependencies.iter().filter(|d| d.direct).count();
    let transitive = report.dependencies.len() - direct;

    let mut findings_html = String::new();
    let mut sorted: Vec<_> = report.findings.iter().collect();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.dependency.cmp(&b.dependency)));
    for f in &sorted {
        let enrich_cell = match f.enrich_url.as_deref() {
            Some(u) => format!(
                r#"<td class="enrich"><a href="{u}" target="_blank" rel="noopener noreferrer">↗ enrich</a></td>"#,
                u = esc(u)
            ),
            None => "<td></td>".to_string(),
        };
        findings_html.push_str(&format!(
            r#"<tr class="sev-{sev}"><td><span class="badge badge-{sev}">{sev_label}</span></td><td>{dep}</td><td>{cat}</td><td>{detail}</td><td class="loc">{loc}</td>{enrich_cell}</tr>"#,
            sev = sev_class(f.severity),
            sev_label = sev_label(f.severity),
            dep = esc(&f.dependency),
            cat = f.category.as_str(),
            detail = esc(&f.detail),
            loc = esc(f.location.as_deref().unwrap_or("")),
        ));
    }

    let mut deps_html = String::new();
    let mut deps: Vec<_> = report.dependencies.iter().collect();
    deps.sort_by(|a, b| b.direct.cmp(&a.direct).then(a.name.cmp(&b.name)));
    for d in &deps {
        let parents = if d.parents.is_empty() {
            "-".to_string()
        } else {
            d.parents
                .iter()
                .map(|(n, v)| format!("{}@{}", esc(n), esc(v)))
                .collect::<Vec<_>>()
                .join(", ")
        };
        deps_html.push_str(&format!(
            r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class="loc">{}</td></tr>"#,
            esc(&d.name),
            esc(&d.version),
            d.ecosystem.as_str(),
            if d.direct { "direct" } else { "transitive" },
            parents,
        ));
    }

    format!(r#"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>postmortem report</title>
{style}
</head><body>
<h1>postmortem — dependency scan</h1>
<div class="root">{root}</div>
<div class="summary">
  <div class="card"><b>{total_deps}</b>dependencies</div>
  <div class="card"><b>{direct}</b>direct</div>
  <div class="card"><b>{transitive}</b>transitive</div>
  <div class="card"><b>{critical}</b>critical</div>
  <div class="card"><b>{high}</b>high</div>
  <div class="card"><b>{medium}</b>medium</div>
  <div class="card"><b>{low}</b>low</div>
  <div class="card"><b>{info}</b>info</div>
</div>
<div>ecosystems: <code>{ecos}</code></div>

<h2>Findings</h2>
<table>
  <thead><tr><th>severity</th><th>dependency</th><th>category</th><th>detail</th><th>location</th><th></th></tr></thead>
  <tbody>{findings_body}</tbody>
</table>

<details>
  <summary>Dependencies ({total_deps})</summary>
  <table>
    <thead><tr><th>name</th><th>version</th><th>eco</th><th>kind</th><th>parents</th></tr></thead>
    <tbody>{deps_body}</tbody>
  </table>
</details>
</body></html>
"#,
        style = STYLE,
        root = esc(&report.root),
        total_deps = report.dependencies.len(),
        direct = direct,
        transitive = transitive,
        critical = critical,
        high = high,
        medium = medium,
        low = low,
        info = info,
        ecos = esc(&report.ecosystems.join(", ")),
        findings_body = if findings_html.is_empty() {
            r#"<tr><td colspan="5" style="text-align:center;color:#888;">no findings</td></tr>"#.to_string()
        } else { findings_html },
        deps_body = deps_html,
    )
}

fn sev_class(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn sev_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// The `tree --html` report.
///
/// A different document from [`render`], not a reskin of it: `scan` reports
/// *findings in code*, while `tree --online --vulns` reports *packages and their
/// provenance*. The rows a reader needs are therefore the flagged packages —
/// sorted worst-first, with the repo they resolved to and the signals raised —
/// rather than a file-and-line list.
///
/// Everything is optional and degrades: an offline `tree --html` still produces
/// the inventory and the forest, just without the risk and vulnerability
/// sections. What is absent is stated, never silently omitted.
pub fn render_tree(tree: &crate::tree::Tree) -> String {
    let mut flat: Vec<&crate::tree::Node> = Vec::new();
    collect(&tree.roots, &mut flat);

    // Worst first: severity, then risk, then name — the order a reviewer reads.
    let mut flagged: Vec<&crate::tree::Node> =
        flat.iter().copied().filter(|n| !n.signals.is_empty()).collect();
    flagged.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.risk.cmp(&a.risk))
            .then(a.name.cmp(&b.name))
    });
    // One row per package, not per occurrence in the forest.
    flagged.dedup_by(|a, b| a.name == b.name && a.version == b.version);

    let worst_risk = flat.iter().filter_map(|n| n.risk).max().unwrap_or(0);
    let high_count = flat
        .iter()
        .filter(|n| n.severity.is_some_and(|s| s >= Severity::High))
        .count();
    let vuln_count: usize = tree.vulnerabilities.iter().map(|p| p.vulns.len()).sum();

    let mut flagged_html = String::new();
    for n in &flagged {
        let sev = n.severity.unwrap_or(Severity::Info);
        let repo = match (&n.repo, n.stars) {
            (Some(r), Some(s)) => format!("{} <span class=\"loc\">★{s}</span>", esc(r)),
            (Some(r), None) => esc(r),
            (None, _) => "<span class=\"loc\">unresolved</span>".to_string(),
        };
        flagged_html.push_str(&format!(
            r#"<tr class="sev-{sev}"><td><span class="badge badge-{sev}">{sev_label}</span></td><td>{name}<span class="loc"> @{ver}</span></td><td>{repo}</td><td>{risk}</td><td>{dep}</td><td>{signals}</td></tr>"#,
            sev = sev_class(sev),
            sev_label = sev_label(sev),
            name = esc(&n.name),
            ver = esc(&n.version),
            risk = n.risk.map(|r| r.to_string()).unwrap_or_else(|| "-".into()),
            dep = n.dep.map(|d| d.to_string()).unwrap_or_else(|| "-".into()),
            signals = n.signals.iter().map(|s| esc(s)).collect::<Vec<_>>().join("<br>"),
        ));
    }

    let mut vulns_html = String::new();
    for p in &tree.vulnerabilities {
        for v in &p.vulns {
            vulns_html.push_str(&format!(
                r#"<tr class="sev-{sev}"><td><span class="badge badge-{sev}">{sev_label}</span></td><td>{name}<span class="loc"> @{ver}</span></td><td class="loc">{id}</td><td>{summary}</td></tr>"#,
                sev = sev_class(v.severity),
                sev_label = sev_label(v.severity),
                name = esc(&p.name),
                ver = esc(&p.version),
                id = esc(&v.id),
                summary = esc(&v.summary),
            ));
        }
    }

    let mut diag_html = String::new();
    if !tree.diagnostics.is_empty() {
        diag_html.push_str(r#"<div class="diag"><b>⚠ graph diagnostics</b><ul>"#);
        for d in &tree.diagnostics {
            diag_html.push_str(&format!(
                "<li><code>{}</code> [{}] {}</li>",
                esc(&d.kind),
                esc(&d.ecosystem),
                esc(&d.message)
            ));
        }
        diag_html.push_str("</ul></div>");
    }

    // Sections that depend on an opt-in flag say so rather than rendering an
    // empty table that reads like "we looked and found nothing".
    let risk_section = if tree.scored {
        format!(
            r#"<h2>Flagged packages ({n})</h2>
<table>
  <thead><tr><th>severity</th><th>package</th><th>source repo</th><th>risk</th><th>dep</th><th>signals</th></tr></thead>
  <tbody>{body}</tbody>
</table>"#,
            n = flagged.len(),
            body = if flagged_html.is_empty() {
                r#"<tr><td colspan="6" style="text-align:center;color:#888;">no package raised a signal</td></tr>"#.to_string()
            } else {
                flagged_html
            }
        )
    } else {
        r#"<h2>Flagged packages</h2><p class="loc">Not assessed — re-run with <code>--online</code> for source-repo reputation and provenance signals.</p>"#.to_string()
    };

    let vuln_section = if vulns_html.is_empty() {
        r#"<h2>Vulnerabilities</h2><p class="loc">Not assessed — re-run with <code>--vulns</code> for known advisories.</p>"#.to_string()
    } else {
        format!(
            r#"<h2>Vulnerabilities ({vuln_count})</h2>
<table>
  <thead><tr><th>severity</th><th>package</th><th>id</th><th>summary</th></tr></thead>
  <tbody>{vulns_html}</tbody>
</table>"#
        )
    };

    format!(
        r#"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>postmortem — dependency tree</title>
{style}
<style>
  .diag {{ border-left: 3px solid #fb8c00; padding: 0.5rem 1rem; margin: 1rem 0; background: #fb8c0016; }}
  .diag ul {{ margin: 0.4rem 0 0; padding-left: 1.2rem; font-size: 0.9rem; }}
  .forest {{ font-family: ui-monospace, monospace; font-size: 0.85rem; line-height: 1.5; }}
  .forest ul {{ list-style: none; padding-left: 1.2rem; border-left: 1px solid #ccc4; }}
</style>
</head><body>
<h1>postmortem — dependency tree</h1>
<div class="root">{root}</div>
<div class="summary">
  <div class="card"><b>{total}</b>dependencies</div>
  <div class="card"><b>{direct}</b>direct</div>
  <div class="card"><b>{transitive}</b>transitive</div>
  <div class="card"><b>{depth}</b>max depth</div>
  <div class="card"><b>{worst_risk}</b>worst risk</div>
  <div class="card"><b>{high_count}</b>high-risk</div>
  <div class="card"><b>{vuln_count}</b>vulns</div>
</div>
<div>ecosystems: <code>{ecos}</code></div>
{diag_html}

{risk_section}

{vuln_section}

<details>
  <summary>Full dependency forest ({total})</summary>
  <div class="forest">{forest}</div>
</details>
</body></html>
"#,
        style = STYLE,
        root = esc(&tree.root),
        total = tree.stats.total,
        direct = tree.stats.direct,
        transitive = tree.stats.transitive,
        depth = tree.stats.max_depth,
        ecos = esc(&tree.ecosystems.join(", ")),
        forest = forest_html(&tree.roots),
    )
}

/// Flatten the forest depth-first so summaries can be computed over every node.
fn collect<'a>(nodes: &'a [crate::tree::Node], out: &mut Vec<&'a crate::tree::Node>) {
    for n in nodes {
        out.push(n);
        collect(&n.children, out);
    }
}

/// The forest as nested lists — plain HTML, so it prints and searches natively.
fn forest_html(nodes: &[crate::tree::Node]) -> String {
    if nodes.is_empty() {
        return String::new();
    }
    let mut s = String::from("<ul>");
    for n in nodes {
        let risk = match n.risk {
            Some(r) if r > 0 => format!(r#" <span class="loc">risk {r}</span>"#),
            _ => String::new(),
        };
        // The terminal view marks these too; without them a collapsed diamond
        // dep looks like a leaf that genuinely has no children.
        let mark = if n.deduped {
            r#" <span class="loc">(*)</span>"#
        } else if n.truncated {
            r#" <span class="loc">(…)</span>"#
        } else {
            ""
        };
        s.push_str(&format!(
            "<li>{}<span class=\"loc\">@{}</span>{risk}{mark}{}</li>",
            esc(&n.name),
            esc(&n.version),
            forest_html(&n.children),
        ));
    }
    s.push_str("</ul>");
    s
}
