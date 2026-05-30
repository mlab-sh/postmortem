//! Self-contained HTML report: single file, no external assets, no JS dependencies.

use crate::model::{Report, Severity};

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
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; margin: 2rem; max-width: 1200px; }}
  h1 {{ font-size: 1.5rem; margin-bottom: 0; }}
  .root {{ color: #888; font-family: ui-monospace, monospace; font-size: 0.9rem; }}
  .summary {{ display: flex; gap: 1rem; margin: 1rem 0; flex-wrap: wrap; }}
  .card {{ padding: 0.6rem 1rem; border: 1px solid #ccc4; border-radius: 6px; }}
  .card b {{ display: block; font-size: 1.4rem; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; font-size: 0.9rem; }}
  th, td {{ text-align: left; padding: 0.35rem 0.6rem; border-bottom: 1px solid #ccc4; }}
  th {{ background: #8881; }}
  .loc {{ font-family: ui-monospace, monospace; font-size: 0.8rem; color: #888; }}
  .enrich a {{ font-size: 0.85rem; text-decoration: none; }}
  .badge {{ display: inline-block; padding: 0.1rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
  .badge-critical {{ background: #b00020; color: white; }}
  .badge-high     {{ background: #e53935; color: white; }}
  .badge-medium   {{ background: #fb8c00; color: white; }}
  .badge-low      {{ background: #1e88e5; color: white; }}
  .badge-info     {{ background: #757575; color: white; }}
  details {{ margin-top: 2rem; }}
  details summary {{ cursor: pointer; font-weight: 600; }}
</style>
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
