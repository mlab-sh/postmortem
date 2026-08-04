use comfy_table::{Cell, Table, presets::UTF8_FULL};
use owo_colors::OwoColorize;

use crate::model::{Report, Severity};

pub fn render(report: &Report, show_deps: bool) {
    println!(
        "{} {}",
        "postmortem".bold(),
        format!("scan of {}", report.root).dimmed()
    );
    println!(
        "ecosystems: {}",
        report.ecosystems.join(", ").cyan()
    );

    let direct = report.dependencies.iter().filter(|d| d.direct).count();
    println!(
        "dependencies: {} total, {} direct, {} transitive",
        report.dependencies.len().to_string().bold(),
        direct.to_string().green(),
        (report.dependencies.len() - direct).to_string().yellow()
    );

    if !report.diagnostics.is_empty() {
        crate::tree::render_diagnostics(&report.diagnostics);
    }

    print_findings_summary(report);

    if show_deps && !report.dependencies.is_empty() {
        let mut table = Table::new();
        table.load_preset(UTF8_FULL);
        table.set_header(vec!["name", "version", "kind", "parents"]);
        let mut deps: Vec<_> = report.dependencies.iter().collect();
        deps.sort_by(|a, b| {
            b.direct
                .cmp(&a.direct)
                .then_with(|| a.name.cmp(&b.name))
                .then_with(|| a.version.cmp(&b.version))
        });
        for d in deps.iter().take(200) {
            let kind = if d.direct { "direct" } else { "transitive" };
            let parents = if d.parents.is_empty() {
                "-".to_string()
            } else {
                let mut p: Vec<String> = d
                    .parents
                    .iter()
                    .map(|(n, v)| format!("{n}@{v}"))
                    .collect();
                p.sort();
                if p.len() > 3 {
                    let extra = p.len() - 3;
                    let mut s = p[..3].join(", ");
                    s.push_str(&format!(" (+{extra})"));
                    s
                } else {
                    p.join(", ")
                }
            };
            table.add_row(vec![
                Cell::new(&d.name),
                Cell::new(&d.version),
                Cell::new(kind),
                Cell::new(parents),
            ]);
        }
        println!("{table}");
        if report.dependencies.len() > 200 {
            println!(
                "{}",
                format!(
                    "... {} more dependencies omitted",
                    report.dependencies.len() - 200
                )
                .dimmed()
            );
        }
    }

    if !report.findings.is_empty() {
        let has_enrich = report.findings.iter().any(|f| f.enrich_url.is_some());
        let mut table = Table::new();
        table.load_preset(UTF8_FULL);
        let mut header = vec!["severity", "dependency", "category", "detail", "location"];
        if has_enrich {
            header.push("enrich");
        }
        table.set_header(header);
        let mut findings: Vec<_> = report.findings.iter().collect();
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.dependency.cmp(&b.dependency))
        });
        for f in findings {
            let mut row = vec![
                Cell::new(sev_label(f.severity)),
                Cell::new(&f.dependency),
                Cell::new(f.category.as_str()),
                Cell::new(&f.detail),
                Cell::new(f.location.as_deref().unwrap_or("")),
            ];
            if has_enrich {
                row.push(Cell::new(f.enrich_url.as_deref().unwrap_or("")));
            }
            table.add_row(row);
        }
        println!("{table}");
    }
}

fn print_findings_summary(report: &Report) {
    if report.findings.is_empty() {
        println!("findings: {}", "none".green());
        return;
    }
    let mut counts = [0usize; 5];
    for f in &report.findings {
        counts[f.severity as usize] += 1;
    }
    println!(
        "findings: {} critical, {} high, {} medium, {} low, {} info",
        counts[Severity::Critical as usize].to_string().red().bold(),
        counts[Severity::High as usize].to_string().red(),
        counts[Severity::Medium as usize].to_string().yellow(),
        counts[Severity::Low as usize].to_string().blue(),
        counts[Severity::Info as usize].to_string().dimmed()
    );
}

fn sev_label(s: Severity) -> String {
    match s {
        Severity::Critical => "CRITICAL".red().bold().to_string(),
        Severity::High => "HIGH".red().to_string(),
        Severity::Medium => "MEDIUM".yellow().to_string(),
        Severity::Low => "LOW".blue().to_string(),
        Severity::Info => "INFO".dimmed().to_string(),
    }
}
