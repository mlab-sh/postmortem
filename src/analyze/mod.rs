//! Analysis passes. Each analyzer takes the scan context and emits findings.

pub mod install_hooks;
pub mod ioc;
pub mod obfuscation;
pub mod sensitive_api;
pub mod util;

use std::borrow::Cow;
use std::path::Path;

use crate::detect::Detected;
use crate::model::{Category, Dependency, Finding};
use crate::ui::Ui;

/// Drop IOC findings located in test/fixture directories, unless
/// `allow_test_files`. The test-dir check is made **relative to `base`** (the
/// scanned project root), so a `test/` component that belongs to the harness's
/// own path (e.g. `.../tests/fixtures/...`) doesn't count. Only IOCs are filtered
/// (test code legitimately embeds fake IPs/URLs/domains); obfuscation /
/// sensitive-API / install-hook findings in tests are kept.
pub fn drop_test_iocs(findings: Vec<Finding>, allow_test_files: bool, base: &Path) -> Vec<Finding> {
    if allow_test_files {
        return findings;
    }
    let base = base.to_string_lossy();
    findings
        .into_iter()
        .filter(|f| {
            !(matches!(f.category, Category::Ioc)
                && f.location.as_deref().is_some_and(|loc| {
                    util::is_test_path(loc.strip_prefix(base.as_ref()).unwrap_or(loc))
                }))
        })
        .collect()
}

/// A boxed analyzer invocation that appends its findings to the shared vec.
type RunFn<'a> = Box<dyn FnOnce(&mut Vec<Finding>) + 'a>;

/// One indivisible analysis unit: a single analyzer run over a single directory.
/// Collecting them up front lets us show a determinate progress bar (we know the
/// total before we start) while keeping the per-unit logic a plain closure.
struct Step<'a> {
    label: Cow<'static, str>,
    run: RunFn<'a>,
}

impl<'a> Step<'a> {
    fn new(label: &'static str, run: impl FnOnce(&mut Vec<Finding>) + 'a) -> Self {
        Step {
            label: Cow::Borrowed(label),
            run: Box::new(run),
        }
    }
}

/// Run every content analyzer, for **every language**, over an arbitrary source
/// tree — regardless of ecosystem detection. Used by `system inspect --deep` to
/// scan cloned dependency source directly (a C/Perl/etc. upstream has no
/// lockfile for [`plan`] to key off, but its code should still be inspected).
pub fn scan_source_tree(root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    for &lang in ioc::Lang::ALL {
        ioc::scan_dir(root, &mut out, lang);
    }
    for &lang in obfuscation::Lang::ALL {
        obfuscation::scan_dir(root, &mut out, lang);
    }
    for &lang in sensitive_api::Lang::ALL {
        sensitive_api::scan_dir(root, &mut out, lang);
    }
    out
}

/// Run every analyzer that applies to the detected ecosystems, driving a
/// progress bar over the units. Order is irrelevant — findings are independent.
/// Each analyzer is best-effort: a failure inside one must not abort the scan.
pub fn run_all(detected: &[Detected], deps: &[Dependency], ui: &Ui) -> Vec<Finding> {
    let steps = plan(detected);
    let total = steps.len();

    let mut findings = Vec::new();
    let bar = ui.bar(total as u64, "analyzing");
    for Step { label, run } in steps {
        bar.step(label);
        run(&mut findings);
        bar.inc();
    }
    bar.done(format!(
        "analyzed {total} unit(s) — {} finding(s)",
        findings.len()
    ));

    // Attribute findings without a dependency to "<project>" if possible.
    let _ = deps; // currently each analyzer derives dep from path
    findings
}

/// Enumerate the analysis units for the detected ecosystems. This is the single
/// source of truth for both *what* runs and *how many* steps the bar shows.
fn plan(detected: &[Detected]) -> Vec<Step<'_>> {
    let mut steps = Vec::new();

    for d in detected {
        match d {
            Detected::Node { node_modules: Some(nm), .. } => {
                steps.push(Step::new("node · install-hooks", move |f| install_hooks::scan_node(nm, f)));
                steps.push(Step::new("node · ioc", move |f| ioc::scan_dir(nm, f, ioc::Lang::JavaScript)));
                steps.push(Step::new("node · obfuscation", move |f| obfuscation::scan_dir(nm, f, obfuscation::Lang::JavaScript)));
                steps.push(Step::new("node · sensitive-api", move |f| sensitive_api::scan_dir(nm, f, sensitive_api::Lang::JavaScript)));
            }
            Detected::Node { .. } => { /* no node_modules → static-on-lockfile only */ }
            Detected::Python { root, site_packages, .. } => {
                // Local sources (setup.py, etc.) live at the repo root.
                push_python(&mut steps, root);
                if let Some(sp) = site_packages {
                    push_python(&mut steps, sp);
                }
            }
            Detected::Rust { root, .. } => {
                // Rust deps live in ~/.cargo/registry — we don't scan that by default;
                // we scan the project's own src/ for sensitive APIs as a courtesy.
                // (`join` here so the closure owns a `PathBuf` independent of `root`.)
                let src = root.join("src");
                if src.is_dir() {
                    let ioc_src = src.clone();
                    let obf_src = src.clone();
                    steps.push(Step::new("rust · sensitive-api", move |f| sensitive_api::scan_dir(&src, f, sensitive_api::Lang::Rust)));
                    steps.push(Step::new("rust · ioc", move |f| ioc::scan_dir(&ioc_src, f, ioc::Lang::Rust)));
                    steps.push(Step::new("rust · obfuscation", move |f| obfuscation::scan_dir(&obf_src, f, obfuscation::Lang::Rust)));
                }
            }
            Detected::Ruby { root, .. } => {
                // Gems aren't vendored in-repo (they live in the bundle path), so —
                // like Rust — we scan the project's own Ruby source for sensitive
                // primitives, IOCs, and obfuscation.
                steps.push(Step::new("ruby · sensitive-api", move |f| sensitive_api::scan_dir(root, f, sensitive_api::Lang::Ruby)));
                steps.push(Step::new("ruby · ioc", move |f| ioc::scan_dir(root, f, ioc::Lang::Ruby)));
                steps.push(Step::new("ruby · obfuscation", move |f| obfuscation::scan_dir(root, f, obfuscation::Lang::Ruby)));
            }
            Detected::Php { root, .. } => {
                // Composer vendors dependencies under vendor/ when installed, so a
                // single root walk covers both the project's own PHP and any
                // committed vendor tree.
                steps.push(Step::new("php · sensitive-api", move |f| sensitive_api::scan_dir(root, f, sensitive_api::Lang::Php)));
                steps.push(Step::new("php · ioc", move |f| ioc::scan_dir(root, f, ioc::Lang::Php)));
                steps.push(Step::new("php · obfuscation", move |f| obfuscation::scan_dir(root, f, obfuscation::Lang::Php)));
            }
            Detected::Go { root, .. } => {
                // Go has no install-time hooks; modules live in the module cache
                // or a committed vendor/ tree. We scan the project's own source
                // (and vendor/ if present) for sensitive APIs, IOCs, obfuscation.
                steps.push(Step::new("go · sensitive-api", move |f| sensitive_api::scan_dir(root, f, sensitive_api::Lang::Go)));
                steps.push(Step::new("go · ioc", move |f| ioc::scan_dir(root, f, ioc::Lang::Go)));
                steps.push(Step::new("go · obfuscation", move |f| obfuscation::scan_dir(root, f, obfuscation::Lang::Go)));
            }
            Detected::Java { root, .. } => {
                // JVM dependencies live in the Maven/Gradle caches, not in-repo.
                // We scan the project's own JVM source for sensitive APIs, IOCs,
                // and obfuscation. (Build-script execution is out of scope.)
                steps.push(Step::new("java · sensitive-api", move |f| sensitive_api::scan_dir(root, f, sensitive_api::Lang::Java)));
                steps.push(Step::new("java · ioc", move |f| ioc::scan_dir(root, f, ioc::Lang::Java)));
                steps.push(Step::new("java · obfuscation", move |f| obfuscation::scan_dir(root, f, obfuscation::Lang::Java)));
            }
        }
    }

    steps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    fn ioc(loc: &str) -> Finding {
        Finding {
            dependency: "x".into(),
            severity: Severity::Medium,
            category: Category::Ioc,
            detail: "d".into(),
            location: Some(loc.into()),
            evidence: None,
            enrich_url: None,
        }
    }

    #[test]
    fn drops_test_iocs_by_default_only() {
        let base = std::path::Path::new("");
        let fs = vec![ioc("src/a.rs:1"), ioc("test/b.py:2"), ioc("pkg/tests/c.rs:3")];
        let kept = drop_test_iocs(fs.clone(), false, base);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].location.as_deref(), Some("src/a.rs:1"));
        // A file merely named `test_*` is NOT a test dir.
        assert_eq!(drop_test_iocs(vec![ioc("src/test_util.rs:1")], false, base).len(), 1);
        // --allow-test-files keeps everything.
        assert_eq!(drop_test_iocs(fs, true, base).len(), 3);
    }

    #[test]
    fn test_check_is_relative_to_base() {
        // A `tests` component that belongs to the base path must NOT count.
        let base = std::path::Path::new("/repo/tests/fixtures/proj");
        let f = ioc("/repo/tests/fixtures/proj/node_modules/evil/x.js:1");
        assert_eq!(drop_test_iocs(vec![f], false, base).len(), 1, "harness path ignored");
        // But a test dir *below* the base is filtered.
        let f2 = ioc("/repo/tests/fixtures/proj/test/x.js:1");
        assert_eq!(drop_test_iocs(vec![f2], false, base).len(), 0);
    }

    #[test]
    fn non_ioc_findings_in_tests_are_kept() {
        let mut f = ioc("test/x.rs:1");
        f.category = Category::SensitiveApi;
        assert_eq!(drop_test_iocs(vec![f], false, std::path::Path::new("")).len(), 1);
    }
}

/// Python is scanned identically at the repo root and (if present) the venv's
/// site-packages, so both share one step-emitting helper.
fn push_python<'a>(steps: &mut Vec<Step<'a>>, dir: &'a Path) {
    steps.push(Step::new("python · install-hooks", move |f| install_hooks::scan_python(dir, f)));
    steps.push(Step::new("python · ioc", move |f| ioc::scan_dir(dir, f, ioc::Lang::Python)));
    steps.push(Step::new("python · obfuscation", move |f| obfuscation::scan_dir(dir, f, obfuscation::Lang::Python)));
    steps.push(Step::new("python · sensitive-api", move |f| sensitive_api::scan_dir(dir, f, sensitive_api::Lang::Python)));
}
