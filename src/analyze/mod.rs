//! Analysis passes. Each analyzer takes the scan context and emits findings.

pub mod install_hooks;
pub mod ioc;
pub mod obfuscation;
pub mod sensitive_api;
pub mod util;

use std::borrow::Cow;
use std::path::Path;

use crate::detect::Detected;
use crate::model::{Dependency, Finding};
use crate::ui::Ui;

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
                    steps.push(Step::new("rust · sensitive-api", move |f| sensitive_api::scan_dir(&src, f, sensitive_api::Lang::Rust)));
                    steps.push(Step::new("rust · ioc", move |f| ioc::scan_dir(&ioc_src, f, ioc::Lang::Rust)));
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

/// Python is scanned identically at the repo root and (if present) the venv's
/// site-packages, so both share one step-emitting helper.
fn push_python<'a>(steps: &mut Vec<Step<'a>>, dir: &'a Path) {
    steps.push(Step::new("python · install-hooks", move |f| install_hooks::scan_python(dir, f)));
    steps.push(Step::new("python · ioc", move |f| ioc::scan_dir(dir, f, ioc::Lang::Python)));
    steps.push(Step::new("python · obfuscation", move |f| obfuscation::scan_dir(dir, f, obfuscation::Lang::Python)));
    steps.push(Step::new("python · sensitive-api", move |f| sensitive_api::scan_dir(dir, f, sensitive_api::Lang::Python)));
}
