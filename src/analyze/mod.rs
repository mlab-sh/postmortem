//! Analysis passes. Each analyzer takes the scan context and emits findings.

pub mod install_hooks;
pub mod ioc;
pub mod obfuscation;
pub mod sensitive_api;
pub mod util;

use crate::detect::Detected;
use crate::model::{Dependency, Finding};

/// Run every analyzer that applies to the detected ecosystems. Order is irrelevant —
/// findings are independent. Each analyzer is best-effort: a failure inside one
/// must not abort the whole scan.
pub fn run_all(detected: &[Detected], deps: &[Dependency]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for d in detected {
        match d {
            Detected::Node { node_modules: Some(nm), .. } => {
                install_hooks::scan_node(nm, &mut findings);
                ioc::scan_dir(nm, &mut findings, ioc::Lang::JavaScript);
                obfuscation::scan_dir(nm, &mut findings, obfuscation::Lang::JavaScript);
                sensitive_api::scan_dir(nm, &mut findings, sensitive_api::Lang::JavaScript);
            }
            Detected::Node { .. } => { /* no node_modules → static-on-lockfile only */ }
            Detected::Python { root, site_packages, .. } => {
                // Local sources (setup.py, etc.) live at the repo root.
                install_hooks::scan_python(root, &mut findings);
                ioc::scan_dir(root, &mut findings, ioc::Lang::Python);
                obfuscation::scan_dir(root, &mut findings, obfuscation::Lang::Python);
                sensitive_api::scan_dir(root, &mut findings, sensitive_api::Lang::Python);
                if let Some(sp) = site_packages {
                    install_hooks::scan_python(sp, &mut findings);
                    ioc::scan_dir(sp, &mut findings, ioc::Lang::Python);
                    obfuscation::scan_dir(sp, &mut findings, obfuscation::Lang::Python);
                    sensitive_api::scan_dir(sp, &mut findings, sensitive_api::Lang::Python);
                }
            }
            Detected::Rust { root, .. } => {
                // Rust deps live in ~/.cargo/registry — we don't scan that by default;
                // we scan the project's own src/ for sensitive APIs as a courtesy.
                let src = root.join("src");
                if src.is_dir() {
                    sensitive_api::scan_dir(&src, &mut findings, sensitive_api::Lang::Rust);
                    ioc::scan_dir(&src, &mut findings, ioc::Lang::Rust);
                }
            }
            Detected::Ruby { root, .. } => {
                // Gems aren't vendored in-repo (they live in the bundle path), so —
                // like Rust — we scan the project's own Ruby source for sensitive
                // primitives, IOCs, and obfuscation.
                sensitive_api::scan_dir(root, &mut findings, sensitive_api::Lang::Ruby);
                ioc::scan_dir(root, &mut findings, ioc::Lang::Ruby);
                obfuscation::scan_dir(root, &mut findings, obfuscation::Lang::Ruby);
            }
        }
    }

    // Attribute findings without a dependency to "<project>" if possible.
    let _ = deps; // currently each analyzer derives dep from path
    findings
}
