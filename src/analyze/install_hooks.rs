//! Install-script detection.
//!
//! For Node, every `package.json` inside `node_modules/` is checked for
//! `scripts.preinstall / install / postinstall / preuninstall / postuninstall`.
//! These run automatically on `npm install` and are the #1 supply-chain vector
//! (event-stream → flatmap-stream, ua-parser-js takeover, node-ipc protestware).
//!
//! For Python, `setup.py` runs arbitrary code at install time. We flag any
//! `setup.py` that invokes `subprocess`, `os.system`, `exec`, `eval`, network
//! libs, or base64 — typical exfil patterns (ctx 0.2.6, `request` typosquats).

use serde::Deserialize;
use std::path::Path;

use crate::analyze::util;
use crate::model::{Category, Finding, Severity};

const SUSPICIOUS_SCRIPT_PATTERNS: &[&str] = &[
    "curl ",
    "wget ",
    "node -e",
    "sh -c",
    "eval",
    "base64",
    "child_process",
    "https.get",
    "exec(",
    "spawn(",
    "powershell",
    "cmd /c",
];

#[derive(Debug, Deserialize, Default)]
struct PkgJson {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    scripts: std::collections::BTreeMap<String, String>,
}

pub fn scan_node(node_modules: &Path, out: &mut Vec<Finding>) {
    for pkg_json in util::walk_files(node_modules, &["json"]) {
        if pkg_json.file_name().and_then(|s| s.to_str()) != Some("package.json") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&pkg_json) else {
            continue;
        };
        let Ok(parsed) = serde_json::from_str::<PkgJson>(&text) else {
            continue;
        };
        let dep = parsed
            .name
            .clone()
            .or_else(|| util::node_pkg_from_path(&pkg_json))
            .unwrap_or_else(|| pkg_json.display().to_string());
        let version = parsed.version.clone().unwrap_or_default();

        for hook in [
            "preinstall",
            "install",
            "postinstall",
            "preuninstall",
            "postuninstall",
        ] {
            let Some(cmd) = parsed.scripts.get(hook) else {
                continue;
            };
            let suspicious = SUSPICIOUS_SCRIPT_PATTERNS
                .iter()
                .any(|p| cmd.to_lowercase().contains(&p.to_lowercase()));
            let severity = if suspicious {
                Severity::High
            } else {
                Severity::Medium
            };
            out.push(Finding {
                dependency: if version.is_empty() {
                    dep.clone()
                } else {
                    format!("{dep}@{version}")
                },
                severity,
                category: Category::InstallHook,
                detail: format!(
                    "npm `{hook}` script defined{}",
                    if suspicious {
                        " — references network/exec primitives"
                    } else {
                        ""
                    }
                ),
                location: Some(pkg_json.display().to_string()),
                evidence: Some(util::snippet(cmd, 160)),
                enrich_url: None,
            });
        }
    }
}

const PY_SUSPICIOUS_IN_SETUP: &[&str] = &[
    "subprocess",
    "os.system",
    "os.popen",
    "exec(",
    "eval(",
    "base64",
    "urllib",
    "requests.",
    "socket.",
    "compile(",
    "marshal.loads",
    "__import__",
    "getattr(",
    "os.environ",
];

pub fn scan_python(root: &Path, out: &mut Vec<Finding>) {
    for setup_py in util::walk_files(root, &["py"]) {
        if setup_py.file_name().and_then(|s| s.to_str()) != Some("setup.py") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&setup_py) else {
            continue;
        };
        let hits: Vec<&&str> = PY_SUSPICIOUS_IN_SETUP
            .iter()
            .filter(|p| text.contains(**p))
            .collect();
        if hits.is_empty() {
            continue;
        }
        let dep =
            util::python_pkg_from_path(&setup_py).unwrap_or_else(|| setup_py.display().to_string());
        let severity = if hits.len() >= 3 {
            Severity::Critical
        } else if hits.len() >= 2 {
            Severity::High
        } else {
            Severity::Medium
        };
        out.push(Finding {
            dependency: dep,
            severity,
            category: Category::InstallHook,
            detail: format!(
                "setup.py executes suspicious primitives: {}",
                hits.iter().map(|s| **s).collect::<Vec<_>>().join(", ")
            ),
            location: Some(setup_py.display().to_string()),
            evidence: None,
            enrich_url: None,
        });
    }
}
