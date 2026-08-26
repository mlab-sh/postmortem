//! Install-script detection.
//!
//! For Node, every `package.json` inside `node_modules/` is checked for the
//! lifecycle scripts npm runs when it installs a dependency — see
//! [`crate::lifecycle`] for which those are, which is not simply the familiar
//! three: a dependency built locally (git, `file:`, a remote tarball) also runs
//! its `prepare`, and a package carrying a `binding.gyp` and no install script
//! of its own gets `node-gyp rebuild` synthesised for it. These run
//! automatically on `npm install` and are the #1 supply-chain vector
//! (event-stream → flatmap-stream, ua-parser-js takeover, node-ipc protestware).
//!
//! For Python, `setup.py` runs arbitrary code at install time. We flag any
//! `setup.py` that invokes `subprocess`, `os.system`, `exec`, `eval`, network
//! libs, or base64 — typical exfil patterns (ctx 0.2.6, `request` typosquats).

use serde::Deserialize;
use std::path::Path;

use crate::analyze::util;
use crate::lifecycle;
use crate::model::{Category, Finding, Severity};

/// Uninstall hooks. Not install-time — and npm has not run them since v7 — but
/// a package that ships one is still declaring code it expects to execute, so
/// they stay reported. Kept here rather than in [`crate::lifecycle`], which
/// answers "what runs when you install".
const UNINSTALL_HOOKS: &[&str] = &["preuninstall", "postuninstall"];

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
    /// A package opts out of npm's implicit native build with `false`.
    #[serde(default)]
    gypfile: Option<bool>,
}

pub fn scan_node(node_modules: &Path, sources: &lifecycle::Sources, out: &mut Vec<Finding>) {
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

        // Which lifecycle scripts npm runs here depends on where the package
        // came from, and only the lockfile records that — see `Sources`.
        let source = sources.get(&dep);
        for hook in source.hooks().iter().chain(UNINSTALL_HOOKS) {
            let hook = *hook;
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
                    "npm `{hook}` script defined{}{}",
                    source
                        .note(hook)
                        .map(|n| format!(" — {n}"))
                        .unwrap_or_default(),
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

        // A native package that declares nothing still builds: npm synthesises
        // `node-gyp rebuild` for it, so a C++ toolchain runs over its source on
        // the installing machine. Nothing in `scripts` says so.
        let explicit_install =
            parsed.scripts.contains_key("install") || parsed.scripts.contains_key("preinstall");
        if let Some(dir) = pkg_json.parent()
            && lifecycle::implicit_gyp(dir, explicit_install, parsed.gypfile)
        {
            out.push(Finding {
                dependency: if version.is_empty() {
                    dep.clone()
                } else {
                    format!("{dep}@{version}")
                },
                severity: Severity::Medium,
                category: Category::InstallHook,
                detail: format!(
                    "native build at install: `binding.gyp` and no install script, \
                     so npm runs `{}`",
                    lifecycle::GYP_INSTALL
                ),
                location: Some(pkg_json.display().to_string()),
                evidence: None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::{Source, Sources};

    /// A `node_modules` tree holding one package; returns the `node_modules` dir.
    fn tree(label: &str, pkg: &str, manifest: &str, files: &[&str]) -> std::path::PathBuf {
        let nm = std::env::temp_dir()
            .join(format!("pm-hooks-{}-{label}", std::process::id()))
            .join("node_modules");
        let dir = nm.join(pkg);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("package.json"), manifest).unwrap();
        for f in files {
            std::fs::write(dir.join(f), "{}").unwrap();
        }
        nm
    }

    fn scan(nm: &Path, sources: &Sources) -> Vec<Finding> {
        let mut out = Vec::new();
        scan_node(nm, sources, &mut out);
        std::fs::remove_dir_all(nm.parent().unwrap()).ok();
        out
    }

    const WITH_PREPARE: &str = r#"{"name":"built","version":"1.0.0",
        "scripts":{"prepare":"node ./build.js"}}"#;

    #[test]
    fn a_git_dependencys_prepare_is_an_install_script() {
        let nm = tree("git", "built", WITH_PREPARE, &[]);
        let sources: Sources = [("built".to_string(), Source::NonRegistry)]
            .into_iter()
            .collect();
        let f = scan(&nm, &sources);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].detail.contains("`prepare`"), "{}", f[0].detail);
        assert!(
            f[0].detail.contains("non-registry"),
            "says why it runs: {}",
            f[0].detail
        );
    }

    #[test]
    fn a_registry_dependencys_prepare_is_not() {
        // It ran on the publisher's machine, before the tarball was packed.
        // `"prepare": "tsc"` is half of npm; flagging it would be noise.
        let nm = tree("registry", "built", WITH_PREPARE, &[]);
        assert!(scan(&nm, &Sources::default()).is_empty());
    }

    #[test]
    fn a_gypfile_with_no_script_still_builds() {
        let nm = tree(
            "gyp",
            "native",
            r#"{"name":"native","version":"2.0.0"}"#,
            &["binding.gyp"],
        );
        let f = scan(&nm, &Sources::default());
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].detail.contains("node-gyp rebuild"), "{}", f[0].detail);
        assert_eq!(f[0].dependency, "native@2.0.0");
    }

    #[test]
    fn an_explicit_install_script_is_not_doubled_by_the_gyp_rule() {
        let nm = tree(
            "gyp-explicit",
            "native",
            r#"{"name":"native","version":"2.0.0","scripts":{"install":"make"}}"#,
            &["binding.gyp"],
        );
        let f = scan(&nm, &Sources::default());
        assert_eq!(f.len(), 1, "one finding, the declared script: {f:?}");
        assert!(f[0].detail.contains("`install`"), "{}", f[0].detail);
    }
}
