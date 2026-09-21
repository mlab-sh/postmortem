//! Analysis passes. Each analyzer takes the scan context and emits findings.

pub mod behavior;
pub mod dockerfile;
pub mod gha;
pub mod image_config;
pub mod image_secrets;
pub mod ide_hooks;
pub mod install_hooks;
pub mod ioc;
pub mod obfuscation;
pub mod sensitive_api;
pub mod util;

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::detect::Detected;
use crate::model::{Category, Dependency, Finding};
use crate::ui::Ui;

pub use util::Lang;

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

/// Is the *dependencies'* own code on disk to be analyzed?
///
/// Most ecosystems keep dependencies outside the project — Rust in
/// `~/.cargo/registry`, Ruby in the bundle path, Go in the module cache — so a
/// scan of those reads the project's own source and nothing else. Node is the
/// exception when `node_modules` is present, and PHP when `vendor/` is committed.
///
/// Callers that draw conclusions *about a dependency* need this: with no code to
/// read, "we found no install hook" means "we could not look", and reporting the
/// two the same way would invent a clean result. Mirrors [`plan`].
pub fn scans_dependency_code(detected: &[Detected]) -> bool {
    detected.iter().any(|d| match d {
        Detected::Node { node_modules, .. } => node_modules.is_some(),
        Detected::Python { site_packages, .. } => site_packages.is_some(),
        // Composer vendors in-tree; the walk covers it when it is there.
        Detected::Php { root, .. } => root.join("vendor").is_dir(),
        Detected::Go { root, .. } => root.join("vendor").is_dir(),
        Detected::Rust { .. } | Detected::Ruby { .. } | Detected::Java { .. } => false,
    })
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

/// Read each source file **once** and run every content analyzer over it.
///
/// IOC, obfuscation and sensitive-API detection all want the same files, and
/// each used to walk the tree and read every file itself: three traversals and
/// three `read_to_string` calls for identical bytes. Measured on a 3 954-file
/// project that was 8 walks, 36 508 directory entries visited and 15 025 file
/// reads for 3 954 files on disk. They are pure functions of `(path, text)`, so
/// one pass feeds all three.
///
/// Files are independent, so the pass runs across a small pool of scoped
/// threads — the same cursor-and-workers shape as [`crate::resolve`]. Each
/// worker accumulates into its own `Vec` and they are merged at the end, so
/// there is no lock on the hot path. Worker count is capped: the work is a mix
/// of `read` syscalls and regex scanning, and past the core count the readers
/// just queue on the same disk.
fn scan_content(dir: &Path, out: &mut Vec<Finding>, lang: Lang) {
    let files: Vec<PathBuf> = util::walk_files(dir, lang.exts()).collect();
    let total = files.len();
    if total == 0 {
        return;
    }

    let cursor = AtomicUsize::new(0);
    let sink: Mutex<Vec<Finding>> = Mutex::new(Vec::new());
    let workers = workers().min(total);

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                let mut local = Vec::new();
                loop {
                    let i = cursor.fetch_add(1, Ordering::Relaxed);
                    if i >= total {
                        break;
                    }
                    let path = &files[i];
                    let Ok(text) = std::fs::read_to_string(path) else {
                        continue;
                    };
                    ioc::scan_text(path, &text, &mut local);
                    obfuscation::scan_text(path, &text, &mut local, lang);
                    sensitive_api::scan_text(path, &text, &mut local, lang);
                }
                sink.lock().unwrap().append(&mut local);
            });
        }
    });

    let mut found = sink.into_inner().unwrap();
    // Workers finish in arbitrary order, so findings would otherwise come out
    // shuffled run to run — a moving diff in `--json` output and in the gate's
    // baseline. Sorting by location restores a stable order.
    found.sort_by(|a, b| a.location.cmp(&b.location));
    out.append(&mut found);
}

/// Threads for the content pass. `available_parallelism` fails on a container
/// with no CPU affinity info; 4 is a safe floor there.
fn workers() -> usize {
    std::thread::available_parallelism().map_or(4, |n| n.get())
}

/// Run every content analyzer, for **every language**, over an arbitrary source
/// tree — regardless of ecosystem detection. Used by `system inspect --deep` to
/// scan cloned dependency source directly (a C/Perl/etc. upstream has no
/// lockfile for [`plan`] to key off, but its code should still be inspected).
pub fn scan_source_tree(root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    for &lang in Lang::ALL {
        scan_content(root, &mut out, lang);
    }
    ide_hooks::scan_dir(root, &mut out);
    behavior::scan_dir(root, &mut out);
    gha::scan_dir(root, &mut out);
    out
}

/// Run every analyzer that applies to the detected ecosystems, driving a
/// progress bar over the units. Order is irrelevant — findings are independent.
/// Each analyzer is best-effort: a failure inside one must not abort the scan.
pub fn run_all(detected: &[Detected], deps: &[Dependency], ui: &Ui) -> Vec<Finding> {
    // Where each Node package came from. The installed `package.json` does not
    // record it, so the install-hook analyzer cannot work it out from the tree
    // it walks — and it decides whether a `prepare` runs on install.
    let sources = crate::lifecycle::Sources::from_deps(deps);
    let steps = plan(detected, &sources);
    let total = steps.len();

    let mut findings = Vec::new();
    let bar = ui.bar_ticks(total as u64, "gochi analyzing", crate::gochi::SCANNING);
    for Step { label, run } in steps {
        bar.step(label);
        run(&mut findings);
        bar.inc();
    }
    bar.done(format!(
        "analyzed {total} unit(s) — {} finding(s)",
        findings.len()
    ));

    findings
}

/// Enumerate the analysis units for the detected ecosystems. This is the single
/// source of truth for both *what* runs and *how many* steps the bar shows.
fn plan<'a>(detected: &'a [Detected], sources: &'a crate::lifecycle::Sources) -> Vec<Step<'a>> {
    let mut steps = Vec::new();

    // IDE/agent autostart-hook scan runs once per unique project root (covers the
    // root's own `.vscode`/`.claude` and every dependency's under `node_modules`).
    let mut seen_roots: Vec<&Path> = Vec::new();
    for d in detected {
        let root = d.root();
        if !seen_roots.contains(&root) {
            seen_roots.push(root);
            steps.push(Step::new("ide/agent · autostart-hooks", move |f| {
                ide_hooks::scan_dir(root, f)
            }));
            steps.push(Step::new(
                "behaviour · secrets/persistence/worm",
                move |f| behavior::scan_dir(root, f),
            ));
            steps.push(Step::new("ci · github-actions workflows", move |f| {
                gha::scan_dir(root, f)
            }));
            steps.push(Step::new("build · dockerfiles", move |f| {
                dockerfile::scan_dir(root, f)
            }));
        }
    }

    for d in detected {
        match d {
            Detected::Node {
                node_modules: Some(nm),
                ..
            } => {
                steps.push(Step::new("node · install-hooks", move |f| {
                    install_hooks::scan_node(nm, sources, f)
                }));
                steps.push(Step::new("node · ioc/obfuscation/sensitive-api", move |f| {
                    scan_content(nm, f, Lang::JavaScript)
                }));
            }
            Detected::Node { .. } => { /* no node_modules → static-on-lockfile only */ }
            Detected::Python {
                root,
                site_packages,
                ..
            } => {
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
                    steps.push(Step::new(
                        "rust · ioc/obfuscation/sensitive-api",
                        move |f| scan_content(&src, f, Lang::Rust),
                    ));
                }
            }
            Detected::Ruby { root, .. } => {
                // Gems aren't vendored in-repo (they live in the bundle path), so —
                // like Rust — we scan the project's own Ruby source for sensitive
                // primitives, IOCs, and obfuscation.
                steps.push(Step::new("ruby · ioc/obfuscation/sensitive-api", move |f| {
                    scan_content(root, f, Lang::Ruby)
                }));
            }
            Detected::Php { root, .. } => {
                // Composer vendors dependencies under vendor/ when installed, so a
                // single root walk covers both the project's own PHP and any
                // committed vendor tree.
                steps.push(Step::new("php · ioc/obfuscation/sensitive-api", move |f| {
                    scan_content(root, f, Lang::Php)
                }));
            }
            Detected::Go { root, .. } => {
                // Go has no install-time hooks; modules live in the module cache
                // or a committed vendor/ tree. We scan the project's own source
                // (and vendor/ if present) for sensitive APIs, IOCs, obfuscation.
                steps.push(Step::new("go · ioc/obfuscation/sensitive-api", move |f| {
                    scan_content(root, f, Lang::Go)
                }));
            }
            Detected::Java { root, .. } => {
                // JVM dependencies live in the Maven/Gradle caches, not in-repo.
                // We scan the project's own JVM source for sensitive APIs, IOCs,
                // and obfuscation. (Build-script execution is out of scope.)
                steps.push(Step::new("java · ioc/obfuscation/sensitive-api", move |f| {
                    scan_content(root, f, Lang::Java)
                }));
            }
        }
    }

    steps
}

/// Python is scanned identically at the repo root and (if present) the venv's
/// site-packages, so both share one step-emitting helper.
fn push_python<'a>(steps: &mut Vec<Step<'a>>, dir: &'a Path) {
    steps.push(Step::new("python · install-hooks", move |f| {
        install_hooks::scan_python(dir, f)
    }));
    steps.push(Step::new("python · ioc/obfuscation/sensitive-api", move |f| {
        scan_content(dir, f, Lang::Python)
    }));
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
        let fs = vec![
            ioc("src/a.rs:1"),
            ioc("test/b.py:2"),
            ioc("pkg/tests/c.rs:3"),
        ];
        let kept = drop_test_iocs(fs.clone(), false, base);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].location.as_deref(), Some("src/a.rs:1"));
        // A file merely named `test_*` is NOT a test dir.
        assert_eq!(
            drop_test_iocs(vec![ioc("src/test_util.rs:1")], false, base).len(),
            1
        );
        // --allow-test-files keeps everything.
        assert_eq!(drop_test_iocs(fs, true, base).len(), 3);
    }

    #[test]
    fn test_check_is_relative_to_base() {
        // A `tests` component that belongs to the base path must NOT count.
        let base = std::path::Path::new("/repo/tests/fixtures/proj");
        let f = ioc("/repo/tests/fixtures/proj/node_modules/evil/x.js:1");
        assert_eq!(
            drop_test_iocs(vec![f], false, base).len(),
            1,
            "harness path ignored"
        );
        // But a test dir *below* the base is filtered.
        let f2 = ioc("/repo/tests/fixtures/proj/test/x.js:1");
        assert_eq!(drop_test_iocs(vec![f2], false, base).len(), 0);
    }

    #[test]
    fn non_ioc_findings_in_tests_are_kept() {
        let mut f = ioc("test/x.rs:1");
        f.category = Category::SensitiveApi;
        assert_eq!(
            drop_test_iocs(vec![f], false, std::path::Path::new("")).len(),
            1
        );
    }
}
