//! Debian/Ubuntu `apt` / `dpkg` backend.
//!
//! The installed set, the dependency edges, the manually-installed roots, holds
//! and diversions all come from **dpkg's own database files** rather than from
//! `dpkg-query` / `apt-mark` / `dpkg-divert`. Those tools only ever describe the
//! machine they run on, and parsing the files they read is what lets the same
//! backend inventory a container image from a laptop with no dpkg installed.
//!
//! Around that sits the trust surface: untrusted sources, custom and expired
//! keys, a legacy keyring, pins, foreign architectures and maintainer scripts.
//!
//! Three signals genuinely need a working apt on the machine being described —
//! per-package provenance (`apt-cache policy`), available upgrades
//! (`apt list --upgradable`) and content tampering (`dpkg --verify`). They are
//! collected for this machine and **reported as not collected** for an image,
//! because an image ships no apt lists and "no third-party packages found" and
//! "provenance was never checked" are different answers.

use std::path::{Path, PathBuf};

use super::privilege::{find_setuid_files_at, persistence_signals, verify_line_is_tamper};
use super::recipe::{analyze_recipe, host_domain};
use super::*;

// --- apt / dpkg backend ------------------------------------------------------

/// Read this machine's installed dpkg forest. See [`apt_inventory_at`].
pub fn apt_inventory(opts: Opts) -> Result<Inventory> {
    apt_inventory_at(Path::new("/"), opts)
}

/// Read the installed dpkg forest under `root` into an [`Inventory`].
///
/// `root` is `/` for this machine and an extracted image root for `--image`.
/// Everything below resolves against it.
pub fn apt_inventory_at(root: &Path, opts: Opts) -> Result<Inventory> {
    // Only this machine can be asked questions that need a running apt.
    let live = root == Path::new("/");

    let stanzas: Vec<DpkgStanza> = dpkg_status(root)?
        .into_iter()
        .filter(DpkgStanza::is_installed)
        .collect();
    let names: Vec<String> = stanzas.iter().map(|p| p.name.clone()).collect();
    let (manual, manual_known) = apt_manual_at(root, &names);
    let deps = apt_graph(&dpkg_status_as_columns(&stanzas), &manual);

    // Provenance per package (non-official source + archive component), plus the
    // held / foreign-arch sets: the provenance & source surface. ("Obsolete" — a
    // package no longer in any archive — is *the same observable state* as a bare
    // `.deb`: apt-cache policy shows only /var/lib/dpkg/status for both, so it is
    // already reported as `third-party-source (manual)` rather than mislabeling
    // every sideloaded vendor `.deb` as obsolete.)
    let prov = if live {
        apt_provenance(&names)
    } else {
        HashMap::new()
    };
    let held = apt_held_at(&stanzas);
    let foreign = apt_foreign_arch_at(&stanzas);
    // Execution & privilege surface: what each package's installed files set up
    // (services, timers, auth config, setuid bins) + file-hijacking diversions.
    let list_index = apt_list_index_at(root);
    let setuid = find_setuid_files_at(root);
    let diversions = apt_diversions_at(root);
    let mut signals: HashMap<String, Vec<SysSignal>> = HashMap::new();
    for d in &deps {
        let source = prov.get(&d.name).and_then(|p| p.source.clone());
        // Non-official source (PPA / manually-installed .deb) = the untrusted surface.
        if let Some(src) = &source {
            push_signal(
                &mut signals,
                &d.name,
                SysSignal::new(format!("third-party-source ({src})"), Category::ThirdPartySource, Severity::Medium, 30),
            );
        }
        // Community / non-free archive component (universe, multiverse, non-free…):
        // installed from an official host but a less-curated section.
        if let Some(comp) = prov.get(&d.name).and_then(|p| p.component.as_deref())
            && is_community_component(comp)
        {
            push_signal(
                &mut signals,
                &d.name,
                SysSignal::new(format!("component ({comp})"), Category::ThirdPartySource, Severity::Info, 0),
            );
        }
        // Held back: excluded from upgrades, so stuck on its current version.
        if held.contains(&d.name) {
            push_signal(
                &mut signals,
                &d.name,
                SysSignal::new("held (upgrades pinned off)", Category::Policy, Severity::Low, 10),
            );
        }
        // Installed solely for a non-native architecture (e.g. a pure i386 package
        // on amd64): extra, easily-overlooked surface.
        if let Some(arch) = foreign.get(&d.name) {
            push_signal(
                &mut signals,
                &d.name,
                SysSignal::new(format!("foreign-arch ({arch})"), Category::Policy, Severity::Low, 5),
            );
        }
        // Maintainer scripts (preinst/postinst/…): install-time code execution.
        let scripts = apt_scripts_at(root, &d.name);
        if !scripts.is_empty() {
            push_signal(
                &mut signals,
                &d.name,
                SysSignal::new("install-script (runs code at install)", Category::InstallHook, Severity::Info, 0),
            );
            // Static-analyze them for third-party packages (the untrusted ones).
            // In an image nothing can be shown to be third-party, so every script
            // is analyzed rather than none — the alternative is reading an
            // untrusted artifact and looking at none of the code it runs — but the
            // findings are reported unscored, because the premise that makes them
            // meaningful is exactly the one that could not be checked.
            if source.is_some() {
                for sig in analyze_recipe(&d.name, &scripts, "sh") {
                    push_signal(&mut signals, &d.name, sig);
                }
            } else if !live {
                for sig in analyze_recipe(&d.name, &scripts, "sh") {
                    push_signal(&mut signals, &d.name, sig.unscored());
                }
            }
        }
        // Execution & privilege: the boot/login/scheduled/auth/setuid surface a
        // package sets up through the files it ships.
        if let Some(paths) = list_index.get(&d.name) {
            let files = read_pkg_files(paths);
            for sig in persistence_signals(&files, &setuid) {
                push_signal(&mut signals, &d.name, sig);
            }
        }
        // Diverting another package's file in place of its own is a hijack vector.
        if let Some(path) = diversions.get(&d.name) {
            push_signal(
                &mut signals,
                &d.name,
                SysSignal::new(
                    format!("dpkg-divert (overrides {path})"),
                    Category::Tamper,
                    Severity::Medium,
                    20,
                ),
            );
        }
    }

    if live {
        for (name, (old, new)) in apt_outdated() {
            signals
                .entry(name)
                .or_default()
                .push(outdated_signal(&old, &new));
        }
    }

    let _ = opts; // apt reputation comes from the shared `--online` path
    let direct = deps.iter().filter(|d| d.direct).count();
    let summary = format!("{} package(s) ({direct} manually installed)", deps.len());

    // Trust caveats: sources that disable signature checks, and custom keys added
    // to the apt keyring (extending trust beyond the official archives).
    let mut warnings = Vec::new();
    if !manual_known {
        warnings.push(
            "no apt extended_states file: every package reads as manually installed, so the \
             direct/transitive split is unknown"
                .into(),
        );
    }
    let untrusted = apt_untrusted_sources_at(root);
    if untrusted > 0 {
        warnings.push(format!(
            "{untrusted} apt source(s) set [trusted=yes] (signature verification disabled)"
        ));
    }
    let keys = apt_custom_keys_at(root);
    if keys > 0 {
        warnings.push(format!(
            "{keys} custom signing key(s) added to the apt keyring"
        ));
    }
    let pins = apt_pins_at(root);
    if pins > 0 {
        warnings.push(format!(
            "{pins} apt pin(s) configured (/etc/apt/preferences): version/source overrides"
        ));
    }
    // Signature & integrity caveats.
    let repos = apt_repos_at(root);
    let http = repos
        .iter()
        .filter(|r| r.name.starts_with("http://"))
        .count();
    if http > 0 {
        warnings.push(format!(
            "{http} apt source(s) over http (no transport encryption)"
        ));
    }
    if apt_legacy_keyring_at(root) {
        warnings.push(
            "legacy monolithic keyring /etc/apt/trusted.gpg in use (trusts every source)".into(),
        );
    }
    let expired = apt_expired_keys_at(root);
    if expired > 0 {
        warnings.push(format!(
            "{expired} expired signing key(s) in the apt keyring"
        ));
    }
    if live {
        let modified = apt_modified_files();
        if modified > 0 {
            warnings.push(format!(
                "{modified} installed file(s) modified since install (md5 mismatch)"
            ));
        }
    } else {
        // Stated, not skipped. These three need a working apt describing itself,
        // and an image ships no apt lists — so the honest report is which checks
        // did not run, rather than a clean result they never produced.
        warnings.push(
            "not checked in an image: per-package provenance, available upgrades, and file \
             tampering (all need a working apt and its package lists)"
                .into(),
        );
    }

    Ok(Inventory {
        manager: "apt",
        deps,
        repos,
        signals,
        claims: Vec::new(),
        summary,
        notes: warnings,
    })
}

/// Count apt sources that disable signature verification (`[trusted=yes]` in a
/// classic line, or `Trusted: yes` in deb822) — a real integrity risk.
fn apt_untrusted_sources_at(root: &Path) -> usize {
    apt_source_files_at(root)
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .flat_map(|t| t.lines().map(str::to_string).collect::<Vec<_>>())
        .filter(|l| {
            let l = l.trim();
            (l.starts_with("deb") && l.contains("trusted=yes"))
                || l.eq_ignore_ascii_case("trusted: yes")
        })
        .count()
}

/// Count custom signing keys added to the apt keyring (files in
/// `trusted.gpg.d` / `keyrings` that aren't the official Debian/Ubuntu ones).
fn apt_custom_keys_at(root: &Path) -> usize {
    [
        root.join("etc/apt/trusted.gpg.d"),
        root.join("etc/apt/keyrings"),
    ]
    .iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flatten()
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_lowercase();
            !n.starts_with("ubuntu-") && !n.starts_with("debian-") && n != "readme"
        })
        .count()
}

/// The apt source files: `sources.list` + everything under `sources.list.d/`.
fn apt_source_files_at(root: &Path) -> Vec<PathBuf> {
    let mut files = vec![root.join("etc/apt/sources.list")];
    if let Ok(dir) = std::fs::read_dir(root.join("etc/apt/sources.list.d")) {
        files.extend(dir.flatten().map(|e| e.path()));
    }
    files
}

/// Is the deprecated monolithic `/etc/apt/trusted.gpg` present and non-empty? Keys
/// there are trusted for *every* source (unlike per-repo `signed-by=` keyrings).
fn apt_legacy_keyring_at(root: &Path) -> bool {
    std::fs::metadata(root.join("etc/apt/trusted.gpg"))
        .map(|m| m.len() > 0)
        .unwrap_or(false)
}

/// Every apt keyring file: the legacy `trusted.gpg` + `trusted.gpg.d/` + `keyrings/`.
fn apt_keyring_files_at(root: &Path) -> Vec<PathBuf> {
    let mut files = vec![root.join("etc/apt/trusted.gpg")];
    for d in [
        root.join("etc/apt/trusted.gpg.d"),
        root.join("etc/apt/keyrings"),
    ] {
        if let Ok(dir) = std::fs::read_dir(d) {
            files.extend(dir.flatten().map(|e| e.path()));
        }
    }
    files
}

/// Count expired signing keys across the apt keyrings. `gpg --show-keys` reads a
/// key file (armored or binary) without importing it; the `pub` record's
/// expiration field (a unix timestamp, index 6) is compared to now. Best-effort:
/// skips files gpg can't read.
fn apt_expired_keys_at(root: &Path) -> usize {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now == 0 {
        return 0;
    }
    apt_keyring_files_at(root)
        .iter()
        .map(|f| {
            let Ok(out) = Command::new("gpg")
                .args(["--show-keys", "--with-colons"])
                .arg(f)
                .output()
            else {
                return 0;
            };
            if !out.status.success() {
                return 0;
            }
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|l| l.starts_with("pub:"))
                .filter(|l| {
                    l.split(':')
                        .nth(6)
                        .and_then(|e| e.parse::<u64>().ok())
                        .is_some_and(|exp| exp != 0 && exp < now)
                })
                .count()
        })
        .sum()
}

/// Count installed files whose content was modified since install (`dpkg --verify`
/// md5 mismatch), excluding conffiles (admins are expected to edit those).
fn apt_modified_files() -> usize {
    let Ok(out) = Command::new("dpkg").arg("--verify").output() else {
        return 0;
    };
    // `dpkg --verify` exits non-zero precisely when it finds discrepancies.
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| verify_line_is_tamper(l))
        .count()
}

// --- dpkg's own database ------------------------------------------------------

/// One `var/lib/dpkg/status` stanza, reduced to the fields the inventory needs.
pub(super) struct DpkgStanza {
    name: String,
    version: String,
    depends: String,
    pre_depends: String,
    homepage: String,
    architecture: String,
    /// The `Status:` triple — `<want> <error> <state>`, e.g. `install ok installed`.
    status: String,
}

impl DpkgStanza {
    /// Only a package in state `installed` has files on disk. A removed one that
    /// kept its configuration (`deinstall ok config-files`) still has a stanza,
    /// and counting it as installed would put a package that ships no code into
    /// the graph — and into the vulnerability scan.
    ///
    /// A stanza with no `Status:` at all means the `status.d/` layout, where each
    /// file was written by the image builder to record a package it put in: there
    /// is no state machine and nothing was ever removed, so the stanza's existence
    /// is the statement. A real `status` file always carries the field, so this
    /// cannot loosen the check for it.
    fn is_installed(&self) -> bool {
        self.status.is_empty() || self.status.split_whitespace().nth(2) == Some("installed")
    }

    /// `hold` in the *want* field: the admin excluded it from upgrades, so it is
    /// pinned to whatever version it is on.
    fn is_held(&self) -> bool {
        self.status.split_whitespace().next() == Some("hold")
    }
}

/// Read and parse the dpkg database under `root`.
///
/// This is the file `dpkg-query` itself reads. Going to it directly is what
/// removes the requirement for dpkg to exist on the machine running postmortem,
/// which is the whole point for an image: the scanner and the scanned no longer
/// have to be the same distribution.
///
/// Two layouts exist. A normal system keeps one `status` file holding every
/// stanza. An image assembled *without* dpkg — distroless, and anything built by
/// bazel or ko — instead drops one stanza per package into `status.d/` and has no
/// `status` file at all. Reading only the first layout reported the images people
/// choose *for* their small attack surface as containing no packages whatsoever,
/// which is the least useful thing that can be said about them.
fn dpkg_status(root: &Path) -> Result<Vec<DpkgStanza>> {
    let single = root.join("var/lib/dpkg/status");
    if single.is_file() {
        let text = std::fs::read_to_string(&single)
            .with_context(|| format!("reading {}", single.display()))?;
        return Ok(parse_dpkg_status(&text));
    }

    let dir = root.join("var/lib/dpkg/status.d");
    let entries = std::fs::read_dir(&dir)
        .with_context(|| format!("reading {} or {}", single.display(), dir.display()))?;
    let mut out = Vec::new();
    for e in entries.flatten() {
        let p = e.path();
        // The same directory holds `<pkg>.md5sums` beside the stanzas.
        if !p.is_file() || p.extension().is_some() {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&p) {
            out.extend(parse_dpkg_status(&text));
        }
    }
    if out.is_empty() {
        anyhow::bail!(
            "no dpkg stanzas under {} — the database is present but unreadable",
            dir.display()
        );
    }
    Ok(out)
}

/// Parse the RFC822-style stanzas of a dpkg status file.
///
/// Continuation lines (leading whitespace) are skipped rather than joined: no
/// field this reads is ever multi-line, and a `Description` continuation
/// containing a colon would otherwise parse as a field of its own.
fn parse_dpkg_status(text: &str) -> Vec<DpkgStanza> {
    let mut out = Vec::new();
    for block in text.split("\n\n") {
        let mut f: HashMap<&str, &str> = HashMap::new();
        for line in block.lines() {
            if line.starts_with(' ') || line.starts_with('\t') {
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                f.entry(k.trim()).or_insert_with(|| v.trim());
            }
        }
        let Some(name) = f.get("Package") else { continue };
        if name.is_empty() {
            continue;
        }
        let get = |k: &str| f.get(k).copied().unwrap_or_default().to_string();
        out.push(DpkgStanza {
            name: name.to_string(),
            version: get("Version"),
            depends: get("Depends"),
            pre_depends: get("Pre-Depends"),
            homepage: get("Homepage"),
            architecture: get("Architecture"),
            status: get("Status"),
        });
    }
    out
}

/// Render stanzas in the tab-separated shape [`apt_graph`] consumes.
///
/// Keeping one graph builder behind one input format means the edge logic cannot
/// drift between how this machine and an image are read.
fn dpkg_status_as_columns(stanzas: &[DpkgStanza]) -> String {
    stanzas
        .iter()
        .map(|p| {
            format!(
                "{}\t{}\t{}\t{}\t{}\n",
                p.name, p.version, p.depends, p.pre_depends, p.homepage
            )
        })
        .collect()
}

/// The manually-installed (direct) set under `root`, and whether it is knowable.
///
/// apt records the inverse of what is asked for here: `extended_states` lists
/// what apt pulled in *automatically*, so manual is every installed package not
/// marked auto. When the file is absent — some minimal images drop it — the
/// answer is "unknown" rather than "everything is direct", and the caller says so.
fn apt_manual_at(root: &Path, installed: &[String]) -> (std::collections::HashSet<String>, bool) {
    let Ok(text) = std::fs::read_to_string(root.join("var/lib/apt/extended_states")) else {
        return (installed.iter().cloned().collect(), false);
    };
    let mut auto = std::collections::HashSet::new();
    let mut current = String::new();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("Package:") {
            // Foreign-arch entries are qualified (`hello:armhf`) while the graph
            // keys on the bare name.
            let v = v.trim();
            current = v.split(':').next().unwrap_or(v).to_string();
        } else if line.trim() == "Auto-Installed: 1" && !current.is_empty() {
            auto.insert(std::mem::take(&mut current));
        }
    }
    (
        installed
            .iter()
            .filter(|n| !auto.contains(*n))
            .cloned()
            .collect(),
        true,
    )
}

/// Parse `dpkg-query` output into the dependency forest.
fn apt_graph(text: &str, manual: &std::collections::HashSet<String>) -> Vec<Dependency> {
    struct P {
        name: String,
        version: String,
        depends: Vec<String>,
        homepage: String,
    }
    let pkgs: Vec<P> = text
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 5 || f[0].is_empty() {
                return None;
            }
            let mut depends = apt_dep_names(f[2]);
            depends.extend(apt_dep_names(f[3])); // Pre-Depends
            Some(P {
                name: f[0].into(),
                version: f[1].into(),
                depends,
                homepage: f[4].into(),
            })
        })
        .collect();

    let installed: HashMap<&str, ()> = pkgs.iter().map(|p| (p.name.as_str(), ())).collect();
    let mut parents: HashMap<String, Vec<DepRef>> = HashMap::new();
    for p in &pkgs {
        for d in &p.depends {
            if installed.contains_key(d.as_str()) {
                parents
                    .entry(d.clone())
                    .or_default()
                    .push((p.name.clone(), p.version.clone()));
            }
        }
    }
    pkgs.into_iter()
        .map(|p| Dependency {
            direct: manual.contains(&p.name),
            scope: Scope::Prod,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url: (!p.homepage.is_empty()).then(|| p.homepage.clone()),
            parents: parents.remove(&p.name).unwrap_or_default(),
            name: p.name,
            version: p.version,
            ecosystem: Ecosystem::Apt,
            integrity: None,
        })
        .collect()
}

/// A dpkg `Depends`/`Pre-Depends` field → package names: take the first of each
/// comma-separated clause (dropping `| alternatives`), strip a `(version)`
/// constraint and a `:arch` qualifier.
fn apt_dep_names(field: &str) -> Vec<String> {
    field
        .split(',')
        .filter_map(|clause| {
            let first = clause.split('|').next()?.trim();
            let name = first.split('(').next()?.trim();
            let name = name.split(':').next()?.trim();
            (!name.is_empty()).then(|| name.to_string())
        })
        .collect()
}

/// The provenance of an installed package's version: its source (a non-official
/// host / `manual` for a bare `.deb`, `None` for an official archive) and the
/// archive component it came from (`main` / `universe` / `non-free` / …).
struct AptProv {
    source: Option<String>,
    component: Option<String>,
}

/// `apt-cache policy <names…>` → each package's installed-version provenance
/// (source host + archive component). Maps `name → AptProv`. Best-effort; a name
/// missing from the map just has no policy data.
fn apt_provenance(names: &[String]) -> HashMap<String, AptProv> {
    let mut out = HashMap::new();
    for chunk in names.chunks(400) {
        let Ok(res) = Command::new("apt-cache").arg("policy").args(chunk).output() else {
            continue;
        };
        if !res.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&res.stdout);
        let mut cur: Option<String> = None;
        let mut in_installed = false;
        for line in text.lines() {
            if !line.starts_with(' ') && line.ends_with(':') {
                cur = Some(line.trim_end_matches(':').to_string());
                in_installed = false;
            } else if line.starts_with(" *** ") {
                in_installed = true; // the installed version's source lines follow
            } else if in_installed && line.trim_start().starts_with(|c: char| c.is_ascii_digit()) {
                // e.g. "  500 http://.../ubuntu jammy/universe amd64 Packages" or
                // "  100 /var/lib/dpkg/status"
                let toks: Vec<&str> = line.split_whitespace().collect();
                let src = toks.get(1).copied().unwrap_or("");
                // The suite/component token ("jammy/universe") → its component half.
                let component = toks
                    .get(2)
                    .and_then(|s| s.split('/').nth(1))
                    .map(str::to_string);
                if let Some(host) = host_domain(src) {
                    if let Some(name) = cur.take() {
                        let source = (!apt_official_host(&host)).then_some(host);
                        out.insert(name, AptProv { source, component });
                    }
                    in_installed = false;
                } else if src.starts_with("/var/lib/dpkg") {
                    // Only the local status file backs this version → manual .deb.
                    if let Some(name) = cur.take() {
                        out.insert(
                            name,
                            AptProv {
                                source: Some("manual".into()),
                                component: None,
                            },
                        );
                    }
                    in_installed = false;
                }
            }
        }
    }
    out
}

/// A less-curated archive component: Ubuntu's community/non-free sections
/// (`universe`/`multiverse`/`restricted`) or Debian's (`contrib`/`non-free`).
fn is_community_component(c: &str) -> bool {
    matches!(
        c,
        "universe" | "multiverse" | "restricted" | "contrib" | "non-free" | "non-free-firmware"
    )
}

/// Packages held back from upgrades (`apt-mark showhold`): pinned to their current
/// version, so they never receive updates (incl. security).
fn apt_held_at(stanzas: &[DpkgStanza]) -> std::collections::HashSet<String> {
    stanzas
        .iter()
        .filter(|p| p.is_held())
        .map(|p| p.name.clone())
        .collect()
}

/// Packages installed *solely* for a non-native architecture (a pure i386 package
/// on an amd64 host). Maps `name → foreign arch`. Ordinary multiarch libraries
/// (which also have a native copy) are excluded; only fully-foreign packages count.
fn apt_foreign_arch_at(stanzas: &[DpkgStanza]) -> HashMap<String, String> {
    // `dpkg --print-architecture` is not available when reading someone else's
    // filesystem, and `var/lib/dpkg/arch` only exists once multiarch has been
    // configured. The native architecture is instead the concrete one most of the
    // packages are built for; `all` is architecture-independent and never a
    // candidate.
    let mut tally: HashMap<&str, usize> = HashMap::new();
    for p in stanzas {
        if !p.architecture.is_empty() && p.architecture != "all" {
            *tally.entry(p.architecture.as_str()).or_default() += 1;
        }
    }
    let Some(native) = tally
        .into_iter()
        .max_by_key(|(_, n)| *n)
        .map(|(a, _)| a.to_string())
    else {
        return HashMap::new();
    };
    let mut arches: HashMap<String, Vec<String>> = HashMap::new();
    for p in stanzas {
        arches
            .entry(p.name.clone())
            .or_default()
            .push(p.architecture.clone());
    }
    arches
        .into_iter()
        .filter_map(|(name, a)| {
            // Every installed instance is a non-native, concrete arch → fully foreign.
            (!a.is_empty() && a.iter().all(|x| x != &native && x != "all"))
                .then(|| (name, a[0].clone()))
        })
        .collect()
}

/// Count apt pin rules across `/etc/apt/preferences(.d)` — each `Pin:` line forces
/// a version/source/priority, and can hold a package back or prefer a foreign one.
fn apt_pins_at(root: &Path) -> usize {
    let mut files = vec![root.join("etc/apt/preferences")];
    if let Ok(dir) = std::fs::read_dir(root.join("etc/apt/preferences.d")) {
        files.extend(dir.flatten().map(|e| e.path()));
    }
    files
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .map(|t| {
            t.lines()
                .filter(|l| l.trim_start().to_lowercase().starts_with("pin:"))
                .count()
        })
        .sum()
}

/// An official Debian/Ubuntu archive host.
fn apt_official_host(host: &str) -> bool {
    host.ends_with("ubuntu.com") || host.ends_with("debian.org")
}

/// Concatenated maintainer scripts (`preinst`/`postinst`/`prerm`/`postrm`) for a
/// package, from `/var/lib/dpkg/info/`. Empty when it ships none.
fn apt_scripts_at(root: &Path, name: &str) -> String {
    let mut code = String::new();
    for kind in ["preinst", "postinst", "prerm", "postrm"] {
        if let Ok(c) = std::fs::read_to_string(root.join(format!("var/lib/dpkg/info/{name}.{kind}")))
        {
            code.push_str(&c);
            code.push('\n');
        }
    }
    code
}

// --- execution & privilege surface --------------------------------------------

/// Index the dpkg file manifests once: `package name → its .list file(s)` (the
/// `:arch` qualifier is folded into the bare name). Reading them per-package in
/// the loop would be O(n²); this is one directory scan.
fn apt_list_index_at(root: &Path) -> HashMap<String, Vec<PathBuf>> {
    let mut idx: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for e in std::fs::read_dir(root.join("var/lib/dpkg/info"))
        .into_iter()
        .flatten()
        .flatten()
    {
        let p = e.path();
        let Some(stem) = p
            .file_name()
            .and_then(|s| s.to_str())
            .and_then(|f| f.strip_suffix(".list"))
        else {
            continue;
        };
        let name = stem.split(':').next().unwrap_or(stem).to_string();
        idx.entry(name).or_default().push(p);
    }
    idx
}

/// `package name → the file paths it installed`, for layer attribution.
///
/// Separate from [`Inventory`] because only the image path needs it: the
/// machine's own scan has no layers to attribute anything to.
pub(super) fn apt_file_index_at(root: &Path) -> HashMap<String, Vec<String>> {
    apt_list_index_at(root)
        .into_iter()
        .map(|(name, paths)| (name, read_pkg_files(&paths)))
        .collect()
}

/// The installed file paths a package ships, read from its dpkg `.list` manifest(s).
fn read_pkg_files(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .flat_map(|t| t.lines().map(str::to_string).collect::<Vec<_>>())
        .collect()
}

/// Package-created dpkg diversions → `package → diverted path`.
///
/// Read from `var/lib/dpkg/diversions`, the file `dpkg-divert` itself reads:
/// three lines per entry, the original path, what it was diverted to, and the
/// owning package (`:` for an admin-local one). The merged-usr transition
/// (`*.usr-is-merged`) and local diversions are excluded, leaving genuine file
/// overrides — one package standing its own file where another package's belongs.
fn apt_diversions_at(root: &Path) -> HashMap<String, String> {
    let Ok(text) = std::fs::read_to_string(root.join("var/lib/dpkg/diversions")) else {
        return HashMap::new();
    };
    let lines: Vec<&str> = text.lines().collect();
    let mut map = HashMap::new();
    for e in lines.chunks(3) {
        let [path, target, pkg] = e else { continue };
        let (path, target, pkg) = (path.trim(), target.trim(), pkg.trim());
        if pkg == ":" || pkg.is_empty() || target.ends_with(".usr-is-merged") {
            continue;
        }
        map.entry(pkg.to_string()).or_insert_with(|| path.to_string());
    }
    map
}

/// `apt list --upgradable` → `name → (installed, current)`. Best-effort.
fn apt_outdated() -> HashMap<String, (String, String)> {
    let Ok(out) = Command::new("apt").args(["list", "--upgradable"]).output() else {
        return HashMap::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            // "name/suite newver arch [upgradable from: oldver]"
            let name = l.split('/').next()?;
            let new = l.split_whitespace().nth(1)?;
            let old = l.split("from: ").nth(1)?.trim_end_matches(']');
            (!name.is_empty() && !name.contains(' '))
                .then(|| (name.to_string(), (old.to_string(), new.to_string())))
        })
        .collect()
}

/// Configured apt sources (`sources.list` + `sources.list.d/`), classic and
/// deb822. Official Debian/Ubuntu archives vs third-party (PPAs / custom).
fn apt_repos_at(root: &Path) -> Vec<Repo> {
    let mut seen = std::collections::HashSet::new();
    let mut repos = Vec::new();
    for f in apt_source_files_at(root) {
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        for line in text.lines() {
            let l = line.trim();
            // Classic: `deb [opts] URI suite comps`; deb822: `URIs: URI`.
            let uri = if let Some(rest) = l
                .strip_prefix("deb ")
                .or_else(|| l.strip_prefix("deb-src "))
            {
                rest.split_whitespace().find(|t| t.contains("://"))
            } else if let Some(rest) = l.strip_prefix("URIs:") {
                rest.split_whitespace().next()
            } else {
                None
            };
            if let Some(uri) = uri
                && seen.insert(uri.to_string())
            {
                let official = host_domain(uri).is_some_and(|h| apt_official_host(&h));
                repos.push(Repo {
                    name: uri.to_string(),
                    url: String::new(),
                    official,
                });
            }
        }
    }
    repos
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apt_dep_names_parses() {
        assert_eq!(
            apt_dep_names("base-files (>= 2.1.12), debianutils (>= 5.6-0.1)"),
            vec!["base-files", "debianutils"]
        );
        // Alternatives take the first; `:any` qualifier stripped.
        assert_eq!(
            apt_dep_names("libc6 (>= 2.34) | libc6-udeb, perl:any"),
            vec!["libc6", "perl"]
        );
        assert!(apt_dep_names("").is_empty());
    }

    #[test]
    fn apt_community_component_classifies() {
        // Ubuntu community/non-free + Debian non-free sections flag; the curated
        // `main` (and a third-party PPA's own `main`) do not.
        for c in [
            "universe",
            "multiverse",
            "restricted",
            "contrib",
            "non-free",
            "non-free-firmware",
        ] {
            assert!(is_community_component(c), "{c} should flag");
        }
        assert!(!is_community_component("main"));
        assert!(!is_community_component(""));
    }

    #[test]
    fn apt_graph_builds_edges_and_direct() {
        let dpkg = "app\t1.0\tlib (>= 1)\t\thttps://github.com/o/app\nlib\t0.9\t\t\t\n";
        let manual: std::collections::HashSet<String> = ["app".to_string()].into_iter().collect();
        let deps = apt_graph(dpkg, &manual);
        assert_eq!(deps.len(), 2);
        let app = deps.iter().find(|d| d.name == "app").unwrap();
        let lib = deps.iter().find(|d| d.name == "lib").unwrap();
        assert!(app.direct, "in showmanual ⇒ direct");
        assert!(!lib.direct);
        assert_eq!(
            app.resolved_url.as_deref(),
            Some("https://github.com/o/app")
        );
        assert_eq!(lib.parents, vec![("app".to_string(), "1.0".to_string())]);
    }

    /// The status file is the whole basis for reading a Debian image, so its
    /// parser is checked against the shapes dpkg actually writes: multi-line
    /// fields, a package that is *not* installed, and a held one.
    #[test]
    fn dpkg_status_parses_stanzas_and_states() {
        let text = "\
Package: bash
Status: install ok installed
Architecture: arm64
Version: 5.2.15-2
Depends: libc6 (>= 2.34), debianutils (>= 5.6-0.1)
Homepage: https://www.gnu.org/software/bash/
Description: GNU Bourne Again SHell
 Bash is a sh-compatible command language interpreter.
 Note: this continuation line contains a colon.

Package: removed-pkg
Status: deinstall ok config-files
Architecture: arm64
Version: 1.0

Package: pinned
Status: hold ok installed
Architecture: all
Version: 2.0
";
        let all = parse_dpkg_status(text);
        assert_eq!(all.len(), 3, "every stanza is parsed");

        let installed: Vec<&DpkgStanza> =
            all.iter().filter(|p| p.is_installed()).collect();
        assert_eq!(installed.len(), 2, "the config-files package is not installed");
        assert!(!all.iter().any(|p| p.name.contains("Note")), "a continuation line is not a field");

        let bash = all.iter().find(|p| p.name == "bash").expect("bash");
        assert_eq!(bash.version, "5.2.15-2");
        assert_eq!(bash.architecture, "arm64");
        assert_eq!(bash.homepage, "https://www.gnu.org/software/bash/");
        assert!(!bash.is_held());

        let pinned = all.iter().find(|p| p.name == "pinned").expect("pinned");
        assert!(pinned.is_held(), "`hold` in the want field");
        assert_eq!(apt_held_at(&all), ["pinned".to_string()].into_iter().collect());

        // The graph is built from these same stanzas, through the one column format.
        let manual = ["bash".to_string()].into_iter().collect();
        let deps = apt_graph(&dpkg_status_as_columns(&installed.iter().map(|p| DpkgStanza {
            name: p.name.clone(),
            version: p.version.clone(),
            depends: p.depends.clone(),
            pre_depends: p.pre_depends.clone(),
            homepage: p.homepage.clone(),
            architecture: p.architecture.clone(),
            status: p.status.clone(),
        }).collect::<Vec<_>>()), &manual);
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().find(|d| d.name == "bash").expect("bash").direct);
    }

    /// apt records what it installed *automatically*; manual is the complement.
    /// A missing file means the split is unknown, which the caller must be told.
    #[test]
    fn manual_set_is_the_complement_of_auto_and_reports_when_unknown() {
        let root = std::env::temp_dir().join(format!("postmortem-apttest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("var/lib/apt")).expect("dirs");
        let installed = vec!["app".to_string(), "lib".to_string(), "tool".to_string()];

        // No file yet: unknown, and nothing may be claimed as transitive.
        let (manual, known) = apt_manual_at(&root, &installed);
        assert!(!known, "absence is reported, not guessed");
        assert_eq!(manual.len(), 3);

        std::fs::write(
            root.join("var/lib/apt/extended_states"),
            "Package: lib\nArchitecture: arm64\nAuto-Installed: 1\n\n\
             Package: tool:armhf\nArchitecture: armhf\nAuto-Installed: 1\n\n\
             Package: other\nArchitecture: arm64\nAuto-Installed: 0\n",
        )
        .expect("extended_states");
        let (manual, known) = apt_manual_at(&root, &installed);
        let _ = std::fs::remove_dir_all(&root);
        assert!(known);
        // `tool:armhf` is qualified in the file and bare in the graph.
        assert_eq!(manual, ["app".to_string()].into_iter().collect());
    }

    /// The diversions file is three lines per entry. A local diversion (`:`) has
    /// no owning package, and the merged-usr transition is not a hijack.
    #[test]
    fn diversions_are_read_from_dpkgs_own_file() {
        let root = std::env::temp_dir().join(format!("postmortem-aptdiv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("var/lib/dpkg")).expect("dirs");
        std::fs::write(
            root.join("var/lib/dpkg/diversions"),
            "/bin/sh\n/bin/sh.distrib\ndash\n\
             /usr/bin/x\n/usr/bin/x.usr-is-merged\nusrmerge\n\
             /etc/local\n/etc/local.orig\n:\n",
        )
        .expect("diversions");
        let d = apt_diversions_at(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(d.get("dash").map(String::as_str), Some("/bin/sh"));
        assert!(!d.contains_key("usrmerge"), "merged-usr is not a hijack");
        assert!(!d.contains_key(":"), "an admin-local diversion has no owner");
    }

    /// Without `dpkg --print-architecture`, the native arch is the one most
    /// packages carry; `all` is architecture-independent and never native.
    #[test]
    fn foreign_arch_falls_back_to_the_majority_architecture() {
        let mk = |name: &str, arch: &str| DpkgStanza {
            name: name.into(),
            version: "1".into(),
            depends: String::new(),
            pre_depends: String::new(),
            homepage: String::new(),
            architecture: arch.into(),
            status: "install ok installed".into(),
        };
        let stanzas = vec![
            mk("a", "arm64"),
            mk("b", "arm64"),
            mk("c", "all"),
            mk("d", "armhf"),
        ];
        let foreign = apt_foreign_arch_at(&stanzas);
        assert_eq!(foreign.get("d").map(String::as_str), Some("armhf"));
        assert!(!foreign.contains_key("a") && !foreign.contains_key("c"));
    }

    /// The layout distroless and other dpkg-less builders use: one stanza file
    /// per package, no `status` file, and no `Status:` field in the stanzas.
    /// Reading only the single-file layout reported these images as empty.
    #[test]
    fn the_status_d_layout_is_read_too() {
        let root = std::env::temp_dir().join(format!("postmortem-statusd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let d = root.join("var/lib/dpkg/status.d");
        std::fs::create_dir_all(&d).expect("status.d");
        std::fs::write(
            d.join("libc6"),
            "Package: libc6\nVersion: 2.36-9\nArchitecture: arm64\nDescription: GNU C Library\n",
        )
        .expect("libc6");
        std::fs::write(
            d.join("base-files"),
            "Package: base-files\nVersion: 12.4\nArchitecture: arm64\nPre-Depends: awk\n",
        )
        .expect("base-files");
        // The same directory holds checksum files, which are not stanzas.
        std::fs::write(d.join("libc6.md5sums"), "abc  /lib/libc.so\n").expect("md5sums");

        let stanzas = dpkg_status(&root).expect("status.d is a database");
        let _ = std::fs::remove_dir_all(&root);

        let mut names: Vec<&str> = stanzas.iter().map(|p| p.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["base-files", "libc6"], "checksums are not packages");
        assert!(
            stanzas.iter().all(DpkgStanza::is_installed),
            "a stanza with no Status: exists because the builder put the package in"
        );
    }

    /// The loosened `is_installed` must not loosen the real layout: a package
    /// removed but not purged still has to stay out of the graph.
    #[test]
    fn a_status_field_still_decides_when_there_is_one() {
        let installed = DpkgStanza {
            name: "a".into(),
            version: "1".into(),
            depends: String::new(),
            pre_depends: String::new(),
            homepage: String::new(),
            architecture: "arm64".into(),
            status: "install ok installed".into(),
        };
        let removed = DpkgStanza {
            status: "deinstall ok config-files".into(),
            ..installed_like(&installed)
        };
        assert!(installed.is_installed());
        assert!(!removed.is_installed());
    }

    /// A clone helper, because `DpkgStanza` is deliberately not `Clone` in
    /// production code.
    fn installed_like(p: &DpkgStanza) -> DpkgStanza {
        DpkgStanza {
            name: p.name.clone(),
            version: p.version.clone(),
            depends: p.depends.clone(),
            pre_depends: p.pre_depends.clone(),
            homepage: p.homepage.clone(),
            architecture: p.architecture.clone(),
            status: p.status.clone(),
        }
    }
}
