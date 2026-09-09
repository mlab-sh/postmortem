//! Fedora/RHEL `dnf` / `rpm` backend.
//!
//! Split by which tool can answer where. **rpm** reads a package database it is
//! pointed at, so `--root` lets the same queries describe an extracted container
//! image; the inventory, the capability graph, scriptlets, signatures, file
//! manifests and `rpm -Va` tampering all come from there. **dnf** only ever
//! describes the system it is configured for, so the origin repo, the
//! user-installed set, orphans and available upgrades are collected for this
//! machine and reported as *not collected* for an image.
//!
//! Unlike apt, rpm's database is a binary store rather than a text file, so
//! reading an image needs an `rpm` binary on the machine running postmortem. When
//! there is none the backend fails loudly and the caller turns that into a
//! diagnostic — never into an image that appears to have no packages.

use std::path::Path;

use super::privilege::{find_setuid_files_at, persistence_signals, verify_line_is_tamper};
use super::recipe::analyze_recipe;
use super::*;

// --- dnf / rpm backend -------------------------------------------------------

/// Official RPM vendors: a package stamped with one of these came from the
/// distribution proper, not a third-party repo / a locally-built `.rpm`.
const RPM_OFFICIAL_VENDORS: &[&str] = &[
    "Fedora Project",
    "Red Hat, Inc.",
    "CentOS",
    "Rocky Enterprise Software Foundation",
    "AlmaLinux",
    "openSUSE",
    "Oracle America",
    "Amazon Linux",
];

/// Read the installed rpm forest into an [`Inventory`]. `rpm -qa` dumps every
/// package (name, version, url, vendor) in one call; the dependency edges come
/// from the capability graph (`PROVIDENAME` ↔ `REQUIRENAME`); `dnf
/// --userinstalled` marks the direct set. Third-party (non-distro-vendor) packages
/// are the untrusted surface and get their scriptlets analyzed.
pub fn dnf_inventory(opts: Opts) -> Result<Inventory> {
    dnf_inventory_at(Path::new("/"), opts)
}

/// Read the installed rpm forest under `root`. See [`dnf_inventory`].
pub fn dnf_inventory_at(root: &Path, opts: Opts) -> Result<Inventory> {
    let _ = opts; // dnf reputation comes from the shared `--online` path
    // Only this machine can be asked the questions that need a configured dnf.
    let live = root == Path::new("/");
    if !live && rpm_dbpath(root).is_none() {
        anyhow::bail!(
            "no rpm database found under {} (looked in {}) — its packages were not examined",
            root.display(),
            RPM_DB_DIRS.join(", ")
        );
    }
    let text = rpm_qa(root, "%{NAME}\t%{VERSION}-%{RELEASE}\t%{URL}\t%{VENDOR}\n")?;
    struct N {
        name: String,
        version: String,
        url: String,
        vendor: String,
    }
    let nodes: Vec<N> = text
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            // Skip `gpg-pubkey` pseudo-packages (imported keys, not real rpms).
            if f.len() < 4 || f[0].is_empty() || f[0] == "gpg-pubkey" {
                return None;
            }
            Some(N {
                name: f[0].into(),
                version: f[1].into(),
                url: f[2].into(),
                vendor: f[3].into(),
            })
        })
        .collect();

    let names: std::collections::HashSet<&str> = nodes.iter().map(|n| n.name.as_str()).collect();
    let version_of: HashMap<&str, &str> = nodes
        .iter()
        .map(|n| (n.name.as_str(), n.version.as_str()))
        .collect();
    let userinstalled = if live {
        dnf_userinstalled()
    } else {
        Default::default()
    };
    let mut parents = dnf_edges(root, &names, &version_of);
    let scripted = dnf_scripted(root);
    let unsigned = dnf_unsigned(root);
    // A rpm image built with `--nogpgcheck` reports everything unsigned, which is
    // noise; only surface `unsigned` when it's the exception, not the rule.
    let mostly_unsigned = !nodes.is_empty() && unsigned.len() * 10 >= nodes.len() * 9;
    let from_repo = if live {
        dnf_from_repo()
    } else {
        HashMap::new()
    };
    let file_index = rpm_file_index(root);
    let setuid = find_setuid_files_at(root);
    let held = dnf_held_at(root);
    let foreign = dnf_foreign_arch(root);
    // Orphans (installed, offered by no enabled repo). Needs repo metadata; when it
    // can't be computed it reports everything, so guard as with `unsigned`.
    let orphans = if live {
        dnf_orphans()
    } else {
        Default::default()
    };
    let mostly_orphan = !nodes.is_empty() && orphans.len() * 10 >= nodes.len() * 9;

    let mut signals: HashMap<String, Vec<SysSignal>> = HashMap::new();
    let mut deps = Vec::with_capacity(nodes.len());
    for n in &nodes {
        // Provenance: the origin repo is authoritative when known (catches copr /
        // rpmfusion even though they keep a distribution vendor), else the vendor.
        let repo = from_repo.get(&n.name).map(String::as_str);
        let third_party = match dnf_provenance_label(repo, &n.vendor) {
            Some(label) => {
                push_signal(
                    &mut signals,
                    &n.name,
                    SysSignal::new(label, Category::ThirdPartySource, Severity::Medium, 30),
                );
                true
            }
            None => false,
        };
        // Unsigned = no header signature (tampered / untrusted origin), unless the
        // whole image is unsigned.
        if !mostly_unsigned && unsigned.contains(&n.name) {
            push_signal(
                &mut signals,
                &n.name,
                SysSignal::new("unsigned", Category::Unsigned, Severity::High, 40),
            );
        }
        // Scriptlets run code at install/upgrade/erase. Surfaced for all; analyzed
        // for the untrusted (third-party) ones, whose recipes aren't review-gated.
        if scripted.contains(&n.name) {
            push_signal(
                &mut signals,
                &n.name,
                SysSignal::new("install-script (runs code at install)", Category::InstallHook, Severity::Info, 0),
            );
            // In an image nothing can be shown to be third-party (the origin repo
            // needs dnf), so every scriptlet is analyzed rather than none — but
            // unscored, since the premise that makes those findings meaningful is
            // the one that could not be checked.
            if third_party || !live {
                // rpm scriptlets are usually shell but may be Lua (`-p <lua>`);
                // analyze with the matching language.
                let ext = if dnf_script_is_lua(root, &n.name) {
                    "lua"
                } else {
                    "sh"
                };
                for sig in analyze_recipe(&n.name, &dnf_scripts(root, &n.name), ext) {
                    push_signal(
                        &mut signals,
                        &n.name,
                        if third_party { sig } else { sig.unscored() },
                    );
                }
            }
        }
        // Execution & privilege: the boot/scheduled/auth/setuid surface a package
        // sets up through the files it ships (shared with the apt backend).
        if let Some(files) = file_index.get(&n.name) {
            for sig in persistence_signals(files, &setuid) {
                push_signal(&mut signals, &n.name, sig);
            }
        }
        // Held (version-locked): excluded from upgrades, so stuck on its version.
        if held.contains(&n.name) {
            push_signal(
                &mut signals,
                &n.name,
                SysSignal::new("held (version locked)", Category::Policy, Severity::Low, 10),
            );
        }
        // Installed only for a non-native architecture (pure multilib package).
        if let Some(arch) = foreign.get(&n.name) {
            push_signal(
                &mut signals,
                &n.name,
                SysSignal::new(format!("foreign-arch ({arch})"), Category::Policy, Severity::Low, 5),
            );
        }
        // Installed but offered by no enabled repo (removed upstream / local build).
        if !mostly_orphan && orphans.contains(&n.name) {
            push_signal(
                &mut signals,
                &n.name,
                SysSignal::new("orphan (not in any repo)", Category::ThirdPartySource, Severity::Low, 10),
            );
        }
        deps.push(Dependency {
            direct: userinstalled.is_empty() || userinstalled.contains(&n.name),
            scope: Scope::Prod,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url: (!n.url.is_empty()).then(|| n.url.clone()),
            parents: parents.remove(&n.name).unwrap_or_default(),
            name: n.name.clone(),
            version: n.version.clone(),
            ecosystem: Ecosystem::Dnf,
            integrity: None,
        });
    }

    if live {
        for (name, (old, new)) in dnf_outdated() {
            signals
                .entry(name)
                .or_default()
                .push(outdated_signal(&old, &new));
        }
    }

    // Trust & integrity caveats (repo signature/transport posture + tampered files).
    let mut warnings = dnf_trust_warnings_at(root);
    let modified = dnf_modified_files(root);
    if modified > 0 {
        warnings.push(format!(
            "{modified} installed file(s) modified since install (rpm -Va)"
        ));
    }
    if !live {
        // Stated, not skipped: these four need a configured dnf describing its own
        // system, and an image carries no repo metadata.
        warnings.push(
            "not checked in an image: origin repo, orphans and available upgrades (all need a \
             configured dnf and its repo metadata)"
                .into(),
        );
        // `dnf repoquery --userinstalled` is what separates what was asked for
        // from what was pulled in. Without it every package reads as direct, and
        // saying so is the difference between a flat graph and a wrong one.
        warnings.push(
            "no user-installed set in an image: every package reads as directly installed, so the \
             direct/transitive split is unknown"
                .into(),
        );
    }

    let direct = deps.iter().filter(|d| d.direct).count();
    let summary = format!("{} package(s) ({direct} user-installed)", deps.len());
    Ok(Inventory {
        manager: "dnf",
        deps,
        repos: dnf_repos_at(root),
        signals,
        claims: Vec::new(),
        summary,
        notes: warnings,
    })
}

/// Installed packages' origin repo, `name → repo id`, via `dnf repoquery
/// --installed`. Only *usable* origins are kept: dnf5 emits an opaque hash for
/// packages installed outside dnf (a container image), which we drop so the caller
/// falls back to the vendor.
fn dnf_from_repo() -> HashMap<String, String> {
    let Ok(out) = Command::new("dnf")
        .args([
            "repoquery",
            "--installed",
            "--qf",
            "%{name}\t%{from_repo}\n",
        ])
        .output()
    else {
        return HashMap::new();
    };
    if !out.status.success() {
        return HashMap::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let (name, repo) = l.split_once('\t')?;
            let repo = repo.trim();
            dnf_repo_usable(repo).then(|| (name.trim().to_string(), repo.to_string()))
        })
        .collect()
}

/// Is a `from_repo` value a real repo id we can reason about? dnf5 returns a 32-hex
/// hash for image-installed packages and `@System` when the origin is lost; both
/// are unusable, so the caller falls back to the vendor.
fn dnf_repo_usable(repo: &str) -> bool {
    !repo.is_empty()
        && repo != "@System"
        && repo != "<unknown>"
        && !(repo.len() == 32 && repo.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Decide provenance from the origin repo (authoritative when known) then the
/// vendor. Returns the `third-party-source (...)` label, or `None` for a
/// first-party package.
fn dnf_provenance_label(repo: Option<&str>, vendor: &str) -> Option<String> {
    if let Some(r) = repo {
        if is_official_dnf_repo(r) {
            return None;
        }
        if r == "@commandline" {
            return Some("third-party-source (local .rpm)".to_string());
        }
        return Some(format!("third-party-source ({r})"));
    }
    if RPM_OFFICIAL_VENDORS.contains(&vendor) {
        return None;
    }
    Some(if vendor.is_empty() || vendor == "(none)" {
        "third-party-source (local .rpm)".to_string()
    } else {
        format!("third-party-source ({vendor})")
    })
}

/// `name → installed files`, from one `rpm -qa` over `FILENAMES`. Multiarch copies
/// of a package are unioned under the bare name.
fn rpm_file_index(root: &Path) -> HashMap<String, Vec<String>> {
    let Ok(text) = rpm_qa(root, "%{NAME}\t[%{FILENAMES},]\n") else {
        return HashMap::new();
    };
    let mut idx: HashMap<String, Vec<String>> = HashMap::new();
    for line in text.lines() {
        let Some((name, files)) = line.split_once('\t') else {
            continue;
        };
        let list = files
            .split(',')
            .filter(|f| !f.is_empty())
            .map(str::to_string);
        idx.entry(name.to_string()).or_default().extend(list);
    }
    idx
}

/// Trust caveats from the dnf repo config: signature checking disabled
/// (`gpgcheck=0`, the analog of apt's `[trusted=yes]`) or a plain-http source, over
/// the enabled repos in `/etc/yum.repos.d/*.repo`.
fn dnf_trust_warnings_at(root: &Path) -> Vec<String> {
    let (mut nogpg, mut http) = (0usize, 0usize);
    if let Ok(dir) = std::fs::read_dir(root.join("etc/yum.repos.d")) {
        for entry in dir.flatten() {
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            for section in text.split('[').skip(1) {
                let Some((id, body)) = section.split_once(']') else {
                    continue;
                };
                if id.trim().is_empty() {
                    continue;
                }
                let key_is = |key: &str, val: char| {
                    body.lines()
                        .filter_map(|l| l.trim().strip_prefix(key))
                        .any(|v| v.trim_start_matches([' ', '=']).starts_with(val))
                };
                if key_is("enabled", '0') {
                    continue; // disabled repo, ignore
                }
                if key_is("gpgcheck", '0') {
                    nogpg += 1;
                }
                if body.lines().any(|l| {
                    let l = l.trim();
                    (l.starts_with("baseurl")
                        || l.starts_with("metalink")
                        || l.starts_with("mirrorlist"))
                        && l.contains("http://")
                }) {
                    http += 1;
                }
            }
        }
    }
    let mut w = Vec::new();
    if nogpg > 0 {
        w.push(format!(
            "{nogpg} dnf repo(s) with gpgcheck=0 (signature checking disabled)"
        ));
    }
    if http > 0 {
        w.push(format!(
            "{http} dnf repo(s) over http (no transport encryption)"
        ));
    }
    w
}

/// Count installed files whose content no longer matches the rpm database
/// (`rpm -Va` digest mismatch), excluding config/doc/ghost files.
fn dnf_modified_files(root: &Path) -> usize {
    let Ok(out) = rpm_at(root).arg("-Va").output() else {
        return 0;
    };
    // `rpm -Va` exits non-zero precisely when it finds discrepancies.
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| verify_line_is_tamper(l))
        .count()
}

/// Where an rpm database can live inside a filesystem, newest layout first.
pub(super) const RPM_DB_DIRS: &[&str] = &["usr/lib/sysimage/rpm", "var/lib/rpm"];

/// The files that mark one of those directories as an actual database: sqlite
/// (rpm 4.16+), ndb, or the historical Berkeley DB.
const RPM_DB_FILES: &[&str] = &["rpmdb.sqlite", "Packages.db", "Packages"];

/// The rpm database inside `root`, as a path relative to it.
///
/// rpm's default `_dbpath` is a property of the rpm *doing the reading*, not of
/// the filesystem being read. Fedora moved its database to
/// `/usr/lib/sysimage/rpm` while RHEL 9 and its rebuilds still keep it in
/// `/var/lib/rpm`, so reading an AlmaLinux image from a Fedora machine with the
/// default finds an empty directory and reports **zero packages** — a silent,
/// confident, wrong answer, and the worst possible failure for a scanner. The
/// location is probed instead of assumed.
pub(super) fn rpm_dbpath(root: &Path) -> Option<&'static str> {
    RPM_DB_DIRS.iter().copied().find(|d| {
        let dir = root.join(d);
        RPM_DB_FILES.iter().any(|f| dir.join(f).is_file())
    })
}

/// An `rpm` invocation pointed at `root`.
///
/// `--root` is what makes rpm read *another* filesystem's database, and it is the
/// whole reason an image can be inventoried at all. Both flags are omitted for
/// `/` so this machine is queried exactly as it was before they existed.
fn rpm_at(root: &Path) -> Command {
    let mut c = Command::new("rpm");
    if root != Path::new("/") {
        c.arg("--root").arg(root);
        // Interpreted relative to `--root`, so the leading slash is the image's.
        if let Some(db) = rpm_dbpath(root) {
            c.arg("--dbpath").arg(format!("/{db}"));
        }
    }
    c
}

/// `rpm -qa --qf <fmt>` under `root` → stdout as a string.
///
/// Errors when rpm is missing or refuses the database. That error is the point:
/// it reaches the user as "these packages were not examined", never as an image
/// that happens to contain nothing.
fn rpm_qa(root: &Path, fmt: &str) -> Result<String> {
    let out = rpm_at(root)
        .args(["-qa", "--qf", fmt])
        .output()
        .context("running `rpm -qa` — is rpm installed on this machine?")?;
    if !out.status.success() {
        anyhow::bail!(
            "`rpm -qa` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The user-installed (direct) set via `dnf repoquery --userinstalled`. Empty when
/// dnf is unavailable, in which case the caller treats every package as direct.
fn dnf_userinstalled() -> std::collections::HashSet<String> {
    Command::new("dnf")
        .args(["repoquery", "--userinstalled", "--qf", "%{name}\n"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Build the dependency edges from the rpm capability graph: every package's
/// `REQUIRENAME` entries resolved through a `capability → providing package` map
/// (built from `PROVIDENAME`, which includes package names, sonames, and files).
/// `rpmlib(...)` build-time pseudo-capabilities and self-edges are dropped.
fn dnf_edges(
    root: &Path,
    names: &std::collections::HashSet<&str>,
    version_of: &HashMap<&str, &str>,
) -> HashMap<String, Vec<DepRef>> {
    // capability → a providing package (first wins; only installed packages).
    let mut provider: HashMap<String, String> = HashMap::new();
    if let Ok(text) = rpm_qa(root, "%{NAME}\t[%{PROVIDENAME},]\n") {
        for line in text.lines() {
            let Some((name, caps)) = line.split_once('\t') else {
                continue;
            };
            for cap in caps.split(',').filter(|c| !c.is_empty()) {
                provider
                    .entry(cap.to_string())
                    .or_insert_with(|| name.to_string());
            }
        }
    }
    let mut parents: HashMap<String, Vec<DepRef>> = HashMap::new();
    if let Ok(text) = rpm_qa(root, "%{NAME}\t[%{REQUIRENAME},]\n") {
        for line in text.lines() {
            let Some((name, caps)) = line.split_once('\t') else {
                continue;
            };
            if !names.contains(name) {
                continue;
            }
            let mut seen = std::collections::HashSet::new();
            for cap in caps.split(',').filter(|c| !c.is_empty()) {
                if cap.starts_with("rpmlib(") {
                    continue;
                }
                let Some(child) = provider.get(cap) else {
                    continue;
                };
                // A package depends on the provider: the provider gets this as a
                // parent. Skip self-edges and duplicate parents.
                if child != name && seen.insert(child.clone()) {
                    let ver = version_of.get(name).copied().unwrap_or("").to_string();
                    parents
                        .entry(child.clone())
                        .or_default()
                        .push((name.to_string(), ver));
                }
            }
        }
    }
    parents
}

/// Packages that ship any rpm scriptlet (`%pre`/`%post`/`%preun`/`%postun`). The
/// `%|TAG?{1}:{0}|` conditional avoids pulling the (multi-line) script bodies.
fn dnf_scripted(root: &Path) -> std::collections::HashSet<String> {
    let fmt = "%{NAME}\t%|PREIN?{1}:{0}|%|POSTIN?{1}:{0}|%|PREUN?{1}:{0}|%|POSTUN?{1}:{0}|\n";
    let Ok(text) = rpm_qa(root, fmt) else {
        return Default::default();
    };
    text.lines()
        .filter_map(|l| {
            let (name, bits) = l.split_once('\t')?;
            (bits.contains('1')).then(|| name.to_string())
        })
        .collect()
}

/// The concatenated scriptlet bodies of one package (for static analysis).
fn dnf_scripts(root: &Path, name: &str) -> String {
    rpm_at(root)
        .args([
            "-q",
            "--qf",
            "%{PREIN}\n%{POSTIN}\n%{PREUN}\n%{POSTUN}\n",
            name,
        ])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).replace("(none)", ""))
        .unwrap_or_default()
}

/// Packages with no header signature. `%|RSAHEADER?...|` falls through the modern
/// (header) and legacy (payload) signature tags; only a fully-unsigned package
/// ends up in the set.
fn dnf_unsigned(root: &Path) -> std::collections::HashSet<String> {
    let fmt = "%{NAME}\t%|DSAHEADER?{s}:{%|RSAHEADER?{s}:{%|SIGGPG?{s}:{%|SIGPGP?{s}:{U}|}|}|}|\n";
    let Ok(text) = rpm_qa(root, fmt) else {
        return Default::default();
    };
    text.lines()
        .filter_map(|l| {
            let (name, sig) = l.split_once('\t')?;
            (sig == "U").then(|| name.to_string())
        })
        .collect()
}

/// `dnf check-update` → `name → (installed?, current)`. rpm doesn't record the
/// installed version here, so only the available one is known. Best-effort: needs
/// repo metadata, empty otherwise. Exit code 100 means updates are available.
fn dnf_outdated() -> HashMap<String, (String, String)> {
    let Ok(out) = Command::new("dnf")
        .args(["--cacheonly", "check-update", "--qf", "%{name}\t%{evr}\n"])
        .output()
    else {
        return HashMap::new();
    };
    // 0 = up to date, 100 = updates available; anything else is an error.
    if !matches!(out.status.code(), Some(0) | Some(100)) {
        return HashMap::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let (name, new) = l.split_once('\t')?;
            let name = name.trim();
            (!name.is_empty() && !name.contains(' ') && !new.trim().is_empty())
                .then(|| (name.to_string(), (String::new(), new.trim().to_string())))
        })
        .collect()
}

/// Configured dnf repos from `/etc/yum.repos.d/*.repo` (only the enabled ones).
/// Fedora/RHEL-family archive ids are official; anything else is third-party.
fn dnf_repos_at(root: &Path) -> Vec<Repo> {
    let Ok(dir) = std::fs::read_dir(root.join("etc/yum.repos.d")) else {
        return Vec::new();
    };
    let mut repos = Vec::new();
    for entry in dir.flatten() {
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        // Each `[id]` starts a section; `enabled=0` (default is on) drops it.
        for section in text.split('[').skip(1) {
            let Some((id, body)) = section.split_once(']') else {
                continue;
            };
            let id = id.trim();
            let enabled = !body
                .lines()
                .filter_map(|l| l.trim().strip_prefix("enabled"))
                .any(|v| v.trim_start_matches([' ', '=']).starts_with('0'));
            if enabled && !id.is_empty() {
                repos.push(Repo {
                    name: id.to_string(),
                    url: String::new(),
                    official: is_official_dnf_repo(id),
                });
            }
        }
    }
    repos
}

/// Does a package's scriptlets use the embedded Lua interpreter (`rpm -q --scripts`
/// labels them `(using <lua>)`) rather than shell?
fn dnf_script_is_lua(root: &Path, name: &str) -> bool {
    rpm_at(root)
        .args(["-q", "--scripts", name])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some_and(|o| String::from_utf8_lossy(&o.stdout).contains("using <lua>"))
}

/// Version-locked packages from the dnf versionlock plugin
/// (`/etc/dnf/plugins/versionlock.list`): pinned, so excluded from upgrades.
fn dnf_held_at(root: &Path) -> std::collections::HashSet<String> {
    let Ok(text) = std::fs::read_to_string(root.join("etc/dnf/plugins/versionlock.list")) else {
        return Default::default();
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            // Entries are NEVRA-ish (`name-epoch:version-release.arch`, maybe `!`
            // or glob); the name is everything before the first `-<digit>` segment.
            let l = l.trim_start_matches('!');
            let bytes = l.as_bytes();
            let mut cut = None;
            for (i, w) in bytes.windows(2).enumerate() {
                if w[0] == b'-' && w[1].is_ascii_digit() {
                    cut = Some(i);
                    break;
                }
            }
            let name = match cut {
                Some(i) => &l[..i],
                None => l.split_whitespace().next().unwrap_or(l),
            };
            (!name.is_empty()).then(|| name.to_string())
        })
        .collect()
}

/// Packages installed *only* for a non-native architecture (a pure multilib
/// package). Maps `name → foreign arch`; ordinary packages with a native or
/// `noarch` copy are excluded.
fn dnf_foreign_arch(root: &Path) -> HashMap<String, String> {
    // `%{_arch}` is rpm's *own* build architecture, which describes the machine
    // running postmortem rather than the image being read. For an image the
    // native architecture is instead the concrete one most packages carry.
    let native = if root == Path::new("/") {
        Command::new("rpm")
            .args(["--eval", "%{_arch}"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };
    let Ok(text) = rpm_qa(root, "%{NAME}\t%{ARCH}\n") else {
        return HashMap::new();
    };
    let mut arches: HashMap<String, Vec<String>> = HashMap::new();
    for line in text.lines() {
        if let Some((name, arch)) = line.split_once('\t') {
            arches
                .entry(name.to_string())
                .or_default()
                .push(arch.to_string());
        }
    }
    let native = if native.is_empty() {
        let mut tally: HashMap<&str, usize> = HashMap::new();
        for a in arches.values().flatten() {
            if a != "noarch" && !a.is_empty() {
                *tally.entry(a.as_str()).or_default() += 1;
            }
        }
        match tally.into_iter().max_by_key(|(_, n)| *n) {
            Some((a, _)) => a.to_string(),
            None => return HashMap::new(),
        }
    } else {
        native
    };
    arches
        .into_iter()
        .filter_map(|(name, a)| {
            (!a.is_empty() && a.iter().all(|x| x != &native && x != "noarch"))
                .then(|| (name, a[0].clone()))
        })
        .collect()
}

/// Installed packages offered by no enabled repo (`dnf repoquery --extras`), the
/// analog of apt's obsolete set. `--cacheonly` avoids a network round-trip;
/// best-effort (empty when repo metadata isn't cached).
fn dnf_orphans() -> std::collections::HashSet<String> {
    let Ok(out) = Command::new("dnf")
        .args(["--cacheonly", "repoquery", "--extras", "--qf", "%{name}\n"])
        .output()
    else {
        return Default::default();
    };
    if !out.status.success() {
        return Default::default();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.contains(' '))
        .map(str::to_string)
        .collect()
}

/// A distribution (first-party) dnf repo id: the Fedora / RHEL-family archives and
/// their debug/source/testing variants.
fn is_official_dnf_repo(id: &str) -> bool {
    const OFFICIAL: &[&str] = &[
        "fedora",
        "updates",
        "rawhide",
        "fedora-modular",
        "updates-modular",
        "fedora-cisco-openh264",
        "anaconda",
        "baseos",
        "appstream",
        "crb",
        "powertools",
        "extras",
        "rhel",
        "epel",
    ];
    // Strip the debug / source / testing variant suffixes before matching.
    let base = id
        .trim_end_matches("-debuginfo")
        .trim_end_matches("-source")
        .trim_end_matches("-testing");
    OFFICIAL.contains(&base) || base.starts_with("rhel-") || base.starts_with("epel")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dnf_provenance_repo_then_vendor() {
        // A usable repo id is authoritative: copr / rpmfusion flag even with a
        // distribution vendor (copr stamps "Fedora Project"); official repos don't.
        assert_eq!(dnf_provenance_label(Some("fedora"), "Fedora Project"), None);
        assert_eq!(
            dnf_provenance_label(Some("copr:copr.fedorainfracloud.org:u:p"), "Fedora Project"),
            Some("third-party-source (copr:copr.fedorainfracloud.org:u:p)".to_string())
        );
        assert_eq!(
            dnf_provenance_label(Some("@commandline"), "Fedora Project"),
            Some("third-party-source (local .rpm)".to_string())
        );
        // No usable repo → fall back to the vendor.
        assert_eq!(dnf_provenance_label(None, "Fedora Project"), None);
        assert_eq!(
            dnf_provenance_label(None, ""),
            Some("third-party-source (local .rpm)".to_string())
        );
        assert_eq!(
            dnf_provenance_label(None, "Some Vendor"),
            Some("third-party-source (Some Vendor)".to_string())
        );
        // Hash / @System origins are unusable (fall back to vendor).
        assert!(!dnf_repo_usable("42d8710061e642fcad14d10645570ecc"));
        assert!(!dnf_repo_usable("@System"));
        assert!(!dnf_repo_usable("<unknown>"));
        assert!(dnf_repo_usable("copr:x"));
    }

    #[test]
    fn dnf_official_repo_classifies() {
        for id in [
            "fedora",
            "updates",
            "updates-testing",
            "fedora-source",
            "rhel-9-baseos",
            "epel",
        ] {
            assert!(is_official_dnf_repo(id), "{id} should be official");
        }
        for id in [
            "rpmfusion-free",
            "copr:someuser:proj",
            "docker-ce",
            "google-chrome",
        ] {
            assert!(!is_official_dnf_repo(id), "{id} should be third-party");
        }
    }

    /// The bug this probe exists to prevent: rpm's default `_dbpath` describes
    /// the machine doing the reading, so a Fedora host reading an EL9 image with
    /// the default finds an empty directory and reports zero packages.
    #[test]
    fn the_rpm_database_is_probed_in_both_layouts() {
        let base = std::env::temp_dir().join(format!("postmortem-rpmdb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        // EL9 and its rebuilds.
        let el9 = base.join("el9");
        std::fs::create_dir_all(el9.join("var/lib/rpm")).expect("dirs");
        std::fs::write(el9.join("var/lib/rpm/rpmdb.sqlite"), b"x").expect("db");
        assert_eq!(rpm_dbpath(&el9), Some("var/lib/rpm"));

        // Fedora / RHEL 10.
        let fedora = base.join("fedora");
        std::fs::create_dir_all(fedora.join("usr/lib/sysimage/rpm")).expect("dirs");
        std::fs::write(fedora.join("usr/lib/sysimage/rpm/rpmdb.sqlite"), b"x").expect("db");
        assert_eq!(rpm_dbpath(&fedora), Some("usr/lib/sysimage/rpm"));

        // The historical Berkeley DB layout.
        let old = base.join("old");
        std::fs::create_dir_all(old.join("var/lib/rpm")).expect("dirs");
        std::fs::write(old.join("var/lib/rpm/Packages"), b"x").expect("db");
        assert_eq!(rpm_dbpath(&old), Some("var/lib/rpm"));

        // An empty directory is not a database — exactly the state a Debian image
        // or a half-extracted root presents.
        let empty = base.join("empty");
        std::fs::create_dir_all(empty.join("var/lib/rpm")).expect("dirs");
        assert_eq!(rpm_dbpath(&empty), None);

        let _ = std::fs::remove_dir_all(&base);
    }
}
