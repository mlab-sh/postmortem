//! Nix backend — the store closure reachable from the installed profiles, with
//! signature provenance (which substituter/key signed each store path).

use super::*;

// --- nix backend (store closure + profiles) ----------------------------------

const NIX_DEFAULT_CACHE: &str = "cache.nixos.org-1";

#[derive(Deserialize, Default)]
struct NixPathInfo {
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    signatures: Vec<String>,
    #[serde(default)]
    ca: Option<String>,
    #[serde(default)]
    ultimate: bool,
}

/// Read the installed Nix closure into an [`Inventory`]. Unlike dpkg/rpm there is
/// no flat "installed set": the roots are the packages referenced by the profile
/// generations, and the forest is the store **closure** (`--references` edges).
/// The trust question is provenance: was a store path signed by a trusted binary
/// cache, built locally, or served unverified by some substituter.
pub fn nix_inventory(opts: Opts) -> Result<Inventory> {
    let _ = opts; // no per-package registry; nix reputation isn't in the store
    let roots = nix_profile_roots();
    if roots.is_empty() {
        anyhow::bail!("no nix profiles found under /nix/var/nix/profiles");
    }
    let closure = nix_closure(&roots);
    if closure.is_empty() {
        anyhow::bail!("`nix-store -qR` returned no paths");
    }
    let info = nix_path_info(&closure);
    let trusted = nix_trusted_keys();
    let root_set: std::collections::HashSet<&str> = roots.iter().map(String::as_str).collect();
    let in_closure: std::collections::HashSet<&str> = closure.iter().map(String::as_str).collect();

    // Each store path → its (name, version) key (output suffix folded into version
    // so distinct outputs stay distinct nodes).
    let key_of: HashMap<&str, (String, String)> = closure
        .iter()
        .map(|p| (p.as_str(), parse_store_name(store_basename(p))))
        .collect();

    // Reference edges → parent adjacency (only within the closure).
    let mut parents: HashMap<String, Vec<DepRef>> = HashMap::new();
    for path in &closure {
        let Some(pi) = info.get(path) else { continue };
        let parent = &key_of[path.as_str()];
        for r in &pi.references {
            if r == path || !in_closure.contains(r.as_str()) {
                continue; // drop self-references and out-of-closure edges
            }
            if let Some(child) = key_of.get(r.as_str()) {
                parents
                    .entry(child.0.clone())
                    .or_default()
                    .push(parent.clone());
            }
        }
    }

    // A store path is "unverified" when nothing vouches for it: no signature from a
    // trusted cache, not content-addressed, not built here. A store shipped without
    // signatures (a container image) reports everything unverified, so guard it.
    let unverified = |pi: Option<&NixPathInfo>| -> bool {
        match pi {
            Some(i) => {
                !i.ultimate
                    && i.ca.is_none()
                    && !i
                        .signatures
                        .iter()
                        .any(|s| s.split(':').next().is_some_and(|k| trusted.contains(k)))
            }
            None => false,
        }
    };
    let unverified_count = closure.iter().filter(|p| unverified(info.get(*p))).count();
    let mostly_unverified = unverified_count * 10 >= closure.len() * 9;

    let mut signals: HashMap<String, Vec<SysSignal>> = HashMap::new();
    let mut deps = Vec::with_capacity(closure.len());
    for path in &closure {
        let (name, version) = key_of[path.as_str()].clone();
        let pi = info.get(path);
        if !mostly_unverified && unverified(pi) {
            push_signal(
                &mut signals,
                &name,
                SysSignal::new("unverified (no trusted signature)", Category::Unsigned, Severity::Medium, 30),
            );
        }
        if pi.is_some_and(|i| i.ultimate) {
            push_signal(
                &mut signals,
                &name,
                SysSignal::new("built-locally", Category::Unsigned, Severity::Info, 0),
            );
        }
        deps.push(Dependency {
            direct: root_set.contains(path.as_str()),
            scope: Scope::Prod,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url: None,
            parents: parents.remove(&name).unwrap_or_default(),
            name,
            version,
            ecosystem: Ecosystem::Nix,
            integrity: None,
        });
    }

    let direct = deps.iter().filter(|d| d.direct).count();
    let summary = format!("{} store path(s) ({direct} in profiles)", deps.len());
    let notes = nix_notes();
    Ok(Inventory {
        manager: "nix",
        deps,
        repos: nix_substituters(),
        signals,
        summary,
        notes,
    })
}

/// The store paths installed into the profile generations: for every current
/// profile (top-level pointers + `per-user/*/profile`), the paths it references.
fn nix_profile_roots() -> Vec<String> {
    let base = std::path::Path::new("/nix/var/nix/profiles");
    let mut profiles: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(dir) = std::fs::read_dir(base) {
        for e in dir.flatten() {
            let p = e.path();
            // Skip the `<name>-<n>-link` generation snapshots; keep current pointers.
            let is_gen = p
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|n| n.ends_with("-link"));
            if !is_gen && p.is_symlink() {
                profiles.push(p);
            }
        }
    }
    if let Ok(dir) = std::fs::read_dir(base.join("per-user")) {
        for user in dir.flatten() {
            let prof = user.path().join("profile");
            if prof.exists() {
                profiles.push(prof);
            }
        }
    }
    let mut roots = std::collections::HashSet::new();
    for prof in profiles {
        let Ok(store) = std::fs::canonicalize(&prof) else {
            continue;
        };
        for r in nix_references(&store.to_string_lossy()) {
            roots.insert(r);
        }
    }
    roots.into_iter().collect()
}

/// `nix-store -q --references <path>` — a path's direct store references.
fn nix_references(path: &str) -> Vec<String> {
    Command::new("nix-store")
        .args(["-q", "--references", path])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// `nix-store -qR <roots…>` — the full closure (requisites) of the roots.
fn nix_closure(roots: &[String]) -> Vec<String> {
    let Ok(out) = Command::new("nix-store").arg("-qR").args(roots).output() else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

/// `nix path-info --json` over the closure → `path → info` (references, signatures,
/// ca, ultimate). Chunked; needs the `nix-command` experimental feature enabled
/// for the invocation.
fn nix_path_info(paths: &[String]) -> HashMap<String, NixPathInfo> {
    let mut out = HashMap::new();
    for chunk in paths.chunks(256) {
        let res = Command::new("nix")
            .args([
                "--extra-experimental-features",
                "nix-command",
                "path-info",
                "--json",
                "--sigs",
            ])
            .args(chunk)
            .output();
        let Ok(res) = res else { continue };
        if !res.status.success() {
            continue;
        }
        if let Ok(map) = serde_json::from_slice::<HashMap<String, NixPathInfo>>(&res.stdout) {
            out.extend(map);
        }
    }
    out
}

/// Trusted binary-cache key names from `nix.conf` (`trusted-public-keys`), always
/// including the default `cache.nixos.org-1`.
fn nix_trusted_keys() -> std::collections::HashSet<String> {
    let mut keys = std::collections::HashSet::new();
    keys.insert(NIX_DEFAULT_CACHE.to_string());
    for line in nix_conf_lines() {
        if let Some(v) = nix_conf_value(&line, "trusted-public-keys") {
            for entry in v.split_whitespace() {
                if let Some(name) = entry.split(':').next() {
                    keys.insert(name.to_string());
                }
            }
        }
    }
    keys
}

/// Machine-wide trust caveats from `nix.conf`: signature checking disabled, or
/// binary caches beyond the official one.
fn nix_notes() -> Vec<String> {
    let mut warnings = Vec::new();
    let mut extra_caches = 0usize;
    for line in nix_conf_lines() {
        if let Some(v) = nix_conf_value(&line, "require-sigs")
            && (v.trim() == "false")
        {
            warnings.push("nix signature verification disabled (require-sigs = false)".to_string());
        }
        if let Some(v) = nix_conf_value(&line, "substituters")
            .or_else(|| nix_conf_value(&line, "extra-substituters"))
        {
            extra_caches += v
                .split_whitespace()
                .filter(|s| !s.contains("cache.nixos.org"))
                .count();
        }
    }
    if extra_caches > 0 {
        warnings.push(format!(
            "{extra_caches} extra binary cache(s) configured beyond cache.nixos.org"
        ));
    }
    warnings
}

/// Configured substituters (binary caches) as source repos. `cache.nixos.org` is
/// official; anything else is third-party.
fn nix_substituters() -> Vec<Repo> {
    let mut seen = std::collections::HashSet::new();
    let mut repos = Vec::new();
    for line in nix_conf_lines() {
        for key in ["substituters", "extra-substituters", "trusted-substituters"] {
            if let Some(v) = nix_conf_value(&line, key) {
                for url in v.split_whitespace() {
                    if seen.insert(url.to_string()) {
                        let official = url.contains("cache.nixos.org");
                        repos.push(Repo {
                            name: url.to_string(),
                            url: String::new(),
                            official,
                        });
                    }
                }
            }
        }
    }
    if repos.is_empty() {
        repos.push(Repo {
            name: "https://cache.nixos.org".into(),
            url: String::new(),
            official: true,
        });
    }
    repos
}

/// The `nix.conf` lines from the system and user configs (best-effort).
fn nix_conf_lines() -> Vec<String> {
    [
        "/etc/nix/nix.conf",
        &format!(
            "{}/.config/nix/nix.conf",
            std::env::var("HOME").unwrap_or_default()
        ),
    ]
    .iter()
    .filter_map(|p| std::fs::read_to_string(p).ok())
    .flat_map(|t| t.lines().map(str::to_string).collect::<Vec<_>>())
    .collect()
}

/// A `key = value` line from `nix.conf` → its value, if the key matches.
fn nix_conf_value(line: &str, key: &str) -> Option<String> {
    let (k, v) = line.split_once('=')?;
    (k.trim() == key).then(|| v.trim().to_string())
}

/// The basename of a store path (`/nix/store/<hash>-<name>-<ver>` → the last bit).
fn store_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Parse a store basename into `(name, version)`: strip the 32-char hash prefix,
/// then split at the first `-` component that starts with a digit (the version).
/// Any output suffix (`-bin`/`-lib`/…) is folded into the version so the key stays
/// unique per store path.
fn parse_store_name(base: &str) -> (String, String) {
    // The hash is 32 chars followed by '-'.
    let rest = if base.len() > 33 && base.as_bytes()[32] == b'-' {
        &base[33..]
    } else {
        base
    };
    let parts: Vec<&str> = rest.split('-').collect();
    match parts
        .iter()
        .position(|p| p.starts_with(|c: char| c.is_ascii_digit()))
    {
        Some(i) if i > 0 => (parts[..i].join("-"), parts[i..].join("-")),
        _ => (rest.to_string(), String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nix_store_name_parses() {
        let h = "8gdgwydsf6gia9j178nymxwm2bl0z3m3"; // 32-char hash
        // version starts at the first digit-leading component; output folds in.
        assert_eq!(
            parse_store_name(&format!("{h}-curl-8.20.0-bin")),
            ("curl".into(), "8.20.0-bin".into())
        );
        assert_eq!(
            parse_store_name(&format!("{h}-nss-cacert-3.123")),
            ("nss-cacert".into(), "3.123".into())
        );
        assert_eq!(
            parse_store_name(&format!("{h}-gcc-15.2.0-lib")),
            ("gcc".into(), "15.2.0-lib".into())
        );
        assert_eq!(
            parse_store_name(&format!("{h}-aws-c-mqtt-0.13.3")),
            ("aws-c-mqtt".into(), "0.13.3".into())
        );
        // No version component → all name.
        assert_eq!(
            parse_store_name(&format!("{h}-hello")),
            ("hello".into(), String::new())
        );
    }
}
