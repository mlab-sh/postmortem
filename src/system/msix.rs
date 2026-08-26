//! MSIX / AppX backend — Store and sideloaded Windows app packages.
//!
//! Everything comes from **one** PowerShell invocation: `Get-AppxPackage` for
//! identity and signing, plus each package's manifest for capabilities and
//! startup extensions. Spawning a process per package would mean 106 of them on
//! a stock machine, so the script does the join and emits JSON-lines.
//!
//! Two calibrations here come from measuring a real machine rather than from
//! reading the docs, and both prevent a scanner that cries wolf:
//!
//! - `SignatureKind` is **not** a provenance verdict on its own. Microsoft ships
//!   `Developer`-signed packages — Edge, DevHome and QuickAssist were all
//!   `Developer` on the reference box. The publisher CN is what separates a
//!   sideloaded package from a first-party one.
//! - `runFullTrust` is carried by 31 of 106 packages. It is how desktop-bridge
//!   apps work, so it is context, not a finding. `allowElevation` (3) and
//!   `broadFileSystemAccess` (5) are rare enough to mean something.

use super::*;

/// One installed package, as emitted by [`PS_INVENTORY`].
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub(crate) struct AppxPkg {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Publisher")]
    pub publisher: String,
    /// `Store`, `System`, `Developer`, `Enterprise` or `None`.
    #[serde(rename = "SignatureKind")]
    pub signature: String,
    /// `Ok` on a healthy package; anything else means Windows itself considers
    /// the install damaged or modified.
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "Capabilities")]
    pub capabilities: Vec<String>,
    #[serde(rename = "StartupTask")]
    pub startup_task: bool,
    #[serde(rename = "BackgroundTasks")]
    pub background_tasks: bool,
}

/// Emits one compact JSON object per installed package. Written to avoid double
/// quotes entirely so it survives the trip through `-EncodedCommand`.
const PS_INVENTORY: &str = r"
$ErrorActionPreference = 'SilentlyContinue'
foreach ($p in Get-AppxPackage) {
  $caps = @()
  $st = $false
  $bt = $false
  $m = Get-AppxPackageManifest $p
  if ($m) {
    # XML comment nodes come through as '#comment'; drop anything not a real element.
    foreach ($n in $m.Package.Capabilities.ChildNodes) { if ($n.Name -and -not $n.Name.StartsWith('#')) { $caps += $n.Name } }
    $xml = $m.InnerXml
    if ($xml -match 'windows\.startupTask') { $st = $true }
    if ($xml -match 'windows\.backgroundTasks') { $bt = $true }
  }
  [pscustomobject]@{
    Name            = $p.Name
    Version         = [string]$p.Version
    Publisher       = $p.Publisher
    SignatureKind   = [string]$p.SignatureKind
    Status          = [string]$p.Status
    Capabilities    = @($caps)
    StartupTask     = $st
    BackgroundTasks = $bt
  } | ConvertTo-Json -Compress -Depth 3
}
";

/// Reads whether sideloading was explicitly turned on.
const PS_SIDELOAD: &str = r"
$k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock'
$p = Get-ItemProperty $k -ErrorAction SilentlyContinue
[pscustomobject]@{
  AllowAllTrustedApps = [int]$p.AllowAllTrustedApps
  AllowDevelopment    = [int]$p.AllowDevelopmentWithoutDevLicense
} | ConvertTo-Json -Compress
";

/// Capabilities worth a finding, with why. Deliberately excludes
/// `runFullTrust`: measured on 31 of 106 packages, it is the desktop-bridge
/// norm and flagging it would bury the rare ones below.
const NOTABLE_CAPS: &[(&str, Category, Severity, u8, &str)] = &[
    (
        "allowelevation",
        Category::WeakAcl,
        Severity::Medium,
        20,
        "can request elevation",
    ),
    (
        "broadfilesystemaccess",
        Category::WeakAcl,
        Severity::Medium,
        20,
        "reads and writes the whole user file system",
    ),
    (
        "packagemanagement",
        Category::Persistence,
        Severity::Low,
        10,
        "can install and remove other packages",
    ),
    (
        "internetclientserver",
        Category::Persistence,
        Severity::Low,
        10,
        "accepts inbound network connections",
    ),
];

// --- parsing ------------------------------------------------------------------

/// Parse the JSON-lines of [`PS_INVENTORY`]. A line we cannot read is skipped
/// rather than failing the inventory — one odd package must not hide the rest.
pub(crate) fn parse_packages(stdout: &str) -> Vec<AppxPkg> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<AppxPkg>(l).ok())
        .collect()
}

/// Is the signing publisher Microsoft itself?
///
/// Matched on the `O=` (organisation) field rather than on `CN=`: the common
/// name varies across Microsoft's signing certificates, the organisation does
/// not. Anchored on the field boundary so `O=NotMicrosoft Corporation` cannot
/// pass.
pub(crate) fn publisher_is_microsoft(publisher: &str) -> bool {
    publisher.split(',').map(str::trim).any(|field| {
        field
            .strip_prefix("O=")
            .is_some_and(|org| org.eq_ignore_ascii_case("Microsoft Corporation"))
    })
}

/// The provenance verdict for a package's signature.
///
/// `Store` and `System` are the curated paths. `Developer` and `Enterprise`
/// mean the package was sideloaded — *unless* Microsoft signed it, which they
/// do for Edge, DevHome and QuickAssist among others. `None` is unsigned and
/// has no excuse.
pub(crate) fn signature_signal(pkg: &AppxPkg) -> Option<SysSignal> {
    let kind = pkg.signature.to_ascii_lowercase();
    match kind.as_str() {
        "store" | "system" => None,
        "none" | "" => Some(SysSignal::new(
            "unsigned-msix (no signature at all)",
            Category::Unsigned,
            Severity::Critical,
            50,
        )),
        _ if publisher_is_microsoft(&pkg.publisher) => None,
        _ => Some(SysSignal::new(
            format!("sideloaded ({} signature, publisher outside Microsoft)", pkg.signature),
            Category::ThirdPartySource,
            Severity::High,
            40,
        )),
    }
}

/// Windows' own health verdict on the installed files.
pub(crate) fn status_signal(pkg: &AppxPkg) -> Option<SysSignal> {
    if pkg.status.eq_ignore_ascii_case("Ok") || pkg.status.is_empty() {
        return None;
    }
    Some(SysSignal::new(
        format!("package not healthy (Windows reports {})", pkg.status),
        Category::Tamper,
        Severity::High,
        40,
    ))
}

/// Capability and persistence signals for one package.
///
/// On a first-party package these are **context, not findings**. Measured on
/// the reference machine: 17 of the 18 packages carrying a notable capability
/// were published by Microsoft, and they carry it because it is their job —
/// the Store declares `packageManagement`, the servicing stack declares
/// `broadFileSystemAccess`. Scoring those buries the one that mattered. They
/// stay visible at `Info`/0 rather than being dropped, because a first-party
/// component can still be abused; what changes is that they no longer move the
/// score.
pub(crate) fn surface_signals(pkg: &AppxPkg) -> Vec<SysSignal> {
    let first_party = publisher_is_microsoft(&pkg.publisher);
    let mut out = Vec::new();
    // Case-insensitive on purpose: manifests in the wild carry both
    // `broadFileSystemAccess` and `broadFilesystemAccess`, sometimes in the
    // same package.
    let caps: Vec<String> = pkg
        .capabilities
        .iter()
        .map(|c| c.to_ascii_lowercase())
        .collect();
    for (needle, category, severity, points, why) in NOTABLE_CAPS {
        if caps.iter().any(|c| c == needle) {
            let (severity, points) = if first_party {
                (Severity::Info, 0)
            } else {
                (*severity, *points)
            };
            out.push(SysSignal::new(
                format!("capability {needle} ({why})"),
                *category,
                severity,
                points,
            ));
        }
    }
    if pkg.startup_task {
        let (severity, points) = if first_party {
            (Severity::Info, 0)
        } else {
            (Severity::Low, 10)
        };
        out.push(SysSignal::new(
            "installs-startup-task (runs at logon)",
            Category::Persistence,
            severity,
            points,
        ));
    }
    if pkg.background_tasks {
        out.push(SysSignal::new(
            "registers-background-task",
            Category::Persistence,
            Severity::Info,
            0,
        ));
    }
    out
}

// --- inventory ----------------------------------------------------------------

/// Build the MSIX/AppX inventory.
pub fn msix_inventory(opts: Opts) -> Result<Inventory> {
    let _ = opts;
    let stdout = powershell(PS_INVENTORY).context("listing AppX packages")?;
    let pkgs = parse_packages(&stdout);
    if pkgs.is_empty() {
        anyhow::bail!(
            "`Get-AppxPackage` returned nothing postmortem could read — refusing to report \
             an empty inventory as a clean one"
        );
    }

    let mut signals: HashMap<String, Vec<SysSignal>> = HashMap::new();
    let mut deps = Vec::with_capacity(pkgs.len());
    for p in &pkgs {
        for sig in signature_signal(p)
            .into_iter()
            .chain(status_signal(p))
            .chain(surface_signals(p))
        {
            push_signal(&mut signals, &p.name, sig);
        }
        deps.push(Dependency {
            name: p.name.clone(),
            version: p.version.clone(),
            ecosystem: Ecosystem::Msix,
            direct: true,
            scope: Scope::Prod,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url: None,
            integrity: None,
            parents: Vec::new(),
        });
    }

    // Sideloading is a machine-wide posture, not a property of any one package.
    let mut notes = Vec::new();
    if let Ok(raw) = powershell(PS_SIDELOAD)
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(raw.trim())
    {
        if v.get("AllowAllTrustedApps").and_then(|x| x.as_i64()) == Some(1) {
            notes.push(
                "sideloading is enabled (AllowAllTrustedApps) — packages can be installed \
                 outside the Store"
                    .to_string(),
            );
        }
        if v.get("AllowDevelopment").and_then(|x| x.as_i64()) == Some(1) {
            notes.push(
                "developer mode is enabled (AllowDevelopmentWithoutDevLicense) — unsigned \
                 packages can be deployed"
                    .to_string(),
            );
        }
    }

    let store = pkgs
        .iter()
        .filter(|p| p.signature.eq_ignore_ascii_case("Store"))
        .count();
    let system = pkgs
        .iter()
        .filter(|p| p.signature.eq_ignore_ascii_case("System"))
        .count();
    let summary = format!(
        "{} package(s): {store} Store, {system} System, {} other",
        pkgs.len(),
        pkgs.len() - store - system
    );
    Ok(Inventory {
        manager: "msix",
        deps,
        repos: Vec::new(),
        signals,
        claims: Vec::new(),
        summary,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim output of [`PS_INVENTORY`] on a real Windows 11 machine, kept
    /// exactly as emitted — `#comment` capability entries included, because the
    /// parser has to survive them.
    const PKGS: &str = r##"{"Name":"SpotifyAB.SpotifyMusic","Version":"1.297.270.0","Publisher":"CN=453637B3-4E12-4CDF-B0D3-2A3C863BF6EF","SignatureKind":"Store","Status":"Ok","Capabilities":["internetClient","runFullTrust","packageQuery","#comment","#comment"],"StartupTask":true,"BackgroundTasks":true}
{"Name":"MicrosoftWindows.Client.CBS","Version":"1000.26100.344.0","Publisher":"CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US","SignatureKind":"System","Status":"Ok","Capabilities":["shellExperience","packageContents","internetClient","dependencyTarget","unvirtualizedResources","runFullTrust","packageQuery","userSigninSupport","userAccountInformation","privateNetworkClientServer","smbios","activitySystem","inputInjection","registryRead","enterpriseCloudSSO","cloudStore","imeSystem","inputForegroundObservation","systemRegistrar","windowManagement","broadFileSystemAccess","storeAppInstall","cloudExperienceHost","contacts","remoteSystem","broadFilesystemAccess","slapiQueryLicenseValue","userDataSystem","activityData","cortanaSettings","indexedContent","polarisService","searchSettings","visualElementsSystem","userManagementSystem","bluetoothDeviceSettings","personalizationDeviceSettings","networkDeviceSettings","deviceManagementRegistration","updateAndSecurityDeviceSettings","regionSettings","languageAndRegionDeviceSettings","languageSettings","dateAndTimeDeviceSettings","capabilityAccessConsentDeviceSettings","confirmAppClose","liveIdService","lockScreenCreatives","packageManagement","userOnboardingState","firstSignInSettings","targetedContent","internetClientServer","Microsoft.coreAppActivation_8wekyb3d8bbwe","microphone","bluetooth","radios"],"StartupTask":false,"BackgroundTasks":true}
{"Name":"Microsoft.MicrosoftEdge.Stable","Version":"151.0.4129.107","Publisher":"CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US","SignatureKind":"Developer","Status":"Ok","Capabilities":["runFullTrust","packageManagement","unvirtualizedResources"],"StartupTask":false,"BackgroundTasks":false}"##;

    fn pkg(name: &str) -> AppxPkg {
        parse_packages(PKGS)
            .into_iter()
            .find(|p| p.name == name)
            .expect("fixture package")
    }

    /// Hand-rolled encoder, so it is checked against vectors computed
    /// independently rather than against itself.
    #[test]
    fn the_powershell_encoder_matches_known_base64() {
        assert_eq!(base64_utf16le(""), "");
        assert_eq!(base64_utf16le("a"), "YQA=");
        assert_eq!(base64_utf16le("ab"), "YQBiAA==");
        assert_eq!(base64_utf16le("abc"), "YQBiAGMA");
        assert_eq!(
            base64_utf16le("Get-AppxPackage"),
            "RwBlAHQALQBBAHAAcAB4AFAAYQBjAGsAYQBnAGUA"
        );
        // Non-ASCII, including a character outside the Latin-1 range.
        assert_eq!(base64_utf16le("é€"), "6QCsIA==");
    }

    /// The regression this backend is calibrated around: Microsoft ships
    /// `Developer`-signed packages. Edge is one. Treating `SignatureKind` alone
    /// as provenance flags three first-party packages on a stock machine.
    #[test]
    fn a_developer_signature_from_microsoft_is_not_sideloaded() {
        let edge = pkg("Microsoft.MicrosoftEdge.Stable");
        assert_eq!(edge.signature, "Developer");
        assert!(signature_signal(&edge).is_none());
    }

    /// The same signature kind from anyone else is the finding.
    #[test]
    fn a_developer_signature_from_a_third_party_is_flagged() {
        let mut impostor = pkg("Microsoft.MicrosoftEdge.Stable");
        impostor.publisher = "CN=Someone, O=Someone Ltd, C=FR".into();
        let sig = signature_signal(&impostor).expect("should flag");
        assert_eq!(sig.severity, Severity::High);
        assert_eq!(sig.category, Category::ThirdPartySource);
    }

    /// The publisher is matched on `O=`, not `CN=`: a genuine Microsoft system
    /// package signs with `CN=Microsoft Windows`, and a `CN=`-based check would
    /// call it third-party.
    #[test]
    fn the_publisher_is_read_from_the_organisation_field() {
        assert!(publisher_is_microsoft(&pkg("MicrosoftWindows.Client.CBS").publisher));
        assert!(publisher_is_microsoft(
            "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
        ));
        // A Store publisher identified only by a GUID has no organisation.
        assert!(!publisher_is_microsoft(&pkg("SpotifyAB.SpotifyMusic").publisher));
        // Must not be fooled by a lookalike organisation.
        assert!(!publisher_is_microsoft("CN=x, O=NotMicrosoft Corporation"));
        assert!(!publisher_is_microsoft("CN=x, O=Microsoft Corporation Ltd"));
    }

    #[test]
    fn an_unsigned_package_is_critical() {
        let mut p = pkg("SpotifyAB.SpotifyMusic");
        p.signature = "None".into();
        let sig = signature_signal(&p).expect("should flag");
        assert_eq!(sig.severity, Severity::Critical);
        assert_eq!(sig.category, Category::Unsigned);
    }

    /// Capability names differ in case between manifests — this very package
    /// declares `broadFileSystemAccess` AND `broadFilesystemAccess`.
    #[test]
    fn capabilities_are_matched_regardless_of_case() {
        let cbs = pkg("MicrosoftWindows.Client.CBS");
        assert!(cbs.capabilities.iter().any(|c| c == "broadFileSystemAccess"));
        assert!(cbs.capabilities.iter().any(|c| c == "broadFilesystemAccess"));
        let labels: Vec<String> = surface_signals(&cbs).iter().map(|s| s.label.clone()).collect();
        assert_eq!(
            labels.iter().filter(|l| l.contains("broadfilesystemaccess")).count(),
            1,
            "the two spellings are one capability, reported once"
        );
    }

    /// `runFullTrust` sits on 31 of 106 packages on a stock machine: it is how
    /// desktop-bridge apps work, so reporting it would bury the rare ones.
    #[test]
    fn run_full_trust_is_too_common_to_report() {
        let edge = pkg("Microsoft.MicrosoftEdge.Stable");
        assert!(edge.capabilities.iter().any(|c| c == "runFullTrust"));
        let labels: Vec<String> = surface_signals(&edge).iter().map(|s| s.label.clone()).collect();
        assert!(!labels.iter().any(|l| l.contains("runfulltrust")), "got {labels:?}");
    }

    /// 17 of the 18 packages carrying a notable capability on the reference
    /// machine were Microsoft's own, declaring what their job requires. They
    /// stay visible but stop moving the score.
    #[test]
    fn a_first_party_capability_is_context_not_a_finding() {
        let cbs = pkg("MicrosoftWindows.Client.CBS");
        assert!(publisher_is_microsoft(&cbs.publisher));
        let sigs = surface_signals(&cbs);
        assert!(!sigs.is_empty(), "still reported");
        assert!(
            sigs.iter().all(|s| s.severity == Severity::Info && s.points == 0),
            "a first-party capability must not move the score"
        );
    }

    /// The same capability on anyone else's package is the finding.
    #[test]
    fn the_same_capability_scores_on_a_third_party_package() {
        let mut third = pkg("MicrosoftWindows.Client.CBS");
        third.publisher = "CN=Acme, O=Acme Ltd, C=FR".into();
        let sigs = surface_signals(&third);
        let elevated = sigs
            .iter()
            .find(|s| s.label.contains("broadfilesystemaccess"))
            .expect("should flag");
        assert_eq!(elevated.severity, Severity::Medium);
        assert!(elevated.points > 0);
    }

    #[test]
    fn a_startup_task_is_persistence() {
        let spotify = pkg("SpotifyAB.SpotifyMusic");
        assert!(spotify.startup_task);
        assert!(!publisher_is_microsoft(&spotify.publisher));
        let sig = surface_signals(&spotify)
            .into_iter()
            .find(|s| s.label.starts_with("installs-startup-task"))
            .expect("should flag");
        assert_eq!(sig.category, Category::Persistence);
        assert!(sig.points > 0, "a third-party startup task still scores");
    }

    /// A healthy package says so; anything else is Windows telling us the files
    /// on disk are not what it installed.
    #[test]
    fn only_an_unhealthy_package_raises_tamper() {
        let mut p = pkg("SpotifyAB.SpotifyMusic");
        assert!(status_signal(&p).is_none());
        p.status = "Modified".into();
        assert_eq!(status_signal(&p).unwrap().category, Category::Tamper);
    }

    /// Comment nodes leak into the capability list; they must not become
    /// findings or crash the parse.
    #[test]
    fn xml_comment_nodes_are_harmless() {
        let spotify = pkg("SpotifyAB.SpotifyMusic");
        assert!(spotify.capabilities.iter().any(|c| c == "#comment"));
        assert!(!surface_signals(&spotify).iter().any(|s| s.label.contains("#comment")));
    }
}
