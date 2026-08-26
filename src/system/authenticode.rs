//! Authenticode verification — Windows' answer to a signed repository.
//!
//! Linux trusts an archive and everything in it inherits that trust. Windows
//! signs individual files, so trust has to be established per binary.
//!
//! Two things this module deliberately does **not** do, both measured:
//!
//! - It does not verify shims. Scoop and Chocolatey generate their own
//!   wrappers in `shims\`/`bin\`, and nobody signs them: 13 of the 16 on the
//!   reference machine came back `NotSigned`. Reporting those would be 13 false
//!   positives about files the package manager wrote itself. What matters is
//!   the binary a shim *points at*.
//! - It does not verify everything. `Get-AuthenticodeSignature` costs about
//!   **120 ms per file**, so a whole install tree would take minutes. The
//!   bounded, meaningful set is what a manager puts on `PATH`.
//!
//! Microsoft-signed binaries are a baseline, reported at `Info` — but never
//! skipped silently when they sit outside `System32` or `Program Files`, since
//! a Microsoft-signed binary in an odd place is exactly what a proxying attack
//! looks like.

use super::*;

/// What Windows says about one file's signature.
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(default)]
pub(crate) struct SigInfo {
    #[serde(rename = "Path")]
    pub path: String,
    /// `Valid`, `NotSigned`, `HashMismatch`, `NotTrusted`, `UnknownError`, …
    #[serde(rename = "Status")]
    pub status: String,
    /// `Authenticode` (embedded) or `Catalog` (system catalog).
    #[serde(rename = "Type")]
    pub kind: String,
    /// Windows' own flag for a binary that ships with the OS.
    #[serde(rename = "IsOSBinary")]
    pub is_os_binary: bool,
    #[serde(rename = "Signer")]
    pub signer: String,
    #[serde(rename = "Issuer")]
    pub issuer: String,
    /// The signing certificate's algorithm, e.g. `sha256RSA`.
    #[serde(rename = "Algorithm")]
    pub algorithm: String,
    /// Whether a countersignature pins when the signing happened.
    #[serde(rename = "Timestamped")]
    pub timestamped: bool,
    /// The certificate has passed its `NotAfter`.
    #[serde(rename = "Expired")]
    pub expired: bool,
    /// A `Zone.Identifier` alternate stream is still attached.
    #[serde(rename = "MarkOfWeb")]
    pub mark_of_web: bool,
}

/// Paths Windows' own binaries legitimately live under. A Microsoft signature
/// on something outside these is still reported.
const SYSTEM_ROOTS: &[&str] = &[
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\winsxs",
    r"c:\program files\",
    r"c:\program files (x86)\",
];

// --- verification -------------------------------------------------------------

/// Verify a batch of files in one PowerShell round-trip.
///
/// Batched on purpose: at ~120 ms per file, one process per path would dominate
/// the scan.
pub(crate) fn verify(paths: &[String]) -> Vec<SigInfo> {
    if paths.is_empty() {
        return Vec::new();
    }
    let list = paths
        .iter()
        .map(|p| format!("'{}'", p.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        r"
$ErrorActionPreference = 'SilentlyContinue'
foreach ($p in @({list})) {{
  if (-not (Test-Path -LiteralPath $p)) {{ continue }}
  $s = Get-AuthenticodeSignature -LiteralPath $p
  $cert = $s.SignerCertificate
  $motw = $null -ne (Get-Item -LiteralPath $p -Stream Zone.Identifier)
  [pscustomobject]@{{
    Path        = $p
    Status      = [string]$s.Status
    Type        = [string]$s.SignatureType
    IsOSBinary  = [bool]$s.IsOSBinary
    Signer      = [string]$cert.Subject
    Issuer      = [string]$cert.Issuer
    Algorithm   = [string]$cert.SignatureAlgorithm.FriendlyName
    Timestamped = ($null -ne $s.TimeStamperCertificate)
    Expired     = ($null -ne $cert -and $cert.NotAfter -lt (Get-Date))
    MarkOfWeb   = $motw
  }} | ConvertTo-Json -Compress
}}
"
    );
    powershell(&script).map(|o| parse(&o)).unwrap_or_default()
}

pub(crate) fn parse(stdout: &str) -> Vec<SigInfo> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<SigInfo>(l).ok())
        .collect()
}

/// Is this the signature of a Microsoft binary?
///
/// `IsOSBinary` is Windows' own verdict and is trusted first; the organisation
/// field is the fallback for Microsoft-signed software that is not part of the
/// OS.
pub(crate) fn is_microsoft(info: &SigInfo) -> bool {
    info.is_os_binary
        || info.signer.split(',').map(str::trim).any(|f| {
            f.strip_prefix("O=")
                .is_some_and(|o| o.eq_ignore_ascii_case("Microsoft Corporation"))
        })
}

/// Does this path sit where Windows' own binaries belong?
pub(crate) fn in_system_location(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    SYSTEM_ROOTS.iter().any(|r| p.starts_with(r))
}

/// The signals a whole package's binaries earn, collapsed.
///
/// Per-file signals are the wrong unit at package level: `7zip.portable` ships
/// seven unsigned binaries, which as seven separate signals both floods the
/// node and pushes its score to the cap — as though it were seven times worse
/// than a package with one. Findings of the same kind are folded into one
/// signal carrying the count, and scored once.
pub(crate) fn signals_for_batch(infos: &[SigInfo]) -> Vec<SysSignal> {
    // Keyed on the text after the filename, which is the finding itself.
    let mut groups: Vec<(String, Severity, u8, Category, Vec<String>)> = Vec::new();
    for info in infos {
        for sig in signals_for(info) {
            let (file, kind) = match sig.label.split_once(": ") {
                Some((f, k)) => (f.to_string(), k.to_string()),
                None => (String::new(), sig.label.clone()),
            };
            match groups.iter_mut().find(|(k, ..)| *k == kind) {
                Some((_, _, _, _, files)) => files.push(file),
                None => groups.push((kind, sig.severity, sig.points, sig.category, vec![file])),
            }
        }
    }
    groups
        .into_iter()
        .map(|(kind, severity, points, category, files)| {
            let label = match files.len() {
                0 => kind.clone(),
                1 => format!("{}: {kind}", files[0]),
                n => format!("{kind} ({n} files, e.g. {})", files[0]),
            };
            SysSignal::new(label, category, severity, points)
        })
        .collect()
}

/// The signals one verified file earns.
pub(crate) fn signals_for(info: &SigInfo) -> Vec<SysSignal> {
    let mut out = Vec::new();
    let file = info
        .path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&info.path)
        .to_string();

    match info.status.to_ascii_lowercase().as_str() {
        // A signature that verifies but whose file no longer hashes to what was
        // signed means the bytes changed after signing. Nothing legitimate does
        // that.
        "hashmismatch" => out.push(SysSignal::new(
            format!("{file}: signed hash does not match the file (tampered after signing)"),
            Category::Tamper,
            Severity::Critical,
            50,
        )),
        "notsigned" => out.push(SysSignal::new(
            format!("{file}: not signed"),
            Category::Unsigned,
            Severity::High,
            40,
        )),
        "nottrusted" => out.push(SysSignal::new(
            format!("{file}: signed by a publisher this machine does not trust"),
            Category::Unsigned,
            Severity::High,
            40,
        )),
        "valid" => {
            if is_microsoft(info) {
                // The baseline, never a silent skip: a Microsoft signature on a
                // binary outside the system locations is worth saying out loud.
                let severity = if in_system_location(&info.path) {
                    Severity::Info
                } else {
                    Severity::Low
                };
                out.push(SysSignal::new(
                    format!("{file}: Microsoft-signed ({})", info.kind.to_lowercase()),
                    Category::Policy,
                    severity,
                    0,
                ));
            }
        }
        // `UnknownError` is what Windows returns for a file type it cannot
        // check at all. Unverified is not the same as unsigned, and not the
        // same as fine.
        other => out.push(SysSignal::new(
            format!("{file}: signature could not be verified ({other})"),
            Category::Unsigned,
            Severity::Medium,
            20,
        )),
    }

    // The remaining checks only mean something on a signature that verified.
    if info.status.eq_ignore_ascii_case("Valid") {
        // An expired certificate only matters when nothing pins *when* the
        // signing happened. A countersignature is exactly that, which is why
        // Windows still reports these as Valid — `MicrosoftEdgeUpdate.exe` on
        // the reference machine is signed by a certificate that expired in May
        // and is perfectly sound.
        if info.expired && !info.timestamped {
            out.push(SysSignal::new(
                format!("{file}: signing certificate has expired, and the signature is not timestamped"),
                Category::Unsigned,
                Severity::High,
                40,
            ));
        }
        if !info.timestamped {
            // Without a countersignature the signature stops being verifiable
            // the moment the certificate expires.
            out.push(SysSignal::new(
                format!("{file}: signature is not timestamped"),
                Category::Unsigned,
                Severity::Medium,
                20,
            ));
        }
        if info.algorithm.to_ascii_lowercase().starts_with("sha1") {
            out.push(SysSignal::new(
                format!("{file}: signed with SHA-1 ({})", info.algorithm),
                Category::Unsigned,
                Severity::Medium,
                20,
            ));
        }
    }

    // Mark-of-the-Web on something a package manager installed means the file
    // arrived from a browser download rather than through the manager.
    if info.mark_of_web {
        out.push(SysSignal::new(
            format!("{file}: still carries Mark-of-the-Web (downloaded from the internet)"),
            Category::ThirdPartySource,
            Severity::Medium,
            20,
        ));
    }
    out
}


#[cfg(test)]
mod tests {
    use super::*;

    fn info(json: &str) -> SigInfo {
        parse(json).pop().expect("one record")
    }

    /// Shapes taken verbatim from the reference machine: a catalog-signed OS
    /// binary, and a third-party binary with an embedded Authenticode
    /// signature and a countersignature.
    const NOTEPAD: &str = r#"{"Path":"C:\\Windows\\System32\\notepad.exe","Status":"Valid","Type":"Catalog","IsOSBinary":true,"Signer":"CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US","Issuer":"CN=Microsoft Windows Production PCA 2011","Algorithm":"sha256RSA","Timestamped":true,"Expired":false,"MarkOfWeb":false}"#;
    const PUTTY: &str = r#"{"Path":"C:\\Users\\alice\\scoop\\apps\\putty\\current\\PUTTY.EXE","Status":"Valid","Type":"Authenticode","IsOSBinary":false,"Signer":"CN=Simon Tatham, O=Simon Tatham, S=Cambridgeshire, C=GB","Issuer":"CN=Sectigo Public Code Signing CA R36","Algorithm":"sha384RSA","Timestamped":true,"Expired":false,"MarkOfWeb":false}"#;

    /// A properly signed third-party binary earns nothing. If a clean machine
    /// is noisy the signal is worthless.
    #[test]
    fn a_correctly_signed_third_party_binary_is_silent() {
        assert!(signals_for(&info(PUTTY)).is_empty());
    }

    /// Microsoft is the baseline, reported but not scored.
    #[test]
    fn a_microsoft_binary_in_system32_is_baseline_only() {
        let sigs = signals_for(&info(NOTEPAD));
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].severity, Severity::Info);
        assert_eq!(sigs[0].points, 0);
    }

    /// ...but never a silent skip: the same signature somewhere unexpected is
    /// exactly what a proxying attack looks like.
    #[test]
    fn a_microsoft_binary_outside_the_system_locations_is_still_reported() {
        let mut i = info(NOTEPAD);
        i.path = r"C:\Users\alice\AppData\Local\Temp\notepad.exe".into();
        let sigs = signals_for(&i);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].severity, Severity::Low, "louder than the baseline");
    }

    #[test]
    fn system_locations_are_recognised_case_insensitively() {
        assert!(in_system_location(r"C:\Windows\System32\notepad.exe"));
        assert!(in_system_location(r"c:\program files\thing\a.exe"));
        assert!(!in_system_location(r"C:\Users\alice\a.exe"));
        assert!(!in_system_location(r"C:\ProgramData\chocolatey\bin\a.exe"));
    }

    /// The one that outranks everything else: the signature verifies, but the
    /// bytes are not the bytes that were signed.
    #[test]
    fn a_hash_mismatch_is_critical_tampering() {
        let mut i = info(PUTTY);
        i.status = "HashMismatch".into();
        let s = &signals_for(&i)[0];
        assert_eq!(s.severity, Severity::Critical);
        assert_eq!(s.category, Category::Tamper);
    }

    #[test]
    fn unsigned_and_untrusted_are_both_high() {
        for status in ["NotSigned", "NotTrusted"] {
            let mut i = info(PUTTY);
            i.status = status.into();
            let s = &signals_for(&i)[0];
            assert_eq!(s.severity, Severity::High, "{status}");
            assert_eq!(s.category, Category::Unsigned);
        }
    }

    /// Unverifiable is not the same as unsigned, and not the same as fine.
    #[test]
    fn an_unverifiable_file_is_reported_as_such() {
        let mut i = info(PUTTY);
        i.status = "UnknownError".into();
        let s = &signals_for(&i)[0];
        assert_eq!(s.severity, Severity::Medium);
        assert!(s.label.contains("could not be verified"), "{}", s.label);
    }

    /// These only mean something on a signature that verified — an unsigned
    /// file must not also be scolded for lacking a timestamp.
    #[test]
    fn the_quality_checks_only_apply_to_a_valid_signature() {
        let mut unsigned = info(PUTTY);
        unsigned.status = "NotSigned".into();
        unsigned.timestamped = false;
        unsigned.expired = true;
        assert_eq!(signals_for(&unsigned).len(), 1, "one finding, not three");
    }

    /// Timestamping exists precisely so a signature outlives its certificate.
    /// `MicrosoftEdgeUpdate.exe` on the reference machine is signed by a
    /// certificate that expired in May, is countersigned, and Windows reports
    /// it `Valid` — flagging it would be flagging correct practice.
    #[test]
    fn an_expired_certificate_only_matters_without_a_timestamp() {
        let mut expired_but_timestamped = info(PUTTY);
        expired_but_timestamped.expired = true;
        expired_but_timestamped.timestamped = true;
        assert!(
            !signals_for(&expired_but_timestamped).iter().any(|s| s.label.contains("expired")),
            "a countersignature pins when the signing happened"
        );

        let mut expired_and_bare = info(PUTTY);
        expired_and_bare.expired = true;
        expired_and_bare.timestamped = false;
        let sigs = signals_for(&expired_and_bare);
        assert!(sigs.iter().any(|s| s.label.contains("expired")));
    }

    #[test]
    fn missing_timestamp_and_sha1_are_each_flagged() {

        let mut untimed = info(PUTTY);
        untimed.timestamped = false;
        assert!(signals_for(&untimed).iter().any(|s| s.label.contains("not timestamped")));

        let mut sha1 = info(PUTTY);
        sha1.algorithm = "sha1RSA".into();
        assert!(signals_for(&sha1).iter().any(|s| s.label.contains("SHA-1")));
    }

    /// A file a package manager installed should not still be carrying the
    /// browser's download marker.
    #[test]
    fn mark_of_the_web_survives_onto_an_installed_file() {
        let mut i = info(PUTTY);
        i.mark_of_web = true;
        let s = signals_for(&i)
            .into_iter()
            .find(|s| s.label.contains("Mark-of-the-Web"))
            .expect("should flag");
        assert_eq!(s.category, Category::ThirdPartySource);
    }

    /// Seven unsigned binaries in one package is one finding about that
    /// package, not seven — and it is scored once, not seven times into the cap.
    #[test]
    fn repeated_findings_across_a_packages_binaries_are_folded() {
        let infos: Vec<SigInfo> = ["7za.exe", "7-zip.dll", "7zxa.dll"]
            .iter()
            .map(|f| {
                let mut i = info(PUTTY);
                i.path = format!(r"C:\ProgramData\chocolatey\lib\7zip\tools\{f}");
                i.status = "NotSigned".into();
                i
            })
            .collect();

        let per_file: usize = infos.iter().map(|i| signals_for(i).len()).sum();
        assert_eq!(per_file, 3, "three findings before folding");

        let folded = signals_for_batch(&infos);
        assert_eq!(folded.len(), 1, "one after");
        assert!(folded[0].label.contains("3 files"), "{}", folded[0].label);
        assert_eq!(folded[0].points, 40, "scored once, not three times");
    }

    /// Different kinds of finding stay separate.
    #[test]
    fn unlike_findings_are_not_folded_together() {
        let mut unsigned = info(PUTTY);
        unsigned.status = "NotSigned".into();
        let mut sha1 = info(PUTTY);
        sha1.path = r"C:\x\b.exe".into();
        sha1.algorithm = "sha1RSA".into();
        assert_eq!(signals_for_batch(&[unsigned, sha1]).len(), 2);
    }

    /// `IsOSBinary` is Windows' own verdict; the organisation field covers
    /// Microsoft software that is not part of the OS.
    #[test]
    fn microsoft_is_recognised_by_either_signal() {
        assert!(is_microsoft(&info(NOTEPAD)));
        let mut not_os = info(NOTEPAD);
        not_os.is_os_binary = false;
        assert!(is_microsoft(&not_os), "the O= field should still match");
        assert!(!is_microsoft(&info(PUTTY)));
    }
}
