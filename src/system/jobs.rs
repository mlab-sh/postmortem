//! Jobs and file-based persistence — the corners that are normally empty.
//!
//! Unlike services and scheduled tasks, where the problem is volume, every
//! location here is empty or default on a healthy machine. That makes them high
//! signal: on the reference box BITS held no jobs, `WER\LocalDumps` did not
//! exist, `RunOnce\Setup` did not exist, and none of the 36 `Image File
//! Execution Options` subkeys carried a debugger. What is left is worth
//! reading.
//!
//! **Answer files are handled carefully.** `unattend.xml` routinely carries a
//! plaintext local administrator password; this module extracts command lines
//! and nothing else, and never reads a credential element.

use super::*;

/// One file-based or job-based persistence entry.
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(default)]
pub(crate) struct JobEntry {
    /// Where it was found, e.g. `IFEO\Debugger` or `unattend.xml`.
    #[serde(rename = "Location")]
    pub location: String,
    /// The image or file it applies to.
    #[serde(rename = "Name")]
    pub name: String,
    /// The command or path configured there.
    #[serde(rename = "Value")]
    pub value: String,
}

impl JobEntry {
    pub fn full_name(&self) -> String {
        format!("{}\\{}", self.location, self.name)
    }
}

/// IFEO values that redirect or attach to a process launch. A subkey on its own
/// means nothing — Windows ships 36 of them — so only these are read.
const IFEO_HIJACK_VALUES: &[(&str, Severity, u8, &str)] = &[
    (
        "Debugger",
        Severity::Critical,
        50,
        "every launch of this image runs the named program instead",
    ),
    (
        "MonitorProcess",
        Severity::Critical,
        50,
        "the named program is launched alongside this image (silent process exit)",
    ),
    (
        "GlobalFlag",
        Severity::Medium,
        20,
        "instrumentation is enabled for this image, which is what silent-process-exit hijacks set",
    ),
    (
        "VerifierDlls",
        Severity::High,
        40,
        "the named DLL is loaded into this image by Application Verifier",
    ),
];

// --- scoring ------------------------------------------------------------------

/// The signal one entry earns.
pub(crate) fn signals_for(entry: &JobEntry) -> Option<SysSignal> {
    let (severity, points, label) = match entry.location.as_str() {
        loc if loc.starts_with("IFEO\\") => {
            let value = loc.trim_start_matches("IFEO\\");
            let (_, sev, pts, why) = IFEO_HIJACK_VALUES.iter().find(|(n, ..)| *n == value)?;
            (
                *sev,
                *pts,
                format!("image hijack on {}: {why}", entry.name),
            )
        }
        // `AeDebug` names the debugger Windows launches when any process
        // crashes; it is a legitimate developer setting and a persistence
        // mechanism at the same time.
        "AeDebug" => (
            Severity::High,
            40,
            format!("a custom debugger runs on every process crash ({})", entry.value),
        ),
        "WER\\LocalDumps" => (
            Severity::Medium,
            20,
            "crash-dump collection is redirected".to_string(),
        ),
        "RunOnce\\Setup" => (
            Severity::High,
            40,
            "a setup command is queued to run at next logon".to_string(),
        ),
        "Setup\\Scripts" => (
            Severity::High,
            40,
            format!("a setup script runs with SYSTEM privileges ({})", entry.name),
        ),
        "unattend" => (
            Severity::Medium,
            20,
            "an answer file declares a command to run at first logon".to_string(),
        ),
        "BITS" => (
            Severity::High,
            40,
            format!("a BITS transfer job persists across reboots ({})", entry.value),
        ),
        "Provisioning" => (
            Severity::Medium,
            20,
            "a third-party provisioning package is installed".to_string(),
        ),
        // An application-compatibility shim database rewrites how a process
        // starts — the original in-memory patching mechanism, and still a
        // persistence one. Both registry locations are empty on a healthy
        // machine.
        "AppCompat\\InstalledSDB" => (
            Severity::High,
            40,
            "a custom application-compatibility shim database is installed".to_string(),
        ),
        "AppCompat\\Custom" => (
            Severity::High,
            40,
            format!("a shim database is applied to {}", entry.name),
        ),
        // The spooler loads printer drivers into a SYSTEM process.
        "PrinterDriver" => (
            Severity::High,
            40,
            format!("printer driver outside the driver store ({})", entry.value),
        ),
        // Weak on its own: a terminal profile only runs when someone opens that
        // profile. Recorded so an odd command line is visible.
        "WindowsTerminal" => (
            Severity::Info,
            0,
            format!("terminal profile runs a custom command ({})", entry.name),
        ),
        _ => return None,
    };

    // An interpreter in any of these outranks the location itself.
    if let Some(why) = super::asep::lolbin_in(&entry.value) {
        return Some(SysSignal::new(
            format!("{label} — and it uses {why}"),
            Category::Persistence,
            Severity::Critical,
            50,
        ));
    }
    Some(SysSignal::new(
        label,
        Category::Persistence,
        severity,
        points,
    ))
}

/// Is this provisioning package Microsoft's own?
///
/// Decided on its **signature**, not its file name. The reference machine
/// carries 21, and an earlier version of this matched their names — built from
/// the first four it saw, which missed the `Power.Settings.*` family entirely
/// and reported twelve Windows packages as third-party. They are all
/// Authenticode-signed by `O=Microsoft Corporation`, which no name list can
/// keep up with.
pub(crate) fn provisioning_is_microsoft(info: &super::authenticode::SigInfo) -> bool {
    info.status.eq_ignore_ascii_case("Valid") && super::authenticode::is_microsoft(info)
}

// --- enumeration ---------------------------------------------------------------

/// Read the job- and file-based persistence points.
///
/// The answer-file section reads `<CommandLine>` elements only. `unattend.xml`
/// commonly holds a plaintext administrator password, and nothing here has any
/// business touching it.
const PS_JOBS: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'

function Emit($location, $name, $value) {
  if (-not $value) { return }
  [pscustomobject]@{ Location = $location; Name = $name; Value = [string]$value } | ConvertTo-Json -Compress
}

# Image File Execution Options: the subkey means nothing, the values do.
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
foreach ($k in Get-ChildItem $ifeo) {
  $p = Get-ItemProperty $k.PSPath
  foreach ($v in @('Debugger','MonitorProcess','GlobalFlag','VerifierDlls')) {
    if ($null -ne $p.$v -and "$($p.$v)" -ne '') { Emit ('IFEO\' + $v) $k.PSChildName $p.$v }
  }
}
# The same key exists per-image under SilentProcessExit.
$spe = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
foreach ($k in Get-ChildItem $spe) {
  $p = Get-ItemProperty $k.PSPath
  if ($p.MonitorProcess) { Emit 'IFEO\MonitorProcess' $k.PSChildName $p.MonitorProcess }
}

# A debugger attached to every crash.
$ae = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug'
if ($ae.Debugger -and $ae.Debugger -notmatch 'vsjitdebugger|WerFault') { Emit 'AeDebug' 'Debugger' $ae.Debugger }

$wer = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'
if ($wer.DumpFolder) { Emit 'WER\LocalDumps' 'DumpFolder' $wer.DumpFolder }

foreach ($h in @('HKLM','HKCU')) {
  $k = Get-Item ($h + ':\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\Setup')
  if ($k) { foreach ($v in $k.Property) { Emit 'RunOnce\Setup' ($h + '\' + $v) ([string]$k.GetValue($v)) } }
}

# Setup scripts run as SYSTEM before the first user session.
foreach ($f in (Get-ChildItem "$env:WINDIR\Setup\Scripts" -File)) { Emit 'Setup\Scripts' $f.Name $f.FullName }

# Answer files: command lines only, never a credential element.
foreach ($a in @("$env:WINDIR\Panther\unattend.xml", "$env:WINDIR\System32\Sysprep\unattend.xml")) {
  if (-not (Test-Path -LiteralPath $a)) { continue }
  $raw = Get-Content -LiteralPath $a -Raw
  foreach ($m in [regex]::Matches($raw, '(?s)<CommandLine>(.*?)</CommandLine>')) {
    Emit 'unattend' (Split-Path $a -Leaf) $m.Groups[1].Value.Trim()
  }
}

# Persistent BITS transfers.
foreach ($j in (Get-BitsTransfer -AllUsers)) {
  Emit 'BITS' ([string]$j.DisplayName) ([string]$j.JobId + ' -> ' + ([string]($j.FileList | Select-Object -First 1).RemoteName))
}

# Application-compatibility shim databases rewrite how a process starts.
foreach ($k in (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB')) {
  $p = Get-ItemProperty $k.PSPath
  Emit 'AppCompat\InstalledSDB' $k.PSChildName ([string]$p.DatabasePath)
}
foreach ($k in (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom')) {
  Emit 'AppCompat\Custom' $k.PSChildName ($k.Property -join ',')
}

# Printer drivers are loaded into the spooler, which runs as SYSTEM. A driver
# outside the protected driver store is the PrintNightmare shape.
foreach ($d in (Get-PrinterDriver)) {
  $inf = [string]$d.InfPath
  if ($inf -and $inf -notmatch 'DriverStore\\FileRepository') { Emit 'PrinterDriver' ([string]$d.Name) $inf }
}

# A Windows Terminal profile can carry its own command line.
$wt = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
if (Test-Path -LiteralPath $wt) {
  $j = Get-Content -LiteralPath $wt -Raw | ConvertFrom-Json
  foreach ($prof in $j.profiles.list) {
    if ($prof.commandline -and $prof.source -ne 'Windows.Terminal.PowershellCore') {
      Emit 'WindowsTerminal' ([string]$prof.name) ([string]$prof.commandline)
    }
  }
}

# Provisioning packages apply arbitrary configuration.
foreach ($p in (Get-ChildItem "$env:WINDIR\Provisioning\Packages" -Filter *.ppkg -Recurse -File)) {
  Emit 'Provisioning' $p.Name $p.FullName
}
"#;

pub(crate) fn parse_entries(stdout: &str) -> Vec<JobEntry> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<JobEntry>(l).ok())
        .filter(|e: &JobEntry| !e.location.is_empty())
        .collect()
}

pub fn jobs_inventory(opts: Opts) -> Result<Inventory> {
    let _ = opts;
    let raw = powershell(PS_JOBS).context("enumerating job and file-based persistence")?;
    let all = parse_entries(&raw);

    // Provisioning packages are judged on their signature: Windows' own are
    // Microsoft-signed, and a name list cannot tell them apart reliably.
    let ppkg: Vec<String> = all
        .iter()
        .filter(|e| e.location == "Provisioning")
        .map(|e| e.value.clone())
        .collect();
    let microsoft: std::collections::HashSet<String> = if ppkg.is_empty() {
        std::collections::HashSet::new()
    } else {
        super::authenticode::verify(&ppkg)
            .into_iter()
            .filter(provisioning_is_microsoft)
            .map(|i| i.path.to_ascii_lowercase())
            .collect()
    };
    let entries: Vec<JobEntry> = all
        .into_iter()
        .filter(|e| {
            e.location != "Provisioning" || !microsoft.contains(&e.value.to_ascii_lowercase())
        })
        .collect();

    let mut signals: HashMap<String, Vec<SysSignal>> = HashMap::new();
    let mut deps = Vec::with_capacity(entries.len());
    for e in &entries {
        let name = e.full_name();
        if let Some(sig) = signals_for(e) {
            push_signal(&mut signals, &name, sig);
        }
        deps.push(Dependency {
            name,
            version: String::new(),
            ecosystem: Ecosystem::Job,
            direct: true,
            scope: Scope::Prod,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url: None,
            integrity: None,
            parents: Vec::new(),
        });
    }

    // These locations are normally empty; saying so is the useful answer.
    let notes = if entries.is_empty() {
        vec![
            "no image hijacks, setup scripts, BITS jobs or third-party provisioning packages \
             found — these locations are empty on a healthy machine"
                .to_string(),
        ]
    } else {
        Vec::new()
    };

    let summary = format!("{} job/file-based persistence entry(ies)", entries.len());
    Ok(Inventory {
        manager: "jobs",
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

    fn e(location: &str, name: &str, value: &str) -> JobEntry {
        JobEntry { location: location.into(), name: name.into(), value: value.into() }
    }

    /// An IFEO subkey on its own means nothing — Windows ships 36 of them and
    /// none carried a debugger on the reference machine. The *values* are the
    /// subject.
    #[test]
    fn an_ifeo_subkey_without_a_hijack_value_is_not_a_finding() {
        assert!(signals_for(&e("IFEO", "notepad.exe", "")).is_none());
        assert!(signals_for(&e("IFEO\\Unknown", "notepad.exe", "x")).is_none());

        let dbg = signals_for(&e("IFEO\\Debugger", "sethc.exe", r"C:\x\evil.exe"))
            .expect("a debugger redirects every launch");
        assert_eq!(dbg.severity, Severity::Critical);
        assert!(dbg.label.contains("sethc.exe"), "{}", dbg.label);
    }

    #[test]
    fn each_ifeo_value_carries_its_own_weight() {
        assert_eq!(
            signals_for(&e("IFEO\\MonitorProcess", "a.exe", "x")).unwrap().severity,
            Severity::Critical
        );
        assert_eq!(
            signals_for(&e("IFEO\\VerifierDlls", "a.exe", "evil.dll")).unwrap().severity,
            Severity::High
        );
        assert_eq!(
            signals_for(&e("IFEO\\GlobalFlag", "a.exe", "512")).unwrap().severity,
            Severity::Medium
        );
    }

    /// An interpreter in any of these locations outranks the location itself.
    #[test]
    fn an_interpreter_raises_any_of_these_to_critical() {
        let plain = signals_for(&e("unattend", "unattend.xml", r"C:\vendor\setup.exe /q")).unwrap();
        assert_eq!(plain.severity, Severity::Medium);

        let hostile = signals_for(&e("unattend", "unattend.xml", "powershell -enc SQBFAFgA")).unwrap();
        assert_eq!(hostile.severity, Severity::Critical);
        assert!(hostile.label.contains("and it uses"), "{}", hostile.label);
    }

    #[test]
    fn the_remaining_locations_each_report() {
        for (loc, sev) in [
            ("AeDebug", Severity::High),
            ("WER\\LocalDumps", Severity::Medium),
            ("RunOnce\\Setup", Severity::High),
            ("Setup\\Scripts", Severity::High),
            ("BITS", Severity::High),
            ("Provisioning", Severity::Medium),
        ] {
            let s = signals_for(&e(loc, "n", r"C:\x\a.exe")).unwrap_or_else(|| panic!("{loc}"));
            assert_eq!(s.severity, sev, "{loc}");
            assert_eq!(s.category, Category::Persistence);
        }
        // An unknown location is not invented into a finding.
        assert!(signals_for(&e("Something", "n", "v")).is_none());
    }

    /// Judged on the signature, never the name. An earlier version matched
    /// names built from the first four packages it saw, missed the
    /// `Power.Settings.*` family, and reported twelve Windows packages as
    /// third-party.
    #[test]
    fn provisioning_packages_are_judged_on_their_signature() {
        let ms: super::super::authenticode::SigInfo = serde_json::from_str(
            r#"{"Path":"C:\\WINDOWS\\Provisioning\\Packages\\Power.Settings.PCIExpress.ppkg","Status":"Valid","IsOSBinary":false,"Signer":"CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond"}"#,
        )
        .unwrap();
        assert!(provisioning_is_microsoft(&ms));

        let third: super::super::authenticode::SigInfo = serde_json::from_str(
            r#"{"Path":"C:\\x\\corp.ppkg","Status":"Valid","IsOSBinary":false,"Signer":"CN=Acme, O=Acme Ltd"}"#,
        )
        .unwrap();
        assert!(!provisioning_is_microsoft(&third));

        // A Microsoft signature that does not verify is not a pass either.
        let broken: super::super::authenticode::SigInfo = serde_json::from_str(
            r#"{"Path":"C:\\x\\a.ppkg","Status":"HashMismatch","IsOSBinary":false,"Signer":"CN=Microsoft Windows, O=Microsoft Corporation"}"#,
        )
        .unwrap();
        assert!(!provisioning_is_microsoft(&broken));
    }

    /// `iex` occurs inside `PCIExpress`, which is how a Windows provisioning
    /// package came to be reported as running `Invoke-Expression`.
    #[test]
    fn a_lolbin_token_inside_a_longer_word_is_not_a_match() {
        let path = r"C:\WINDOWS\Provisioning\Packages\Power.Settings.PCIExpress.ppkg";
        let s = signals_for(&e("Provisioning", "Power.Settings.PCIExpress.ppkg", path)).unwrap();
        assert!(!s.label.contains("and it uses"), "{}", s.label);
        assert_eq!(s.severity, Severity::Medium);

        // The real token still matches.
        let real = signals_for(&e("Provisioning", "x.ppkg", "iex http://198.51.100.7/a")).unwrap();
        assert_eq!(real.severity, Severity::Critical);
    }

    /// Both shim-database locations are empty on a healthy machine, which is
    /// what makes them worth reading at all.
    #[test]
    fn a_custom_shim_database_is_a_finding() {
        let sdb = signals_for(&e("AppCompat\\InstalledSDB", "{GUID}", r"C:\x\evil.sdb")).unwrap();
        assert_eq!(sdb.severity, Severity::High);
        let custom = signals_for(&e("AppCompat\\Custom", "target.exe", "{GUID}.sdb")).unwrap();
        assert!(custom.label.contains("target.exe"), "{}", custom.label);
    }

    /// The spooler loads drivers into a SYSTEM process. Every driver on the
    /// reference machine sits in the protected driver store, so only one
    /// outside it is emitted at all.
    #[test]
    fn a_printer_driver_outside_the_driver_store_is_a_finding() {
        let s = signals_for(&e("PrinterDriver", "Vendor PCL", r"C:\vendor\drv.inf")).unwrap();
        assert_eq!(s.severity, Severity::High);
        assert!(s.label.contains(r"C:\vendor\drv.inf"), "{}", s.label);
    }

    /// A terminal profile only runs when somebody opens that profile, so it is
    /// recorded rather than scored.
    #[test]
    fn a_terminal_profile_is_recorded_not_scored() {
        let s = signals_for(&e("WindowsTerminal", "Ubuntu", "wsl.exe -d Ubuntu")).unwrap();
        assert_eq!(s.severity, Severity::Info);
        assert_eq!(s.points, 0);

        // Unless it carries an interpreter, which outranks the location.
        let bad = signals_for(&e("WindowsTerminal", "x", "powershell -enc SQBFAFgA")).unwrap();
        assert_eq!(bad.severity, Severity::Critical);
    }

    #[test]
    fn entries_are_parsed_from_the_enumerators_json() {
        let json = r#"{"Location":"IFEO\\Debugger","Name":"sethc.exe","Value":"C:\\x\\evil.exe"}
{"Location":"","Name":"x","Value":"y"}"#;
        let got = parse_entries(json);
        assert_eq!(got.len(), 1, "an entry with no location is not an entry");
        assert_eq!(got[0].full_name(), r"IFEO\Debugger\sethc.exe");
    }
}
