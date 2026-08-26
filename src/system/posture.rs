//! Privilege posture — Windows has no setuid; the primitives are the DACL, the
//! token, and auto-elevation.
//!
//! Every check here is machine-wide, so each becomes a node of its own rather
//! than a property of some package.
//!
//! One principle runs through the scoring: **a default is not a decision, a
//! change is.** Hardening that was never turned on is a gap, reported low;
//! a protection that somebody explicitly switched off is a finding. Without
//! that distinction the layer would report Credential Guard on every consumer
//! machine in the world at the same weight as a disabled UAC.

use super::*;

/// One posture reading.
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(default)]
pub(crate) struct Reading {
    /// The check's identifier, e.g. `UAC\EnableLUA`.
    #[serde(rename = "Check")]
    pub check: String,
    /// The value found, empty when the value is not set at all.
    #[serde(rename = "Value")]
    pub value: String,
    /// Free-form context: a path, an identity, a member list.
    #[serde(rename = "Detail")]
    pub detail: String,
}

impl Reading {
    /// Was the value explicitly set, or is this Windows' default?
    pub fn is_set(&self) -> bool {
        !self.value.trim().is_empty()
    }

    fn as_u32(&self) -> Option<u32> {
        self.value.trim().parse().ok()
    }
}

// --- scoring ------------------------------------------------------------------

/// The signal one reading earns, if any.
pub(crate) fn signals_for(r: &Reading) -> Option<SysSignal> {
    let (severity, points, label) = match r.check.as_str() {
        // An MSI installed by anyone runs as SYSTEM. Both hives must be set for
        // it to work, which makes the pair unambiguous — nobody sets these by
        // accident.
        "Installer\\AlwaysInstallElevated" => {
            if r.as_u32() != Some(1) {
                return None;
            }
            (
                Severity::Critical,
                50,
                format!(
                    "AlwaysInstallElevated is on ({}) — any MSI installs with SYSTEM privileges",
                    r.detail
                ),
            )
        }
        "UAC\\EnableLUA" => {
            if r.as_u32() != Some(0) {
                return None;
            }
            (
                Severity::Critical,
                50,
                "UAC is switched off entirely — every administrator process runs elevated \
                 without consent"
                    .to_string(),
            )
        }
        "UAC\\ConsentPromptBehaviorAdmin" => {
            if r.as_u32() != Some(0) {
                return None;
            }
            (
                Severity::High,
                40,
                "administrators elevate without any prompt".to_string(),
            )
        }
        "UAC\\LocalAccountTokenFilterPolicy" => {
            if r.as_u32() != Some(1) {
                return None;
            }
            (
                Severity::High,
                40,
                "remote UAC filtering is disabled — a local account keeps its full token over \
                 the network"
                    .to_string(),
            )
        }
        // Only meaningful while the built-in Administrator can actually log in;
        // it is disabled by default, and reporting this on a machine where it
        // is would be noise.
        "UAC\\FilterAdministratorToken" => {
            if r.as_u32() == Some(1) || r.detail != "builtin-admin-enabled" {
                return None;
            }
            (
                Severity::Medium,
                20,
                "the built-in Administrator account is enabled and exempt from UAC".to_string(),
            )
        }
        // Explicitly re-enabling WDigest puts plaintext credentials back in
        // memory. Nothing does that by accident.
        "LSA\\WDigest" => {
            if r.as_u32() != Some(1) {
                return None;
            }
            (
                Severity::High,
                40,
                "WDigest is enabled — logon credentials are held in memory in plaintext"
                    .to_string(),
            )
        }
        // Absent hardening, not a disabled protection.
        "LSA\\RunAsPPL" => {
            if matches!(r.as_u32(), Some(1 | 2)) {
                return None;
            }
            let (sev, pts) = if r.is_set() {
                // Present and zero: somebody turned it off.
                (Severity::Medium, 20)
            } else {
                (Severity::Low, 10)
            };
            (
                sev,
                pts,
                "LSA Protection is not enabled — LSASS can be opened by any administrator process"
                    .to_string(),
            )
        }
        "LSA\\CredentialGuard" => {
            if matches!(r.as_u32(), Some(1 | 2)) {
                return None;
            }
            (
                Severity::Info,
                0,
                "Credential Guard is not configured".to_string(),
            )
        }
        // A user-writable directory early on the machine PATH is a hijack for
        // every process that resolves a bare command name.
        "PATH\\UserWritable" => (
            Severity::High,
            40,
            format!(
                "the machine PATH contains a user-writable directory ({}) at position {}",
                r.detail, r.value
            ),
        ),
        "ACL\\ProgramFiles" => (
            Severity::High,
            40,
            format!("{} is writable without elevation ({})", r.detail, r.value),
        ),
        "ACL\\ScoopGlobal" => (
            Severity::Critical,
            50,
            format!(
                "the global Scoop root is writable without elevation ({})",
                r.detail
            ),
        ),
        // --- policy that weakens trust ---------------------------------------
        // Turning real-time protection off is never incidental.
        "Defender\\RealTime" => {
            if r.value != "False" {
                return None;
            }
            (
                Severity::Critical,
                50,
                "Defender real-time protection is off".to_string(),
            )
        }
        "Defender\\TamperProtection" => {
            if r.value != "False" {
                return None;
            }
            (
                Severity::High,
                40,
                "Defender tamper protection is off — its own settings can be rewritten"
                    .to_string(),
            )
        }
        // An exclusion is a hole by design; how big a hole is the question.
        "Defender\\Exclusion" => {
            let (sev, pts, kind) = if is_broad_exclusion(&r.detail) {
                (Severity::High, 40, "a broad")
            } else {
                (Severity::Medium, 20, "an")
            };
            (
                sev,
                pts,
                format!("Defender has {kind} exclusion ({}: {})", r.value, r.detail),
            )
        }
        // The firmware type is read first: `Confirm-SecureBootUEFI` is also
        // false on legacy BIOS, which is a different machine, not a weakened one.
        "Boot\\SecureBoot" => {
            if r.value != "0" || r.detail != "Uefi" {
                return None;
            }
            (
                Severity::High,
                40,
                "Secure Boot is disabled on UEFI firmware".to_string(),
            )
        }
        "Boot\\TestSigning" => {
            if r.value != "1" {
                return None;
            }
            (
                Severity::High,
                40,
                "test signing is enabled — unsigned drivers load".to_string(),
            )
        }
        // Not enabled by default on all hardware, so absence is a gap.
        "Boot\\HVCI" => {
            if r.value == "1" {
                return None;
            }
            (
                Severity::Low,
                10,
                "memory integrity (HVCI) is not running".to_string(),
            )
        }
        "PowerShell\\ExecutionPolicy" => {
            if !matches!(r.value.as_str(), "Unrestricted" | "Bypass") {
                return None;
            }
            (
                Severity::High,
                40,
                format!("the machine PowerShell execution policy is {}", r.value),
            )
        }
        // Rarely enabled anywhere; their absence is a gap in evidence, not a
        // weakened protection.
        "PowerShell\\ScriptBlockLogging" | "PowerShell\\Transcription" => {
            if r.value == "1" {
                return None;
            }
            (
                Severity::Info,
                0,
                format!("{} is not enabled", r.check.replace("PowerShell\\", "PowerShell ")),
            )
        }
        "Defender\\SmartScreen" => {
            if !r.value.eq_ignore_ascii_case("Off") {
                return None;
            }
            (Severity::Medium, 20, "SmartScreen is switched off".to_string())
        }
        "Defender\\ControlledFolderAccess" => {
            if r.value == "1" {
                return None;
            }
            (
                Severity::Info,
                0,
                "Controlled Folder Access is not enabled".to_string(),
            )
        }
        // Absence is only a finding on a machine that claims to be gated, which
        // postmortem cannot know. Reported so the claim can be checked.
        // --- firmware and boot -----------------------------------------------
        // Info by design: a machine without a TPM or with BitLocker off is a
        // configuration, not a compromise. What makes this section matter is
        // the combination below.
        "Boot\\Tpm" => {
            if r.value == "True" {
                return None;
            }
            (Severity::Info, 0, "no TPM is present or ready".to_string())
        }
        "Boot\\BitLocker" => {
            if r.value == "On" {
                return None;
            }
            (Severity::Info, 0, "BitLocker is not protecting the system volume".to_string())
        }
        "Boot\\KernelDma" => {
            if r.value == "1" {
                return None;
            }
            (Severity::Info, 0, "Kernel DMA protection is not running".to_string())
        }
        // A boot manager somewhere other than the Microsoft path is worth a
        // look; a bootkit is out of scope, its footprint is not.
        "Boot\\Manager" => {
            if r.value.eq_ignore_ascii_case(r"\EFI\MICROSOFT\BOOT\BOOTMGFW.EFI") {
                return None;
            }
            (
                Severity::Medium,
                20,
                format!("the boot manager is not at the Microsoft path ({})", r.value),
            )
        }
        // These switch off driver signature enforcement outright.
        "Boot\\IntegrityChecks" => {
            if r.value != "1" {
                return None;
            }
            (
                Severity::High,
                40,
                format!("driver integrity checks are disabled ({})", r.detail),
            )
        }
        "AppControl\\Policy" => match r.value.as_str() {
            "audit" => (
                Severity::Low,
                10,
                "an application-control policy is in audit mode — it logs, it does not block"
                    .to_string(),
            ),
            "none" => (
                Severity::Info,
                0,
                "no WDAC or AppLocker policy is in force".to_string(),
            ),
            _ => return None,
        },
        _ => return None,
    };
    // Permission findings and configuration findings are different lenses, and
    // the category is what carries that into JSON and SARIF.
    let category = if r.check.starts_with("ACL\\") || r.check.starts_with("PATH\\") {
        Category::WeakAcl
    } else {
        Category::Policy
    };
    Some(SysSignal::new(label, category, severity, points))
}


/// Does this exclusion cover a whole tree rather than one program?
///
/// A drive root, a user-profile root, or a package manager's own directory
/// turns the exclusion into "and also, do not look here" for everything the
/// machine installs.
pub(crate) fn is_broad_exclusion(path: &str) -> bool {
    let p = path.trim().trim_end_matches('\\').to_ascii_lowercase();
    // A bare drive root.
    if p.len() <= 3 && p.contains(':') {
        return true;
    }
    const BROAD: &[&str] = &[
        r"c:\users",
        r"c:\programdata",
        r"c:\program files",
        r"c:\program files (x86)",
        r"c:\windows",
        r"c:\temp",
        "downloads",
    ];
    if BROAD.iter().any(|b| p == *b || p.ends_with(b)) {
        return true;
    }
    // A wildcard that is not anchored to a file.
    p.ends_with('*') && p.matches('\\').count() <= 2
}

// --- enumeration ---------------------------------------------------------------

/// Read the machine's privilege posture.
const PS_POSTURE: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'

function Emit($check, $value, $detail) {
  [pscustomobject]@{ Check = $check; Value = [string]$value; Detail = [string]$detail } | ConvertTo-Json -Compress
}
function V($path, $name) { (Get-ItemProperty -Path $path -Name $name).$name }

# AlwaysInstallElevated only works when BOTH hives are set, so the pair is what
# matters, not either half.
$hklm = V 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
$hkcu = V 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
if ($hklm -eq 1 -and $hkcu -eq 1) { Emit 'Installer\AlwaysInstallElevated' 1 'HKLM and HKCU' }
elseif ($hklm -eq 1 -or $hkcu -eq 1) { Emit 'Installer\AlwaysInstallElevated' 1 $(if ($hklm -eq 1) { 'HKLM only' } else { 'HKCU only' }) }

$sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
foreach ($n in @('EnableLUA','ConsentPromptBehaviorAdmin','LocalAccountTokenFilterPolicy')) {
  Emit ('UAC\' + $n) (V $sys $n) ''
}
# FilterAdministratorToken only matters while the built-in Administrator can
# log in at all.
$builtin = Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' }
Emit 'UAC\FilterAdministratorToken' (V $sys 'FilterAdministratorToken') `
     $(if ($builtin.Enabled) { 'builtin-admin-enabled' } else { 'builtin-admin-disabled' })

Emit 'LSA\RunAsPPL' (V 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL') ''
Emit 'LSA\WDigest' (V 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential') ''
Emit 'LSA\CredentialGuard' (V 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags') ''

function Writable([string]$p) {
  if (-not $p -or -not (Test-Path -LiteralPath $p)) { return $null }
  foreach ($a in (Get-Acl -LiteralPath $p).Access) {
    if ($a.AccessControlType -ne 'Allow') { continue }
    if ($a.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
    if ("$($a.IdentityReference)" -notmatch 'BUILTIN\\Users|Everyone|Authenticated Users|INTERACTIVE') { continue }
    if ("$($a.FileSystemRights)" -notmatch 'FullControl|Modify|CreateFiles|WriteData') { continue }
    return "$($a.IdentityReference): $($a.FileSystemRights)"
  }
  return $null
}

# A user-writable directory on the machine PATH hijacks every bare command name.
$i = 0
foreach ($d in (([Environment]::GetEnvironmentVariable('Path','Machine') -split ';') | Where-Object { $_ })) {
  $i++
  $w = Writable ([Environment]::ExpandEnvironmentVariables($d))
  if ($w) { Emit 'PATH\UserWritable' $i $d }
}

# What a package installed into Program Files can be replaced by anyone.
foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
  foreach ($d in (Get-ChildItem $root -Directory)) {
    $w = Writable $d.FullName
    if ($w) { Emit 'ACL\ProgramFiles' $w $d.FullName }
  }
}

$sg = Join-Path $env:ProgramData 'scoop'
$w = Writable $sg
if ($w) { Emit 'ACL\ScoopGlobal' $w $sg }

# --- policy that weakens trust ------------------------------------------------
$mp = Get-MpPreference
$ms = Get-MpComputerStatus
Emit 'Defender\RealTime' $ms.RealTimeProtectionEnabled ''
Emit 'Defender\TamperProtection' $ms.IsTamperProtected ''
Emit 'Defender\ControlledFolderAccess' $mp.EnableControlledFolderAccess ''
# `@($null).Count` is 1, so an empty exclusion list must be filtered before it
# is counted - otherwise a clean machine reports one of each.
foreach ($kind in @('ExclusionPath','ExclusionProcess','ExclusionExtension')) {
  foreach ($v in ($mp.$kind | Where-Object { $_ })) { Emit 'Defender\Exclusion' $kind $v }
}
Emit 'Defender\SmartScreen' (V 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled') ''

# Read the firmware type too: `Confirm-SecureBootUEFI` is also false on legacy
# BIOS, which is a different machine rather than a weakened one.
$fw = (Get-CimInstance Win32_ComputerSystem).PCSystemType
$fwType = if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State') { 'Uefi' } else { 'Bios' }
Emit 'Boot\SecureBoot' (V 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled') $fwType
$bcd = (& bcdedit /enum '{current}') -join "`n"
Emit 'Boot\TestSigning' $(if ($bcd -match 'testsigning\s+Yes') { 1 } else { 0 }) ''
$dg = Get-CimInstance Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
Emit 'Boot\HVCI' $(if (@($dg.SecurityServicesRunning) -contains 2) { 1 } else { 0 }) ''

$ps = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
Emit 'PowerShell\ScriptBlockLogging' (V ($ps + '\ScriptBlockLogging') 'EnableScriptBlockLogging') ''
Emit 'PowerShell\Transcription' (V ($ps + '\Transcription') 'EnableTranscripting') ''
$mach = (Get-ExecutionPolicy -List | Where-Object { $_.Scope -eq 'LocalMachine' }).ExecutionPolicy
Emit 'PowerShell\ExecutionPolicy' $mach ''

# WDAC user-mode enforcement, else AppLocker, else nothing in force.
$umci = [int]$dg.UsermodeCodeIntegrityPolicyEnforcementStatus
$applocker = @(@(Get-AppLockerPolicy -Effective).RuleCollections | Where-Object { $_.Count -gt 0 }).Count
$state = if ($umci -eq 2) { 'enforced' } elseif ($umci -eq 1) { 'audit' } elseif ($applocker -gt 0) { 'enforced' } else { 'none' }
Emit 'AppControl\Policy' $state ''

# --- firmware and boot --------------------------------------------------------
$tpm = Get-Tpm
Emit 'Boot\Tpm' $(if ($tpm.TpmPresent -and $tpm.TpmReady) { 'True' } else { 'False' }) ''
Emit 'Boot\BitLocker' ((Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus) ''
Emit 'Boot\KernelDma' $(if (@($dg.SecurityServicesRunning) -contains 3) { 1 } else { 0 }) ''
$bm = ((& bcdedit /enum '{bootmgr}') | Select-String '^path\s+(.+)$').Matches.Groups[1].Value
Emit 'Boot\Manager' ($bm -replace '\s+$','') ''
foreach ($f in @('nointegritychecks','disableintegritychecks')) {
  if ($bcd -match "$f\s+Yes") { Emit 'Boot\IntegrityChecks' 1 $f }
}
"#;

pub(crate) fn parse_readings(stdout: &str) -> Vec<Reading> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<Reading>(l).ok())
        .filter(|r: &Reading| !r.check.is_empty())
        .collect()
}

pub fn posture_inventory(opts: Opts) -> Result<Inventory> {
    let _ = opts;
    let raw = powershell(PS_POSTURE).context("reading the machine's privilege posture")?;
    let readings = parse_readings(&raw);
    if readings.is_empty() {
        anyhow::bail!(
            "the machine's privilege posture could not be read — refusing to report an \
             unexamined machine as a sound one"
        );
    }

    let mut signals: HashMap<String, Vec<SysSignal>> = HashMap::new();
    let mut deps = Vec::with_capacity(readings.len());
    let mut findings = 0usize;
    for r in &readings {
        // A reading is named by what it examined, so two ACL findings on
        // different directories stay distinct.
        let name = if r.detail.is_empty() || r.check.starts_with("UAC") || r.check.starts_with("LSA")
        {
            r.check.clone()
        } else {
            format!("{}\\{}", r.check, r.detail)
        };
        if let Some(sig) = signals_for(r) {
            findings += 1;
            push_signal(&mut signals, &name, sig);
        }
        deps.push(Dependency {
            name,
            version: String::new(),
            ecosystem: Ecosystem::Posture,
            direct: true,
            scope: Scope::Prod,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url: None,
            integrity: None,
            parents: Vec::new(),
        });
    }

    let summary = format!(
        "{} posture check(s): {findings} raised something",
        readings.len()
    );
    Ok(Inventory {
        manager: "posture",
        deps,
        repos: Vec::new(),
        signals,
        claims: Vec::new(),
        summary,
        notes: Vec::new(),
    })
}


#[cfg(test)]
mod tests {
    use super::*;

    fn r(check: &str, value: &str, detail: &str) -> Reading {
        Reading { check: check.into(), value: value.into(), detail: detail.into() }
    }

    /// The principle the whole layer rests on: a default is not a decision.
    /// The reference machine has `EnableLUA=1`, `RunAsPPL=2`, WDigest unset and
    /// no `AlwaysInstallElevated` — it must raise nothing but the Credential
    /// Guard note.
    #[test]
    fn a_machine_at_its_defaults_raises_almost_nothing() {
        let stock = [
            r("UAC\\EnableLUA", "1", ""),
            r("UAC\\ConsentPromptBehaviorAdmin", "5", ""),
            r("UAC\\LocalAccountTokenFilterPolicy", "", ""),
            r("UAC\\FilterAdministratorToken", "", "builtin-admin-disabled"),
            r("LSA\\RunAsPPL", "2", ""),
            r("LSA\\WDigest", "", ""),
        ];
        for reading in &stock {
            assert!(signals_for(reading).is_none(), "{} should be silent", reading.check);
        }
    }

    /// An MSI installed by anyone then runs as SYSTEM. It takes both hives to
    /// work, and nobody sets that by accident.
    #[test]
    fn always_install_elevated_is_critical() {
        let s = signals_for(&r("Installer\\AlwaysInstallElevated", "1", "HKLM and HKCU")).unwrap();
        assert_eq!(s.severity, Severity::Critical);
        assert!(s.label.contains("HKLM and HKCU"), "{}", s.label);
        assert!(signals_for(&r("Installer\\AlwaysInstallElevated", "0", "")).is_none());
    }

    #[test]
    fn uac_switched_off_outranks_uac_merely_loosened() {
        assert_eq!(
            signals_for(&r("UAC\\EnableLUA", "0", "")).unwrap().severity,
            Severity::Critical
        );
        assert_eq!(
            signals_for(&r("UAC\\ConsentPromptBehaviorAdmin", "0", "")).unwrap().severity,
            Severity::High
        );
        assert_eq!(
            signals_for(&r("UAC\\LocalAccountTokenFilterPolicy", "1", "")).unwrap().severity,
            Severity::High
        );
    }

    /// The built-in Administrator is disabled by default, so its UAC exemption
    /// is moot until somebody enables the account.
    #[test]
    fn the_builtin_administrator_exemption_needs_the_account_enabled() {
        assert!(signals_for(&r("UAC\\FilterAdministratorToken", "0", "builtin-admin-disabled")).is_none());
        let s = signals_for(&r("UAC\\FilterAdministratorToken", "0", "builtin-admin-enabled")).unwrap();
        assert_eq!(s.severity, Severity::Medium);
        // Hardened: exempt from nothing.
        assert!(signals_for(&r("UAC\\FilterAdministratorToken", "1", "builtin-admin-enabled")).is_none());
    }

    /// Absent hardening is a gap; a protection somebody switched off is a
    /// finding. Without that distinction this layer would report Credential
    /// Guard on every consumer machine at the weight of a disabled UAC.
    #[test]
    fn absent_hardening_weighs_less_than_disabled_hardening() {
        // Never configured.
        let absent = signals_for(&r("LSA\\RunAsPPL", "", "")).unwrap();
        assert_eq!(absent.severity, Severity::Low);
        // Present and set to zero: a decision.
        let off = signals_for(&r("LSA\\RunAsPPL", "0", "")).unwrap();
        assert_eq!(off.severity, Severity::Medium);

        // Credential Guard is unconfigured almost everywhere.
        let cg = signals_for(&r("LSA\\CredentialGuard", "", "")).unwrap();
        assert_eq!(cg.severity, Severity::Info);
        assert_eq!(cg.points, 0);

        // WDigest is off by default; switching it on puts plaintext credentials
        // back in memory.
        assert!(signals_for(&r("LSA\\WDigest", "", "")).is_none());
        assert_eq!(signals_for(&r("LSA\\WDigest", "1", "")).unwrap().severity, Severity::High);
    }

    /// The reference machine's one real ACL finding: Steam grants
    /// `BUILTIN\Users` full control of its own install directory, and Steam
    /// auto-starts.
    #[test]
    fn a_writable_program_files_directory_is_a_finding() {
        let s = signals_for(&r(
            "ACL\\ProgramFiles",
            "BUILTIN\\Users: FullControl",
            r"C:\Program Files (x86)\Steam",
        ))
        .unwrap();
        assert_eq!(s.severity, Severity::High);
        assert_eq!(s.category, Category::WeakAcl);
        assert!(s.label.contains("Steam"), "{}", s.label);
    }

    #[test]
    fn a_writable_path_entry_and_a_writable_scoop_root_are_reported() {
        let path = signals_for(&r("PATH\\UserWritable", "2", r"C:\Users\alice\bin")).unwrap();
        assert_eq!(path.severity, Severity::High);
        assert!(path.label.contains("position 2"), "{}", path.label);

        let scoop = signals_for(&r("ACL\\ScoopGlobal", "Everyone: FullControl", r"C:\ProgramData\scoop")).unwrap();
        assert_eq!(scoop.severity, Severity::Critical);
    }

    /// Turning real-time protection off, or letting its own settings be
    /// rewritten, is never incidental.
    #[test]
    fn defender_switched_off_is_the_heaviest_finding_here() {
        assert_eq!(
            signals_for(&r("Defender\\RealTime", "False", "")).unwrap().severity,
            Severity::Critical
        );
        assert!(signals_for(&r("Defender\\RealTime", "True", "")).is_none());
        assert_eq!(
            signals_for(&r("Defender\\TamperProtection", "False", "")).unwrap().severity,
            Severity::High
        );
    }

    /// An exclusion is a hole by design; how big a hole is the question.
    #[test]
    fn a_broad_exclusion_outweighs_a_narrow_one() {
        for broad in [
            r"C:\",
            r"C:\Users",
            r"C:\ProgramData",
            r"C:\Users\alice\Downloads",
            r"D:\",
            r"C:\ProgramData\*",
        ] {
            assert!(is_broad_exclusion(broad), "{broad}");
        }
        for narrow in [
            r"C:\Program Files\Vendor\app.exe",
            r"C:\ProgramData\Vendor\cache\db.bin",
            "",
        ] {
            assert!(!is_broad_exclusion(narrow), "{narrow}");
        }

        let wide = signals_for(&r("Defender\\Exclusion", "ExclusionPath", r"C:\")).unwrap();
        assert_eq!(wide.severity, Severity::High);
        let one = signals_for(&r("Defender\\Exclusion", "ExclusionPath", r"C:\Vendor\app.exe")).unwrap();
        assert_eq!(one.severity, Severity::Medium);
    }

    /// `Confirm-SecureBootUEFI` is false on legacy BIOS too — a different
    /// machine, not a weakened one.
    #[test]
    fn secure_boot_is_only_a_finding_on_uefi_firmware() {
        let uefi_off = signals_for(&r("Boot\\SecureBoot", "0", "Uefi")).unwrap();
        assert_eq!(uefi_off.severity, Severity::High);
        assert!(signals_for(&r("Boot\\SecureBoot", "1", "Uefi")).is_none());
        assert!(
            signals_for(&r("Boot\\SecureBoot", "0", "Bios")).is_none(),
            "legacy firmware has no Secure Boot to disable"
        );
    }

    #[test]
    fn test_signing_outweighs_absent_memory_integrity() {
        assert_eq!(
            signals_for(&r("Boot\\TestSigning", "1", "")).unwrap().severity,
            Severity::High
        );
        assert!(signals_for(&r("Boot\\TestSigning", "0", "")).is_none());
        // Not enabled by default on all hardware: a gap, not a decision.
        assert_eq!(
            signals_for(&r("Boot\\HVCI", "0", "")).unwrap().severity,
            Severity::Low
        );
        assert!(signals_for(&r("Boot\\HVCI", "1", "")).is_none());
    }

    #[test]
    fn a_machine_wide_bypass_execution_policy_is_a_finding() {
        for p in ["Unrestricted", "Bypass"] {
            assert_eq!(
                signals_for(&r("PowerShell\\ExecutionPolicy", p, "")).unwrap().severity,
                Severity::High,
                "{p}"
            );
        }
        for p in ["Undefined", "RemoteSigned", "AllSigned", "Restricted"] {
            assert!(signals_for(&r("PowerShell\\ExecutionPolicy", p, "")).is_none(), "{p}");
        }
    }

    /// Absent logging is missing evidence, not a weakened protection — and it
    /// is absent nearly everywhere.
    #[test]
    fn absent_logging_and_absent_app_control_are_recorded_not_scored() {
        for check in ["PowerShell\\ScriptBlockLogging", "PowerShell\\Transcription"] {
            let s = signals_for(&r(check, "", "")).unwrap();
            assert_eq!(s.severity, Severity::Info);
            assert_eq!(s.points, 0);
            assert!(signals_for(&r(check, "1", "")).is_none());
        }

        // Application control: enforced is silent, audit-only is a gap worth a
        // word, absent is recorded because postmortem cannot know whether this
        // machine was meant to be gated.
        assert!(signals_for(&r("AppControl\\Policy", "enforced", "")).is_none());
        assert_eq!(signals_for(&r("AppControl\\Policy", "audit", "")).unwrap().severity, Severity::Low);
        assert_eq!(signals_for(&r("AppControl\\Policy", "none", "")).unwrap().points, 0);
    }

    /// Permissions and configuration are different lenses, and the category is
    /// what carries that distinction into JSON and SARIF.
    #[test]
    fn acl_findings_and_policy_findings_carry_different_categories() {
        let acl = signals_for(&r("ACL\\ProgramFiles", "BUILTIN\\Users: FullControl", r"C:\x")).unwrap();
        assert_eq!(acl.category, Category::WeakAcl);
        let path = signals_for(&r("PATH\\UserWritable", "1", r"C:\Users\alice\bin")).unwrap();
        assert_eq!(path.category, Category::WeakAcl);

        let policy = signals_for(&r("Defender\\RealTime", "False", "")).unwrap();
        assert_eq!(policy.category, Category::Policy);
        let uac = signals_for(&r("UAC\\EnableLUA", "0", "")).unwrap();
        assert_eq!(uac.category, Category::Policy);
    }

    /// The one combination in the firmware section that is not Info. Each half
    /// is ordinary; together they mean the machine loads kernel code nobody
    /// vouched for.
    #[test]
    fn test_signing_plus_a_third_party_driver_is_critical() {
        let mut inv = Inventory {
            manager: "system",
            deps: Vec::new(),
            repos: Vec::new(),
            signals: HashMap::new(),
            claims: Vec::new(),
            summary: String::new(),
            notes: Vec::new(),
        };
        push_signal(&mut inv.signals, "VendorDrv", SysSignal::new(
            "driver starts automatically from outside System32",
            Category::Persistence, Severity::Info, 0));

        // Third-party driver alone: nothing added.
        flag_unsigned_driver_risk(&mut inv);
        assert_eq!(inv.signals["VendorDrv"].len(), 1);

        // Add the boot flag and the pair becomes the finding.
        push_signal(&mut inv.signals, "Boot\\TestSigning", SysSignal::new(
            "test signing is enabled — unsigned drivers load",
            Category::Policy, Severity::High, 40));
        flag_unsigned_driver_risk(&mut inv);
        let added = inv.signals["VendorDrv"]
            .iter()
            .find(|s| s.label.contains("driver signing is not enforced"))
            .expect("the combination is the finding");
        assert_eq!(added.severity, Severity::Critical);
    }

    /// Test signing on a machine with no third-party driver stays what it was.
    #[test]
    fn test_signing_alone_escalates_nothing() {
        let mut inv = Inventory {
            manager: "system", deps: Vec::new(), repos: Vec::new(),
            signals: HashMap::new(), claims: Vec::new(),
            summary: String::new(), notes: Vec::new(),
        };
        push_signal(&mut inv.signals, "Boot\\TestSigning", SysSignal::new(
            "test signing is enabled — unsigned drivers load",
            Category::Policy, Severity::High, 40));
        flag_unsigned_driver_risk(&mut inv);
        assert_eq!(inv.signals.len(), 1);
        assert_eq!(inv.signals["Boot\\TestSigning"].len(), 1);
    }

    /// Firmware readings are Info: a machine without a TPM is a configuration,
    /// not a compromise.
    #[test]
    fn the_firmware_readings_are_context() {
        for (check, value) in [("Boot\\Tpm", "False"), ("Boot\\BitLocker", "Off"), ("Boot\\KernelDma", "0")] {
            let s = signals_for(&r(check, value, "")).unwrap();
            assert_eq!(s.severity, Severity::Info, "{check}");
            assert_eq!(s.points, 0);
        }
        assert!(signals_for(&r("Boot\\Tpm", "True", "")).is_none());
        assert!(signals_for(&r("Boot\\BitLocker", "On", "")).is_none());

        // The standard boot manager path is silent; anything else is not.
        assert!(signals_for(&r("Boot\\Manager", r"\EFI\MICROSOFT\BOOT\BOOTMGFW.EFI", "")).is_none());
        assert_eq!(
            signals_for(&r("Boot\\Manager", r"\EFI\vendor\boot.efi", "")).unwrap().severity,
            Severity::Medium
        );
        // Disabled integrity checks are a decision, not a gap.
        assert_eq!(
            signals_for(&r("Boot\\IntegrityChecks", "1", "nointegritychecks")).unwrap().severity,
            Severity::High
        );
    }

    #[test]
    fn readings_are_parsed_and_a_missing_value_is_not_a_zero() {
        let json = r#"{"Check":"LSA\\RunAsPPL","Value":"","Detail":""}
{"Check":"","Value":"1","Detail":""}"#;
        let got = parse_readings(json);
        assert_eq!(got.len(), 1, "a reading with no check is not a reading");
        assert!(!got[0].is_set(), "unset must not read as zero");
    }
}

/// Escalate the one combination in the firmware section that is not Info.
///
/// Test signing on its own is a developer machine; a third-party driver on its
/// own is ordinary. **Together** they mean the machine will load a kernel
/// driver nobody vouched for, which is the whole reason to read boot flags in a
/// supply-chain scanner.
///
/// Runs over the **merged** inventory: the boot flag comes from this layer and
/// the drivers from [`super::service`], so neither can see it alone.
pub fn flag_unsigned_driver_risk(inv: &mut Inventory) {
    let test_signing = inv.signals.values().flatten().any(|s| {
        s.label.contains("test signing is enabled")
            || s.label.contains("driver integrity checks are disabled")
    });
    if !test_signing {
        return;
    }
    // Drivers the service layer reported as starting from outside System32.
    let drivers: Vec<String> = inv
        .signals
        .iter()
        .filter(|(_, sigs)| {
            sigs.iter()
                .any(|s| s.label.starts_with("driver starts automatically from outside"))
        })
        .map(|(name, _)| name.clone())
        .collect();

    for name in drivers {
        push_signal(
            &mut inv.signals,
            &name,
            SysSignal::new(
                "third-party driver on a machine where driver signing is not enforced",
                Category::Unsigned,
                Severity::Critical,
                50,
            ),
        );
    }
}
