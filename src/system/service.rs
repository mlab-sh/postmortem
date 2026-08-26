//! Services and drivers — what the machine runs before anyone logs in.
//!
//! `HKLM\SYSTEM\CurrentControlSet\Services` holds **761 keys** on a stock
//! Windows 11 machine: 404 of them are drivers, and 473 never start unless
//! something asks. Enumerating is easy; saying something useful about it is the
//! work.
//!
//! The unquoted-path check is the one that punishes a naive reading. Matching
//! "an unquoted `ImagePath` containing a space" flags **255 of the 761** —
//! nearly all of them `C:\WINDOWS\system32\svchost.exe -k netsvcs -p`, where
//! the space separates the *arguments*, not part of the path. The vulnerability
//! needs a space **inside the executable path**, so that Windows tries
//! `C:\Program.exe` before the real target. Read that way, the reference
//! machine has exactly **one**.

use super::*;

/// One service or driver, read from the registry.
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(default)]
pub(crate) struct Service {
    #[serde(rename = "Name")]
    pub name: String,
    /// The raw `ImagePath`, exactly as stored.
    #[serde(rename = "ImagePath")]
    pub image_path: String,
    /// For a svchost-hosted service, the DLL that actually holds the code.
    #[serde(rename = "ServiceDll")]
    pub service_dll: String,
    /// 0 Boot, 1 System, 2 Auto, 3 Manual, 4 Disabled.
    #[serde(rename = "Start")]
    pub start: Option<u32>,
    /// 1/2 kernel and file-system drivers, 16/32 Win32 services.
    #[serde(rename = "Type")]
    pub kind: Option<u32>,
    /// The program run when the service fails, if any.
    #[serde(rename = "FailureCommand")]
    pub failure_command: String,
    /// The resolved executable, absolute and expanded.
    #[serde(rename = "Target")]
    pub target: String,
    #[serde(rename = "Exists")]
    pub exists: bool,
    /// Directories that would be searched *before* the real target when the
    /// path is unquoted, and that an ordinary user can write to.
    #[serde(rename = "InterceptDirs")]
    pub intercept_dirs: Vec<String>,
}

impl Service {
    /// A driver rather than a user-mode service.
    pub fn is_driver(&self) -> bool {
        matches!(self.kind, Some(1 | 2 | 8))
    }

    /// Starts on its own, before anyone can intervene.
    pub fn is_autostart(&self) -> bool {
        matches!(self.start, Some(0 | 1 | 2))
    }

    /// Lives where Windows' own binaries live.
    pub fn is_system_path(&self) -> bool {
        let p = self.target.to_ascii_lowercase();
        p.contains(r"\system32\") || p.contains(r"\syswow64\") || p.contains(r"\winsxs\")
    }
}

/// Split an `ImagePath` into its executable and its arguments.
///
/// Registry image paths take every shape: quoted, unquoted, relative to
/// `%SystemRoot%`, or prefixed `\SystemRoot\` or `\??\`.
pub(crate) fn split_image_path(image: &str) -> (String, String) {
    let raw = image.trim();
    if let Some(rest) = raw.strip_prefix('"') {
        return match rest.split_once('"') {
            Some((path, args)) => (path.to_string(), args.trim().to_string()),
            None => (rest.to_string(), String::new()),
        };
    }
    // Unquoted: the executable ends at its extension, not at the first space.
    let lower = raw.to_ascii_lowercase();
    for ext in [".exe", ".sys", ".dll"] {
        if let Some(at) = lower.find(ext) {
            let end = at + ext.len();
            if end == lower.len() || lower[end..].starts_with([' ', '\t']) {
                return (raw[..end].to_string(), raw[end..].trim().to_string());
            }
        }
    }
    match raw.split_once(char::is_whitespace) {
        Some((p, a)) => (p.to_string(), a.trim().to_string()),
        None => (raw.to_string(), String::new()),
    }
}

/// Is this image path exploitable through Windows' unquoted-path search?
///
/// Both conditions are required, and it is the second that a naive check drops:
/// the path must be unquoted **and** the executable portion must itself contain
/// a space. `C:\WINDOWS\system32\svchost.exe -k netsvcs` is unquoted and
/// contains spaces, but its *path* does not — Windows never has to guess.
pub(crate) fn is_unquoted_with_space(image: &str) -> bool {
    let raw = image.trim();
    if raw.starts_with('"') || raw.is_empty() {
        return false;
    }
    // A path relative to the system root cannot be intercepted from a
    // user-writable directory the way an absolute one can.
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with(r"\systemroot") || lower.starts_with("system32") || lower.starts_with(r"\??\") {
        return false;
    }
    let (path, _) = split_image_path(raw);
    path.contains(' ')
}

// --- scoring ------------------------------------------------------------------

/// Placeholders Windows and vendors leave in `FailureCommand`. They name no
/// program and run nothing.
const FAILURE_PLACEHOLDERS: &[&str] = &["not used", "customscript.cmd", "", "-"];

/// The signals one service earns.
pub(crate) fn signals_for(svc: &Service) -> Vec<SysSignal> {
    let mut out = Vec::new();

    if is_unquoted_with_space(&svc.image_path) {
        // Whether it is *exploitable* depends on whether one of the directories
        // Windows searches first can be written to. Both are reported, because
        // an unquoted path is worth fixing either way.
        let (severity, points, detail) = if svc.intercept_dirs.is_empty() {
            (
                Severity::Medium,
                20,
                "no writable directory on the search path — not exploitable as configured".to_string(),
            )
        } else {
            (
                Severity::Critical,
                50,
                format!(
                    "a user-writable directory sits on the search path ({})",
                    svc.intercept_dirs.join(", ")
                ),
            )
        };
        out.push(SysSignal::new(
            format!("unquoted service path with spaces — {detail}"),
            Category::WeakAcl,
            severity,
            points,
        ));
    }

    if !svc.target.is_empty() && !svc.exists {
        out.push(SysSignal::new(
            format!("service image is missing ({})", svc.target),
            Category::Persistence,
            if svc.is_autostart() {
                Severity::High
            } else {
                Severity::Medium
            },
            if svc.is_autostart() { 40 } else { 20 },
        ));
    }

    let failure = svc.failure_command.trim().to_ascii_lowercase();
    if !FAILURE_PLACEHOLDERS.contains(&failure.as_str()) && !failure.is_empty() {
        out.push(SysSignal::new(
            format!(
                "runs a program on failure ({})",
                crate::analyze::util::snippet(&svc.failure_command, 60)
            ),
            Category::Persistence,
            Severity::Low,
            10,
        ));
    }

    // Context rather than a finding: 212 of 761 start on their own, which is
    // what a service is for. It qualifies the findings above.
    if svc.is_autostart() && !svc.is_system_path() && !svc.target.is_empty() {
        out.push(SysSignal::new(
            format!(
                "{} starts automatically from outside System32",
                if svc.is_driver() { "driver" } else { "service" }
            ),
            Category::Persistence,
            Severity::Info,
            0,
        ));
    }
    out
}

// --- enumeration ---------------------------------------------------------------

/// Read every service and driver key, resolve its image, and work out whether
/// an unquoted path could be intercepted.
const PS_SERVICES: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'

function Acl-Writers([string]$p) {
  if (-not $p -or -not (Test-Path -LiteralPath $p)) { return @() }
  $out = @()
  foreach ($a in (Get-Acl -LiteralPath $p).Access) {
    if ($a.AccessControlType -ne 'Allow') { continue }
    # An inherit-only ACE applies to child objects created later, never to this
    # one. `C:\` carries such an ACE granting Authenticated Users GENERIC_WRITE,
    # while the ACE that actually governs `C:\` grants only AppendData - the
    # right to create a subdirectory, not a file.
    if ($a.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
    $out += ([string]$a.IdentityReference + '|' + [string]$a.FileSystemRights)
  }
  return $out
}

$root = 'HKLM:\SYSTEM\CurrentControlSet\Services'
foreach ($k in Get-ChildItem $root) {
  $p = Get-ItemProperty $k.PSPath
  $image = [string]$p.ImagePath
  if (-not $image) { continue }

  $exe = Resolve-Image $image

  # For an unquoted path with spaces, the directories Windows searches first.
  $intercept = @()
  if (-not $image.Trim().StartsWith('"') -and $exe -match '\s' -and $exe -match '^[A-Za-z]:') {
    $acc = ''
    foreach ($part in ($exe -split ' ')) {
      if ($acc) { $acc += ' ' }
      $acc += $part
      if ($acc.Length -ge $exe.Length) { break }
      $dir = Split-Path $acc
      if ($dir -and (Test-Path -LiteralPath $dir)) { $intercept += ($dir + '||' + (Acl-Writers $dir | Out-String)) }
    }
  }

  [pscustomobject]@{
    Name           = $k.PSChildName
    ImagePath      = $image
    ServiceDll     = [string](Get-ItemProperty ($k.PSPath + '\Parameters')).ServiceDll
    Start          = $p.Start
    Type           = $p.Type
    FailureCommand = [string]$p.FailureCommand
    Target         = $exe
    Exists         = [bool]($exe -and (Test-Path -LiteralPath $exe))
    InterceptRaw   = @($intercept)
  } | ConvertTo-Json -Compress
}
"#;

/// The raw enumerator record, before intercept directories are judged.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
struct RawService {
    #[serde(flatten)]
    svc: Service,
    /// `dir||identity|rights\nidentity|rights…` for each searched directory.
    #[serde(rename = "InterceptRaw")]
    intercept_raw: Vec<String>,
}

pub(crate) fn parse_services(stdout: &str) -> Vec<Service> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<RawService>(l).ok())
        .map(|mut r| {
            // A searched directory only matters when somebody unprivileged can
            // write to it.
            r.svc.intercept_dirs = r
                .intercept_raw
                .iter()
                .filter_map(|entry| {
                    let (dir, acl) = entry.split_once("||")?;
                    let writable = acl.lines().any(|l| match l.trim().split_once('|') {
                        Some((identity, rights)) => super::is_unprivileged_writer(identity, rights),
                        None => false,
                    });
                    writable.then(|| dir.to_string())
                })
                .collect();
            r.svc.intercept_dirs.dedup();
            r.svc
        })
        .filter(|s: &Service| !s.name.is_empty())
        .collect()
}

pub fn service_inventory(opts: Opts) -> Result<Inventory> {
    let raw = powershell(&format!("{}{}", super::PS_RESOLVE_IMAGE, PS_SERVICES)).context("enumerating services and drivers")?;
    let services = parse_services(&raw);
    if services.is_empty() {
        anyhow::bail!(
            "no services could be read — refusing to report an empty inventory as a clean one"
        );
    }

    let mut signals: HashMap<String, Vec<SysSignal>> = HashMap::new();
    let mut deps = Vec::with_capacity(services.len());
    let (mut drivers, mut autostart) = (0usize, 0usize);

    for s in &services {
        if s.is_driver() {
            drivers += 1;
        }
        if s.is_autostart() {
            autostart += 1;
        }
        for sig in signals_for(s) {
            push_signal(&mut signals, &s.name, sig);
        }
        deps.push(Dependency {
            name: s.name.clone(),
            version: String::new(),
            ecosystem: Ecosystem::Service,
            direct: true,
            scope: Scope::Prod,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url: None,
            integrity: None,
            parents: Vec::new(),
        });
    }

    // Per-binary trust, over what starts on its own from outside System32 —
    // the set where an unsigned image actually means something. Verifying all
    // 761 would restate that Windows signs Windows, slowly.
    if opts.signatures {
        let targets: Vec<&Service> = services
            .iter()
            .filter(|s| s.exists && s.is_autostart() && !s.is_system_path())
            .collect();
        if !targets.is_empty() {
            let paths: Vec<String> = targets.iter().map(|s| s.target.clone()).collect();
            let verified = super::authenticode::verify(&paths);
            for s in &targets {
                let mine: Vec<_> = verified
                    .iter()
                    .filter(|i| i.path.eq_ignore_ascii_case(&s.target))
                    .cloned()
                    .collect();
                for sig in super::authenticode::signals_for_batch(&mine) {
                    push_signal(&mut signals, &s.name, sig);
                }
            }
        }
    }

    let summary = format!(
        "{} service(s) and driver(s): {drivers} drivers, {autostart} start automatically",
        services.len()
    );
    Ok(Inventory {
        manager: "service",
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

    fn svc(image: &str) -> Service {
        let (target, _) = split_image_path(image);
        Service {
            name: "S".into(),
            image_path: image.into(),
            target,
            exists: true,
            start: Some(2),
            kind: Some(32),
            ..Service::default()
        }
    }

    /// The check that punishes a naive reading. `svchost.exe -k netsvcs` is
    /// unquoted and full of spaces, but its *path* has none — Windows never has
    /// to guess. Reading it loosely flagged 255 of the machine's 761 services.
    #[test]
    fn arguments_containing_spaces_are_not_an_unquoted_path() {
        for image in [
            r"C:\WINDOWS\system32\svchost.exe -k netsvcs -p",
            r"C:\WINDOWS\system32\svchost.exe -k LocalServiceNetworkRestricted -p",
            r"C:\WINDOWS\System32\drivers\storahci.sys",
        ] {
            assert!(!is_unquoted_with_space(image), "{image}");
        }
    }

    /// The one the reference machine actually has: an elevation service whose
    /// unquoted path contains spaces.
    #[test]
    fn a_space_inside_the_executable_path_is_the_finding() {
        let real = r"C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher Core\UpcElevationService.exe";
        assert!(is_unquoted_with_space(real));
        // Quoting it removes the ambiguity entirely.
        assert!(!is_unquoted_with_space(&format!("\"{real}\"")));
    }

    /// Paths relative to the system root cannot be intercepted from a
    /// user-writable directory.
    #[test]
    fn system_relative_paths_are_not_candidates() {
        for image in [
            r"\SystemRoot\System32\drivers\a b.sys",
            r"system32\DRIVERS\a b.sys",
            r"\??\C:\a b\x.sys",
            "",
        ] {
            assert!(!is_unquoted_with_space(image), "{image}");
        }
    }

    #[test]
    fn an_image_path_is_split_at_its_extension() {
        assert_eq!(
            split_image_path(r"C:\WINDOWS\system32\svchost.exe -k netsvcs -p"),
            (r"C:\WINDOWS\system32\svchost.exe".into(), "-k netsvcs -p".into())
        );
        assert_eq!(
            split_image_path(r#""C:\Program Files\A B\svc.exe" /service"#),
            (r"C:\Program Files\A B\svc.exe".into(), "/service".into())
        );
        assert_eq!(
            split_image_path(r"C:\Program Files\A B\svc.exe"),
            (r"C:\Program Files\A B\svc.exe".into(), String::new())
        );
    }

    /// Windows tries each space-separated prefix in turn. Those are the
    /// positions an attacker needs to be able to write to.
    #[test]
    /// An unquoted path is worth fixing either way, but only exploitable when
    /// something on the search path can be written to.
    #[test]
    fn exploitability_decides_the_severity() {
        let mut plain = svc(r"C:\Program Files\A B\svc.exe");
        let s = signals_for(&plain).into_iter().find(|s| s.label.starts_with("unquoted")).unwrap();
        assert_eq!(s.severity, Severity::Medium);
        assert!(s.label.contains("not exploitable as configured"));

        plain.intercept_dirs = vec![r"C:\Program Files".into()];
        let s = signals_for(&plain).into_iter().find(|s| s.label.starts_with("unquoted")).unwrap();
        assert_eq!(s.severity, Severity::Critical);
        assert!(s.label.contains(r"C:\Program Files"));
    }

    /// Windows and vendors leave placeholders in `FailureCommand`; only three
    /// of 761 services set it at all, and two of those name no program.
    #[test]
    fn failure_command_placeholders_are_not_findings() {
        for placeholder in ["not used", "customScript.cmd", "", "  "] {
            let mut s = svc(r"C:\WINDOWS\system32\a.exe");
            s.failure_command = placeholder.into();
            assert!(
                !signals_for(&s).iter().any(|x| x.label.contains("on failure")),
                "{placeholder:?}"
            );
        }
        let mut real = svc(r"C:\WINDOWS\system32\a.exe");
        real.failure_command = r"cmd.exe /C C:\vendor\recover.bat".into();
        assert!(signals_for(&real).iter().any(|x| x.label.contains("on failure")));
    }

    #[test]
    fn drivers_and_start_modes_are_read_from_the_registry_values() {
        let mut d = svc(r"C:\WINDOWS\System32\drivers\x.sys");
        d.kind = Some(1);
        d.start = Some(0);
        assert!(d.is_driver() && d.is_autostart() && d.is_system_path());

        let mut manual = svc(r"C:\vendor\x.exe");
        manual.kind = Some(32);
        manual.start = Some(3);
        assert!(!manual.is_driver() && !manual.is_autostart() && !manual.is_system_path());
        // Manual start from outside System32 is not even context.
        assert!(!signals_for(&manual).iter().any(|s| s.label.contains("starts automatically")));
    }

    /// Only an unprivileged writer on the search path counts; the enumerator's
    /// raw ACL facts are judged here.
    #[test]
    fn intercept_directories_are_filtered_by_who_can_write_them() {
        let json = concat!(
            r#"{"Name":"Svc","ImagePath":"C:\\Program Files\\A B\\svc.exe","Start":2,"Type":32,"#,
            r#""Target":"C:\\Program Files\\A B\\svc.exe","Exists":true,"InterceptRaw":["#,
            r#""C:\\||NT AUTHORITY\\SYSTEM|FullControl","#,
            r#""C:\\Program Files||BUILTIN\\Users|Modify, Synchronize"]}"#
        );
        let s = &parse_services(json)[0];
        assert_eq!(s.intercept_dirs, vec![r"C:\Program Files".to_string()],
                   "only the user-writable one survives");
    }
}
