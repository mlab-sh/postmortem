//! Scheduled tasks — the other half of the logon/boot persistence surface.
//!
//! A stock Windows 11 machine has ~250 scheduled tasks and **243 of them live
//! under `\Microsoft\`**. Scoring a task for running as SYSTEM (154 of 252) or
//! elevated (91 of 252) would describe Windows, not a threat. The folder is the
//! discriminator the surface actually offers: only **9** tasks sat outside
//! `\Microsoft\` on the reference machine, and those are the ones worth
//! resolving.
//!
//! So privilege is scored **in combination** with provenance, never alone.

use super::asep::split_command;
use super::*;

/// One scheduled task, as emitted by [`PS_TASKS`].
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(default)]
pub(crate) struct Task {
    /// Folder path, e.g. `\Microsoft\Windows\Defrag\` or `\Ubisoft\`.
    #[serde(rename = "Path")]
    pub path: String,
    #[serde(rename = "Name")]
    pub name: String,
    /// `SYSTEM`, `LOCAL SERVICE`, a user, or empty.
    #[serde(rename = "UserId")]
    pub user: String,
    /// `Highest` or `Limited`.
    #[serde(rename = "RunLevel")]
    pub run_level: String,
    /// `Exec` or `ComHandler`.
    #[serde(rename = "ActionKind")]
    pub action_kind: String,
    /// The executable for an `Exec` action, empty for a COM handler.
    #[serde(rename = "Execute")]
    pub execute: String,
    #[serde(rename = "Arguments")]
    pub arguments: String,
    /// The COM class a `ComHandler` action instantiates.
    #[serde(rename = "ClassId")]
    pub class_id: String,
    /// Trigger kinds, e.g. `Boot`, `Logon`, `Event`.
    #[serde(rename = "Triggers")]
    pub triggers: Vec<String>,
    /// The resolved executable path (forward slashes normalised).
    #[serde(rename = "Target")]
    pub target: String,
    #[serde(rename = "Exists")]
    pub exists: bool,
    /// Raw `identity|rights` pairs for the task's definition file.
    #[serde(rename = "AclEntries")]
    pub acl_entries: Vec<String>,
}

impl Task {
    /// The task's definition can be rewritten by an ordinary user.
    pub fn file_writable(&self) -> bool {
        self.acl_entries.iter().any(|e| match e.split_once('|') {
            Some((identity, rights)) => super::is_unprivileged_writer(identity, rights),
            None => false,
        })
    }

    /// The full identity, folder included: task names repeat across folders.
    pub fn full_name(&self) -> String {
        format!("{}{}", self.path, self.name)
    }

    /// Tasks Windows ships live under `\Microsoft\`. This is provenance, not a
    /// verdict — Microsoft also registers tasks at the root (`OneDrive …`,
    /// `MicrosoftEdgeUpdateTask…`), which is why the signature of what a task
    /// runs still decides.
    pub fn is_microsoft_folder(&self) -> bool {
        self.path.to_ascii_lowercase().starts_with(r"\microsoft\")
    }

    /// Runs with more authority than the user who registered it.
    pub fn is_privileged(&self) -> bool {
        let u = self.user.to_ascii_uppercase();
        self.run_level.eq_ignore_ascii_case("Highest")
            || u == "SYSTEM"
            || u.ends_with("\\SYSTEM")
            || u == "LOCAL SERVICE"
            || u == "NETWORK SERVICE"
    }

    /// Fires without anyone asking.
    pub fn is_autostart(&self) -> bool {
        self.triggers
            .iter()
            .any(|t| matches!(t.as_str(), "Boot" | "Logon" | "SessionStateChange"))
    }
}

/// Normalise a task's `Execute` value.
///
/// Task XML carries forward slashes as readily as backslashes — the reference
/// machine's Ubisoft task reads `C:/Program Files (x86)/…/upc.exe` — and the
/// value may or may not be quoted.
pub(crate) fn normalise_target(execute: &str) -> String {
    let (path, _) = split_command(execute.trim());
    path.replace('/', "\\")
}

// --- scoring ------------------------------------------------------------------

/// The signals one task earns.
pub(crate) fn signals_for(task: &Task) -> Vec<SysSignal> {
    let mut out = Vec::new();
    let first_party = task.is_microsoft_folder();

    // Anyone able to rewrite the definition owns whatever it runs — and 154 of
    // these run as SYSTEM. This one stands on its own, whoever registered it.
    if task.file_writable() {
        out.push(SysSignal::new(
            "task definition is writable without elevation",
            Category::WeakAcl,
            if task.is_privileged() {
                Severity::Critical
            } else {
                Severity::High
            },
            if task.is_privileged() { 50 } else { 40 },
        ));
    }

    // Privilege is not a finding by itself: it describes most of Windows. It is
    // one when the task did not come from Windows.
    if !first_party && task.is_privileged() && task.is_autostart() {
        out.push(SysSignal::new(
            format!(
                "third-party task runs privileged at {} (as {}, {})",
                task.triggers.join("/"),
                if task.user.is_empty() { "-" } else { &task.user },
                task.run_level
            ),
            Category::Persistence,
            Severity::Medium,
            20,
        ));
    }

    if !task.target.is_empty() && !task.exists {
        out.push(SysSignal::new(
            format!("task action target is missing ({})", task.target),
            Category::Persistence,
            if task.is_privileged() {
                Severity::High
            } else {
                Severity::Medium
            },
            if task.is_privileged() { 40 } else { 20 },
        ));
    }

    // An interpreter in the command line is how a good part of Windows works:
    // 22 of the machine's own tasks drive `rundll32`. It is a finding when the
    // task did not come from Windows, and context when it did — the same rule
    // the MSIX capabilities follow.
    let line = format!("{} {}", task.execute, task.arguments);
    if let Some(why) = super::asep::lolbin_in(&line) {
        let (severity, points) = if first_party {
            (Severity::Info, 0)
        } else {
            (Severity::High, 40)
        };
        out.push(SysSignal::new(
            format!("task command uses {why}"),
            Category::Persistence,
            severity,
            points,
        ));
    }

    // A COM handler runs an in-process class rather than a named executable, so
    // there is no path to verify. Ordinary for Windows' own tasks (155 of 252);
    // worth surfacing when it is somebody else's.
    if task.action_kind.eq_ignore_ascii_case("ComHandler") && !first_party {
        out.push(SysSignal::new(
            format!(
                "third-party task runs a COM handler ({}) — no executable to verify",
                task.class_id
            ),
            Category::Persistence,
            Severity::Low,
            10,
        ));
    }
    out
}

/// Tasks present in the scheduler's cache but absent from the enumeration.
///
/// The registry cache is what the service reads; the enumeration is what the UI
/// and `Get-ScheduledTask` show. A task in one and not the other is hiding.
pub(crate) fn hidden_tasks(cached: &[String], enumerated: &[String]) -> Vec<String> {
    let live: std::collections::HashSet<String> = enumerated
        .iter()
        .map(|t| t.to_ascii_lowercase())
        .collect();
    cached
        .iter()
        .filter(|c| !live.contains(&c.to_ascii_lowercase()))
        .cloned()
        .collect()
}

// --- enumeration ---------------------------------------------------------------

/// Enumerate every scheduled task, resolve its action, and read the cache the
/// scheduler itself uses.
const PS_TASKS: &str = r#"
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

foreach ($t in Get-ScheduledTask) {
  $a = @($t.Actions)[0]
  $kind = if ($a.CimClass.CimClassName -eq 'MSFT_TaskComHandlerAction') { 'ComHandler' } else { 'Exec' }
  $exec = [string]$a.Execute
  $target = ''
  if ($exec) {
    $e = $exec.Trim('"').Replace('/', '\')
    $target = [Environment]::ExpandEnvironmentVariables($e)
  }
  # The definition file is the task: whoever can rewrite it owns what it runs.
  $file = Join-Path $env:WINDIR ('System32\Tasks' + $t.TaskPath + $t.TaskName)
  $triggers = @()
  foreach ($tr in $t.Triggers) {
    $triggers += (($tr.CimClass.CimClassName -replace '^MSFT_Task', '') -replace 'Trigger$', '')
  }
  [pscustomobject]@{
    Path         = [string]$t.TaskPath
    Name         = [string]$t.TaskName
    UserId       = [string]$t.Principal.UserId
    RunLevel     = [string]$t.Principal.RunLevel
    ActionKind   = $kind
    Execute      = $exec
    Arguments    = [string]$a.Arguments
    ClassId      = [string]$a.ClassId
    Triggers     = @($triggers)
    Target       = $target
    Exists       = [bool]($target -and (Test-Path -LiteralPath $target))
    AclEntries   = @(Acl-Writers $file)
  } | ConvertTo-Json -Compress
}
"#;

/// The scheduler's own cache — what the service reads, as opposed to what the
/// enumeration shows.
const PS_TASKCACHE: &str = r"
$ErrorActionPreference = 'SilentlyContinue'
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks' |
  ForEach-Object { (Get-ItemProperty $_.PSPath).Path } |
  Where-Object { $_ } |
  ForEach-Object { $_ }
";

pub(crate) fn parse_tasks(stdout: &str) -> Vec<Task> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<Task>(l).ok())
        .filter(|t: &Task| !t.name.is_empty())
        .collect()
}

pub fn task_inventory(opts: Opts) -> Result<Inventory> {
    let raw = powershell(PS_TASKS).context("enumerating scheduled tasks")?;
    let tasks = parse_tasks(&raw);
    if tasks.is_empty() {
        anyhow::bail!(
            "no scheduled tasks could be read — refusing to report an empty inventory as a \
             clean one"
        );
    }

    let mut signals: HashMap<String, Vec<SysSignal>> = HashMap::new();
    let mut deps = Vec::with_capacity(tasks.len());
    let mut third_party = 0usize;

    for t in &tasks {
        let name = t.full_name();
        if !t.is_microsoft_folder() {
            third_party += 1;
        }
        for sig in signals_for(t) {
            push_signal(&mut signals, &name, sig);
        }
        deps.push(Dependency {
            name,
            version: String::new(),
            ecosystem: Ecosystem::Task,
            direct: true,
            scope: Scope::Prod,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url: None,
            integrity: None,
            parents: Vec::new(),
        });
    }

    // Per-binary trust over what the tasks actually run. Only the third-party
    // ones: verifying 243 Microsoft tasks would cost time to restate that
    // Windows signs Windows.
    if opts.signatures {
        let targets: Vec<&Task> = tasks
            .iter()
            .filter(|t| t.exists && !t.target.is_empty() && !t.is_microsoft_folder())
            .collect();
        if !targets.is_empty() {
            let paths: Vec<String> = targets.iter().map(|t| t.target.clone()).collect();
            let verified = super::authenticode::verify(&paths);
            for t in &targets {
                let mine: Vec<_> = verified
                    .iter()
                    .filter(|i| i.path.eq_ignore_ascii_case(&t.target))
                    .cloned()
                    .collect();
                for sig in super::authenticode::signals_for_batch(&mine) {
                    push_signal(&mut signals, &t.full_name(), sig);
                }
            }
        }
    }

    // A task the scheduler knows about but the enumeration does not show is
    // hiding, which no legitimate installer needs to do.
    let mut notes = Vec::new();
    if let Ok(cache) = powershell(PS_TASKCACHE) {
        let cached: Vec<String> = cache
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with('\\'))
            .map(String::from)
            .collect();
        let enumerated: Vec<String> = tasks.iter().map(Task::full_name).collect();
        for h in hidden_tasks(&cached, &enumerated) {
            notes.push(format!(
                "task '{h}' is registered in the scheduler's cache but absent from the task \
                 listing [High] — it runs without being visible"
            ));
        }
    }

    let summary = format!(
        "{} scheduled task(s): {third_party} outside \\Microsoft\\",
        tasks.len()
    );
    Ok(Inventory {
        manager: "task",
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

    fn task(path: &str, user: &str, level: &str, triggers: &[&str]) -> Task {
        Task {
            path: path.into(),
            name: "T".into(),
            user: user.into(),
            run_level: level.into(),
            action_kind: "Exec".into(),
            execute: r"C:\x\a.exe".into(),
            target: r"C:\x\a.exe".into(),
            exists: true,
            triggers: triggers.iter().map(|s| (*s).into()).collect(),
            ..Task::default()
        }
    }

    /// Task XML carries forward slashes as readily as backslashes — the
    /// reference machine's Ubisoft task reads `C:/Program Files (x86)/…`.
    #[test]
    fn a_target_is_normalised_whatever_slashes_it_uses() {
        assert_eq!(
            normalise_target("C:/Program Files (x86)/Ubisoft/Ubisoft Game Launcher/upc.exe"),
            r"C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\upc.exe"
        );
        assert_eq!(
            normalise_target(r#""C:\Program Files\Thing\run.exe" --flag"#),
            r"C:\Program Files\Thing\run.exe"
        );
    }

    /// The discriminator the surface actually offers: 243 of 252 tasks live
    /// under `\Microsoft\`.
    #[test]
    fn the_folder_separates_windows_own_tasks() {
        assert!(task(r"\Microsoft\Windows\Defrag\", "SYSTEM", "Highest", &[]).is_microsoft_folder());
        assert!(task(r"\microsoft\windows\", "SYSTEM", "Highest", &[]).is_microsoft_folder());
        assert!(!task(r"\Ubisoft\", "alice", "Limited", &[]).is_microsoft_folder());
        // Microsoft also registers tasks at the root, which the folder alone
        // cannot tell apart - the signature of what they run does.
        assert!(!task(r"\", "SYSTEM", "Highest", &[]).is_microsoft_folder());
    }

    /// Privilege alone describes Windows: SYSTEM covers 154 of 252 tasks and
    /// `Highest` 91. It is a finding only combined with provenance and a
    /// trigger that fires on its own.
    #[test]
    fn privilege_alone_is_not_a_finding() {
        // Windows' own, privileged, boot-triggered: silent.
        let ms = task(r"\Microsoft\Windows\Defrag\", "SYSTEM", "Highest", &["Boot"]);
        assert!(!signals_for(&ms).iter().any(|s| s.label.contains("privileged")));

        // Third party, privileged, but only ever run on demand: silent too.
        let ondemand = task(r"\Vendor\", "SYSTEM", "Highest", &["Time"]);
        assert!(!signals_for(&ondemand).iter().any(|s| s.label.contains("privileged")));

        // Third party, privileged, fires at boot: that is the combination.
        let third = task(r"\Vendor\", "SYSTEM", "Highest", &["Boot"]);
        let s = signals_for(&third)
            .into_iter()
            .find(|s| s.label.contains("privileged"))
            .expect("should flag");
        assert_eq!(s.severity, Severity::Medium);
        assert_eq!(s.category, Category::Persistence);
    }

    /// The reference machine's own third-party tasks run as the user, and must
    /// stay quiet.
    #[test]
    fn an_ordinary_third_party_task_is_silent() {
        let mut ubisoft = task(r"\Ubisoft\", "alice", "Limited", &["Logon"]);
        ubisoft.execute = "C:/Program Files (x86)/Ubisoft/Ubisoft Game Launcher/upc.exe".into();
        ubisoft.arguments = "-upc_scheduled_task update".into();
        ubisoft.target = normalise_target(&ubisoft.execute);
        assert!(signals_for(&ubisoft).is_empty(), "{:?}", signals_for(&ubisoft).iter().map(|s| s.label.clone()).collect::<Vec<_>>());
    }

    /// Whoever can rewrite the definition owns what it runs - and most of these
    /// run as SYSTEM. This one stands whoever registered it.
    #[test]
    fn a_writable_definition_stands_on_its_own() {
        let mut ms = task(r"\Microsoft\Windows\Defrag\", "SYSTEM", "Highest", &["Boot"]);
        ms.acl_entries = vec![r"BUILTIN\Users|Modify, Synchronize".to_string()];
        let s = signals_for(&ms)
            .into_iter()
            .find(|s| s.label.contains("writable without elevation"))
            .expect("should flag even for a Microsoft task");
        assert_eq!(s.severity, Severity::Critical, "it runs privileged");

        let mut plain = task(r"\Vendor\", "alice", "Limited", &["Logon"]);
        plain.acl_entries = vec![r"BUILTIN\Users|Modify, Synchronize".to_string()];
        let s = signals_for(&plain).into_iter().find(|s| s.label.contains("writable")).unwrap();
        assert_eq!(s.severity, Severity::High);
    }

    #[test]
    fn a_missing_action_target_is_scored_by_privilege() {
        let mut priv_ = task(r"\Vendor\", "SYSTEM", "Highest", &["Boot"]);
        priv_.exists = false;
        assert_eq!(
            signals_for(&priv_).iter().find(|s| s.label.contains("missing")).unwrap().severity,
            Severity::High
        );

        let mut user = task(r"\Vendor\", "alice", "Limited", &["Logon"]);
        user.exists = false;
        assert_eq!(
            signals_for(&user).iter().find(|s| s.label.contains("missing")).unwrap().severity,
            Severity::Medium
        );
    }

    #[test]
    fn an_interpreter_in_a_task_command_is_the_finding() {
        let mut t = task(r"\Vendor\", "SYSTEM", "Highest", &["Boot"]);
        t.execute = "powershell.exe".into();
        t.arguments = "-enc SQBFAFgA".into();
        let sigs = signals_for(&t);
        assert_eq!(sigs.iter().filter(|s| s.label.starts_with("task command uses")).count(), 1);
    }

    /// COM handlers are how 155 of 252 Windows tasks work, so they are only
    /// surfaced when somebody else uses one.
    #[test]
    fn a_com_handler_is_only_surfaced_for_a_third_party_task() {
        let mut ms = task(r"\Microsoft\Windows\Shell\", "SYSTEM", "Highest", &["Logon"]);
        ms.action_kind = "ComHandler".into();
        ms.execute = String::new();
        ms.target = String::new();
        ms.class_id = "{ABC}".into();
        assert!(!signals_for(&ms).iter().any(|s| s.label.contains("COM handler")));

        let mut third = ms.clone();
        third.path = r"\Vendor\".into();
        let s = signals_for(&third)
            .into_iter()
            .find(|s| s.label.contains("COM handler"))
            .expect("should surface");
        assert_eq!(s.severity, Severity::Low);
        assert!(s.label.contains("{ABC}"));
    }

    /// A task the scheduler knows but the listing does not show is hiding.
    /// On the reference machine both sides held 252 entries and this found
    /// nothing, which is the correct answer there.
    #[test]
    fn a_task_present_only_in_the_cache_is_hidden() {
        let cached = vec![
            r"\Microsoft\Windows\Defrag\ScheduledDefrag".to_string(),
            r"\Vendor\Sneaky".to_string(),
        ];
        let listed = vec![r"\Microsoft\Windows\Defrag\ScheduledDefrag".to_string()];
        assert_eq!(hidden_tasks(&cached, &listed), vec![r"\Vendor\Sneaky".to_string()]);

        // Matching is case-insensitive, and a clean machine yields nothing.
        let listed_odd = vec![r"\microsoft\windows\defrag\scheduleddefrag".to_string(), r"\vendor\sneaky".to_string()];
        assert!(hidden_tasks(&cached, &listed_odd).is_empty());
    }

    #[test]
    fn tasks_are_parsed_from_the_enumerators_json() {
        let json = r#"{"Path":"\\Ubisoft\\","Name":"Ubisoft Connect Background Update","UserId":"alice","RunLevel":"Limited","ActionKind":"Exec","Execute":"C:/Program Files (x86)/Ubisoft/upc.exe","Arguments":"-upc_scheduled_task update","ClassId":"","Triggers":["Logon"],"Target":"C:\\Program Files (x86)\\Ubisoft\\upc.exe","Exists":true,"AclEntries":[]}"#;
        let t = parse_tasks(json);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].full_name(), r"\Ubisoft\Ubisoft Connect Background Update");
        assert_eq!(t[0].triggers, vec!["Logon".to_string()]);
        assert!(!t[0].is_microsoft_folder());
    }
}
