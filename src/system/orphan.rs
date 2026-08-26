//! Orphan backend — what is installed that no package manager claims.
//!
//! WinGet reports a slice of Add/Remove Programs, not all of it: on the
//! reference machine winget surfaced 15 ARP entries against 163 in the
//! registry. Without this layer the scan describes the packages a manager
//! happens to know and calls the machine covered.
//!
//! Two measured calibrations shape it:
//!
//! - **130 of those 163 carry `SystemComponent=1`** — runtimes, redistributables
//!   and driver pieces that Windows deliberately hides from Add/Remove
//!   Programs. Reporting them as findings would bury the 33 that a person
//!   actually installed. They are kept and labelled, never scored: setting
//!   `SystemComponent` is also how something hides itself, so dropping them
//!   would be worse than noisy.
//! - The join back to WinGet is **exact, not fuzzy**: a winget entry for an ARP
//!   package carries the registry key inside its id
//!   (`ARP\Machine\X64\{GUID}`), so matching is on the key, never on a
//!   localized display name.

use super::*;

/// One Add/Remove Programs entry.
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(default)]
pub(crate) struct ArpEntry {
    /// The registry key name — a `{GUID}` product code for an MSI install.
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Publisher")]
    pub publisher: String,
    #[serde(rename = "Location")]
    pub location: String,
    /// Hidden from Add/Remove Programs.
    #[serde(rename = "SystemComponent")]
    pub system_component: bool,
    /// `HKLM`, `HKLM32` (WOW6432Node) or `HKCU`.
    #[serde(rename = "Hive")]
    pub hive: String,
}

/// Enumerate Add/Remove Programs across both hives and both registry views.
///
/// `Win32_Product` is deliberately not used: it is slow and it triggers an MSI
/// self-repair on every package it touches. The registry holds the same data
/// without side effects.
const PS_ARP: &str = r"
$ErrorActionPreference = 'SilentlyContinue'
$views = @(
  @{ Hive = 'HKLM';   Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' },
  @{ Hive = 'HKLM32'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' },
  @{ Hive = 'HKCU';   Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' }
)
foreach ($v in $views) {
  foreach ($p in Get-ItemProperty $v.Path) {
    if (-not $p.DisplayName) { continue }
    [pscustomobject]@{
      Key             = $p.PSChildName
      Name            = $p.DisplayName
      Version         = [string]$p.DisplayVersion
      Publisher       = [string]$p.Publisher
      Location        = [string]$p.InstallLocation
      SystemComponent = ($p.SystemComponent -eq 1)
      Hive            = $v.Hive
    } | ConvertTo-Json -Compress
  }
}
";

/// A ClickOnce deployment leaves no ARP entry of its own worth trusting; its
/// presence is what matters.
const CLICKONCE_DIR: &str = r"Apps\2.0";

// --- parsing ------------------------------------------------------------------

pub(crate) fn parse_arp(stdout: &str) -> Vec<ArpEntry> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<ArpEntry>(l).ok())
        .filter(|e| !e.name.is_empty())
        .collect()
}

/// Is this registry key an MSI product code?
pub(crate) fn is_product_code(key: &str) -> bool {
    let b = key.as_bytes();
    b.len() == 38
        && b[0] == b'{'
        && b[37] == b'}'
        && key[1..37]
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// The identity another layer would use for this entry.
///
/// WinGet names ARP packages `ARP\<scope>\<arch>\<key>`, so the registry key is
/// the join. Lower-cased because nothing guarantees the casing matches.
pub(crate) fn join_key(entry: &ArpEntry) -> String {
    entry.key.to_ascii_lowercase()
}

/// Does any package name from the other layers claim this entry?
///
/// Matches a winget ARP id by its trailing key segment; falls back to an exact
/// name match for the managers that use the display name as the package name.
pub(crate) fn is_claimed(entry: &ArpEntry, claims: &std::collections::HashSet<String>) -> bool {
    let key = join_key(entry);
    if claims.contains(&key) {
        return true;
    }
    let name = entry.name.to_ascii_lowercase();
    claims.contains(&name)
}

/// The set of identities the other layers already account for.
///
/// A winget id like `ARP\Machine\X64\{GUID}` contributes its final segment;
/// every package also contributes its own lower-cased name.
pub(crate) fn claims_from(names: impl Iterator<Item = String>) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    for n in names {
        let lower = n.to_ascii_lowercase();
        if let Some(last) = lower.rsplit('\\').next() {
            out.insert(last.to_string());
        }
        out.insert(lower);
    }
    out
}

// --- inventory ----------------------------------------------------------------

pub fn orphan_inventory(opts: Opts) -> Result<Inventory> {
    let _ = opts;
    let raw = powershell(PS_ARP).context("enumerating Add/Remove Programs")?;
    let entries = parse_arp(&raw);
    if entries.is_empty() {
        anyhow::bail!(
            "no Add/Remove Programs entries could be read — refusing to report an empty \
             inventory as a clean one"
        );
    }

    let mut signals: HashMap<String, Vec<SysSignal>> = HashMap::new();
    let mut deps = Vec::with_capacity(entries.len());
    let (mut hidden, mut user_scope) = (0usize, 0usize);

    for e in &entries {
        // Measured at 130 of 163: the norm, not a finding. Labelled rather than
        // dropped, because hiding here is also a technique.
        if e.system_component {
            hidden += 1;
            push_signal(
                &mut signals,
                &e.name,
                SysSignal::new(
                    "hidden-from-add-remove (SystemComponent)",
                    Category::Policy,
                    Severity::Info,
                    0,
                ),
            );
        }
        if e.hive == "HKCU" {
            user_scope += 1;
            push_signal(
                &mut signals,
                &e.name,
                SysSignal::new(
                    "user-scope install (writable without elevation)",
                    Category::WeakAcl,
                    Severity::Low,
                    10,
                ),
            );
        }
        // An installer that records no publisher gives nothing to attribute it
        // to — the ARP equivalent of an unsigned artefact.
        if e.publisher.trim().is_empty() && !e.system_component {
            push_signal(
                &mut signals,
                &e.name,
                SysSignal::new(
                    "no publisher recorded",
                    Category::Unsigned,
                    Severity::Low,
                    10,
                ),
            );
        }

        deps.push(Dependency {
            name: e.name.clone(),
            version: if e.version.is_empty() {
                "unknown".to_string()
            } else {
                e.version.clone()
            },
            ecosystem: Ecosystem::Arp,
            direct: true,
            scope: Scope::Prod,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url: None,
            // The product code is the closest thing ARP has to an integrity
            // identifier, and it is what joins this entry to other layers.
            integrity: is_product_code(&e.key).then(|| e.key.clone()),
            parents: Vec::new(),
        });
    }

    let mut notes = Vec::new();
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        let dir = std::path::Path::new(&local).join(CLICKONCE_DIR);
        if dir.is_dir() {
            notes.push(
                "ClickOnce deployments are present (%LOCALAPPDATA%\\Apps\\2.0) — they install \
                 per-user without elevation and are not listed by any package manager"
                    .to_string(),
            );
        }
    }

    let summary = format!(
        "{} Add/Remove entry(ies): {} visible, {hidden} system-hidden, {user_scope} user-scope",
        entries.len(),
        entries.len() - hidden
    );
    Ok(Inventory {
        manager: "arp",
        deps,
        repos: Vec::new(),
        signals,
        claims: Vec::new(),
        summary,
        notes,
    })
}

/// Mark the Add/Remove entries that no other layer accounts for.
///
/// Runs over the **merged** inventory, once every layer has been read — it is
/// the only point where "nobody claims this" can be said truthfully.
///
/// Only entries a person would see are candidates. The system-hidden ones
/// (measured at 130 of 163) are runtimes and driver pieces that no package
/// manager was ever going to claim; flagging them would turn the finding into
/// 90% of the machine and make it worthless.
pub fn flag_unclaimed(inv: &mut Inventory) {
    let claims = claims_from(
        inv.deps
            .iter()
            .filter(|d| d.ecosystem != Ecosystem::Arp)
            .map(|d| d.name.clone())
            // Plus the aliases each layer published: a manager's package name
            // is not always the name the registry knows it by.
            .chain(inv.claims.iter().cloned()),
    );

    for dep in inv.deps.iter().filter(|d| d.ecosystem == Ecosystem::Arp) {
        let hidden = inv.signals.get(&dep.name).is_some_and(|sigs| {
            sigs.iter()
                .any(|s| s.label.starts_with("hidden-from-add-remove"))
        });
        if hidden {
            continue;
        }
        let name = dep.name.to_ascii_lowercase();
        let by_code = dep
            .integrity
            .as_deref()
            .map(str::to_ascii_lowercase)
            .is_some_and(|c| claims.contains(&c));
        if by_code || claims.contains(&name) {
            continue;
        }
        push_signal(
            &mut inv.signals,
            &dep.name,
            SysSignal::new(
                "unclaimed (no package manager reports this install)",
                Category::ThirdPartySource,
                Severity::Medium,
                20,
            ),
        );
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim rows from the reference machine's registry, as emitted by
    /// [`PS_ARP`] — one visible MSI package, one system-hidden runtime, one
    /// per-user install.
    const ARP: &str = r#"{"Key":"{6F320B93-EE3C-4826-85E0-ADF79F8D4C61}","Name":"NVIDIA PhysX","Version":"4.9.50.62957","Publisher":"NVIDIA Corporation","Location":"","SystemComponent":false,"Hive":"HKLM"}
{"Key":"{1851460E-0E63-4117-B5BA-25A2F045801B}","Name":"Microsoft Visual C++ 2022 X86 Additional Runtime","Version":"17.7.40001","Publisher":"Microsoft Corporation","Location":"","SystemComponent":true,"Hive":"HKLM32"}
{"Key":"Discord","Name":"Discord","Version":"1.0.9255","Publisher":"Discord Inc.","Location":"C:\\Users\\alice\\AppData\\Local\\Discord","SystemComponent":false,"Hive":"HKCU"}"#;

    fn entries() -> Vec<ArpEntry> {
        parse_arp(ARP)
    }

    #[test]
    fn every_hive_and_view_is_read() {
        let e = entries();
        assert_eq!(e.len(), 3);
        assert_eq!(e[0].hive, "HKLM");
        assert_eq!(e[1].hive, "HKLM32");
        assert_eq!(e[2].hive, "HKCU");
    }

    #[test]
    fn an_msi_key_is_recognised_as_a_product_code() {
        assert!(is_product_code("{6F320B93-EE3C-4826-85E0-ADF79F8D4C61}"));
        // Discord's key is its own name, not a product code.
        assert!(!is_product_code("Discord"));
        assert!(!is_product_code("{too-short}"));
        assert!(!is_product_code("6F320B93-EE3C-4826-85E0-ADF79F8D4C61"));
    }

    /// WinGet names an ARP package `ARP\<scope>\<arch>\<key>`, so the join is
    /// the registry key — never the display name, which is localized.
    #[test]
    fn a_winget_arp_id_claims_the_entry_by_its_key() {
        let claims = claims_from(
            ["ARP\\Machine\\X64\\{6F320B93-EE3C-4826-85E0-ADF79F8D4C61}".to_string()].into_iter(),
        );
        let e = entries();
        assert!(is_claimed(&e[0], &claims), "the product code should join");
        assert!(!is_claimed(&e[2], &claims));
    }

    #[test]
    fn a_manager_that_uses_the_display_name_also_claims_it() {
        let claims = claims_from(["Discord".to_string()].into_iter());
        assert!(is_claimed(&entries()[2], &claims));
    }

    /// The calibration that keeps this layer usable: 130 of the machine's 163
    /// entries are system-hidden runtimes. They are never orphan candidates —
    /// no package manager was going to claim them, and flagging them would make
    /// the finding 90% of the machine.
    #[test]
    fn system_hidden_components_are_never_reported_as_orphans() {
        let mut inv = Inventory {
            manager: "system",
            deps: entries()
                .iter()
                .map(|e| Dependency {
                    name: e.name.clone(),
                    version: e.version.clone(),
                    ecosystem: Ecosystem::Arp,
                    direct: true,
                    scope: Scope::Prod,
                    licenses: Vec::new(),
                    license_source: LicenseSource::Unknown,
                    resolved_url: None,
                    integrity: is_product_code(&e.key).then(|| e.key.clone()),
                    parents: Vec::new(),
                })
                .collect(),
            repos: Vec::new(),
            signals: HashMap::new(),
            claims: Vec::new(),
            summary: String::new(),
            notes: Vec::new(),
        };
        // The hidden runtime carries the marker the real backend attaches.
        push_signal(
            &mut inv.signals,
            "Microsoft Visual C++ 2022 X86 Additional Runtime",
            SysSignal::new(
                "hidden-from-add-remove (SystemComponent)",
                Category::Policy,
                Severity::Info,
                0,
            ),
        );

        flag_unclaimed(&mut inv);

        let unclaimed = |name: &str| {
            inv.signals
                .get(name)
                .is_some_and(|s| s.iter().any(|x| x.label.starts_with("unclaimed")))
        };
        assert!(!unclaimed("Microsoft Visual C++ 2022 X86 Additional Runtime"));
        assert!(unclaimed("NVIDIA PhysX"), "a visible unclaimed install is the finding");
        assert!(unclaimed("Discord"));
    }

    /// The false positive this alias exists for: winget reports the package as
    /// `Ubisoft.Connect` while the registry records `Ubisoft Connect`, and the
    /// registry key winget covers is never exposed. Without the display-name
    /// alias, a package winget actively manages reads as unclaimed.
    #[test]
    fn a_layers_display_name_alias_claims_the_registry_entry() {
        let arp = Dependency {
            name: "Ubisoft Connect".into(),
            version: "172.0.13225".into(),
            ecosystem: Ecosystem::Arp,
            direct: true,
            scope: Scope::Prod,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url: None,
            integrity: None,
            parents: Vec::new(),
        };
        let winget = Dependency {
            name: "Ubisoft.Connect".into(),
            ecosystem: Ecosystem::Winget,
            ..arp.clone()
        };
        let build = |claims: Vec<String>, deps: Vec<Dependency>| Inventory {
            manager: "system",
            deps,
            repos: Vec::new(),
            signals: HashMap::new(),
            claims,
            summary: String::new(),
            notes: Vec::new(),
        };

        // Without the alias, the winget id does not match the display name.
        let mut bare = build(Vec::new(), vec![arp.clone(), winget.clone()]);
        flag_unclaimed(&mut bare);
        assert!(bare.signals.contains_key("Ubisoft Connect"));

        // With it, the entry is correctly recognised as managed.
        let mut aliased = build(vec!["Ubisoft Connect".into()], vec![arp, winget]);
        flag_unclaimed(&mut aliased);
        assert!(
            !aliased.signals.contains_key("Ubisoft Connect"),
            "the display-name alias must claim it"
        );
    }

    /// And an entry another layer does claim is not an orphan.
    #[test]
    fn an_entry_claimed_by_another_layer_is_left_alone() {
        let mut inv = Inventory {
            manager: "system",
            deps: vec![
                Dependency {
                    name: "NVIDIA PhysX".into(),
                    version: "4.9".into(),
                    ecosystem: Ecosystem::Arp,
                    direct: true,
                    scope: Scope::Prod,
                    licenses: Vec::new(),
                    license_source: LicenseSource::Unknown,
                    resolved_url: None,
                    integrity: Some("{6F320B93-EE3C-4826-85E0-ADF79F8D4C61}".into()),
                    parents: Vec::new(),
                },
                Dependency {
                    name: "ARP\\Machine\\X64\\{6F320B93-EE3C-4826-85E0-ADF79F8D4C61}".into(),
                    version: "4.9".into(),
                    ecosystem: Ecosystem::Winget,
                    direct: true,
                    scope: Scope::Prod,
                    licenses: Vec::new(),
                    license_source: LicenseSource::Unknown,
                    resolved_url: None,
                    integrity: None,
                    parents: Vec::new(),
                },
            ],
            repos: Vec::new(),
            signals: HashMap::new(),
            claims: Vec::new(),
            summary: String::new(),
            notes: Vec::new(),
        };
        flag_unclaimed(&mut inv);
        assert!(inv.signals.get("NVIDIA PhysX").is_none());
    }
}
