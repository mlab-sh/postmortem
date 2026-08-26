//! WinGet backend — Windows' first-party package manager.
//!
//! Three commands feed it, and each choice is deliberate:
//!
//! - `winget source export` emits **JSON-lines** carrying `Type` and
//!   `TrustLevel`. Every source verdict keys off those, never off a name
//!   allowlist: Microsoft ships a *third* default source (`winget-font`)
//!   beside `winget` and `msstore`, so an allowlist of the latter two reports a
//!   third-party source on a stock machine.
//! - `winget list` is the only complete view. It merges three layers into one
//!   table — winget-managed packages, MSIX/Appx, and registry Uninstall
//!   entries — and has no machine-readable output, so it is parsed positionally
//!   from its own header.
//! - `winget export` is deliberately **not** used: it silently drops every
//!   package it cannot resolve to a source, which is exactly the set worth
//!   looking at.

use super::*;

/// Which layer an entry came from, read off the `Id` prefix. `winget list`
/// reports all of them side by side, and the prefix is the only stable
/// discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// A package winget resolves to one of its sources.
    Winget,
    /// An MSIX/Appx package — Store-managed, not winget's to govern.
    Msix,
    /// A registry Uninstall entry, machine scope.
    ArpMachine,
    /// A registry Uninstall entry, per-user scope: installed into a location
    /// the user can rewrite without elevating.
    ArpUser,
}

impl Origin {
    fn of(id: &str) -> Origin {
        // Case-insensitive: the prefixes are winget's own, but nothing
        // guarantees their casing across versions.
        let up = id.to_ascii_uppercase();
        if up.starts_with("MSIX\\") {
            Origin::Msix
        } else if up.starts_with("ARP\\USER") {
            Origin::ArpUser
        } else if up.starts_with("ARP\\") {
            Origin::ArpMachine
        } else {
            Origin::Winget
        }
    }
}

/// One row of `winget list`.
///
/// The `Name` column is deliberately discarded: it is **localized** (a French
/// machine reports "Bloc-notes Windows"), so anything keyed on it breaks with
/// the display language. `Id` is stable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Row {
    pub id: String,
    pub version: String,
    /// The newer version winget knows about, when it knows of one. Empty is the
    /// common case and means "nothing newer", not "unknown".
    pub available: String,
    /// The source winget resolved it to; empty when winget does not manage it.
    pub source: String,
}

/// One configured winget source, as reported by `winget source export`.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct WingetSource {
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "Arg", default)]
    pub arg: String,
    #[serde(rename = "Type", default)]
    pub kind: String,
    #[serde(rename = "TrustLevel", default)]
    pub trust: Vec<String>,
}

/// Hosts whose sources are Microsoft's own. Checked as a domain suffix on the
/// source URL rather than by source name, so renaming a source cannot launder
/// it into looking first-party.
const MS_SOURCE_HOSTS: &[&str] = &["cdn.winget.microsoft.com", "storeedgefd.dsx.mp.microsoft.com"];

/// Admin settings that *weaken* verification when enabled, with what each one
/// actually costs. All default to `Disabled`; a machine that enabled one has
/// traded away a specific guarantee.
const RISKY_ADMIN_SETTINGS: &[(&str, Severity, &str)] = &[
    (
        "InstallerHashOverride",
        Severity::Critical,
        "installer hash mismatches can be overridden — the SHA256 in the manifest stops being binding",
    ),
    (
        "LocalManifestFiles",
        Severity::High,
        "packages can be installed from arbitrary local manifests, bypassing the curated sources",
    ),
    (
        "BypassCertificatePinningForMicrosoftStore",
        Severity::High,
        "Store certificate pinning is off — Store traffic is open to interception",
    ),
    (
        "LocalArchiveMalwareScanOverride",
        Severity::High,
        "the malware scan on local archives can be skipped",
    ),
    (
        "ConfigurationProcessorPath",
        Severity::High,
        "a custom configuration processor can be loaded from an arbitrary path",
    ),
    (
        "ProxyCommandLineOptions",
        Severity::Medium,
        "a proxy can be set per-invocation, redirecting where installers are fetched from",
    ),
];

// --- parsing ------------------------------------------------------------------

/// Parse the JSON-lines of `winget source export`.
///
/// Malformed lines are skipped rather than failing the whole read: a source we
/// cannot parse must not hide the ones we can.
pub(crate) fn parse_sources(stdout: &str) -> Vec<WingetSource> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<WingetSource>(l).ok())
        .collect()
}

/// Parse the fixed-width table of `winget list`.
///
/// Column offsets are read off the header on **every run** — winget sizes each
/// column to its widest value, so they are not constants. Slicing is by
/// character, never by byte: the localized `Name` column is multi-byte in UTF-8
/// ("Améliorations…"), and byte offsets would cut the following `Id` in half.
///
/// Returns `None` when the table shape is not recognised, so the caller can
/// report an unreadable inventory rather than an empty one.
pub(crate) fn parse_list(stdout: &str) -> Option<Vec<Row>> {
    let lines: Vec<&str> = stdout.lines().collect();
    // The separator is a run of dashes; the header is the line above it. Anchor
    // on the separator because the header's own words are localized.
    let sep = lines
        .iter()
        .position(|l| l.chars().filter(|c| *c == '-').count() > 10)?;
    let header = lines.get(sep.checked_sub(1)?)?;

    let cols = header_columns(header);
    if cols.len() < 4 {
        return None;
    }
    // Column indices, not offsets: every field is bounded by the *next* column's
    // start. Reading `Version` all the way to `Source` swallows `Available`, and
    // a package with an upgrade pending comes out as
    // "< 172.1.0.13247   172.1.0.13247".
    let idx = |name: &str| cols.iter().position(|(t, _)| t.eq_ignore_ascii_case(name));
    // Positional fallback: winget's column order is Name, Id, Version,
    // Available, Source whatever the display language.
    let (c_id, c_ver) = match (idx("Id"), idx("Version")) {
        (Some(a), Some(b)) => (a, b),
        _ => (1, 2),
    };
    let c_avail = idx("Available").unwrap_or(c_ver + 1);
    let c_src = cols.len() - 1;
    let start = |i: usize| cols[i].1;
    let end = |i: usize| cols.get(i + 1).map_or(usize::MAX, |c| c.1);

    let rows = lines[sep + 1..]
        .iter()
        .filter_map(|l| {
            let id = slice_chars(l, start(c_id), end(c_id));
            if id.is_empty() {
                return None;
            }
            Some(Row {
                id,
                version: slice_chars(l, start(c_ver), end(c_ver)),
                available: slice_chars(l, start(c_avail), end(c_avail)),
                source: slice_chars(l, start(c_src), usize::MAX),
            })
        })
        .collect();
    Some(rows)
}

/// `(token, starting char offset)` for each column of a header line.
fn header_columns(header: &str) -> Vec<(String, usize)> {
    let chars: Vec<char> = header.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        // A single space inside a header word is possible in some languages, so
        // a column only ends on two consecutive spaces.
        while i < chars.len() && !(chars[i] == ' ' && chars.get(i + 1) == Some(&' ')) {
            i += 1;
        }
        out.push((chars[start..i].iter().collect::<String>().trim().to_string(), start));
        i += 1;
    }
    out
}

/// `[from, to)` of a line, counted in characters, clamped to its length.
fn slice_chars(line: &str, from: usize, to: usize) -> String {
    line.chars()
        .skip(from)
        .take(to.saturating_sub(from))
        .collect::<String>()
        .trim()
        .to_string()
}

/// Parse the `Admin Setting` / `State` table of `winget --info` into
/// `(setting, enabled)`.
pub(crate) fn parse_admin_settings(info: &str) -> Vec<(String, bool)> {
    info.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let name = it.next()?;
            let state = it.next()?;
            // Only the two-token rows of that table look like this, and only
            // the settings we know about are kept — so other tables in the
            // same output cannot leak in.
            let known = RISKY_ADMIN_SETTINGS.iter().any(|(n, _, _)| *n == name);
            match (known, state) {
                (true, "Enabled") => Some((name.to_string(), true)),
                (true, "Disabled") => Some((name.to_string(), false)),
                _ => None,
            }
        })
        .collect()
}

// --- scoring ------------------------------------------------------------------

/// Is this source one of Microsoft's own? Keyed on the URL host and the trust
/// level winget itself reports, never on the source's name.
pub(crate) fn source_is_official(s: &WingetSource) -> bool {
    let trusted = s.trust.iter().any(|t| t.eq_ignore_ascii_case("Trusted"));
    let host = s
        .arg
        .split("//")
        .nth(1)
        .and_then(|r| r.split('/').next())
        .unwrap_or("")
        .to_ascii_lowercase();
    trusted && MS_SOURCE_HOSTS.iter().any(|h| host == *h)
}

/// The machine-wide caveat a non-official source deserves.
///
/// A custom `Microsoft.PreIndexed.Package` outranks a custom REST source: its
/// index is an MSIX that must be signed by a machine-trusted certificate, so a
/// custom one means an installed trust anchor we cannot see from here.
pub(crate) fn source_note(s: &WingetSource) -> String {
    let kind = if s.kind.eq_ignore_ascii_case("Microsoft.PreIndexed.Package") {
        "custom pre-indexed source (its MSIX index is signed by a certificate this machine was made to trust)"
    } else if s.kind.eq_ignore_ascii_case("Microsoft.Rest") {
        "self-hosted REST source"
    } else {
        "third-party source"
    };
    let trust = if s.trust.is_empty() {
        "no trust level".to_string()
    } else {
        s.trust.join("+")
    };
    format!("{}: {} [{}] — {kind}, trust: {trust}", s.name, s.arg, s.kind)
}

// --- inventory ----------------------------------------------------------------

/// Build the winget inventory: configured sources, then the installed table.
pub fn winget_inventory(opts: Opts) -> Result<Inventory> {
    let _ = opts; // winget reputation comes from the shared `--online` path

    let sources = run_winget(&["source", "export"])
        .map(|o| parse_sources(&o))
        .unwrap_or_default();
    let repos: Vec<Repo> = sources
        .iter()
        .map(|s| Repo {
            name: s.name.clone(),
            url: s.arg.clone(),
            official: source_is_official(s),
        })
        .collect();

    let listing = run_winget(&["list", "--disable-interactivity"])
        .context("running `winget list`")?;
    let rows = parse_list(&listing).context(
        "`winget list` produced a table postmortem could not read — refusing to report a \
         partial inventory as a complete one",
    )?;

    let mut signals: HashMap<String, Vec<SysSignal>> = HashMap::new();
    let mut deps = Vec::with_capacity(rows.len());
    let (mut msix, mut arp) = (0usize, 0usize);

    for r in &rows {
        let origin = Origin::of(&r.id);
        match origin {
            Origin::Msix => msix += 1,
            Origin::ArpMachine | Origin::ArpUser => arp += 1,
            Origin::Winget => {}
        }

        // Deliberately Info, not a finding. On a stock machine most entries are
        // MSIX or ARP and winget does not manage them — measured at 53 of 88 on
        // the reference box. Scoring that as "shadow install" would light up
        // two thirds of every scan and mean nothing. A genuine shadow install
        // is a package winget *knows* that was installed around it, which needs
        // cross-referencing a source, not an empty column.
        if origin != Origin::Winget {
            push_signal(
                &mut signals,
                &r.id,
                SysSignal::new(
                    "unmanaged-by-winget",
                    Category::ThirdPartySource,
                    Severity::Info,
                    0,
                ),
            );
        }
        // winget already resolved what the current release is; that is exactly
        // the input `outdated_signal` wants, so an upgrade pending becomes a
        // scored signal rather than a column nobody reads.
        if !r.available.is_empty() && r.available != r.version {
            push_signal(
                &mut signals,
                &r.id,
                outdated_signal(&r.version, &r.available),
            );
        }
        if origin == Origin::ArpUser {
            push_signal(
                &mut signals,
                &r.id,
                SysSignal::new(
                    "user-scope install (writable without elevation)",
                    Category::WeakAcl,
                    Severity::Low,
                    10,
                ),
            );
        }

        deps.push(Dependency {
            name: r.id.clone(),
            version: r.version.clone(),
            ecosystem: Ecosystem::Winget,
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
    for s in sources.iter().filter(|s| !source_is_official(s)) {
        notes.push(source_note(s));
    }
    // Machine-wide, so it has no package to hang off: surfaced as a caveat
    // until unattributed findings get a home in the model.
    if let Ok(info) = run_winget(&["--info"]) {
        for (name, enabled) in parse_admin_settings(&info) {
            if !enabled {
                continue;
            }
            if let Some((_, sev, why)) = RISKY_ADMIN_SETTINGS.iter().find(|(n, _, _)| *n == name) {
                notes.push(format!("admin setting {name} is enabled [{sev:?}] — {why}"));
            }
        }
    }

    let summary = format!(
        "{} package(s): {} via winget, {msix} MSIX, {arp} registry-uninstall",
        rows.len(),
        rows.len() - msix - arp
    );
    Ok(Inventory {
        manager: "winget",
        deps,
        repos,
        signals,
        summary,
        notes,
    })
}

/// Run winget and return stdout. `--disable-interactivity` is the caller's job:
/// some subcommands reject it.
fn run_winget(args: &[&str]) -> Result<String> {
    let out = Command::new("winget")
        .args(args)
        .output()
        .with_context(|| format!("running `winget {}`", args.join(" ")))?;
    if !out.status.success() {
        anyhow::bail!(
            "`winget {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim `winget list` output from a French Windows 11 box. Kept exactly
    /// as emitted — the column offsets and the accented first row are the point.
    const LIST: &str = r#"Name                                                         Id                                                                                    Version           Available        Source
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Améliorations de la compatibilité des applications Windows   MSIX\Microsoft.ApplicationCompatibilityEnhancements_1.2511.9.0_x64__8wekyb3d8bbwe     1.2511.9.0                         
App Installer                                                Microsoft.AppInstaller                                                                1.29.289.0                         winget
Discord                                                      ARP\User\X64\Discord                                                                  1.0.9255                           
Ubisoft Connect                                              Ubisoft.Connect                                                                       < 172.1.0.13247   172.1.0.13247    winget"#;

    /// Verbatim `winget source export` output from the same machine: the three
    /// sources a stock Windows ships with.
    const SOURCES: &str = r#"{"Arg":"https://storeedgefd.dsx.mp.microsoft.com/v9.0","Data":"","Explicit":false,"Identifier":"StoreEdgeFD","Name":"msstore","TrustLevel":["Trusted"],"Type":"Microsoft.Rest"}
{"Arg":"https://cdn.winget.microsoft.com/cache","Data":"Microsoft.Winget.Source_8wekyb3d8bbwe","Explicit":false,"Identifier":"Microsoft.Winget.Source_8wekyb3d8bbwe","Name":"winget","TrustLevel":["Trusted","StoreOrigin"],"Type":"Microsoft.PreIndexed.Package"}
{"Arg":"https://cdn.winget.microsoft.com/fonts","Data":"Microsoft.Winget.Fonts.Source_8wekyb3d8bbwe","Explicit":true,"Identifier":"Microsoft.Winget.Fonts.Source_8wekyb3d8bbwe","Name":"winget-font","TrustLevel":["Trusted","StoreOrigin"],"Type":"Microsoft.PreIndexed.Package"}"#;

    /// The row that would break a byte-indexed parser: its Name column carries
    /// two accented characters, so the line is 182 characters but 184 bytes.
    /// Slicing on byte offsets lands two positions late and truncates the Id.
    #[test]
    fn columns_are_sliced_by_character_not_by_byte() {
        let accented = LIST.lines().nth(2).expect("fixture row");
        assert_ne!(
            accented.chars().count(),
            accented.len(),
            "this fixture must stay multi-byte or it stops testing anything"
        );

        let rows = parse_list(LIST).expect("table should parse");
        assert_eq!(
            rows[0].id,
            "MSIX\\Microsoft.ApplicationCompatibilityEnhancements_1.2511.9.0_x64__8wekyb3d8bbwe"
        );
    }

    /// `Name` is localized ("Améliorations…"), so the parser reads `Id`.
    #[test]
    fn a_row_is_keyed_on_id_version_and_source() {
        let rows = parse_list(LIST).expect("table should parse");
        assert_eq!(rows.len(), 4);

        assert_eq!(rows[1].id, "Microsoft.AppInstaller");
        assert_eq!(rows[1].version, "1.29.289.0");
        assert_eq!(rows[1].source, "winget");

        // Unmanaged entries carry no source; the column is simply absent.
        assert_eq!(rows[0].source, "");
        assert_eq!(rows[2].id, "ARP\\User\\X64\\Discord");
        assert_eq!(rows[2].version, "1.0.9255");
    }

    #[test]
    fn the_layer_is_read_off_the_id_prefix() {
        let rows = parse_list(LIST).expect("table should parse");
        assert_eq!(Origin::of(&rows[0].id), Origin::Msix);
        assert_eq!(Origin::of(&rows[1].id), Origin::Winget);
        assert_eq!(Origin::of(&rows[2].id), Origin::ArpUser);
        assert_eq!(Origin::of("ARP\\Machine\\X64\\Steam App 3274580"), Origin::ArpMachine);
    }

    /// The regression this backend was designed around: a stock machine ships
    /// THREE Microsoft sources, not two. An allowlist of {winget, msstore}
    /// reports `winget-font` as third-party on a clean install.
    #[test]
    fn microsofts_own_font_source_is_not_third_party() {
        let sources = parse_sources(SOURCES);
        assert_eq!(sources.len(), 3);
        for s in &sources {
            assert!(
                source_is_official(s),
                "{} is a Microsoft source and must not be flagged",
                s.name
            );
        }
    }

    /// Trust is not a name. A source calling itself `winget` from someone
    /// else's host is exactly what the check exists to catch.
    #[test]
    fn a_source_is_judged_on_its_host_and_trust_not_its_name() {
        let impostor = r#"{"Name":"winget","Arg":"https://packages.internal.corp/v1","Type":"Microsoft.Rest","TrustLevel":["Trusted"]}"#;
        let s = &parse_sources(impostor)[0];
        assert!(!source_is_official(s));
        assert!(source_to_note_mentions(s, "self-hosted REST source"));

        // Trusted host, but winget itself withholds the trust level.
        let untrusted = r#"{"Name":"winget","Arg":"https://cdn.winget.microsoft.com/cache","Type":"Microsoft.PreIndexed.Package","TrustLevel":[]}"#;
        assert!(!source_is_official(&parse_sources(untrusted)[0]));
    }

    /// A custom pre-indexed source outranks a custom REST one: its MSIX index
    /// is signed by a certificate someone made this machine trust.
    #[test]
    fn a_custom_preindexed_source_says_why_it_is_worse() {
        let s = r#"{"Name":"corp","Arg":"https://pkgs.internal/","Type":"Microsoft.PreIndexed.Package","TrustLevel":[]}"#;
        assert!(source_to_note_mentions(
            &parse_sources(s)[0],
            "signed by a certificate this machine was made to trust"
        ));
    }

    fn source_to_note_mentions(s: &WingetSource, needle: &str) -> bool {
        source_note(s).contains(needle)
    }

    /// Verbatim from `winget --info` on the reference machine: every setting
    /// disabled, which is the default and must produce no caveat.
    #[test]
    fn admin_settings_report_only_what_is_enabled() {
        const INFO: &str = "Admin Setting                             State
--------------------------------------------------
LocalManifestFiles                        Disabled
BypassCertificatePinningForMicrosoftStore Disabled
InstallerHashOverride                     Disabled
LocalArchiveMalwareScanOverride           Disabled
ProxyCommandLineOptions                   Disabled
ConfigurationProcessorPath                Disabled
DefaultProxy                              Disabled";
        let got = parse_admin_settings(INFO);
        assert!(!got.is_empty(), "the known settings should be recognised");
        assert!(
            got.iter().all(|(_, enabled)| !enabled),
            "a stock machine must raise nothing"
        );

        let loosened = INFO.replace("InstallerHashOverride                     Disabled",
                                    "InstallerHashOverride                     Enabled");
        assert!(
            parse_admin_settings(&loosened)
                .iter()
                .any(|(n, e)| n == "InstallerHashOverride" && *e)
        );
    }

    /// The bug the fixtures could not catch: every row on the reference machine
    /// had an empty `Available` column, so slicing `Version` all the way to
    /// `Source` looked correct until a package with a pending upgrade appeared
    /// and came out as "< 172.1.0.13247   172.1.0.13247".
    #[test]
    fn an_available_upgrade_does_not_bleed_into_the_installed_version() {
        let rows = parse_list(LIST).expect("table should parse");
        let up = rows
            .iter()
            .find(|r| r.id == "Ubisoft.Connect")
            .expect("fixture row");
        assert_eq!(up.version, "< 172.1.0.13247");
        assert_eq!(up.available, "172.1.0.13247");
        assert_eq!(up.source, "winget");

        // And the common case stays empty rather than echoing the version.
        let installed = rows.iter().find(|r| r.id == "Microsoft.AppInstaller").unwrap();
        assert_eq!(installed.available, "");
    }

    /// Fail loud, not empty: an unrecognised table must not be reported as a
    /// machine with nothing installed.
    #[test]
    fn an_unreadable_table_is_refused_rather_than_read_as_empty() {
        assert!(parse_list("").is_none());
        assert!(parse_list("winget: command failed\nno packages").is_none());
    }
}
