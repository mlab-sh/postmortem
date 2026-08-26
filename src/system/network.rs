//! Machine network posture — system-level IOCs.
//!
//! Useful in incident response, secondary for supply chain, so the whole layer
//! sits behind `--deep`.
//!
//! Two readings need calibrating before they mean anything, both measured on a
//! stock machine: **156 inbound Allow firewall rules** are enabled, of which
//! 138 carry a `Group` (they belong to a Windows feature) and 18 do not — those
//! 18 are the third-party applications. And **12 DoH servers** are configured,
//! every one of them a template Windows ships (Quad9, Google, Cloudflare); a
//! resolver worth reporting is one that is not on that list.

use super::*;

/// One network reading.
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(default)]
pub(crate) struct NetReading {
    #[serde(rename = "Check")]
    pub check: String,
    #[serde(rename = "Value")]
    pub value: String,
    #[serde(rename = "Detail")]
    pub detail: String,
}

/// DNS-over-HTTPS templates Windows ships with. A resolver outside this list is
/// somebody's choice, and worth saying so.
const KNOWN_DOH: &[&str] = &[
    "dns.quad9.net",
    "dns.google",
    "cloudflare-dns.com",
    "dns.nextdns.io",
    "doh.opendns.com",
    "family.cloudflare-dns.com",
    "security.cloudflare-dns.com",
];

/// Is this DoH template one Windows already knows?
pub(crate) fn is_known_doh(template: &str) -> bool {
    let host = template
        .trim()
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    KNOWN_DOH.contains(&host.as_str())
}

// --- scoring ------------------------------------------------------------------

pub(crate) fn signals_for(r: &NetReading) -> Option<SysSignal> {
    let (severity, points, label) = match r.check.as_str() {
        // Any non-comment line is a redirection somebody wrote by hand.
        "Hosts" => (
            Severity::Medium,
            20,
            format!("the hosts file redirects a name ({})", r.value),
        ),
        "Proxy\\WinHTTP" => (
            Severity::Medium,
            20,
            format!("a system-wide WinHTTP proxy is configured ({})", r.value),
        ),
        // A port forward on the machine itself is a pivot, and nothing installs
        // one by accident.
        "PortProxy" => (
            Severity::High,
            40,
            format!("a netsh port proxy is configured ({})", r.value),
        ),
        "Dns\\Doh" => {
            if is_known_doh(&r.detail) {
                return None;
            }
            (
                Severity::High,
                40,
                format!("an unrecognised DNS-over-HTTPS resolver is configured ({})", r.detail),
            )
        }
        // A root certificate the machine was made to trust is what makes TLS
        // interception invisible — but postmortem **cannot tell offline**
        // which roots shipped with Windows and which were added. Neither the
        // issuer name nor the `AuthRoot` thumbprint list separates them: 12 of
        // this machine's 39 roots are absent from `AuthRoot`, and every one of
        // those is a Microsoft root built into the OS.
        //
        // What *is* measurable is age. The most recently issued legitimate root
        // on the reference machine dates from 2021 — six years old. A root
        // generated in the last three years has the shape of an interception
        // CA, and that is the only claim made here.
        "Certificate\\RecentRoot" => (
            Severity::Medium,
            20,
            format!(
                "a root certificate trusted machine-wide was issued recently ({}, {})",
                r.detail, r.value
            ),
        ),
        // Reported, not scored: 18 of these on a stock machine, all ordinary
        // desktop applications. The signature of the program they admit is what
        // decides, and that is checked separately.
        "Firewall\\Inbound" => (
            Severity::Info,
            0,
            format!("inbound rule for a non-Windows program ({})", r.detail),
        ),
        _ => return None,
    };
    Some(SysSignal::new(label, Category::Ioc, severity, points))
}

// --- enumeration ---------------------------------------------------------------

const PS_NETWORK: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
function Emit($check, $value, $detail) {
  [pscustomobject]@{ Check = $check; Value = [string]$value; Detail = [string]$detail } | ConvertTo-Json -Compress
}

foreach ($l in (Get-Content "$env:WINDIR\System32\drivers\etc\hosts")) {
  if ($l -match '^\s*[^#\s]') { Emit 'Hosts' ($l.Trim()) '' }
}

$p = & netsh winhttp show proxy
if (($p -join ' ') -notmatch 'Direct access') {
  Emit 'Proxy\WinHTTP' (($p | Where-Object { $_ -match 'Proxy Server' }) -replace '\s+', ' ') ''
}

foreach ($l in (& netsh interface portproxy show all)) {
  if ($l -match '^\s*\d+\.\d+\.\d+\.\d+\s') { Emit 'PortProxy' ($l -replace '\s+', ' ') '' }
}

foreach ($d in (Get-DnsClientDohServerAddress)) {
  Emit 'Dns\Doh' $d.ServerAddress $d.DohTemplate
}

# Root CAs: age is the only property that separates a shipped root from a
# freshly generated interception CA without a name list.
$cutoff = (Get-Date).AddYears(-3)
$roots = @(Get-ChildItem Cert:\LocalMachine\Root)
foreach ($c in $roots) {
  if ($c.NotBefore -lt $cutoff) { continue }
  Emit 'Certificate\RecentRoot' ($c.NotBefore.ToString('yyyy-MM-dd')) $c.Subject
}
Emit 'Certificate\Count' $roots.Count ''

# A rule without a Group belongs to an application rather than a Windows
# feature: 138 of the machine's 156 enabled inbound Allow rules carry one.
foreach ($r in (Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True)) {
  if ($r.Group) { continue }
  $f = $r | Get-NetFirewallApplicationFilter
  if ($f.Program -and $f.Program -ne 'Any') { Emit 'Firewall\Inbound' $r.DisplayName $f.Program }
}
"#;

pub(crate) fn parse_readings(stdout: &str) -> Vec<NetReading> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<NetReading>(l).ok())
        .filter(|r: &NetReading| !r.check.is_empty())
        .collect()
}

pub fn network_inventory(opts: Opts) -> Result<Inventory> {
    // Deliberately gated: this is incident-response material, not supply-chain
    // material, and reading it costs a firewall and certificate enumeration.
    if !opts.deep {
        anyhow::bail!("the network layer is only read with `--deep`");
    }
    let raw = powershell(PS_NETWORK).context("reading the machine's network posture")?;
    let readings = parse_readings(&raw);

    let mut signals: HashMap<String, Vec<SysSignal>> = HashMap::new();
    let mut deps = Vec::with_capacity(readings.len());
    for r in &readings {
        let name = if r.value.is_empty() {
            r.check.clone()
        } else {
            format!("{}\\{}", r.check, r.value)
        };
        if let Some(sig) = signals_for(r) {
            push_signal(&mut signals, &name, sig);
        }
        deps.push(Dependency {
            name,
            version: String::new(),
            ecosystem: Ecosystem::Network,
            direct: true,
            scope: Scope::Prod,
            licenses: Vec::new(),
            license_source: LicenseSource::Unknown,
            resolved_url: None,
            integrity: None,
            parents: Vec::new(),
        });
    }

    let roots = readings
        .iter()
        .find(|r| r.check == "Certificate\\Count")
        .map(|r| r.value.clone());
    let mut notes = Vec::new();
    if let Some(n) = roots {
        notes.push(format!(
            "{n} certificates are trusted as root CAs. postmortem cannot tell offline which \
             of them shipped with Windows and which were added, so only those issued in the \
             last three years are reported"
        ));
    }
    notes.extend(if readings.is_empty() {
        vec![
            "the hosts file, the system proxy, port proxies, DNS resolvers and the root \
             certificate store hold nothing out of the ordinary"
                .to_string(),
        ]
    } else {
        Vec::new()
    });

    let summary = format!("{} network reading(s)", readings.len());
    Ok(Inventory {
        manager: "network",
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

    fn r(check: &str, value: &str, detail: &str) -> NetReading {
        NetReading { check: check.into(), value: value.into(), detail: detail.into() }
    }

    /// All 12 DoH servers on a stock machine are templates Windows ships. A
    /// resolver worth reporting is one that is not among them.
    #[test]
    fn the_shipped_doh_resolvers_are_not_findings() {
        for t in [
            "https://dns.quad9.net/dns-query",
            "https://dns.google/dns-query",
            "https://cloudflare-dns.com/dns-query",
        ] {
            assert!(is_known_doh(t), "{t}");
            assert!(signals_for(&r("Dns\\Doh", "1.1.1.1", t)).is_none());
        }

        let rogue = signals_for(&r("Dns\\Doh", "198.51.100.7", "https://doh.evil.test/dns-query")).unwrap();
        assert_eq!(rogue.severity, Severity::High);
        assert_eq!(rogue.category, Category::Ioc);

        // A lookalike host does not pass.
        assert!(!is_known_doh("https://dns.google.evil.test/dns-query"));
        assert!(!is_known_doh(""));
    }

    /// 18 of the machine's 156 enabled inbound rules belong to applications
    /// rather than Windows features, and they are all ordinary desktop
    /// software. Recorded, not scored.
    #[test]
    fn application_firewall_rules_are_recorded_not_scored() {
        let s = signals_for(&r(
            "Firewall\\Inbound",
            "Steam",
            r"C:\Program Files (x86)\Steam\Steam.exe",
        ))
        .unwrap();
        assert_eq!(s.severity, Severity::Info);
        assert_eq!(s.points, 0);
    }

    /// Nothing writes a port proxy or a hosts entry by accident.
    #[test]
    fn hand_written_redirections_are_findings() {
        assert_eq!(
            signals_for(&r("Hosts", "198.51.100.7 update.vendor.test", "")).unwrap().severity,
            Severity::Medium
        );
        assert_eq!(
            signals_for(&r("PortProxy", "0.0.0.0 4444 10.0.0.5 445", "")).unwrap().severity,
            Severity::High
        );
        assert_eq!(
            signals_for(&r("Proxy\\WinHTTP", "Proxy Server(s) : 127.0.0.1:8080", "")).unwrap().severity,
            Severity::Medium
        );
    }

    /// postmortem cannot tell offline which roots shipped with Windows and
    /// which were added — neither the issuer name nor the `AuthRoot` thumbprint
    /// list separates them (12 of the machine's 39 roots are absent from
    /// `AuthRoot`, and all 12 are Microsoft's own). Age is the one property
    /// that does: the newest legitimate root on the reference machine is from
    /// 2021.
    #[test]
    fn only_a_recently_issued_root_is_reported() {
        let s = signals_for(&r("Certificate\\RecentRoot", "2026-03-01", "CN=Corp Proxy CA, O=Corp")).unwrap();
        assert_eq!(s.severity, Severity::Medium);
        assert_eq!(s.category, Category::Ioc);
        assert!(s.label.contains("Corp Proxy CA"), "{}", s.label);

        // The store size is context, not a finding.
        assert!(signals_for(&r("Certificate\\Count", "39", "")).is_none());
    }

    #[test]
    fn an_unknown_reading_is_not_invented_into_a_finding() {
        assert!(signals_for(&r("Something", "x", "y")).is_none());
        assert_eq!(parse_readings(r#"{"Check":"","Value":"x","Detail":""}"#).len(), 0);
    }

    /// The layer is incident-response material, so it refuses rather than
    /// quietly returning nothing when it was not asked for.
    #[test]
    fn the_layer_refuses_without_deep() {
        let shallow = Opts { deep: false, ..Opts::default() };
        assert!(network_inventory(shallow).is_err());
    }
}
