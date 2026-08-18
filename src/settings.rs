//! Global, user-level settings: `$HOME/.postmortem/config.yml`.
//!
//! This is distinct from the per-project `postmortem.conf` (TOML) that `scan`
//! uses to suppress findings — see [`crate::config`]. This file holds machine-
//! wide knobs for the networked `tree --online` path: the GitHub token and the
//! risk thresholds.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// `$HOME`
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// `$HOME/.postmortem/` — the base directory for settings and cache.
pub fn base_dir() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".postmortem"))
}

fn config_path() -> Option<PathBuf> {
    base_dir().map(|d| d.join("config.yml"))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// GitHub API token for repo stats. Falls back to `$GITHUB_TOKEN`, then an
    /// interactive prompt. Stored here so it's only entered once.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_token: Option<String>,
    /// GitLab API token for repo stats (`gitlab.com/api/v4`). Falls back to
    /// `$GITLAB_TOKEN`. Optional — public projects resolve anonymously.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gitlab_token: Option<String>,
    /// Codeberg (Forgejo) API token for repo stats (`codeberg.org/api/v1`).
    /// Falls back to `$CODEBERG_TOKEN`. Optional — public repos resolve
    /// anonymously.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codeberg_token: Option<String>,
    /// Token for the mlab vuln-scan API (`vuln.mlab.sh`). Falls back to
    /// `$VULN_MLAB_TOKEN`; without one, scans use the anonymous 8/hr limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vuln_token: Option<String>,
    pub tree: TreeSettings,
    /// Corporate-network plumbing: proxy and per-service endpoint overrides.
    pub network: NetworkSettings,
}

/// How postmortem reaches the network.
///
/// Lives in the config file rather than in flags or environment variables on
/// purpose: this is a property of the *machine*, not of a run. A build agent
/// behind a proxy needs it on every invocation of every command, and expressing
/// that as flags means every CI step repeats them and drifts.
///
/// ```yaml
/// network:
///   proxy: "http://proxy.corp:3128"
///   no_proxy: ["nexus.corp", "github.corp"]
///   endpoints:
///     npm: "https://nexus.corp/repository/npm-proxy"
///     github: "https://github.corp/api/v3"
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkSettings {
    /// Proxy URL applied to every outbound request, e.g.
    /// `http://user:pass@proxy.corp:3128`. Both http and https traffic go
    /// through it — ureq resolves the scheme from the URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    /// Hosts reached directly, bypassing `proxy`. Matched as a suffix, so
    /// `corp.example` also covers `nexus.corp.example`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub no_proxy: Vec<String>,
    /// Base-URL overrides per service. Absent entries keep the public default.
    pub endpoints: Endpoints,
}

/// Base URLs postmortem talks to, each overridable for an internal mirror,
/// a pull-through cache, or an on-premises install.
///
/// Every field is the **origin plus any base path**, with no trailing slash —
/// the per-service path is appended by the caller. `deny_unknown_fields` is
/// deliberate: a typo in a key here would otherwise silently leave the public
/// endpoint in use, which on an air-gapped network looks like an outage rather
/// than a config error.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Endpoints {
    /// npm registry. Default `https://registry.npmjs.org`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub npm: Option<String>,
    /// PyPI JSON API. Default `https://pypi.org`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pypi: Option<String>,
    /// crates.io API. Default `https://crates.io`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crates: Option<String>,
    /// RubyGems API. Default `https://rubygems.org`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rubygems: Option<String>,
    /// Packagist API. Default `https://packagist.org`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packagist: Option<String>,
    /// deps.dev API (Java and Go licenses). Default `https://api.deps.dev`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deps_dev: Option<String>,
    /// GitHub API. Set to `https://github.corp/api/v3` for GitHub Enterprise.
    /// Default `https://api.github.com`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github: Option<String>,
    /// Raw file host used to read a repo's `package.json`. Default
    /// `https://raw.githubusercontent.com`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_raw: Option<String>,
    /// GitLab API, for a self-hosted instance. Default `https://gitlab.com/api/v4`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gitlab: Option<String>,
    /// Codeberg / Forgejo API. Default `https://codeberg.org/api/v1`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codeberg: Option<String>,
    /// mlab vulnerability scan API. Default `https://vuln.mlab.sh`. Also covers
    /// the OS-package advisory lookups, which route through the same service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vuln: Option<String>,
    /// Arch security tracker. Default `https://security.archlinux.org`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch_security: Option<String>,
    /// AUR RPC. Default `https://aur.archlinux.org`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aur: Option<String>,
    /// Homebrew formula API. Default `https://formulae.brew.sh`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brew: Option<String>,
}

/// Trim a trailing slash so callers can always append `/path` unconditionally.
fn base(v: &Option<String>, default: &'static str) -> String {
    match v.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => s.trim_end_matches('/').to_string(),
        None => default.to_string(),
    }
}

impl Endpoints {
    pub fn npm(&self) -> String {
        base(&self.npm, "https://registry.npmjs.org")
    }
    pub fn pypi(&self) -> String {
        base(&self.pypi, "https://pypi.org")
    }
    pub fn crates(&self) -> String {
        base(&self.crates, "https://crates.io")
    }
    pub fn rubygems(&self) -> String {
        base(&self.rubygems, "https://rubygems.org")
    }
    pub fn packagist(&self) -> String {
        base(&self.packagist, "https://packagist.org")
    }
    pub fn deps_dev(&self) -> String {
        base(&self.deps_dev, "https://api.deps.dev")
    }
    pub fn github(&self) -> String {
        base(&self.github, "https://api.github.com")
    }
    pub fn github_raw(&self) -> String {
        base(&self.github_raw, "https://raw.githubusercontent.com")
    }
    pub fn gitlab(&self) -> String {
        base(&self.gitlab, "https://gitlab.com/api/v4")
    }
    pub fn codeberg(&self) -> String {
        base(&self.codeberg, "https://codeberg.org/api/v1")
    }
    pub fn vuln(&self) -> String {
        base(&self.vuln, "https://vuln.mlab.sh")
    }
    pub fn arch_security(&self) -> String {
        base(&self.arch_security, "https://security.archlinux.org")
    }
    pub fn aur(&self) -> String {
        base(&self.aur, "https://aur.archlinux.org")
    }
    pub fn brew(&self) -> String {
        base(&self.brew, "https://formulae.brew.sh")
    }
}

impl NetworkSettings {
    /// Apply the proxy to a ureq agent builder.
    ///
    /// An unparseable proxy URL warns and is skipped rather than aborting: the
    /// run may still reach an internal mirror directly, and failing the whole
    /// command over a config typo helps nobody. The warning goes to stderr so it
    /// cannot corrupt a machine format on stdout.
    pub fn apply(&self, builder: ureq::AgentBuilder) -> ureq::AgentBuilder {
        let Some(url) = self
            .proxy
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return builder;
        };
        match ureq::Proxy::new(url) {
            Ok(p) => builder.proxy(p),
            Err(e) => {
                eprintln!("warn: ignoring network.proxy {url:?} — {e}");
                builder
            }
        }
    }

    /// Build the agent pair for these settings.
    pub fn agents(&self, timeout: std::time::Duration) -> Agents {
        let direct = ureq::AgentBuilder::new().timeout(timeout).build();
        let proxied = self
            .apply(ureq::AgentBuilder::new().timeout(timeout))
            .build();
        Agents {
            proxied,
            direct,
            no_proxy: self.no_proxy.clone(),
        }
    }
}

/// A proxied agent plus a direct one, chosen per request.
///
/// ureq applies a proxy to the whole agent with no exemption list, but a
/// corporate setup almost always needs one: the proxy reaches the internet while
/// the *internal* mirror is only reachable directly. So the exemption is honoured
/// here, by picking the agent from the request's host — otherwise `no_proxy`
/// would be a config key that silently does nothing.
pub struct Agents {
    proxied: ureq::Agent,
    direct: ureq::Agent,
    no_proxy: Vec<String>,
}

impl Agents {
    /// The agent to use for `url`.
    pub fn for_url(&self, url: &str) -> &ureq::Agent {
        match host_of(url) {
            Some(h) if self.bypasses(&h) => &self.direct,
            _ => &self.proxied,
        }
    }

    pub(crate) fn bypasses(&self, host: &str) -> bool {
        let host = host.trim_start_matches('.');
        self.no_proxy.iter().any(|n| {
            let n = n.trim().trim_start_matches('.');
            !n.is_empty() && (host == n || host.ends_with(&format!(".{n}")))
        })
    }
}

/// The host of a URL, lowercased, without userinfo or port.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit('@').next()?;
    let host = host.split(':').next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Risk thresholds for `tree --online`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TreeSettings {
    /// Flag repositories with fewer stars than this.
    pub min_stars: u64,
    /// Flag repositories created within this many days.
    pub recent_days: i64,
    /// Flag repositories with no push in this many days.
    pub stale_days: i64,
}

impl Default for TreeSettings {
    fn default() -> Self {
        Self {
            min_stars: 20,
            recent_days: 30,
            stale_days: 365,
        }
    }
}

impl Settings {
    /// Load `config.yml`, or defaults if it's absent.
    pub fn load() -> Result<Self> {
        let Some(p) = config_path() else {
            return Ok(Self::default());
        };
        if !p.is_file() {
            return Ok(Self::default());
        }
        let raw =
            std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
        serde_yaml::from_str(&raw).with_context(|| format!("parsing {}", p.display()))
    }

    /// [`Self::load`], but a malformed config **says so** instead of silently
    /// becoming defaults.
    ///
    /// This matters most for [`NetworkSettings`]. A typo in an endpoint key is
    /// rejected by `deny_unknown_fields`, and if that rejection were swallowed
    /// the run would quietly fall back to the *public* registries — which on an
    /// air-gapped network looks like an outage, and on a connected one means
    /// internal package names are sent to a public service. Neither should
    /// happen without a word.
    ///
    /// Still non-fatal: the warning goes to stderr and defaults apply, so a
    /// stray key cannot brick every command on the machine.
    pub fn load_or_warn() -> Self {
        match Self::load() {
            Ok(s) => s,
            Err(e) => {
                let where_ = config_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();
                eprintln!(
                    "warn: ignoring {where_} — {e:#}\n\
                     warn: continuing with defaults; any `network` overrides in it are NOT applied"
                );
                Self::default()
            }
        }
    }

    /// Write `config.yml` (0600), creating `$HOME/.postmortem/` if needed.
    pub fn save(&self) -> Result<()> {
        let Some(dir) = base_dir() else {
            anyhow::bail!("cannot determine $HOME to save config");
        };
        std::fs::create_dir_all(&dir)?;
        let p = dir.join("config.yml");
        let yaml = serde_yaml::to_string(self)?;
        std::fs::write(&p, format!("# postmortem configuration\n{yaml}"))?;
        restrict_perms(&p);
        Ok(())
    }

    /// Resolve a usable GitHub token: config → `$GITHUB_TOKEN` → interactive
    /// prompt (offering to persist it). Returns `None` when there's no token and
    /// no interactive terminal to ask on — the caller then falls back to the
    /// anonymous (rate-limited) GitHub API.
    pub fn resolve_github_token(&mut self) -> Result<Option<String>> {
        if let Some(t) = self.github_token.clone().filter(|t| !t.trim().is_empty()) {
            return Ok(Some(t));
        }
        if let Ok(t) = std::env::var("GITHUB_TOKEN")
            && !t.trim().is_empty()
        {
            return Ok(Some(t));
        }
        if !std::io::stdin().is_terminal() {
            return Ok(None);
        }

        // (github prompt below)
        eprint!("GitHub token (for repo stats; Enter to skip): ");
        std::io::stderr().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let token = line.trim().to_string();
        if token.is_empty() {
            return Ok(None);
        }

        let where_to = config_path()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        eprint!("Save it to {where_to}? [y/N]: ");
        std::io::stderr().flush().ok();
        let mut ans = String::new();
        std::io::stdin().read_line(&mut ans)?;
        if matches!(ans.trim(), "y" | "Y" | "yes") {
            self.github_token = Some(token.clone());
            self.save()?;
            eprintln!("saved to {where_to}");
        }
        Ok(Some(token))
    }

    /// Resolve the GitLab token: config → `$GITLAB_TOKEN`. No prompt — public
    /// projects work anonymously, a token only raises the rate limit.
    pub fn gitlab_token(&self) -> Option<String> {
        self.gitlab_token
            .clone()
            .filter(|t| !t.trim().is_empty())
            .or_else(|| {
                std::env::var("GITLAB_TOKEN")
                    .ok()
                    .filter(|t| !t.trim().is_empty())
            })
    }

    /// Resolve the Codeberg token: config → `$CODEBERG_TOKEN`. No prompt — public
    /// repos work anonymously.
    pub fn codeberg_token(&self) -> Option<String> {
        self.codeberg_token
            .clone()
            .filter(|t| !t.trim().is_empty())
            .or_else(|| {
                std::env::var("CODEBERG_TOKEN")
                    .ok()
                    .filter(|t| !t.trim().is_empty())
            })
    }

    /// Resolve the mlab vuln-scan token: config → `$VULN_MLAB_TOKEN`. No prompt —
    /// anonymous scanning works (just rate-limited), so this stays quiet.
    pub fn vuln_token(&self) -> Option<String> {
        self.vuln_token
            .clone()
            .filter(|t| !t.trim().is_empty())
            .or_else(|| {
                std::env::var("VULN_MLAB_TOKEN")
                    .ok()
                    .filter(|t| !t.trim().is_empty())
            })
    }
}

#[cfg(unix)]
fn restrict_perms(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_perms(_p: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_default_to_the_public_services() {
        let e = Endpoints::default();
        assert_eq!(e.npm(), "https://registry.npmjs.org");
        assert_eq!(e.github(), "https://api.github.com");
        assert_eq!(e.vuln(), "https://vuln.mlab.sh");
    }

    #[test]
    fn an_override_wins_and_loses_its_trailing_slash() {
        // Callers append `/path` unconditionally, so a trailing slash would
        // produce `//path` against mirrors that are strict about it.
        let e = Endpoints {
            npm: Some("https://nexus.corp/repository/npm/".into()),
            ..Default::default()
        };
        assert_eq!(e.npm(), "https://nexus.corp/repository/npm");
    }

    #[test]
    fn a_blank_override_falls_back_rather_than_producing_a_bare_path() {
        let e = Endpoints {
            npm: Some("   ".into()),
            ..Default::default()
        };
        assert_eq!(e.npm(), "https://registry.npmjs.org");
    }

    #[test]
    fn a_typo_in_an_endpoint_key_is_an_error_not_a_silent_default() {
        // The whole point of `deny_unknown_fields`: falling back to the public
        // registry would send internal package names to a public service.
        let err = serde_yaml::from_str::<NetworkSettings>("endpoints:\n  npmm: https://x.test\n")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("npmm"),
            "the error should name the bad key: {err}"
        );
        assert!(err.contains("npm"), "and list the valid ones: {err}");
    }

    #[test]
    fn no_proxy_matches_a_host_and_its_subdomains() {
        let net = NetworkSettings {
            no_proxy: vec!["corp.example".into()],
            ..Default::default()
        };
        let a = net.agents(std::time::Duration::from_secs(1));
        // Suffix match, which is the shape people write.
        assert!(a.bypasses("corp.example"));
        assert!(a.bypasses("nexus.corp.example"));
        // Not a substring match: a lookalike host must still go via the proxy.
        assert!(!a.bypasses("corp.example.evil.test"));
        assert!(!a.bypasses("notcorp.example"));
        assert!(!a.bypasses("registry.npmjs.org"));
    }

    #[test]
    fn host_is_extracted_without_userinfo_or_port() {
        assert_eq!(
            host_of("https://user:pw@nexus.corp:8443/repo/npm").as_deref(),
            Some("nexus.corp")
        );
        assert_eq!(
            host_of("https://Registry.NPMJS.org/x").as_deref(),
            Some("registry.npmjs.org")
        );
        assert_eq!(host_of("not a url"), Some("not a url".into()));
    }

    #[test]
    fn an_empty_no_proxy_never_bypasses() {
        let a = NetworkSettings::default().agents(std::time::Duration::from_secs(1));
        assert!(!a.bypasses("anything.test"));
    }
}
