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

/// The user's home directory.
///
/// `$HOME` first, then `%USERPROFILE%`: Windows does not set `HOME`, so reading
/// only that leaves every Windows user with no cache, no `config.yml`, and
/// therefore no `[gate]` policy and no allowlist — silently, because a missing
/// home is treated as "caching disabled" rather than as an error.
pub fn home_dir() -> Option<PathBuf> {
    resolve_home(
        std::env::var_os("HOME"),
        std::env::var_os("USERPROFILE"),
    )
}

/// The choice itself, split out so it can be tested without mutating the
/// process environment (which no test can do safely in parallel).
fn resolve_home(
    home: Option<std::ffi::OsString>,
    userprofile: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    // An empty variable is set-but-useless; treat it as absent rather than
    // resolving paths against "".
    home.filter(|v| !v.is_empty())
        .or(userprofile.filter(|v| !v.is_empty()))
        .map(PathBuf::from)
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
    /// How `--webhook` authenticates to the collector.
    pub webhook: WebhookSettings,
}

/// How a report authenticates to the collector `--webhook` posts it to.
///
/// The credential is **never** a command-line argument: `ps` shows it to every
/// user on the box, shells record it, and CI prints the command it ran. It
/// comes from this file or from the environment, the same way the registry
/// tokens do.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhookSettings {
    /// `bearer`, `basic` or a header name. Left unset, a token alone means
    /// `bearer` and a username means `basic`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    /// The credential. Falls back to `$POSTMORTEM_WEBHOOK_TOKEN`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Basic auth only. Falls back to `$POSTMORTEM_WEBHOOK_USER`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Headers sent with every report — routing and tagging, not secrets.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub headers: std::collections::BTreeMap<String, String>,
}

/// The authentication a report carries, resolved from settings and environment.
#[derive(Debug, PartialEq, Eq)]
pub enum WebhookAuth {
    /// No credential configured.
    None,
    /// `Authorization: Bearer <token>`.
    Bearer(String),
    /// `Authorization: Basic base64(user:token)`.
    Basic { username: String, token: String },
    /// A named header carrying the token, e.g. `X-API-Key`.
    Header { name: String, token: String },
}

impl WebhookSettings {
    /// The credential, from this file or the environment.
    pub fn credential(&self) -> Option<String> {
        self.token
            .clone()
            .filter(|t| !t.trim().is_empty())
            .or_else(|| std::env::var("POSTMORTEM_WEBHOOK_TOKEN").ok())
            .filter(|t| !t.trim().is_empty())
    }

    fn user(&self) -> Option<String> {
        self.username
            .clone()
            .filter(|u| !u.trim().is_empty())
            .or_else(|| std::env::var("POSTMORTEM_WEBHOOK_USER").ok())
            .filter(|u| !u.trim().is_empty())
    }

    /// Work out which scheme to use.
    ///
    /// An explicit `auth` decides. Otherwise a username implies `basic` and a
    /// bare token implies `bearer`, which is what a collector expects by
    /// default — and guessing wrong is a 401, not a leak.
    pub fn resolve(&self) -> Result<WebhookAuth> {
        let Some(token) = self.credential() else {
            // A scheme named with no credential behind it is a configuration
            // that will silently authenticate as nobody.
            if let Some(a) = self.auth.as_deref().filter(|a| !a.trim().is_empty()) {
                anyhow::bail!(
                    "webhook.auth is set to {a:?} but no credential is configured — set                      webhook.token or $POSTMORTEM_WEBHOOK_TOKEN"
                );
            }
            return Ok(WebhookAuth::None);
        };
        let scheme = self
            .auth
            .as_deref()
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .map(str::to_ascii_lowercase);

        match scheme.as_deref() {
            Some("bearer") => Ok(WebhookAuth::Bearer(token)),
            Some("basic") => match self.user() {
                Some(username) => Ok(WebhookAuth::Basic { username, token }),
                None => anyhow::bail!(
                    "webhook.auth is \"basic\" but no username is configured — set                      webhook.username or $POSTMORTEM_WEBHOOK_USER"
                ),
            },
            // Anything else names the header to carry the token.
            Some(name) => Ok(WebhookAuth::Header {
                name: self
                    .auth
                    .clone()
                    .unwrap_or_else(|| name.to_string())
                    .trim()
                    .to_string(),
                token,
            }),
            None => match self.user() {
                Some(username) => Ok(WebhookAuth::Basic { username, token }),
                None => Ok(WebhookAuth::Bearer(token)),
            },
        }
    }
}

/// How postmortem reaches the network.
///
/// Lives in the config file first: this is a property of the *machine*, not of
/// a run, and a build agent behind a proxy needs it on every invocation. The
/// global `--proxy` / `--no-proxy` / `--ca-cert` flags override it for one run
/// (see [`set_cli_overrides`]).
///
/// ```yaml
/// network:
///   proxy: "http://proxy.corp:3128"
///   no_proxy: ["nexus.corp", "github.corp"]
///   ca_cert: "/etc/ssl/corp-root.pem"
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
    /// PEM file of extra root CAs (a TLS-inspecting proxy's, an internal
    /// mirror's). **Added to** the public roots, not a replacement for them, so
    /// public hosts reached via `no_proxy` keep working.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_cert: Option<PathBuf>,
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

/// One run's `--proxy` / `--no-proxy` / `--ca-cert`, layered over the config
/// file by [`Settings::load`].
#[derive(Debug, Default)]
pub struct NetworkOverrides {
    pub proxy: Option<String>,
    pub no_proxy: Vec<String>,
    pub ca_cert: Option<PathBuf>,
}

static CLI_NETWORK: std::sync::OnceLock<NetworkOverrides> = std::sync::OnceLock::new();

/// Record the command line's network flags, once, before any command runs.
///
/// A CA file given on the command line is checked here and is fatal when
/// unusable: the user asked for it on this very run, so carrying on would only
/// trade a clear error for a wall of `UnknownIssuer` failures.
pub fn set_cli_overrides(o: NetworkOverrides) -> Result<()> {
    if let Some(p) = &o.ca_cert {
        load_ca(p)?;
    }
    if let Some(u) = o.proxy.as_deref().filter(|u| !u.trim().is_empty()) {
        ureq::Proxy::new(u.trim()).with_context(|| format!("--proxy {u:?}"))?;
    }
    let _ = CLI_NETWORK.set(o);
    Ok(())
}

impl NetworkOverrides {
    /// Flags win over the file; `--no-proxy` adds to the file's list.
    fn apply_to(&self, net: &mut NetworkSettings) {
        if self.proxy.is_some() {
            net.proxy = self.proxy.clone();
        }
        if self.ca_cert.is_some() {
            net.ca_cert = self.ca_cert.clone();
        }
        net.no_proxy.extend(self.no_proxy.iter().cloned());
    }
}

/// Every certificate in a PEM file, or an error naming the file.
fn load_ca(path: &Path) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>> {
    use rustls_pki_types::pem::PemObject;
    let certs = rustls_pki_types::CertificateDer::pem_file_iter(path)
        .and_then(|it| it.collect::<Result<Vec<_>, _>>())
        .map_err(|e| match e {
            rustls_pki_types::pem::Error::Io(io) => anyhow::anyhow!(io),
            other => anyhow::anyhow!("{other:?}"),
        })
        .with_context(|| format!("reading CA certificates from {}", path.display()))?;
    if certs.is_empty() {
        anyhow::bail!("no PEM certificate found in {}", path.display());
    }
    Ok(certs)
}

fn with_tls(
    builder: ureq::AgentBuilder,
    tls: Option<std::sync::Arc<rustls::ClientConfig>>,
) -> ureq::AgentBuilder {
    match tls {
        Some(c) => builder.tls_config(c),
        None => builder,
    }
}

/// rustls config trusting the public roots ureq ships plus every cert in `path`.
fn tls_config(path: &Path) -> Result<std::sync::Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    for cert in load_ca(path)? {
        roots
            .add(cert)
            .with_context(|| format!("unusable CA certificate in {}", path.display()))?;
    }
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(std::sync::Arc::new(config))
}

impl NetworkSettings {
    /// Trust `ca_cert` in addition to the public roots.
    ///
    /// Same policy as a bad proxy URL: warn and carry on with the public roots.
    /// A bad CA on the command line never gets here — [`set_cli_overrides`]
    /// already refused it.
    fn tls(&self) -> Option<std::sync::Arc<rustls::ClientConfig>> {
        let path = self.ca_cert.as_ref()?;
        tls_config(path)
            .inspect_err(|e| eprintln!("warn: ignoring network.ca_cert — {e:#}"))
            .ok()
    }

    fn apply_tls(&self, builder: ureq::AgentBuilder) -> ureq::AgentBuilder {
        with_tls(builder, self.tls())
    }

    /// Apply the proxy and the extra root CA to a ureq agent builder.
    ///
    /// An unparseable proxy URL warns and is skipped rather than aborting: the
    /// run may still reach an internal mirror directly, and failing the whole
    /// command over a config typo helps nobody. The warning goes to stderr so it
    /// cannot corrupt a machine format on stdout.
    pub fn apply(&self, builder: ureq::AgentBuilder) -> ureq::AgentBuilder {
        let builder = self.apply_tls(builder);
        self.apply_proxy(builder)
    }

    fn apply_proxy(&self, builder: ureq::AgentBuilder) -> ureq::AgentBuilder {
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
    ///
    /// `timeout` bounds each socket read and write — the wait for a response,
    /// and any stall mid-body — not the whole exchange. An overall deadline
    /// counted the body too, so a 20 MB packument or a 50 MiB tarball on a slow
    /// link timed out while bytes were still arriving.
    pub fn agents(&self, timeout: std::time::Duration) -> Agents {
        // ureq keeps one idle connection per host by default, so with several
        // workers on one registry every response but one closed its socket and
        // the next request paid a fresh TCP + TLS handshake.
        // The CA applies to both: the internal mirror reached directly is the
        // host most likely to carry the corporate certificate.
        let tls = self.tls();
        let builder = || {
            with_tls(
                ureq::AgentBuilder::new()
                    .timeout_connect(timeout.min(std::time::Duration::from_secs(5)))
                    .timeout_read(timeout)
                    .timeout_write(timeout)
                    .max_idle_connections_per_host(16),
                tls.clone(),
            )
        };
        let direct = builder().build();
        let proxied = self.apply_proxy(builder()).build();
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
    /// Load `config.yml` (or defaults if it's absent), with this run's network
    /// flags layered on top.
    pub fn load() -> Result<Self> {
        Self::load_file().map(Self::with_cli_overrides)
    }

    fn with_cli_overrides(mut self) -> Self {
        if let Some(o) = CLI_NETWORK.get() {
            o.apply_to(&mut self.network);
        }
        self
    }

    fn load_file() -> Result<Self> {
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
                // The flags still hold: they were never in the broken file.
                Self::default().with_cli_overrides()
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
        // `self.network` carries this run's `--proxy`/`--ca-cert`; persisting
        // them would turn a one-off flag (perhaps with proxy credentials) into
        // machine config. Write back the file's own network block instead.
        let mut out = self.clone();
        out.network = Self::load_file().map(|s| s.network).unwrap_or_default();
        let yaml = serde_yaml::to_string(&out)?;
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

    /// The credential is never a command-line argument: `ps` shows it to every
    /// user on the box, shells record it, and CI prints the command it ran.
    /// It comes from the config file or the environment.
    #[test]
    fn a_bare_token_means_bearer_and_a_username_means_basic() {
        let bearer = WebhookSettings { token: Some("t".into()), ..Default::default() };
        assert_eq!(bearer.resolve().unwrap(), WebhookAuth::Bearer("t".into()));

        let basic = WebhookSettings {
            token: Some("t".into()),
            username: Some("alice".into()),
            ..Default::default()
        };
        assert_eq!(
            basic.resolve().unwrap(),
            WebhookAuth::Basic { username: "alice".into(), token: "t".into() }
        );
    }

    #[test]
    fn an_explicit_scheme_wins_and_any_other_name_is_a_header() {
        let forced = WebhookSettings {
            auth: Some("bearer".into()),
            token: Some("t".into()),
            username: Some("alice".into()),
            ..Default::default()
        };
        assert_eq!(forced.resolve().unwrap(), WebhookAuth::Bearer("t".into()));

        let header = WebhookSettings {
            auth: Some("X-API-Key".into()),
            token: Some("t".into()),
            ..Default::default()
        };
        assert_eq!(
            header.resolve().unwrap(),
            WebhookAuth::Header { name: "X-API-Key".into(), token: "t".into() }
        );
    }

    /// A configuration that would authenticate as nobody is a mistake worth
    /// stopping on, not a silent anonymous POST.
    #[test]
    fn a_scheme_without_a_credential_is_refused() {
        let orphan = WebhookSettings { auth: Some("bearer".into()), ..Default::default() };
        let err = orphan.resolve().unwrap_err().to_string();
        assert!(err.contains("no credential"), "{err}");

        let no_user = WebhookSettings {
            auth: Some("basic".into()),
            token: Some("t".into()),
            ..Default::default()
        };
        assert!(no_user.resolve().unwrap_err().to_string().contains("no username"));
    }

    /// Nothing configured is not an error — most collectors are unauthenticated
    /// internal endpoints.
    #[test]
    fn no_credential_at_all_is_not_a_finding() {
        // Only true when the environment does not supply one either.
        if std::env::var("POSTMORTEM_WEBHOOK_TOKEN").is_ok() {
            return;
        }
        assert_eq!(WebhookSettings::default().resolve().unwrap(), WebhookAuth::None);
    }

    /// Whitespace is not a credential.
    #[test]
    fn a_blank_token_counts_as_absent() {
        let blank = WebhookSettings { token: Some("   ".into()), ..Default::default() };
        assert!(blank.credential().is_none() || std::env::var("POSTMORTEM_WEBHOOK_TOKEN").is_ok());
    }

    /// Windows sets `USERPROFILE`, not `HOME`. Reading only `HOME` left the
    /// cache, `config.yml`, the `[gate]` policy and the allowlist quietly
    /// inert on every Windows machine.
    #[test]
    fn the_home_directory_falls_back_to_userprofile() {
        use std::ffi::OsString;
        let home = || Some(OsString::from("/home/alice"));
        let profile = || Some(OsString::from(r"C:\Users\alice"));

        assert_eq!(resolve_home(home(), None).unwrap(), PathBuf::from("/home/alice"));
        assert_eq!(
            resolve_home(None, profile()).unwrap(),
            PathBuf::from(r"C:\Users\alice")
        );
        // HOME wins when both are set, so an explicitly-set HOME on Windows
        // still decides.
        assert_eq!(resolve_home(home(), profile()).unwrap(), PathBuf::from("/home/alice"));
        // Set-but-empty is not a home.
        assert_eq!(
            resolve_home(Some(OsString::new()), profile()).unwrap(),
            PathBuf::from(r"C:\Users\alice")
        );
        assert!(resolve_home(None, None).is_none());
        assert!(resolve_home(Some(OsString::new()), Some(OsString::new())).is_none());
    }

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

    const TEST_CA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls/ca.pem");

    #[test]
    fn ca_cert_is_a_config_key() {
        let net: NetworkSettings = serde_yaml::from_str("ca_cert: /etc/ssl/corp.pem\n").unwrap();
        assert_eq!(net.ca_cert.as_deref(), Some(Path::new("/etc/ssl/corp.pem")));
    }

    #[test]
    fn flags_override_the_file_and_no_proxy_adds_to_it() {
        let mut net = NetworkSettings {
            proxy: Some("http://file:1".into()),
            no_proxy: vec!["file.corp".into()],
            ca_cert: Some("/file.pem".into()),
            ..Default::default()
        };
        NetworkOverrides {
            proxy: Some("http://flag:2".into()),
            no_proxy: vec!["flag.corp".into()],
            ca_cert: None,
        }
        .apply_to(&mut net);
        assert_eq!(net.proxy.as_deref(), Some("http://flag:2"));
        assert_eq!(net.no_proxy, ["file.corp", "flag.corp"]);
        // An absent flag leaves the file's value alone.
        assert_eq!(net.ca_cert.as_deref(), Some(Path::new("/file.pem")));
    }

    #[test]
    fn a_ca_file_without_a_certificate_is_an_error() {
        let dir = std::env::temp_dir().join(format!("pm-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let junk = dir.join("junk.pem");
        std::fs::write(&junk, "not a certificate\n").unwrap();
        assert!(load_ca(&junk).is_err());
        assert!(load_ca(&dir.join("missing.pem")).is_err());
        assert_eq!(load_ca(Path::new(TEST_CA)).unwrap().len(), 1);
        std::fs::remove_dir_all(dir).ok();
    }

    /// A one-shot HTTPS server on 127.0.0.1 presenting the `localhost` leaf
    /// signed by the test root. Returns the URL to fetch.
    fn tls_server() -> String {
        use rustls_pki_types::pem::PemObject;
        use std::io::{Read, Write};
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls/");
        let certs = rustls_pki_types::CertificateDer::pem_file_iter(format!("{dir}localhost.pem"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pki_types::PrivateKeyDer::from_pem_file(format!("{dir}localhost.key")).unwrap();
        let config = std::sync::Arc::new(
            rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for sock in listener.incoming().flatten() {
                let conn = rustls::ServerConnection::new(config.clone()).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, sock);
                let mut buf = [0u8; 1024];
                // A failed handshake (the untrusted case) surfaces here.
                if tls.read(&mut buf).is_ok() {
                    let _ = tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
                    let _ = tls.flush();
                }
            }
        });
        format!("https://localhost:{port}/")
    }

    #[test]
    fn ca_cert_makes_a_privately_signed_server_trusted() {
        let url = tls_server();
        let t = std::time::Duration::from_secs(5);

        // Public roots only: the private root is unknown, the handshake fails.
        let plain = NetworkSettings::default().agents(t);
        assert!(plain.for_url(&url).get(&url).call().is_err());

        // With the root configured, both agents trust it — the direct one too,
        // since an internal mirror under `no_proxy` is the likeliest user.
        let net = NetworkSettings {
            ca_cert: Some(TEST_CA.into()),
            no_proxy: vec!["localhost".into()],
            ..Default::default()
        };
        let body = net.agents(t).for_url(&url).get(&url).call().unwrap().into_string().unwrap();
        assert_eq!(body, "ok");
        let body = net.apply(ureq::AgentBuilder::new()).build().get(&url).call().unwrap().into_string().unwrap();
        assert_eq!(body, "ok");
    }

}
