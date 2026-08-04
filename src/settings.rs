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
    /// Token for the mlab vuln-scan API (`vuln.mlab.sh`). Falls back to
    /// `$VULN_MLAB_TOKEN`; without one, scans use the anonymous 8/hr limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vuln_token: Option<String>,
    pub tree: TreeSettings,
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
        Self { min_stars: 20, recent_days: 30, stale_days: 365 }
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

        let where_to = config_path().map(|p| p.display().to_string()).unwrap_or_default();
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

    /// Resolve the mlab vuln-scan token: config → `$VULN_MLAB_TOKEN`. No prompt —
    /// anonymous scanning works (just rate-limited), so this stays quiet.
    pub fn vuln_token(&self) -> Option<String> {
        self.vuln_token
            .clone()
            .filter(|t| !t.trim().is_empty())
            .or_else(|| std::env::var("VULN_MLAB_TOKEN").ok().filter(|t| !t.trim().is_empty()))
    }
}

#[cfg(unix)]
fn restrict_perms(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_perms(_p: &Path) {}
