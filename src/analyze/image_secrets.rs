//! Credentials that were deleted from an image but never actually removed.
//!
//! A layer does not delete anything. It records that a path should be hidden, and
//! the file goes on living in the layer below, in a blob that ships with the
//! image. So the most common "fix" for a leaked build secret —
//!
//! ```dockerfile
//! COPY .npmrc /root/.npmrc
//! RUN npm ci && rm /root/.npmrc
//! ```
//!
//! — removes nothing. The flattened filesystem is clean, every scanner that looks
//! only at the flattened filesystem says so, and anyone who can pull the image
//! reads the token back out of the earlier layer with `tar`.
//!
//! This is the check that justifies stacking layers by hand rather than letting
//! the runtime flatten them, because a flattened image cannot express the
//! question, let alone answer it.
//!
//! Two filters keep it quiet. The **path** has to look like somewhere credentials
//! live, and the **content** has to look like a credential — a `.pem` holding a
//! certificate is not a leak, and a `.pem` holding a private key is.

use crate::analyze::dockerfile::looks_like_secret;
use crate::model::{Category, Finding, Severity};

/// A file an image deleted in a later layer while still shipping it in an
/// earlier one.
#[derive(Debug, Clone)]
pub struct Removed {
    /// The path as the image saw it, e.g. `/root/.npmrc`.
    pub path: String,
    /// The build step that put it there.
    pub written_by: String,
    /// The build step that hid it.
    pub deleted_by: String,
}

/// Exact file names that exist to hold credentials.
const CREDENTIAL_FILES: &[&str] = &[
    ".npmrc",
    ".netrc",
    "_netrc",
    ".git-credentials",
    ".pypirc",
    ".pgpass",
    ".htpasswd",
    "credentials",
    "kubeconfig",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
];

/// Extensions that carry key material.
const CREDENTIAL_EXTS: &[&str] = &["pem", "key", "p12", "pfx", "jks", "keystore", "ppk"];

/// Path fragments that make an otherwise ordinary name a credential.
const CREDENTIAL_PATHS: &[&str] = &[
    "/.ssh/",
    "/.aws/credentials",
    "/.docker/config.json",
    "/.kube/config",
    "/.gem/credentials",
    "/.config/gh/hosts.yml",
];

/// Does this path name somewhere credentials are kept?
pub fn is_credential_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);

    if CREDENTIAL_FILES.contains(&name) || CREDENTIAL_PATHS.iter().any(|p| lower.contains(p)) {
        return true;
    }
    if name == ".env" || name.starts_with(".env.") {
        return true;
    }
    // `secrets.yaml`, `secret.json`, `service-account-key.json`…
    if (name.starts_with("secret") || name.contains("service-account"))
        && name.contains('.')
        && !name.ends_with(".md")
    {
        return true;
    }
    name.rsplit_once('.')
        .is_some_and(|(_, ext)| CREDENTIAL_EXTS.contains(&ext))
}

/// Does the file's content actually look like a credential?
///
/// The path check alone is too eager: a `.pem` is as often a public certificate
/// as a private key, and an empty `.npmrc` leaks nothing. This is what keeps the
/// finding worth reading.
pub fn holds_credential(path: &str, content: &[u8]) -> bool {
    // Binary key stores cannot be inspected as text; their existence is the
    // signal, and an empty one is not one.
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    let binary = name
        .rsplit_once('.')
        .is_some_and(|(_, e)| matches!(e, "p12" | "pfx" | "jks" | "keystore"));
    if binary {
        return !content.is_empty();
    }

    let Ok(text) = std::str::from_utf8(content) else {
        return !content.is_empty();
    };
    let text = text.trim();
    if text.is_empty() {
        return false;
    }

    // PEM: a private key is a secret, a certificate is public by design.
    if text.contains("-----BEGIN") {
        return text.contains("PRIVATE KEY");
    }
    // Registry and VCS credential files: the token is the value, so an entry
    // with an actual value is the signal.
    if matches!(
        name,
        ".npmrc" | ".netrc" | "_netrc" | ".git-credentials" | ".pypirc" | ".pgpass"
    ) || lower.contains("/.docker/config.json")
        || lower.contains("/.aws/credentials")
    {
        return text.lines().any(|l| {
            let l = l.trim();
            !l.is_empty() && !l.starts_with('#') && (l.contains('=') || l.contains(':'))
        });
    }
    // Environment files: only when a variable that looks like a credential
    // actually has a value.
    if name == ".env" || name.starts_with(".env.") {
        return text.lines().any(|l| {
            l.split_once('=')
                .is_some_and(|(k, v)| looks_like_secret(k.trim()) && !v.trim().is_empty())
        });
    }
    true
}

/// Turn the removals into findings.
pub fn scan(removed: &[Removed], label: &str) -> Vec<Finding> {
    removed
        .iter()
        .map(|r| Finding {
            dependency: label.to_string(),
            severity: Severity::Critical,
            category: Category::SensitiveApi,
            detail: format!(
                "`{}` was added by `{}` and removed by `{}`, but removing a file in a later layer \
                 only hides it — it still ships in the earlier layer and anyone who can pull this \
                 image can read it. Rotate the credential, then rebuild without it ever entering a \
                 layer (a build secret or a multi-stage copy)",
                r.path, r.written_by, r.deleted_by
            ),
            location: Some(format!("{label} ({})", r.path)),
            evidence: None,
            enrich_url: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_paths_are_recognised() {
        for p in [
            "/root/.npmrc",
            "/root/.netrc",
            "/home/app/.git-credentials",
            "/root/.ssh/id_rsa",
            "/root/.ssh/anything",
            "/root/.aws/credentials",
            "/root/.docker/config.json",
            "/etc/ssl/server.pem",
            "/opt/app/tls.key",
            "/opt/keys/store.jks",
            "/app/.env",
            "/app/.env.production",
            "/app/secrets.yaml",
            "/app/service-account-key.json",
            "/root/kubeconfig",
        ] {
            assert!(is_credential_path(p), "{p} should match");
        }
    }

    #[test]
    fn ordinary_paths_are_not_credentials() {
        for p in [
            "/usr/bin/curl",
            "/app/package.json",
            "/app/index.js",
            "/etc/os-release",
            "/app/SECRETS.md",
            "/app/keyboard.conf",
            "/var/lib/dpkg/status",
        ] {
            assert!(!is_credential_path(p), "{p} should not match");
        }
    }

    /// The filter that makes the finding worth reading: a certificate is public
    /// by design, a private key is not.
    #[test]
    fn a_pem_is_judged_by_what_is_inside_it() {
        let cert = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        let key = b"-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n";
        assert!(!holds_credential("/etc/ssl/server.pem", cert));
        assert!(holds_credential("/etc/ssl/server.pem", key));
    }

    #[test]
    fn an_empty_or_commented_credential_file_leaks_nothing() {
        assert!(!holds_credential("/root/.npmrc", b""));
        assert!(!holds_credential("/root/.npmrc", b"   \n\n"));
        assert!(!holds_credential(
            "/root/.npmrc",
            b"# registry config\n# nothing here\n"
        ));
        assert!(holds_credential(
            "/root/.npmrc",
            b"//registry.npmjs.org/:_authToken=npm_live_abc\n"
        ));
    }

    /// An env file is only a leak when a credential-looking variable has a value.
    #[test]
    fn env_files_need_a_credential_with_a_value() {
        assert!(!holds_credential("/app/.env", b"APP_ENV=prod\nPORT=8080\n"));
        assert!(!holds_credential("/app/.env", b"NPM_TOKEN=\n"));
        assert!(holds_credential(
            "/app/.env",
            b"APP_ENV=prod\nNPM_TOKEN=abc123\n"
        ));
    }

    #[test]
    fn a_binary_key_store_counts_when_it_is_not_empty() {
        assert!(holds_credential("/opt/k.jks", &[0u8, 1, 2, 3]));
        assert!(!holds_credential("/opt/k.jks", b""));
    }

    #[test]
    fn the_finding_names_both_build_steps() {
        let f = scan(
            &[Removed {
                path: "/root/.npmrc".into(),
                written_by: "layer 2: COPY .npmrc /root/.npmrc".into(),
                deleted_by: "layer 4: RUN npm ci && rm /root/.npmrc".into(),
            }],
            "image acme/api:1",
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[0].detail.contains("COPY .npmrc"), "{}", f[0].detail);
        assert!(f[0].detail.contains("rm /root/.npmrc"), "{}", f[0].detail);
        assert!(f[0].detail.contains("only hides it"));
    }
}
