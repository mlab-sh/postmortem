//! Dockerfile risk analysis — a static read of the recipe an image is built from.
//!
//! A Dockerfile is the same kind of object the `system` backends already analyze
//! for Homebrew formulae, PKGBUILDs and maintainer scripts: a build recipe whose
//! every instruction runs as root, on a machine you control, before anyone
//! inspects the result. It just happens to be the one recipe nearly every project
//! keeps in its own repository, where a lockfile scanner never looks.
//!
//! The checks are the ones that decide whether the image you shipped is the image
//! you described:
//!
//! - **an unpinned base** — `FROM node:20` is a moving target; whoever controls
//!   that tag controls the bottom of your image on your next build;
//! - **a remote script piped to a shell** — the install pattern behind the
//!   Codecov and several npm-ecosystem incidents;
//! - **`ADD` from a URL** — fetches and unpacks a remote artifact with no
//!   checksum, unlike a `COPY` of something you reviewed;
//! - **secrets baked into the image** — an `ENV`/`ARG` holding a token stays in
//!   the layer forever, readable by anyone who pulls the image;
//! - **verification switched off** — `--no-check-certificate`, `--allow-unauthenticated`,
//!   `gpgcheck=0` and friends, which turn a signed supply chain into an unsigned one;
//! - **root at runtime** — no `USER` instruction, so the container's process is
//!   root and a container escape starts from there.
//!
//! Line-level heuristics rather than a parser: a Dockerfile with templating or a
//! syntax error still gets read, which matters because those are the ones worth
//! looking at.

use std::path::Path;

use crate::analyze::util;
use crate::model::{Category, Finding, Severity};

/// Environment-variable names that hold a credential. Matched case-insensitively
/// against the *segments* of the assigned name, so `MY_API_KEY` and `npm_token`
/// both land while `AUTHOR_NAME` does not.
pub(crate) const SECRET_NAMES: &[&str] = &[
    "token",
    "secret",
    "secrets",
    "password",
    "passwd",
    "pwd",
    "apikey",
    "credential",
    "credentials",
    "auth",
    "key",
    "keys",
];

/// Flags that switch off the verification the surrounding tooling would do.
const VERIFICATION_OFF: &[&str] = &[
    "--no-check-certificate",
    "--allow-unauthenticated",
    "--allow-untrusted",
    "--nogpgcheck",
    "gpgcheck=0",
    "sslverify=false",
    "--insecure",
    "--trusted-host",
    "NODE_TLS_REJECT_UNAUTHORIZED=0",
    "GIT_SSL_NO_VERIFY",
];

/// Is this path a Dockerfile? Covers the conventional spellings and the
/// `<purpose>.Dockerfile` / `Dockerfile.<purpose>` variants, plus the OCI-neutral
/// `Containerfile` podman and buildah use.
fn is_dockerfile(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let lower = name.to_lowercase();
    lower == "dockerfile"
        || lower == "containerfile"
        || lower.starts_with("dockerfile.")
        || lower.starts_with("containerfile.")
        || lower.ends_with(".dockerfile")
        || lower.ends_with(".containerfile")
}

pub fn scan_dir(root: &Path, out: &mut Vec<Finding>) {
    // Dockerfiles have no extension of their own, so the walk cannot filter on
    // one and every file is matched by name instead.
    for path in util::walk_files(root, &[]) {
        if !is_dockerfile(&path) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        scan_text(&text, &path, out);
    }
}

/// Analyze one Dockerfile's text. Split out so the rules are testable without
/// touching the filesystem.
fn scan_text(text: &str, path: &Path, out: &mut Vec<Finding>) {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("Dockerfile")
        .to_string();
    let mk = |severity: Severity, detail: String| Finding {
        dependency: name.clone(),
        severity,
        category: Category::SensitiveApi,
        detail,
        location: Some(path.display().to_string()),
        evidence: None,
        enrich_url: None,
    };

    let mut has_user = false;
    // Stage names introduced by `FROM x AS builder`: a later `FROM builder` refers
    // to this file's own stage, not to a registry image, and pinning it would be
    // meaningless.
    let mut stages: Vec<String> = Vec::new();

    for logical in logical_lines(text) {
        let l = logical.trim();
        let Some((instr, rest)) = l.split_once(char::is_whitespace) else {
            continue;
        };
        let instr = instr.to_uppercase();
        let rest = rest.trim();

        match instr.as_str() {
            "FROM" => {
                let mut it = rest.split_whitespace();
                let Some(image) = it.next() else { continue };
                // `FROM x AS name` declares a stage.
                let mut words = rest.split_whitespace().skip(1);
                while let Some(w) = words.next() {
                    if w.eq_ignore_ascii_case("as")
                        && let Some(alias) = words.next()
                    {
                        stages.push(alias.to_lowercase());
                    }
                }
                if stages.contains(&image.to_lowercase()) || image.starts_with('$') {
                    continue; // an earlier stage, or a build arg
                }
                if !image.contains('@') {
                    let how = match image.rsplit_once(':') {
                        // `:latest` is the worst case: it moves on every push.
                        Some((_, tag)) if tag == "latest" => "`:latest`",
                        Some(_) => "a mutable tag",
                        None => "no tag at all, so `:latest`",
                    };
                    out.push(mk(
                        Severity::Medium,
                        format!(
                            "base image `{image}` is pinned by {how} rather than a digest — \
                             whoever controls that tag controls the bottom of this image"
                        ),
                    ));
                }
            }
            "USER" => has_user = !rest.eq_ignore_ascii_case("root") && !rest.starts_with('0'),
            "ADD" => {
                if let Some(url) = rest.split_whitespace().find(|w| {
                    w.starts_with("http://") || w.starts_with("https://") || w.starts_with("git@")
                }) {
                    out.push(mk(
                        Severity::Medium,
                        format!(
                            "`ADD {url}` fetches a remote artifact into the image with no checksum \
                             — `COPY` something reviewed, or download and verify it in a `RUN`"
                        ),
                    ));
                }
            }
            "ENV" | "ARG" => {
                if let Some(var) = secret_assignment(rest) {
                    out.push(mk(
                        Severity::High,
                        format!(
                            "`{instr} {var}` bakes a credential into an image layer, where it stays \
                             readable to anyone who pulls the image — use a build secret instead"
                        ),
                    ));
                }
            }
            _ => {}
        }

        // `RUN` bodies are shell, and so are the risky flags; checked on every
        // instruction because a `curl … | sh` can also appear in `ENTRYPOINT`.
        if pipes_to_shell(l) {
            out.push(mk(
                Severity::High,
                "pipes a remote script straight to a shell (`curl … | sh`) — the fetched code is \
                 never reviewed and can change between builds"
                    .into(),
            ));
        }
        if let Some(flag) = VERIFICATION_OFF.iter().find(|f| l.contains(**f)) {
            out.push(mk(
                Severity::High,
                format!("`{flag}` disables signature or certificate verification for this step"),
            ));
        }
    }

    if !has_user {
        out.push(mk(
            Severity::Low,
            "no `USER` instruction — the container's main process runs as root, so a compromise \
             of it starts with root inside the container"
                .into(),
        ));
    }
}

/// Join Dockerfile continuation lines (`\` at end of line) into one logical
/// instruction, and drop comments. A `curl … | sh` split across a line break is
/// still a `curl … | sh`, and is exactly how it tends to be written.
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(head) = line.strip_suffix('\\') {
            current.push_str(head.trim_end());
            current.push(' ');
            continue;
        }
        current.push_str(line);
        out.push(std::mem::take(&mut current));
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

/// Does a variable or label name look like it holds a credential?
///
/// Matched per segment rather than as a substring: `contains("auth")` fires on
/// `AUTHOR_NAME`, and a check that cries wolf on an author's name is a check
/// people switch off. Shared with the image-config analyzer so a rule cannot
/// drift between the recipe and the artifact it built.
pub(crate) fn looks_like_secret(name: &str) -> bool {
    name.split(['_', '-', '.', ' '])
        .map(str::to_ascii_lowercase)
        .any(|seg| SECRET_NAMES.contains(&seg.as_str()))
}

/// Does this line fetch something and hand it to a shell?
pub(crate) fn pipes_to_shell(l: &str) -> bool {
    let fetches = l.contains("curl ") || l.contains("wget ");
    if !fetches {
        return false;
    }
    // Normalised so `| sh`, `|sh`, `| bash -` and `|  sudo bash` all match.
    let squashed = l.replace(char::is_whitespace, "");
    ["|sh", "|bash", "|zsh", "|python", "|sudosh", "|sudobash"]
        .iter()
        .any(|p| squashed.contains(p))
}

/// The variable name in an `ENV`/`ARG` body when it looks like a credential, and
/// when a value is actually assigned. A bare `ARG NPM_TOKEN` declares a build
/// argument without baking anything in, which is the correct pattern.
fn secret_assignment(rest: &str) -> Option<String> {
    for pair in rest.split_whitespace() {
        let (name, value) = pair.split_once('=')?;
        if value.trim_matches(['"', '\'']).is_empty() {
            continue;
        }
        if looks_like_secret(name) {
            return Some(name.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(text: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        scan_text(text, Path::new("Dockerfile"), &mut out);
        out
    }
    fn details(text: &str) -> String {
        scan(text)
            .iter()
            .map(|f| f.detail.clone())
            .collect::<Vec<_>>()
            .join(" | ")
    }

    #[test]
    fn a_digest_pinned_base_with_a_user_is_clean() {
        let d = details("FROM alpine@sha256:aaaa\nRUN echo hi\nUSER app\n");
        assert_eq!(d, "", "nothing to report: {d}");
    }

    #[test]
    fn a_mutable_tag_is_flagged_and_latest_is_named() {
        assert!(details("FROM node:20\nUSER app\n").contains("a mutable tag"));
        assert!(details("FROM node:latest\nUSER app\n").contains("`:latest`"));
        assert!(details("FROM node\nUSER app\n").contains("no tag at all"));
    }

    /// `FROM builder` refers to a stage declared earlier in the same file, not to
    /// a registry image — pinning it would mean nothing.
    #[test]
    fn a_later_stage_reference_is_not_an_unpinned_base() {
        let d = details("FROM alpine@sha256:aaaa AS builder\nRUN make\nFROM builder\nUSER app\n");
        assert_eq!(d, "", "the second FROM is this file's own stage: {d}");
    }

    #[test]
    fn a_remote_script_piped_to_a_shell_is_flagged_across_a_line_break() {
        let d = details(
            "FROM alpine@sha256:aaaa\nUSER app\nRUN curl -fsSL https://x.test/i.sh \\\n  | sh\n",
        );
        assert!(d.contains("pipes a remote script"), "{d}");
    }

    #[test]
    fn add_from_a_url_is_flagged_but_a_local_copy_is_not() {
        assert!(
            details("FROM a@sha256:b\nUSER app\nADD https://x.test/t.tgz /opt/\n")
                .contains("fetches a remote artifact")
        );
        assert_eq!(
            details("FROM a@sha256:b\nUSER app\nADD ./local.tgz /opt/\n"),
            ""
        );
    }

    /// A declared build argument bakes nothing into the image; an assigned one does.
    #[test]
    fn only_an_assigned_credential_is_flagged() {
        assert_eq!(details("FROM a@sha256:b\nUSER app\nARG NPM_TOKEN\n"), "");
        let d = details("FROM a@sha256:b\nUSER app\nENV NPM_TOKEN=abc123\n");
        assert!(d.contains("bakes a credential"), "{d}");
    }

    #[test]
    fn disabled_verification_is_flagged() {
        let d = details(
            "FROM a@sha256:b\nUSER app\nRUN wget --no-check-certificate https://x.test/f\n",
        );
        assert!(d.contains("--no-check-certificate"), "{d}");
    }

    #[test]
    fn a_missing_user_instruction_is_reported_once() {
        let d = scan("FROM a@sha256:b\nRUN echo hi\n");
        assert_eq!(d.len(), 1);
        assert!(d[0].detail.contains("no `USER` instruction"));
        // `USER root` is not a user.
        assert_eq!(scan("FROM a@sha256:b\nUSER root\n").len(), 1);
        assert_eq!(scan("FROM a@sha256:b\nUSER 0\n").len(), 1);
    }

    #[test]
    fn comments_are_not_instructions() {
        assert_eq!(
            details("FROM a@sha256:b\nUSER app\n# RUN curl https://x.test | sh\n"),
            ""
        );
    }

    #[test]
    fn dockerfile_names_are_recognised() {
        for n in [
            "Dockerfile",
            "dockerfile",
            "Dockerfile.prod",
            "prod.Dockerfile",
            "Containerfile",
        ] {
            assert!(is_dockerfile(Path::new(n)), "{n}");
        }
        for n in ["docker-compose.yml", "Makefile", "README.md"] {
            assert!(!is_dockerfile(Path::new(n)), "{n}");
        }
    }
}


#[cfg(test)]
mod secret_name_tests {
    use super::looks_like_secret;

    #[test]
    fn credential_names_match_per_segment() {
        for n in [
            "NPM_TOKEN",
            "npm_token",
            "MY_API_KEY",
            "AWS_SECRET_ACCESS_KEY",
            "db.password",
            "io.acme.deploy-key",
            "REGISTRY_AUTH",
        ] {
            assert!(looks_like_secret(n), "{n} should match");
        }
    }

    /// The reason for matching segments rather than substrings: a check that
    /// fires on an author's name is a check people switch off.
    #[test]
    fn ordinary_names_do_not_match() {
        for n in [
            "AUTHOR_NAME",
            "APP_ENV",
            "PATH",
            "KEYBOARD_LAYOUT",
            "MONKEY",
            "TOKENIZER_PATH",
        ] {
            assert!(!looks_like_secret(n), "{n} should not match");
        }
    }
}
