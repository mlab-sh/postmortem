//! Execution & privilege surface, shared by the distro backends (apt, dnf,
//! pacman): what a package's installed files let it do — run at boot, run on a
//! schedule, touch auth config, or hold a setuid bit — and whether its shipped
//! files still match the package database.

use super::*;

/// A `dpkg --verify` / `rpm -Va` line reporting a digest (content) mismatch on a
/// plain file. Both tools share the rpm-style format: `<9-flag string> [attr]
/// <path>`, where the digest check is flag index 2 (`5` = fail) and a single-letter
/// middle token marks a non-plain file (`c` config, `d` doc, `g` ghost, …) that is
/// expected to differ.
pub(super) fn verify_line_is_tamper(line: &str) -> bool {
    let toks: Vec<&str> = line.split_whitespace().collect();
    let Some(flags) = toks.first() else {
        return false;
    };
    let md5_changed = flags.chars().nth(2) == Some('5');
    let special = toks.len() == 3 && toks[1].len() == 1;
    md5_changed && !special
}

/// Setuid/setgid binaries under `/usr` and `/opt` (one `find`, `-perm /6000`).
/// Matched against each package's file list to attribute the binary to its owner.
/// Distro-agnostic: shared by the apt and dnf backends.
pub(super) fn find_setuid_files() -> std::collections::HashSet<String> {
    Command::new("find")
        .args(["/usr", "/opt", "-xdev", "-type", "f", "-perm", "/6000"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Signals derived from the files a package installs: a boot service, a scheduled
/// task, auth config, or a setuid/setgid binary. The first three are contextual
/// (Info); a setuid binary is a real privilege-escalation surface (Low).
pub(super) fn persistence_signals(
    files: &[String],
    setuid: &std::collections::HashSet<String>,
) -> Vec<SysSignal> {
    let mut out = Vec::new();
    if files.iter().any(|f| is_systemd_unit(f, ".service")) {
        out.push(SysSignal::new("installs-service (runs at boot)", Severity::Info, 0));
    }
    if files.iter().any(|f| is_cron_or_timer(f)) {
        out.push(SysSignal::new("installs-scheduled-task (cron/timer)", Severity::Info, 0));
    }
    if files.iter().any(|f| is_auth_config(f)) {
        out.push(SysSignal::new("modifies-auth (sudoers.d/pam)", Severity::Info, 0));
    }
    if let Some(p) = files.iter().find(|f| setuid.contains(f.as_str())) {
        let name = p.rsplit('/').next().unwrap_or(p);
        out.push(SysSignal::new(format!("setuid-binary ({name})"), Severity::Low, 10));
    }
    out
}

/// A systemd unit file of the given kind (`.service` / `.timer`) under a system or
/// user unit directory.
fn is_systemd_unit(f: &str, ext: &str) -> bool {
    f.ends_with(ext) && (f.contains("/systemd/system/") || f.contains("/systemd/user/"))
}

/// A cron job (drop-in dir / crontab / spool) or a systemd timer unit.
fn is_cron_or_timer(f: &str) -> bool {
    const CRON_DIRS: [&str; 5] = [
        "/etc/cron.d/",
        "/etc/cron.hourly/",
        "/etc/cron.daily/",
        "/etc/cron.weekly/",
        "/etc/cron.monthly/",
    ];
    f == "/etc/crontab"
        || f.starts_with("/var/spool/cron/")
        || CRON_DIRS.iter().any(|d| f.starts_with(d))
        || is_systemd_unit(f, ".timer")
}

/// An authentication-config file: sudoers, a sudoers.d drop-in, a PAM service
/// config, or a PAM module.
fn is_auth_config(f: &str) -> bool {
    f == "/etc/sudoers"
        || f.starts_with("/etc/sudoers.d/")
        || f.starts_with("/etc/pam.d/")
        || f.contains("/security/pam_")
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistence_signals_classify() {
        let setuid: std::collections::HashSet<String> =
            ["/usr/bin/sudo".to_string()].into_iter().collect();
        let files = vec![
            "/usr/lib/systemd/system/foo.service".to_string(),
            "/etc/cron.d/foo".to_string(),
            "/etc/pam.d/foo".to_string(),
            "/usr/bin/sudo".to_string(),
            "/usr/share/doc/foo/README".to_string(),
        ];
        let labels: Vec<String> =
            persistence_signals(&files, &setuid).into_iter().map(|s| s.label).collect();
        assert!(labels.iter().any(|l| l.starts_with("installs-service")));
        assert!(labels.iter().any(|l| l.starts_with("installs-scheduled-task")));
        assert!(labels.iter().any(|l| l.starts_with("modifies-auth")));
        assert!(labels.contains(&"setuid-binary (sudo)".to_string()));
        // cron.deny / a plain doc file must not trip cron or the others.
        let quiet = vec!["/etc/cron.deny".to_string(), "/usr/bin/plain".to_string()];
        assert!(persistence_signals(&quiet, &setuid).is_empty());
    }

    #[test]
    fn verify_flags_content_tamper() {
        // md5 (index 2) failed on a normal file → tamper (dpkg and rpm -Va alike).
        assert!(verify_line_is_tamper("??5??????   /usr/bin/bar"));
        assert!(verify_line_is_tamper("S.5....T.    /usr/bin/rpmbin"));
        // Same mismatch but a config/doc/ghost file → expected to differ, not tamper.
        assert!(!verify_line_is_tamper("??5?????? c /etc/foo.conf"));
        assert!(!verify_line_is_tamper("S.5....T. d /usr/share/doc/x"));
        // Missing file / all-checks-pass / empty → not a content mismatch.
        assert!(!verify_line_is_tamper("missing     /usr/bin/gone"));
        assert!(!verify_line_is_tamper("??????????  /usr/bin/ok"));
        assert!(!verify_line_is_tamper(""));
    }
}
