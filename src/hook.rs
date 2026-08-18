//! `postmortem hook` — the git pre-commit hook.
//!
//! ## What this does and does not buy you
//!
//! It does **not** stop a malicious install script. By the time git runs a
//! pre-commit hook, `npm install` has long since finished and anything it was
//! going to execute has executed. Withholding that execution is npm's
//! `allowScripts` job (see [`crate::scripts`]), not a git hook's.
//!
//! What it buys is the next thing: not *propagating* a bad lockfile to everyone
//! else. The developer who ran the install has already taken the hit; the hook
//! stops the team from taking it too.
//!
//! Saying this plainly matters, because a hook advertised as "blocks malicious
//! installs" would give exactly the wrong impression of when protection applies.
//!
//! ## Three constraints, from how hooks actually fail
//!
//! * **Fast, and offline.** A hook that adds seconds to every commit gets
//!   removed within the week. So the generated hook runs the offline scan and
//!   only when a lockfile is actually staged.
//! * **Never clobber.** An existing hook is somebody's work. postmortem refuses
//!   to overwrite one it did not write, and points at the managers (husky,
//!   lefthook, pre-commit) that own the file when it recognises them.
//! * **No pretence of enforcement.** `git commit --no-verify` skips every hook,
//!   and hooks live in `.git/hooks`, which is not cloned. A hook is a convenience
//!   for the person who installs it; the [CI gate](crate::gate) is the control.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use owo_colors::OwoColorize;

/// Marker written into the hook so a later run can tell it is ours and replace
/// it safely. Anything without it is treated as somebody else's file.
const MARKER: &str = "# managed by postmortem — https://github.com/mlab-sh/postmortem";

/// What the pre-commit slot currently holds.
#[derive(Debug, PartialEq, Eq)]
pub enum State {
    /// Nothing installed.
    Absent,
    /// Installed by postmortem, safe to replace.
    Ours,
    /// Somebody else's hook, or a hook manager's.
    Foreign { manager: Option<&'static str> },
}

/// Hook managers that own `.git/hooks/pre-commit` themselves. Fighting them for
/// the file is a losing game, so postmortem tells the user what to add instead.
fn detect_manager(body: &str) -> Option<&'static str> {
    for (needle, name) in [
        ("husky", "husky"),
        ("lefthook", "lefthook"),
        ("pre-commit.com", "pre-commit"),
        ("pre_commit", "pre-commit"),
        ("overcommit", "overcommit"),
    ] {
        if body.contains(needle) {
            return Some(name);
        }
    }
    None
}

/// The `.git` directory for `root`, following a `gitdir:` pointer file so
/// worktrees and submodules resolve to the real hooks directory.
pub fn git_dir(root: &Path) -> Option<PathBuf> {
    let dot = root.join(".git");
    if dot.is_dir() {
        return Some(dot);
    }
    // A worktree or submodule has `.git` as a file containing `gitdir: <path>`.
    let text = std::fs::read_to_string(&dot).ok()?;
    let target = text.strip_prefix("gitdir:")?.trim();
    let p = PathBuf::from(target);
    Some(if p.is_absolute() { p } else { root.join(p) })
}

pub fn hook_path(root: &Path) -> Option<PathBuf> {
    Some(git_dir(root)?.join("hooks").join("pre-commit"))
}

/// Inspect the pre-commit slot.
pub fn state(root: &Path) -> Result<State> {
    let path = hook_path(root).context("not a git repository (no .git)")?;
    let Ok(body) = std::fs::read_to_string(&path) else {
        return Ok(State::Absent);
    };
    if body.contains(MARKER) {
        return Ok(State::Ours);
    }
    Ok(State::Foreign {
        manager: detect_manager(&body),
    })
}

/// The hook script.
///
/// Deliberately small and readable: somebody will open this file wondering why
/// their commit was rejected, and it should answer them without a detour.
fn script(args: &str) -> String {
    format!(
        r#"#!/bin/sh
{MARKER}
#
# Scans staged dependency changes before they reach the rest of the team.
#
# NOTE: this does not stop a malicious install script — that already ran when
# the lockfile was installed. It stops the bad lockfile spreading. Withholding
# install-time execution is npm's `allowScripts`; see `postmortem scripts`.
#
# Remove with:  postmortem hook uninstall
# Skip once:    git commit --no-verify

set -e

# Only when a manifest or lockfile is actually staged — every other commit
# should cost nothing.
if ! git diff --cached --name-only | grep -qE '(^|/)(package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|Cargo\.lock|Gemfile\.lock|composer\.lock|poetry\.lock|Pipfile\.lock|go\.sum|requirements.*\.txt|gradle\.lockfile)$'; then
  exit 0
fi

if ! command -v postmortem >/dev/null 2>&1; then
  echo "postmortem: not on PATH — skipping the pre-commit scan" >&2
  exit 0
fi

echo "postmortem: dependency change staged, scanning…" >&2
exec postmortem {args}
"#
    )
}

/// Install (or replace our own) hook.
///
/// `args` is the command line the hook runs — offline by default, because a
/// hook that reaches the network on every commit is a hook that gets deleted.
pub fn install(root: &Path, args: &str, force: bool) -> Result<PathBuf> {
    let path = hook_path(root).context("not a git repository (no .git)")?;
    match state(root)? {
        State::Foreign { manager } if !force => {
            let hint = match manager {
                Some(m) => format!(
                    "\n{m} owns this file — add `postmortem {args}` to its config instead, \
                     or pass --force to take the file over"
                ),
                None => "\npass --force to replace it".to_string(),
            };
            anyhow::bail!(
                "{} already exists and was not written by postmortem{hint}",
                path.display()
            );
        }
        _ => {}
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    std::fs::write(&path, script(args)).with_context(|| format!("writing {}", path.display()))?;
    make_executable(&path);
    Ok(path)
}

/// Remove the hook, but only if postmortem wrote it.
pub fn uninstall(root: &Path) -> Result<bool> {
    let path = hook_path(root).context("not a git repository (no .git)")?;
    match state(root)? {
        State::Ours => {
            std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
            Ok(true)
        }
        State::Absent => Ok(false),
        // Never delete a file we did not create, even when asked to uninstall.
        State::Foreign { .. } => {
            anyhow::bail!(
                "{} was not written by postmortem — leaving it alone",
                path.display()
            )
        }
    }
}

#[cfg(unix)]
fn make_executable(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755));
}
#[cfg(not(unix))]
fn make_executable(_p: &Path) {}

/// Report the current state.
pub fn render_status(root: &Path, st: &State) {
    let path = hook_path(root)
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    println!("{}  {}", "pre-commit hook".bold(), path.dimmed());
    println!();
    match st {
        State::Ours => {
            println!("  {}  installed by postmortem", "·".green());
            println!(
                "  {}",
                "it scans only commits that stage a lockfile, and runs offline".dimmed()
            );
        }
        State::Absent => {
            println!("  {}  not installed", "·".dimmed());
            println!("  {}", "install with: postmortem hook install".dimmed());
        }
        State::Foreign { manager: Some(m) } => {
            println!("  {}  managed by {m}", "!".truecolor(255, 165, 0));
            println!(
                "  {}",
                format!("add `postmortem scan . --severity high` to your {m} config").dimmed()
            );
        }
        State::Foreign { manager: None } => {
            println!(
                "  {}  a hook is present that postmortem did not write",
                "!".truecolor(255, 165, 0)
            );
            println!("  {}", "pass --force to take it over".dimmed());
        }
    }
    println!(
        "\n  {}",
        "a hook is a convenience, not a control: `--no-verify` skips it and hooks are \
         not cloned with the repo — the CI gate is the control"
            .dimmed()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    fn repo(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pm-hook-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".git").join("hooks")).unwrap();
        d
    }

    #[test]
    fn a_fresh_repository_has_no_hook() {
        let d = repo("fresh");
        assert_eq!(state(&d).unwrap(), State::Absent);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn install_writes_an_executable_marked_hook() {
        let d = repo("install");
        let p = install(&d, "scan . --severity high", false).unwrap();
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(body.contains(MARKER));
        assert!(body.starts_with("#!/bin/sh"));
        assert!(body.contains("postmortem scan . --severity high"));
        assert_eq!(state(&d).unwrap(), State::Ours);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o111,
                0o111
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_hook_exits_early_when_no_lockfile_is_staged() {
        // A hook that costs time on every commit gets deleted within the week.
        let body = script("scan .");
        assert!(body.contains("git diff --cached --name-only"));
        assert!(body.contains("exit 0"));
        // And it must not fail the commit when postmortem is simply absent.
        assert!(body.contains("not on PATH"));
    }

    #[test]
    fn install_refuses_to_clobber_a_foreign_hook() {
        let d = repo("foreign");
        let p = hook_path(&d).unwrap();
        std::fs::write(&p, "#!/bin/sh\necho mine\n").unwrap();
        assert!(matches!(
            state(&d).unwrap(),
            State::Foreign { manager: None }
        ));
        let err = install(&d, "scan .", false).unwrap_err().to_string();
        assert!(err.contains("not written by postmortem"), "got: {err}");
        // The file is untouched.
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "#!/bin/sh\necho mine\n"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn force_takes_over_a_foreign_hook() {
        let d = repo("force");
        std::fs::write(hook_path(&d).unwrap(), "#!/bin/sh\necho mine\n").unwrap();
        install(&d, "scan .", true).unwrap();
        assert_eq!(state(&d).unwrap(), State::Ours);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_hook_manager_is_named_so_the_user_configures_it_instead() {
        let d = repo("husky");
        std::fs::write(
            hook_path(&d).unwrap(),
            "#!/bin/sh\n. \"$(dirname $0)/husky.sh\"\n",
        )
        .unwrap();
        assert_eq!(
            state(&d).unwrap(),
            State::Foreign {
                manager: Some("husky")
            }
        );
        let err = install(&d, "scan .", false).unwrap_err().to_string();
        assert!(err.contains("husky owns this file"), "got: {err}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn reinstalling_our_own_hook_is_allowed() {
        let d = repo("reinstall");
        install(&d, "scan .", false).unwrap();
        install(&d, "audit . --omit dev", false).unwrap();
        let body = std::fs::read_to_string(hook_path(&d).unwrap()).unwrap();
        assert!(body.contains("audit . --omit dev"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn uninstall_removes_ours_and_refuses_a_foreign_one() {
        let d = repo("uninstall");
        install(&d, "scan .", false).unwrap();
        assert!(uninstall(&d).unwrap());
        assert_eq!(state(&d).unwrap(), State::Absent);
        // Nothing to remove is not an error.
        assert!(!uninstall(&d).unwrap());

        // A foreign hook is never deleted, even by an explicit uninstall.
        std::fs::write(hook_path(&d).unwrap(), "#!/bin/sh\necho mine\n").unwrap();
        assert!(uninstall(&d).is_err());
        assert!(hook_path(&d).unwrap().exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_worktree_gitdir_pointer_is_followed() {
        // `.git` is a file in a worktree or submodule; the hooks live elsewhere.
        let d = std::env::temp_dir().join(format!("pm-hook-wt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("real").join("hooks")).unwrap();
        std::fs::create_dir_all(d.join("wt")).unwrap();
        std::fs::write(
            d.join("wt").join(".git"),
            format!("gitdir: {}\n", d.join("real").display()),
        )
        .unwrap();
        assert_eq!(git_dir(&d.join("wt")).unwrap(), d.join("real"));
        install(&d.join("wt"), "scan .", false).unwrap();
        assert!(d.join("real").join("hooks").join("pre-commit").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_directory_that_is_not_a_repository_is_an_error() {
        let d = std::env::temp_dir().join(format!("pm-hook-norepo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        assert!(state(&d).is_err());
        assert!(install(&d, "scan .", false).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
