//! Sensitive-API surface.
//!
//! Cheap substring scan for known dangerous primitives. We deduplicate per (file, api)
//! and roll up at Low severity unless the file ALSO matched obfuscation/install-hook
//! analyzers — escalation is left to the orchestration layer in v2.

use std::collections::HashSet;
use std::path::Path;

use crate::analyze::util;
use crate::model::{Category, Finding, Severity};

#[derive(Copy, Clone)]
pub enum Lang {
    JavaScript,
    Python,
    Rust,
    Ruby,
    Php,
    Go,
    Java,
    /// C and C++ (shared headers, overlapping surface).
    Cpp,
    Perl,
}

impl Lang {
    /// Every language, for a full-tree source scan (`system inspect --deep`).
    pub const ALL: &'static [Lang] = &[
        Lang::JavaScript,
        Lang::Python,
        Lang::Rust,
        Lang::Ruby,
        Lang::Php,
        Lang::Go,
        Lang::Java,
        Lang::Cpp,
        Lang::Perl,
    ];

    fn exts(self) -> &'static [&'static str] {
        match self {
            Lang::JavaScript => &["js", "mjs", "cjs"],
            Lang::Python => &["py"],
            Lang::Rust => &["rs"],
            Lang::Ruby => &["rb"],
            Lang::Php => &["php"],
            Lang::Go => &["go"],
            Lang::Java => &["java", "kt"],
            Lang::Cpp => &["c", "h", "cpp", "cc", "cxx", "hpp", "hh", "hxx"],
            Lang::Perl => &["pl", "pm", "t"],
        }
    }
    fn apis(self) -> &'static [&'static str] {
        match self {
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
        }
    }
}

pub fn scan_dir(root: &Path, out: &mut Vec<Finding>, lang: Lang) {
    for path in util::walk_files(root, lang.exts()) {
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let mut hit: HashSet<&'static str> = HashSet::new();
        for api in lang.apis() {
            if text.contains(api) {
                hit.insert(api);
            }
        }
        if hit.is_empty() {
            continue;
        }
        let dep = util::owner(&path, "<project>");
        let mut apis: Vec<&str> = hit.into_iter().collect();
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_one(file: &str, content: &str, lang: Lang) -> Vec<Finding> {
        let dir = std::env::temp_dir().join(format!("pm-sapi-{}-{file}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(file), content).unwrap();
        let mut out = Vec::new();
        scan_dir(&dir, &mut out, lang);
        std::fs::remove_dir_all(&dir).ok();
        out
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
