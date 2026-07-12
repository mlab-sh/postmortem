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
}

impl Lang {
    fn exts(self) -> &'static [&'static str] {
        match self {
            Lang::JavaScript => &["js", "mjs", "cjs"],
            Lang::Python => &["py"],
            Lang::Rust => &["rs"],
            Lang::Ruby => &["rb"],
            Lang::Php => &["php"],
            Lang::Go => &["go"],
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
