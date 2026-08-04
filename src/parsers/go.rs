//! go.mod / go.sum parser (Go modules).
//!
//! Since Go 1.17 the module graph is pruned and `go.mod` lists every module the
//! build needs: direct requirements plain, transitive ones tagged `// indirect`.
//! That makes go.mod a complete, classified dependency list on its own. go.sum
//! adds a `h1:` checksum per module. The require/require-block form:
//!
//! ```text
//! require github.com/foo/bar v1.2.3
//!
//! require (
//!     github.com/gin-gonic/gin v1.9.1
//!     golang.org/x/crypto v0.14.0 // indirect
//! )
//! ```
//!
//! go.mod/go.sum do not encode which module pulls in which, so parent edges are
//! left empty (a `go mod graph` invocation would be needed, and we stay offline).

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::Path;

use crate::model::{Dependency, Ecosystem};

pub fn parse(manifest: &Path, lockfile: Option<&Path>) -> Result<Vec<Dependency>> {
    let text = std::fs::read_to_string(manifest)
        .with_context(|| format!("reading {}", manifest.display()))?;
    let requires = parse_go_mod(&text);

    let sums = match lockfile {
        Some(p) => std::fs::read_to_string(p)
            .map(|s| parse_go_sum(&s))
            .unwrap_or_default(),
        None => BTreeMap::new(),
    };

    Ok(requires
        .into_iter()
        .map(|r| Dependency {
            integrity: sums.get(&(r.path.clone(), r.version.clone())).cloned(),
            name: r.path,
            version: r.version,
            ecosystem: Ecosystem::Go,
            direct: !r.indirect,
            resolved_url: None,
            parents: Vec::new(),
        })
        .collect())
}

/// `replace` directives from a go.mod. Each redirects a module to a fork, a
/// local path, or a different version — supply-chain-relevant on its own, so we
/// surface them rather than silently ignore them. Returns `(from, to)` strings.
pub fn replaces(manifest: &Path) -> Vec<(String, String)> {
    let Ok(text) = std::fs::read_to_string(manifest) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut in_block = false;
    for raw in text.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        if line == "replace (" {
            in_block = true;
            continue;
        }
        if in_block && line == ")" {
            in_block = false;
            continue;
        }
        let body = if let Some(rest) = line.strip_prefix("replace ") {
            Some(rest)
        } else if in_block && !line.is_empty() {
            Some(line)
        } else {
            None
        };
        if let Some(body) = body
            && let Some((from, to)) = body.split_once("=>")
        {
            out.push((from.trim().to_string(), to.trim().to_string()));
        }
    }
    out
}

struct Require {
    path: String,
    version: String,
    indirect: bool,
}

fn parse_go_mod(text: &str) -> Vec<Require> {
    let mut out = Vec::new();
    let mut in_block = false;

    for raw in text.lines() {
        let line = strip_line_comment_keep_indirect(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if in_block {
            if trimmed == ")" {
                in_block = false;
                continue;
            }
            push_require(trimmed, raw, &mut out);
            continue;
        }

        if trimmed == "require (" || trimmed.starts_with("require (") {
            in_block = true;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("require ") {
            push_require(rest.trim(), raw, &mut out);
        }
        // module / go / toolchain / exclude / replace / retract: ignored.
    }
    out
}

fn push_require(entry: &str, raw_line: &str, out: &mut Vec<Require>) {
    let mut parts = entry.split_whitespace();
    let Some(path) = parts.next() else { return };
    let Some(version) = parts.next() else { return };
    if path.is_empty() || version.is_empty() {
        return;
    }
    out.push(Require {
        path: path.to_string(),
        version: version.to_string(),
        indirect: raw_line.contains("// indirect"),
    });
}

/// Strip a trailing `//` comment unless it is the `// indirect` marker, which we
/// need to keep for classification. Leaves indentation intact.
fn strip_line_comment_keep_indirect(line: &str) -> String {
    if line.contains("// indirect") {
        return line.to_string();
    }
    match line.find("//") {
        Some(i) => line[..i].to_string(),
        None => line.to_string(),
    }
}

/// go.sum has two lines per module: `path version h1:...` (the module zip) and
/// `path version/go.mod h1:...`. We keep the module-zip hash.
fn parse_go_sum(text: &str) -> BTreeMap<(String, String), String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(path), Some(version), Some(hash)) =
            (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if version.ends_with("/go.mod") {
            continue;
        }
        out.insert((path.to_string(), version.to_string()), hash.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const GO_MOD: &str = r#"module github.com/acme/victim

go 1.21

require github.com/sirupsen/logrus v1.9.3

require (
	github.com/gin-gonic/gin v1.9.1
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
)

// a stray comment
replace example.com/x => ./local
"#;

    const GO_SUM: &str = "github.com/gin-gonic/gin v1.9.1 h1:AAAA=\ngithub.com/gin-gonic/gin v1.9.1/go.mod h1:BBBB=\ngolang.org/x/crypto v0.14.0 h1:CCCC=\n";

    #[test]
    fn parses_direct_and_indirect() {
        let reqs = parse_go_mod(GO_MOD);
        assert_eq!(reqs.len(), 4);
        let gin = reqs.iter().find(|r| r.path == "github.com/gin-gonic/gin").unwrap();
        assert!(!gin.indirect, "gin is direct");
        let crypto = reqs.iter().find(|r| r.path == "golang.org/x/crypto").unwrap();
        assert!(crypto.indirect, "x/crypto is // indirect");
        assert_eq!(crypto.version, "v0.14.0");
        // single-line require outside a block
        assert!(reqs.iter().any(|r| r.path == "github.com/sirupsen/logrus" && !r.indirect));
    }

    #[test]
    fn attaches_go_sum_hash_for_zip_not_gomod() {
        let dir = std::env::temp_dir().join("postmortem-go-test");
        std::fs::create_dir_all(&dir).unwrap();
        let modp = dir.join("go.mod");
        let sump = dir.join("go.sum");
        std::fs::write(&modp, GO_MOD).unwrap();
        std::fs::write(&sump, GO_SUM).unwrap();

        let deps = parse(&modp, Some(&sump)).unwrap();
        let gin = deps.iter().find(|d| d.name == "github.com/gin-gonic/gin").unwrap();
        assert_eq!(gin.integrity.as_deref(), Some("h1:AAAA="));
        assert_eq!(gin.ecosystem, Ecosystem::Go);
        assert!(gin.direct);
    }
}
