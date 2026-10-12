//! Clojure / Leiningen `project.clj`.
//!
//! `(defproject name "version" :key value ...)` — read with a small Clojure
//! reader, never evaluated. Leiningen has no lockfile: like a Maven `pom.xml`,
//! this is the **declared** set, flat.
//!
//! * `:dependencies [[group/artifact "version" & opts] ...]` — a bare symbol
//!   (`ring`) is `ring:ring`. `:scope "test"` is development.
//! * `:profiles {:dev {:dependencies [...]}}` — every profile but `:provided`
//!   (which the runtime supplies) is development.
//! * `:managed-dependencies` pins versions; it supplies a missing version,
//!   never a dependency of its own. `:plugins` are build tools, not read.
//!
//! Identity is the Maven coordinate `group:artifact`, reported as `java`.

use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::path::Path;

use crate::model::{Dependency, Ecosystem, LicenseSource, Scope};

#[derive(Debug, Clone, PartialEq)]
enum Form {
    /// Symbols, keywords (with their `:`), numbers, booleans.
    Atom(String),
    Str(String),
    /// Lists, vectors and sets alike — only their elements matter here.
    Seq(Vec<Form>),
    /// A map's flat key/value sequence.
    Map(Vec<Form>),
}

impl Form {
    /// The value of `key` in a map, or in a keyword-argument sequence.
    fn get(&self, key: &str) -> Option<&Form> {
        let items = match self {
            Form::Map(items) | Form::Seq(items) => items,
            _ => return None,
        };
        items
            .iter()
            .position(|f| *f == Form::Atom(key.to_string()))
            .and_then(|i| items.get(i + 1))
    }
}

struct Reader<'a> {
    s: &'a [u8],
    i: usize,
}

impl Reader<'_> {
    fn ws(&mut self) {
        while let Some(&c) = self.s.get(self.i) {
            if c.is_ascii_whitespace() || c == b',' {
                self.i += 1;
            } else if c == b';' {
                while self.s.get(self.i).is_some_and(|&c| c != b'\n') {
                    self.i += 1;
                }
            } else {
                break;
            }
        }
    }

    fn seq(&mut self, close: u8) -> Result<Vec<Form>> {
        let mut out = Vec::new();
        loop {
            self.ws();
            match self.s.get(self.i) {
                Some(&c) if c == close => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(_) => {
                    if let Some(f) = self.form()? {
                        out.push(f);
                    }
                }
                None => bail!("unbalanced `{}`", close as char),
            }
        }
    }

    /// One form; `None` for one that reads as nothing (`#_ x`).
    fn form(&mut self) -> Result<Option<Form>> {
        self.ws();
        let Some(&c) = self.s.get(self.i) else {
            bail!("unexpected end of input");
        };
        self.i += 1;
        Ok(Some(match c {
            b'(' => Form::Seq(self.seq(b')')?),
            b'[' => Form::Seq(self.seq(b']')?),
            b'{' => Form::Map(self.seq(b'}')?),
            b'"' => {
                let mut out = Vec::new();
                while let Some(&c) = self.s.get(self.i) {
                    self.i += 1;
                    match c {
                        b'"' => return Ok(Some(Form::Str(String::from_utf8_lossy(&out).into()))),
                        b'\\' => {
                            out.extend(self.s.get(self.i));
                            self.i += 1;
                        }
                        _ => out.push(c),
                    }
                }
                bail!("unterminated string")
            }
            // Quote, syntax-quote, unquote, deref: the form itself.
            b'\'' | b'`' | b'~' | b'@' => return self.form(),
            // Metadata applies to the next form; it is not a form of its own.
            b'^' => {
                self.form()?;
                return self.form();
            }
            b'#' => match self.s.get(self.i) {
                Some(b'_') => {
                    self.i += 1;
                    self.form()?;
                    return Ok(None);
                }
                Some(b'{') => {
                    self.i += 1;
                    Form::Seq(self.seq(b'}')?)
                }
                Some(b'(') => {
                    self.i += 1;
                    Form::Seq(self.seq(b')')?)
                }
                // `#"regex"`, a tagged literal: the next form.
                _ => return self.form(),
            },
            _ => {
                let start = self.i - 1;
                while self
                    .s
                    .get(self.i)
                    .is_some_and(|&c| !c.is_ascii_whitespace() && !b",;()[]{}\"".contains(&c))
                {
                    self.i += 1;
                }
                Form::Atom(String::from_utf8_lossy(&self.s[start..self.i]).into())
            }
        }))
    }
}

/// `org.clojure/clojure` -> `org.clojure:clojure`; `ring` -> `ring:ring`.
fn coordinate(sym: &str) -> String {
    match sym.split_once('/') {
        Some((g, a)) => format!("{g}:{a}"),
        None => format!("{sym}:{sym}"),
    }
}

/// `[[sym "ver" :scope "test"] ...]` -> (coordinate, version?, test-scoped).
fn entries(deps: Option<&Form>) -> Vec<(String, Option<String>, bool)> {
    let Some(Form::Seq(deps)) = deps else {
        return Vec::new();
    };
    deps.iter()
        .filter_map(|d| {
            let Form::Seq(parts) = d else { return None };
            let Form::Atom(sym) = parts.first()? else {
                return None;
            };
            let version = match parts.get(1) {
                Some(Form::Str(v)) => Some(v.clone()),
                _ => None,
            };
            let test = matches!(d.get(":scope"), Some(Form::Str(s)) if s == "test");
            Some((coordinate(sym), version, test))
        })
        .collect()
}

pub fn parse(path: &Path) -> Result<Vec<Dependency>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut reader = Reader {
        s: text.as_bytes(),
        i: 0,
    };
    // The file may hold other top-level forms; `defproject` is the one.
    let project = loop {
        reader.ws();
        if reader.i >= reader.s.len() {
            bail!("{}: no defproject form", path.display());
        }
        if let Some(Form::Seq(items)) = reader
            .form()
            .with_context(|| format!("parsing {} as project.clj", path.display()))?
            && items.first() == Some(&Form::Atom("defproject".into()))
        {
            // Keyword arguments follow the name and version.
            break Form::Seq(items.into_iter().skip(3).collect());
        }
    };

    let managed: HashMap<String, String> = entries(project.get(":managed-dependencies"))
        .into_iter()
        .filter_map(|(c, v, _)| Some((c, v?)))
        .collect();

    let mut sets = vec![(project.get(":dependencies"), false)];
    if let Some(Form::Map(profiles)) = project.get(":profiles") {
        for pair in profiles.chunks(2) {
            if let [Form::Atom(name), profile] = pair {
                sets.push((profile.get(":dependencies"), name != ":provided"));
            }
        }
    }

    let mut out: Vec<Dependency> = Vec::new();
    for (deps, dev_profile) in sets {
        for (name, version, test) in entries(deps) {
            let version = version
                .or_else(|| managed.get(&name).cloned())
                .unwrap_or_else(|| "managed".to_string());
            let scope = if dev_profile || test {
                Scope::Dev
            } else {
                Scope::Prod
            };
            match out
                .iter_mut()
                .find(|d| d.name == name && d.version == version)
            {
                // Declared in the main set and a profile: it ships.
                Some(d) => d.scope = d.scope.max(scope),
                None => out.push(Dependency {
                    name,
                    version,
                    ecosystem: Ecosystem::Java,
                    direct: true,
                    scope,
                    licenses: Vec::new(),
                    license_source: LicenseSource::Unknown,
                    resolved_url: None,
                    integrity: None,
                    parents: Vec::new(),
                }),
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependencies_profiles_and_managed_versions() {
        let dir = std::env::temp_dir().join(format!("postmortem-lein-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("project.clj");
        std::fs::write(
            &p,
            r#";; a comment
(def shared-version "2.10.0")
(defproject riemann "0.3.13-SNAPSHOT"
  :description "A \"network\" event processor"
  :license {:name "EPL" :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.11.1"]
                 [clj-http "3.10.0" :exclusions [joda-time]]
                 #_[ignored "1.0"]
                 [ring/ring-mock "0.4.0" :scope "test"]
                 [org.jsoup/jsoup]
                 [com.fasterxml.jackson.core/jackson-core ~shared-version]]
  :managed-dependencies [[org.jsoup/jsoup "1.14.3"]]
  :plugins [[lein-codox "0.10.8"]]
  :test-selectors {:default (fn [x] (not (:integration x)))}
  :profiles {:dev {:jvm-opts ["-XX:-OmitStackTraceInFastThrow"]
                   :dependencies [[criterium "0.4.4"] [org.clojure/clojure "1.11.1"]]}
             :provided {:dependencies [[javax.servlet/servlet-api "2.5"]]}
             :uberjar {:aot :all}})
"#,
        )
        .unwrap();
        let deps = parse(&p).unwrap();
        let got: Vec<(&str, &str, Scope)> = deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str(), d.scope))
            .collect();
        assert_eq!(
            got,
            vec![
                ("org.clojure:clojure", "1.11.1", Scope::Prod),
                ("clj-http:clj-http", "3.10.0", Scope::Prod),
                ("ring:ring-mock", "0.4.0", Scope::Dev),
                ("org.jsoup:jsoup", "1.14.3", Scope::Prod),
                (
                    "com.fasterxml.jackson.core:jackson-core",
                    "managed",
                    Scope::Prod
                ),
                ("criterium:criterium", "0.4.4", Scope::Dev),
                ("javax.servlet:servlet-api", "2.5", Scope::Prod),
            ]
        );
    }
}
