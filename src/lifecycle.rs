//! What npm actually runs when it installs a dependency.
//!
//! The list most people carry in their head — `preinstall`, `install`,
//! `postinstall` — is incomplete in two directions, and both are execution on
//! the installing machine:
//!
//! * **`prepare` runs too, but only for a dependency that did not come from the
//!   registry.** npm clones a git (or `file:` / `link:` / remote-tarball)
//!   dependency, installs *its* dependencies, and runs its `prepare` before
//!   packing it — so the script runs on your machine. A registry tarball is the
//!   opposite case: its `prepare` already ran, on the publisher's machine, at
//!   publish time. Flagging both alike would put `"prepare": "tsc"` — half of
//!   npm — next to a real install-time vector.
//! * **A package with a `binding.gyp` and no install script of its own gets one
//!   synthesised**: npm runs `node-gyp rebuild`, compiling C++ locally. The
//!   package declares no script at all, so anything that reads `scripts` sees
//!   nothing.
//!
//! The reference for all three rules is npm's own enumeration, in
//! `@npmcli/arborist`'s `install-scripts.js` — the same list its approval gate
//! (`allowScripts`) is built from. The lockfile's `hasInstallScript` flag is
//! *not* a substitute: arborist computes it as `install || preinstall ||
//! postinstall` alone, so a git dependency's `prepare` is gated by npm at
//! install time and still absent from the flag.

use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;

use crate::model::{Dependency, Ecosystem};

/// Lifecycle scripts npm runs for every dependency, whatever its source.
pub const ALWAYS: &[&str] = &["preinstall", "install", "postinstall"];

/// Every install-time script for a locally built dependency, in npm's order.
/// `prepare` is the one that matters; npm brackets it with `preprepare` and
/// `postprepare`.
pub const WITH_PREPARE: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "preprepare",
    "prepare",
    "postprepare",
];

/// The install script npm synthesises for a native package that declares none.
pub const GYP_INSTALL: &str = "node-gyp rebuild";

/// Where a dependency came from — which is what decides whether its `prepare`
/// runs on *your* machine or already ran on the publisher's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A registry tarball. `prepare` ran at publish time, not here.
    Registry,
    /// git, `file:`, `link:`, or a remote tarball: npm builds it here, so
    /// `prepare` runs here.
    NonRegistry,
}

impl Source {
    /// The lifecycle scripts that execute at install time for this source.
    pub fn hooks(self) -> &'static [&'static str] {
        match self {
            Source::Registry => ALWAYS,
            Source::NonRegistry => WITH_PREPARE,
        }
    }

    /// Why this hook runs, when the reason isn't obvious. `None` for the three
    /// that always run.
    pub fn note(self, hook: &str) -> Option<&'static str> {
        (self == Source::NonRegistry && hook.contains("prepare"))
            .then_some("built locally from a non-registry source, so npm runs it on install")
    }
}

/// npm's own fallback test, ported from arborist's `hasNonRegistryShape`: a
/// registry tarball resolves to `https://host/…/-/name-1.2.3.tgz`, and anything
/// else is built locally.
///
/// A missing `resolved` reads as [`Source::Registry`] — npm's own default for
/// enumeration, and the conservative one here too: better to miss a `prepare`
/// than to invent one for a source we could not confirm.
pub fn source_of(resolved: Option<&str>) -> Source {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^https?://[^/]+/.+/-/[^/]+-\d").unwrap());
    match resolved {
        Some(url) if !re.is_match(url) => Source::NonRegistry,
        _ => Source::Registry,
    }
}

/// Does npm synthesise `install: node-gyp rebuild` for this package?
///
/// Only when it declares no `install`/`preinstall` of its own and does not opt
/// out with `"gypfile": false`. The result is a C++ build on the installing
/// machine — gated by npm like any other install script, and invisible to
/// anything that reads `scripts`, because there is nothing there to read.
pub fn implicit_gyp(dir: &Path, has_explicit_install: bool, gypfile: Option<bool>) -> bool {
    !has_explicit_install && gypfile != Some(false) && dir.join("binding.gyp").is_file()
}

/// Where each Node package in the tree came from, by name.
///
/// Built from the lockfile, because that is the only place the origin is
/// recorded: the `package.json` npm writes into `node_modules` does not say
/// where it came from, so an analyzer reading the installed tree cannot tell a
/// built-from-git package from a registry one on its own.
#[derive(Default)]
pub struct Sources(HashMap<String, Source>);

impl Sources {
    /// One non-registry copy makes the name non-registry: npm builds *that*
    /// copy whatever the others are, and the analyzer sees one tree.
    pub fn from_deps(deps: &[Dependency]) -> Self {
        let mut map = HashMap::new();
        for d in deps.iter().filter(|d| d.ecosystem == Ecosystem::Node) {
            let src = source_of(d.resolved_url.as_deref());
            let slot = map.entry(d.name.clone()).or_insert(src);
            if src == Source::NonRegistry {
                *slot = Source::NonRegistry;
            }
        }
        Sources(map)
    }

    /// Unknown packages read as [`Source::Registry`] — see [`source_of`].
    pub fn get(&self, name: &str) -> Source {
        self.0.get(name).copied().unwrap_or(Source::Registry)
    }
}

impl FromIterator<(String, Source)> for Sources {
    fn from_iter<I: IntoIterator<Item = (String, Source)>>(iter: I) -> Self {
        Sources(iter.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_tarballs_are_recognised() {
        for url in [
            "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz",
            "https://npm.internal.corp/foo/-/foo-2.0.0-beta.1.tgz",
        ] {
            assert_eq!(source_of(Some(url)), Source::Registry, "{url}");
        }
    }

    #[test]
    fn everything_else_is_built_locally() {
        for url in [
            "git+ssh://git@github.com/o/r.git#abc123",
            "git+https://github.com/o/r.git",
            "file:../local-pkg",
            "https://example.test/tarballs/pkg.tgz",
        ] {
            assert_eq!(source_of(Some(url)), Source::NonRegistry, "{url}");
        }
    }

    #[test]
    fn an_unknown_source_does_not_invent_a_prepare() {
        assert_eq!(source_of(None), Source::Registry);
        assert_eq!(Source::Registry.hooks(), ALWAYS);
        assert!(!Source::Registry.hooks().contains(&"prepare"));
        assert!(Source::NonRegistry.hooks().contains(&"prepare"));
    }

    #[test]
    fn gyp_is_implicit_only_without_an_explicit_script() {
        let dir = std::env::temp_dir().join(format!("pm-gyp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("binding.gyp"), "{}").unwrap();
        assert!(
            implicit_gyp(&dir, false, None),
            "gypfile, no script → npm builds"
        );
        assert!(
            !implicit_gyp(&dir, true, None),
            "an explicit install script wins"
        );
        assert!(!implicit_gyp(&dir, false, Some(false)), "opted out");
        std::fs::remove_dir_all(&dir).ok();
        assert!(!implicit_gyp(&dir, false, None), "no binding.gyp");
    }
}
