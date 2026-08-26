//! One module per command: `main` parses and dispatches, each of these owns
//! a command end to end. Anything two of them share lives in [`common`] or
//! [`gate_policy`].

pub mod allowlist;
pub mod audit;
pub mod cache;
pub mod ci;
pub mod common;
pub mod diff;
pub mod fix;
pub mod gate_policy;
pub mod hook;
pub mod licenses;
pub mod overview;
pub mod sbom;
pub mod scan;
pub mod scripts;
pub mod system;
pub mod timeline;
pub mod tree;
pub mod watch;
pub mod why;
