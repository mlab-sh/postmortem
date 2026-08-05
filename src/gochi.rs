//! gochi — the little ASCII companion that narrates postmortem's work.
//!
//! Blob form, **pure ASCII, fixed 5-column frames** so an in-place terminal
//! redraw never tears (see the design notes in memory). gochi has two jobs:
//!
//! 1. **Ride the work.** A [`Loader`] animates while a slow phase runs (resolving
//!    repos, scanning files, querying advisories) and seals with a mood + `✓`.
//! 2. **React to results.** A [`Mood`] is the single source of truth for every
//!    face + its colour; the one-shot [`say`]/[`line`] helpers drop a consistent
//!    `<face>  <message>` line anywhere a command wants to speak.
//!
//! Everything decorative auto-disables off-TTY. Result lines ([`say`]) go to
//! **stdout** (they're content); progress + greetings go to **stderr** (so
//! `--json`/`--sarif` on stdout stay pristine).

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use owo_colors::OwoColorize;

// ─── Faces ──────────────────────────────────────────────────────────────────
// Raw glyphs, kept public for the rare caller that needs the bare string. Prefer
// a `Mood` — it carries the matching colour. Every face is exactly 5 columns.

/// Neutral, ready gochi.
pub const IDLE: &str = "(o_o)";
/// Content little gochi — clean / all-good.
pub const HAPPY: &str = "(^_^)";
/// Alarmed gochi — something's flagged / needs attention.
pub const ALERT: &str = "(@_@)";
/// Distressed gochi — a failure or a critical result.
pub const SAD: &str = "(T_T)";
/// Puzzled gochi — a lookup came up empty / an unknown target.
pub const CURIOUS: &str = "(?_?)";

/// "At work" loop for a network/resolve wait: calm eyes darting, an occasional
/// blink. Every frame is 5 columns.
pub const WORKING: &[&str] =
    &["(o_o)", "(-_o)", "(o_o)", "(o_-)", "(o_o)", "(-_-)", "(o_o)", "(._.)", "(o_o)"];

/// "Hunting" loop for the static malware scan: wide, focused eyes sweeping the
/// code. Distinct from [`WORKING`] so the two waits read differently.
pub const SCANNING: &[&str] =
    &["(O_O)", "(O_o)", "(o_O)", "(O_O)", "(-_-)", "(o_o)", "(O_O)"];

// ─── Mood ───────────────────────────────────────────────────────────────────

/// gochi's expression. The single source of truth mapping a semantic state to a
/// face **and** its colour, so callers never hard-code a glyph or pick a colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mood {
    /// Neutral / ready / thinking.
    Idle,
    /// Clean, all-good.
    Happy,
    /// Something's flagged — attention warranted (warnings, soft risk).
    Alert,
    /// A failure or a critical/high-risk result.
    Bad,
    /// A lookup came up empty / an unknown target.
    Curious,
}

impl Mood {
    /// The bare 5-column face for this mood.
    pub const fn face(self) -> &'static str {
        match self {
            Mood::Idle => IDLE,
            Mood::Happy => HAPPY,
            Mood::Alert => ALERT,
            Mood::Bad => SAD,
            Mood::Curious => CURIOUS,
        }
    }

    /// The face painted in this mood's colour: cyan (idle/busy), green (happy),
    /// yellow (alert), red (bad).
    pub fn paint(self) -> String {
        let f = self.face();
        match self {
            Mood::Idle => f.cyan().to_string(),
            Mood::Happy => f.green().to_string(),
            Mood::Alert => f.yellow().to_string(),
            Mood::Bad => f.red().bold().to_string(),
            Mood::Curious => f.dimmed().to_string(),
        }
    }

    /// Pick a mood from a risk verdict: red on any high-risk tier or a severe
    /// score, yellow on softer risk, green when clean. Shared by the `tree`
    /// recap and the `audit` verdict so they never drift apart.
    pub fn from_risk(risk: u8, high: usize, vulns: usize) -> Mood {
        if high > 0 || risk >= 70 || vulns > 0 {
            Mood::Bad
        } else if risk >= 40 {
            Mood::Alert
        } else {
            Mood::Happy
        }
    }

    /// Pick a mood from a headcount of risk tiers (the `tree` recap's model):
    /// alarmed on any high tier, attentive on suspicious-only, content on clean.
    pub fn from_tiers(high: usize, suspicious: usize) -> Mood {
        if high > 0 {
            Mood::Bad
        } else if suspicious > 0 {
            Mood::Alert
        } else {
            Mood::Happy
        }
    }
}

// ─── One-shot lines ───────────────────────────────────────────────────────────

/// Build a `"<face>  <message>"` line, face painted by mood — for embedding in a
/// larger render. Does not print.
pub fn line(mood: Mood, msg: impl AsRef<str>) -> String {
    format!("{}  {}", mood.paint(), msg.as_ref())
}

/// Print a gochi result line to **stdout**: `<face>  <message>`. This is content
/// (a verdict, a summary, an empty-state), so it always prints — mirror of
/// [`crate::ui::Ui::note`] but for stdout. Callers in machine-output modes
/// (`--json`) simply don't call it.
pub fn say(mood: Mood, msg: impl AsRef<str>) {
    println!("{}", line(mood, msg));
}

/// Say hello on **stderr** before a slow online phase (and before a token
/// prompt), so gochi is the first thing you see. No-op off-TTY.
pub fn greet(enabled: bool) {
    hello(enabled, "gochi — scouting each dependency's source repo");
}

/// Generic stderr greeting with a custom message. No-op off-TTY.
pub fn hello(enabled: bool, msg: impl AsRef<str>) {
    if enabled {
        eprintln!("{}  {}", Mood::Idle.paint(), msg.as_ref().dimmed());
    }
}

// ─── Loader ───────────────────────────────────────────────────────────────────

/// A self-contained animated gochi progress line for a slow phase.
///
/// Deliberately **does not use indicatif**: constructing a `ureq` agent (which
/// the online resolver and advisory lookups do) stops indicatif's steady-tick
/// thread from drawing, so gochi animates from its own thread writing raw ANSI
/// to stderr (`\r` + clear-line). All frames are 5 columns, so the in-place
/// redraw never tears.
pub struct Loader {
    stop: Arc<AtomicBool>,
    pos: Arc<AtomicU64>,
    label: Arc<Mutex<String>>,
    handle: Option<JoinHandle<()>>,
    enabled: bool,
    start: Instant,
}

impl Loader {
    /// A **counted** loading animation (`p/len`) with the [`WORKING`] face, for a
    /// phase with a known number of items. A no-op display when `enabled` is
    /// false (non-TTY); `step`/`inc`/`finish` still work, just silently.
    pub fn start(len: u64, enabled: bool) -> Self {
        Self::spawn(Some(len), String::new(), WORKING, enabled)
    }

    /// An **indeterminate** [`WORKING`] spinner + label — for a single wait of
    /// unknown length (e.g. shelling out to `brew info`, an advisory lookup).
    pub fn spinner(label: impl Into<String>, enabled: bool) -> Self {
        Self::spawn(None, label.into(), WORKING, enabled)
    }

    /// Shared animation loop. `total = Some(len)` shows a `p/len` counter;
    /// `None` runs an indeterminate spinner with just the label.
    fn spawn(
        total: Option<u64>,
        initial_label: String,
        frames: &'static [&'static str],
        enabled: bool,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let pos = Arc::new(AtomicU64::new(0));
        let label = Arc::new(Mutex::new(initial_label));

        let handle = enabled.then(|| {
            let (stop, pos, label) = (stop.clone(), pos.clone(), label.clone());
            std::thread::spawn(move || {
                let mut out = std::io::stderr();
                let mut frame = 0usize;
                while !stop.load(Ordering::Relaxed) {
                    let face = frames[frame % frames.len()];
                    let lbl = label.lock().unwrap().clone();
                    let counter = match total {
                        Some(len) => {
                            format!("  {}", format!("{}/{len}", pos.load(Ordering::Relaxed)).dimmed())
                        }
                        None => String::new(),
                    };
                    let _ = write!(out, "\r\x1b[2K{} {}{}", face.cyan(), lbl, counter);
                    let _ = out.flush();
                    frame += 1;
                    std::thread::sleep(Duration::from_millis(90));
                }
            })
        });

        Loader { stop, pos, label, handle, enabled, start: Instant::now() }
    }

    /// Set the label for the item currently being processed.
    pub fn step(&self, label: impl Into<String>) {
        if let Ok(mut l) = self.label.lock() {
            *l = label.into();
        }
    }

    /// Advance the counter by one.
    pub fn inc(&self) {
        self.pos.fetch_add(1, Ordering::Relaxed);
    }

    /// Stop the animation, clear the line, and commit a persistent `✓ <face>
    /// <msg> (<elapsed>)` summary on stderr in the closing `mood`.
    pub fn finish(mut self, mood: Mood, msg: impl AsRef<str>) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        if self.enabled {
            let human = human_elapsed(self.start.elapsed());
            // Clear the animated line, then commit the summary.
            eprint!("\r\x1b[2K");
            eprintln!("{} {} {} {}", "✓".green(), mood.paint(), msg.as_ref(), format!("({human})").dimmed());
        }
    }
}

/// Compact elapsed: `840ms` under a second, `1.4s` above.
fn human_elapsed(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 1.0 {
        format!("{}ms", d.as_millis())
    } else {
        format!("{secs:.1}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every animated frame and static face MUST be 5 columns (pure ASCII, so
    /// char count == column count) or an in-place redraw tears.
    #[test]
    fn every_frame_is_five_columns() {
        let statics = [IDLE, HAPPY, ALERT, SAD, CURIOUS];
        for f in statics.iter().chain(WORKING).chain(SCANNING) {
            assert!(f.is_ascii(), "{f:?} must be pure ASCII");
            assert_eq!(f.chars().count(), 5, "{f:?} must be 5 columns");
        }
    }

    #[test]
    fn mood_face_and_paint_agree() {
        for m in [Mood::Idle, Mood::Happy, Mood::Alert, Mood::Bad, Mood::Curious] {
            assert_eq!(m.face().chars().count(), 5);
            assert!(m.paint().contains(m.face()));
        }
    }

    #[test]
    fn from_risk_grades() {
        assert_eq!(Mood::from_risk(0, 0, 0), Mood::Happy);
        assert_eq!(Mood::from_risk(45, 0, 0), Mood::Alert);
        assert_eq!(Mood::from_risk(80, 0, 0), Mood::Bad);
        assert_eq!(Mood::from_risk(10, 1, 0), Mood::Bad, "any high-risk dep → bad");
        assert_eq!(Mood::from_risk(10, 0, 3), Mood::Bad, "any known vuln → bad");
    }

    #[test]
    fn from_tiers_grades() {
        assert_eq!(Mood::from_tiers(0, 0), Mood::Happy);
        assert_eq!(Mood::from_tiers(0, 2), Mood::Alert);
        assert_eq!(Mood::from_tiers(1, 5), Mood::Bad);
    }
}
