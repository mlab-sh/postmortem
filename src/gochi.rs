//! gochi — the little ASCII companion.
//!
//! Blob form, pure ASCII, **fixed 5-wide frames** so a terminal redraw never
//! tears (see the design notes in memory). gochi rides the data-loading bar:
//! its eyes dart while packages resolve, and it smiles when the fetch is done.

/// "At work" animation loop for the resolution spinner — eyes darting, an
/// occasional blink. Every frame is 5 columns wide.
///
/// indicatif treats the **last** tick string as the frame shown on finish, so
/// the happy face closes the loop (though we clear the bar before it lands).
pub const WORKING: &[&str] = &[
    "(o_o)", "(-_o)", "(o_o)", "(o_-)", "(-_-)", "(o_o)", "(^_^)",
];

/// Neutral, ready gochi.
pub const IDLE: &str = "(o_o)";

/// Content little gochi — clean / all-good.
pub const HAPPY: &str = "(^_^)";

/// Alarmed gochi — something's flagged.
pub const ALERT: &str = "(@_@)";

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use owo_colors::OwoColorize;

/// Say hello before the online fetch (and before the token prompt) so gochi is
/// the first thing you see when `tree --online` goes to work. No-op off-TTY.
pub fn greet(enabled: bool) {
    if enabled {
        eprintln!(
            "{}  {}",
            IDLE.cyan(),
            "gochi — scouting each dependency's source repo".dimmed()
        );
    }
}

/// A self-contained animated gochi progress line for the data-loading phase.
///
/// Deliberately **does not use indicatif**: constructing a `ureq` agent (which
/// the online resolver does) stops indicatif's steady-tick thread from drawing,
/// so gochi animates from its own thread writing raw ANSI to stderr (`\r` +
/// clear-line). All frames are 5 wide, so the in-place redraw never tears.
pub struct Loader {
    stop: Arc<AtomicBool>,
    pos: Arc<AtomicU64>,
    label: Arc<Mutex<String>>,
    handle: Option<JoinHandle<()>>,
    enabled: bool,
    start: Instant,
}

impl Loader {
    /// Start the animation (a no-op display when `enabled` is false, e.g. a
    /// non-TTY run — `step`/`inc`/`finish` still work, just silently).
    pub fn start(len: u64, enabled: bool) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let pos = Arc::new(AtomicU64::new(0));
        let label = Arc::new(Mutex::new(String::new()));

        let handle = enabled.then(|| {
            let (stop, pos, label) = (stop.clone(), pos.clone(), label.clone());
            std::thread::spawn(move || {
                let mut out = std::io::stderr();
                let mut frame = 0usize;
                // Cycle the working faces only (drop the trailing "finished" one).
                let faces = &WORKING[..WORKING.len() - 1];
                while !stop.load(Ordering::Relaxed) {
                    let face = faces[frame % faces.len()];
                    let lbl = label.lock().unwrap().clone();
                    let p = pos.load(Ordering::Relaxed);
                    let _ = write!(
                        out,
                        "\r\x1b[2K{} {}  {}",
                        face.cyan(),
                        lbl,
                        format!("{p}/{len}").dimmed()
                    );
                    let _ = out.flush();
                    frame += 1;
                    std::thread::sleep(Duration::from_millis(90));
                }
            })
        });

        Loader { stop, pos, label, handle, enabled, start: Instant::now() }
    }

    /// Set the label for the item currently being fetched.
    pub fn step(&self, label: impl Into<String>) {
        if let Ok(mut l) = self.label.lock() {
            *l = label.into();
        }
    }

    /// Advance the counter by one.
    pub fn inc(&self) {
        self.pos.fetch_add(1, Ordering::Relaxed);
    }

    /// Stop the animation, clear the line, and print a persistent `✓` summary.
    /// `face` is the closing gochi mood (happy or alarmed).
    pub fn finish(mut self, face: &str, msg: &str) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        if self.enabled {
            let elapsed = self.start.elapsed();
            let secs = elapsed.as_secs_f64();
            let human = if secs < 1.0 {
                format!("{}ms", elapsed.as_millis())
            } else {
                format!("{secs:.1}s")
            };
            // Clear the animated line, then commit the summary.
            eprint!("\r\x1b[2K");
            eprintln!("{} {face} {msg} {}", "✓".green(), format!("({human})").dimmed());
        }
    }
}
