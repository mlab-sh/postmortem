//! A tiny terminal UI for the scan pipeline: an animated spinner per phase and
//! a determinate progress bar over the analysis units.
//!
//! Design notes on reliability. The scan is often extremely fast (single-digit
//! milliseconds on small projects), which is *shorter than indicatif's redraw
//! interval* — so the animated bars may never paint a single frame. That's fine
//! for the animation (there's nothing worth watching on a 2 ms scan), but it
//! means we must **not** rely on indicatif to emit the persistent summary lines:
//! a throttled/coalesced redraw can be dropped entirely. So the animation goes
//! through indicatif, while every line of *text* (phase summaries, warnings) is
//! written with a plain `eprintln!` — unconditional, never throttled — issued
//! only when the live bar has been cleared or suspended, so it can't tear.
//!
//! Everything is drawn to **stderr**, keeping stdout pristine for the machine
//! formats (`--json` / `--sarif` / `--html`, including `--output -`). Animation
//! auto-disables when stderr is not a TTY, when `NO_COLOR` or `CI` is set, or
//! when `--no-progress` is passed; in that mode the bars are hidden, summaries
//! are suppressed, and only functional warnings reach stderr.

use std::borrow::Cow;
use std::io::IsTerminal;
use std::time::{Duration, Instant};

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use owo_colors::OwoColorize;

/// Braille spinner frames.
const TICK: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"];

const TICK_INTERVAL: Duration = Duration::from_millis(80);

pub struct Ui {
    enabled: bool,
}

impl Ui {
    /// Build the UI. `animate` is the caller's intent (e.g. `!args.no_progress`);
    /// it is ANDed with the environment checks so non-interactive runs are quiet.
    pub fn new(animate: bool) -> Self {
        let enabled = animate
            && std::io::stderr().is_terminal()
            && std::env::var_os("NO_COLOR").is_none()
            && std::env::var_os("CI").is_none();
        Ui { enabled }
    }

    fn spawn(&self, pb: ProgressBar) -> ProgressBar {
        if self.enabled {
            // `ProgressBar::new*` already targets stderr; just start the ticker
            // (re-setting the draw target resets its rate-limiter state).
            pb.enable_steady_tick(TICK_INTERVAL);
            pb.tick(); // force the first frame immediately
        } else {
            pb.set_draw_target(ProgressDrawTarget::hidden());
        }
        pb
    }

    /// Start an indeterminate spinner for a phase whose length we can't predict.
    pub fn phase(&self, msg: impl Into<Cow<'static, str>>) -> Phase {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .unwrap()
                .tick_strings(TICK),
        );
        pb.set_message(msg.into());
        Phase {
            pb: self.spawn(pb),
            enabled: self.enabled,
            start: Instant::now(),
        }
    }

    /// Start a determinate bar with `len` discrete steps and a custom spinner
    /// animation — e.g. the [`gochi`](crate::gochi) companion frames. All frames
    /// must share one width or the line will jitter on redraw.
    pub fn bar_ticks(
        &self,
        len: u64,
        msg: impl Into<Cow<'static, str>>,
        ticks: &'static [&'static str],
    ) -> Bar {
        let pb = ProgressBar::new(len);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.cyan} {msg:<22} {bar:24.cyan/dim} {pos:>2}/{len}",
            )
            .unwrap()
            .tick_strings(ticks)
            .progress_chars("━━╌"),
        );
        pb.set_message(msg.into());
        Bar {
            pb: self.spawn(pb),
            enabled: self.enabled,
            start: Instant::now(),
        }
    }

    /// Whether animation is on (TTY + not suppressed). Lets non-indicatif
    /// widgets (e.g. the gochi [`Loader`](crate::gochi::Loader)) match the UI.
    pub fn animating(&self) -> bool {
        self.enabled
    }

    /// Print a status/warning line. Only safe to call when **no** phase bar is
    /// active (between phases); while a phase runs, route text through
    /// [`Phase::note`] so it suspends the live spinner first.
    pub fn note(&self, msg: impl AsRef<str>) {
        eprintln!("{}", msg.as_ref());
    }
}

/// An indeterminate phase spinner. Call [`Phase::done`] to seal it with a green
/// check and the elapsed time.
pub struct Phase {
    pb: ProgressBar,
    enabled: bool,
    start: Instant,
}

impl Phase {
    /// Update the running message (e.g. the ecosystem currently being parsed).
    pub fn set(&self, msg: impl Into<Cow<'static, str>>) {
        self.pb.set_message(msg.into());
    }

    /// Print a warning line above this live spinner without corrupting it.
    pub fn note(&self, msg: impl AsRef<str>) {
        note_over(&self.pb, self.enabled, msg.as_ref());
    }

    /// Clear the spinner without emitting a `✓` summary — for phases that end in
    /// a failure/early-exit the caller reports itself.
    pub fn abandon(self) {
        self.pb.finish_and_clear();
    }

    pub fn done(self, msg: impl std::fmt::Display) {
        seal(&self.pb, self.enabled, self.start, msg);
    }
}

/// A determinate progress bar over N analysis units.
pub struct Bar {
    pb: ProgressBar,
    enabled: bool,
    start: Instant,
}

impl Bar {
    /// Set the label for the unit about to run, then advance once it's done via
    /// [`Bar::inc`].
    pub fn step(&self, label: impl Into<Cow<'static, str>>) {
        self.pb.set_message(label.into());
    }

    pub fn inc(&self) {
        self.pb.inc(1);
    }

    pub fn done(self, msg: impl std::fmt::Display) {
        seal(&self.pb, self.enabled, self.start, msg);
    }
}

/// Emit a warning line without tearing the live bar. `suspend` clears the bar,
/// runs the (unconditional) `eprintln!`, then repaints — reliable regardless of
/// draw throttling. With animation off there is no bar, so print directly.
fn note_over(pb: &ProgressBar, enabled: bool, msg: &str) {
    if enabled {
        pb.suspend(|| eprintln!("{msg}"));
    } else {
        eprintln!("{msg}");
    }
}

/// Clear the live bar, then emit a persistent `✓ <msg> (<elapsed>)` line via a
/// plain `eprintln!` so it survives even a scan too fast for indicatif to draw.
/// Suppressed when animation is off — the summary is decorative, whereas
/// functional warnings still reach stderr through [`note_over`].
fn seal(pb: &ProgressBar, enabled: bool, start: Instant, msg: impl std::fmt::Display) {
    pb.finish_and_clear();
    if enabled {
        eprintln!(
            "{} {} {}",
            "✓".green(),
            msg,
            format!("({})", human(start.elapsed())).dimmed()
        );
    }
}

/// Compact human duration: `840µs`, `12ms`, `1.4s`.
fn human(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1000.0;
    if ms < 1.0 {
        format!("{}µs", d.as_micros())
    } else if ms < 1000.0 {
        format!("{ms:.0}ms")
    } else {
        format!("{:.1}s", d.as_secs_f64())
    }
}
