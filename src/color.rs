//! Terminal colours that honour `NO_COLOR` (<https://no-color.org>).
//!
//! owo-colors' plain methods (`.red()`, `.bold()`, …) always emit ANSI; only
//! its `if_supports_color` path looks at the environment. Every call site
//! imports [`Paint`] instead — same method names, same borrow shape, and the
//! formatter (width, alignment) still reaches the inner value.

use std::fmt;
use std::sync::OnceLock;

use owo_colors::Style;

/// `NO_COLOR` present and non-empty turns every colour off.
fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty()))
}

pub struct Painted<'a, T: ?Sized>(&'a T, Style);

impl<T: fmt::Display + ?Sized> fmt::Display for Painted<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if enabled() {
            fmt::Display::fmt(&self.1.style(self.0), f)
        } else {
            fmt::Display::fmt(self.0, f)
        }
    }
}

pub trait Paint: fmt::Display {
    fn paint(&self, s: Style) -> Painted<'_, Self> {
        Painted(self, s)
    }
    fn red(&self) -> Painted<'_, Self> {
        self.paint(Style::new().red())
    }
    fn green(&self) -> Painted<'_, Self> {
        self.paint(Style::new().green())
    }
    fn yellow(&self) -> Painted<'_, Self> {
        self.paint(Style::new().yellow())
    }
    fn blue(&self) -> Painted<'_, Self> {
        self.paint(Style::new().blue())
    }
    fn cyan(&self) -> Painted<'_, Self> {
        self.paint(Style::new().cyan())
    }
    fn bold(&self) -> Painted<'_, Self> {
        self.paint(Style::new().bold())
    }
    fn dimmed(&self) -> Painted<'_, Self> {
        self.paint(Style::new().dimmed())
    }
    fn truecolor(&self, r: u8, g: u8, b: u8) -> Painted<'_, Self> {
        self.paint(Style::new().truecolor(r, g, b))
    }
}

impl<T: fmt::Display + ?Sized> Paint for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn width_reaches_the_inner_value() {
        let s = format!("[{:<5}]", "ab".red());
        assert!(s.contains("ab   "), "{s:?}");
    }
}
