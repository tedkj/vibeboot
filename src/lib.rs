//! VibeBoot: everything that starts with this PC, from every hiding place, in one honest list. A
//! VibeWare app: Rust and Slint on the software renderer, one small exe, no runtime beside it.
//!
//! `autostart` is the scanner (shared word for word with VibeScamCheck); `groups`, `changes` and
//! `report` are VibeBoot's face on it; `helper` runs the admin steps in a short-lived elevated
//! copy of this exe, and `records` keeps its own admin-only records of the task switch-offs it
//! made; `controller` ties it to the window, which only lays out and draws.

pub mod autostart;
pub mod changes;
pub mod check;
pub mod controller;
pub mod groups;
pub mod helper;
pub mod host;
pub mod launch;
pub mod portable;
pub mod prefs;
pub mod records;
pub mod report;
pub mod trust;

use serde::{Deserialize, Serialize};
use slint::ComponentHandle;

slint::include_modules!();

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// What the window remembers between runs (prefs.json in %APPDATA%\com.tedkj.vibeboot, or in
/// the portable data folder).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// "dark" or "light" once the user has picked one; until then the system's choice.
    pub theme: Option<String>,
    /// "Added in the last 30 days".
    pub recent: bool,
    /// "New since the last look".
    pub new_only: bool,
    /// "Not from Microsoft only" (on until the user turns it off).
    pub not_ms: Option<bool>,
}

impl Prefs {
    pub fn dark(&self) -> bool {
        match self.theme.as_deref() {
            Some("dark") => true,
            Some("light") => false,
            _ => host::system_dark(),
        }
    }

    pub fn not_ms(&self) -> bool {
        self.not_ms.unwrap_or(true)
    }

    /// Only the values the window offers survive a hand-edited file; the rest fall back.
    pub fn sanitized(mut self) -> Prefs {
        if !matches!(self.theme.as_deref(), None | Some("dark") | Some("light")) {
            self.theme = None;
        }
        self
    }
}

/// The window with its basics wired: theme, version, copying. The controller adds the rest (the
/// theme switch too: it saves on the prefs thread).
pub fn window(prefs: prefs::Store<Prefs>) -> Result<AppWindow, slint::PlatformError> {
    let ui = AppWindow::new()?;
    let p = prefs.load().sanitized();
    ui.global::<Theme>().set_dark(p.dark());
    ui.set_version(VERSION.into());
    ui.on_copy_text(|t| host::copy_text(&t).is_ok());
    Ok(ui)
}
