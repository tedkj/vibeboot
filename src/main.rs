// VibeBoot: one process, no browser engine, the software renderer.
#![windows_subsystem = "windows"]

use slint::ComponentHandle;
use slint::winit_030::{EventResult, WinitWindowAccessor};
use vibeboot::host;

/// The real release-list fetcher (WinHTTP), the exe's alone: it is in no test build, not the
/// lib's, not the integration tests', not this exe's own unit tests', so no test can go online
/// (review RAB-2; tests/pe.rs checks this line).
#[cfg(not(test))]
mod net;

fn main() -> Result<(), slint::PlatformError> {
    // LINK-1, first of all: every DLL loaded from here on comes from System32, never from the
    // exe's own folder (the elevated helper is this exe; on a stick that folder is anyone's). The
    // static imports are covered by the link flag /DEPENDENTLOADFLAG:0x800 (build.rs).
    // SAFETY: a process-wide setting with a valid flag; nothing has been loaded by name yet.
    unsafe {
        use windows_sys::Win32::System::LibraryLoader::{LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories};
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
    // No Windows "No Disk" box: a file call on an empty card reader or drive gets its error back
    // instead of a modal box (review fix-popup, RX1). tests/pe.rs checks this block comes next.
    // SAFETY: a process-wide setting with a valid flag, the bits already set kept.
    unsafe {
        use windows_sys::Win32::System::Diagnostics::Debug::{GetErrorMode, SEM_FAILCRITICALERRORS, SetErrorMode};
        SetErrorMode(GetErrorMode() | SEM_FAILCRITICALERRORS);
    }
    // The admin helper (relaunched elevated for one job): no window, one bounded job. It refuses
    // to run unelevated, with a job not in its table, or without the app's pipe.
    // args_os: an argument that is not Unicode must not panic (panic = abort ends the app).
    let raw: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let args: Vec<Option<String>> = raw.iter().map(|a| a.to_str().map(String::from)).collect();
    if args.first().and_then(|a| a.as_deref()) == Some("--helper") {
        let Some(args) = args.into_iter().collect::<Option<Vec<String>>>() else { std::process::exit(2) };
        std::process::exit(vibeboot::helper::run_helper(&args));
    }
    // The command line is `VibeBoot.exe`, or files dropped on it (the window, and a toast that
    // they were left alone). Anything else, an option above all, ends the process before any
    // window or file (exit code 2, the family rule).
    let dropped = match vibeboot::launch::start(&raw) {
        vibeboot::launch::Start::Window => None,
        vibeboot::launch::Start::Dropped(note) => Some(note),
        vibeboot::launch::Start::Refused => std::process::exit(2),
    };
    // Live checks and measurements only: the app's folders in a place of the developer's choosing,
    // so nothing touches the real profile. Never in a shipped build.
    #[cfg(feature = "dev-hooks")]
    let dev_home = std::env::var_os("VIBEBOOT_DEV_HOME").map(std::path::PathBuf::from);
    #[cfg(not(feature = "dev-hooks"))]
    let dev_home: Option<std::path::PathBuf> = None;
    // Portable or installed, decided before any prefs read.
    let exe = std::env::current_exe().ok();
    let setup = vibeboot::portable::setup(exe.as_deref(), vibeboot::host::paths(), dev_home);
    // The probe hands back the value it was asked about, and `main` goes on with that one only: the
    // old binding is gone (`dev_probe`, review RRF-2).
    #[cfg(feature = "dev-hooks")]
    let setup = dev_probe(setup);
    let prefs = vibeboot::prefs::Store::new(setup.paths.config.join("prefs.json"));
    let ui = vibeboot::window(prefs.clone())?;
    // The one place that names the real release-list fetcher (tests/pe.rs checks it): every test
    // hands the controller a fake, so no test goes online. This exe's unit-test build has no
    // `net` and never runs `main`: it gets a stand-in that fetches nothing.
    #[cfg(not(test))]
    let fetch = std::sync::Arc::new(net::fetch_release_list);
    #[cfg(test)]
    let fetch = std::sync::Arc::new(|_: &str| vibeboot::check::Fetched::Failed("a test build has no fetcher".into()));
    let app = vibeboot::controller::App::attach(&ui, prefs, vibeboot::controller::Services::system(setup, fetch));
    if let Some(note) = dropped {
        app.toast(&note, vibeboot::ToastKind::Info, None);
    }
    // The window opens at its preferred size; on a small or highly scaled screen that runs past
    // the taskbar, so the first window event once it is on screen fits it into the monitor's work
    // area (X15A11Y-3), once (a start minimized waits until the window is restored).
    let fitted = std::cell::Cell::new(false);
    ui.window().on_winit_window_event(move |window, _event| {
        if !fitted.get() && window.with_winit_window(hwnd_of).flatten().and_then(host::fit_to_work_area).is_some() {
            fitted.set(true);
        }
        EventResult::Propagate
    });
    let ran = ui.run();
    app.finish_prefs(); // a change from the last moments, still on its way to disk
    ran
}

/// The window's Win32 handle, for `host::fit_to_work_area`.
fn hwnd_of(w: &slint::winit_030::winit::window::Window) -> Option<isize> {
    use slint::winit_030::winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
    match w.window_handle().ok()?.as_raw() {
        RawWindowHandle::Win32(h) => Some(h.hwnd.get()),
        _ => None,
    }
}

/// Live checks only (review RRE-5, RRF-2): with VIBEBOOT_DEV_PROBE set, `main` writes the
/// app's data folders, one a line on stdout, and ends (exit 0) right after the dev home, before
/// any of them is used and before any window. Else it hands back the value it was given,
/// unchanged, and `main` goes on with it (`let setup = dev_probe(setup);`), so the folders the
/// probe names are the ones `main` uses. tests/pe.rs asks this before it starts the exe for real
/// (`run_exe`): every folder must be inside the scratch dev home it gave, so an override that is
/// gone, compiled out or too late fails there, by what the exe does.
#[cfg(feature = "dev-hooks")]
fn dev_probe(setup: vibeboot::portable::Setup) -> vibeboot::portable::Setup {
    use std::io::Write;
    if std::env::var_os("VIBEBOOT_DEV_PROBE").is_some() {
        let mut out = std::io::stdout().lock();
        for f in [&setup.paths.config, &setup.paths.local_data] {
            let _ = writeln!(out, "{}", f.display());
        }
        let _ = out.flush();
        std::process::exit(0);
    }
    setup
}
