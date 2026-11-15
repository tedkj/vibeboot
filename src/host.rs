//! The Windows side: the app's folders, the shell (web links, Explorer), the clipboard and the
//! system's light or dark mode. The same small set every VibeWare app carries (copied, not shared).

use std::path::{Path, PathBuf};

/// The app's own folders: settings in %APPDATA%, bulkier local state in %LOCALAPPDATA%.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    pub config: PathBuf,
    pub local_data: PathBuf,
}

pub const APP_ID: &str = "com.tedkj.vibeboot";

pub fn paths() -> Paths {
    use windows_sys::Win32::UI::Shell::{FOLDERID_LocalAppData, FOLDERID_RoamingAppData};
    let env = |k: &str| std::env::var_os(k).map(PathBuf::from).unwrap_or_default();
    Paths {
        config: known_folder(&FOLDERID_RoamingAppData).unwrap_or_else(|| env("APPDATA")).join(APP_ID),
        local_data: known_folder(&FOLDERID_LocalAppData).unwrap_or_else(|| env("LOCALAPPDATA")).join(APP_ID),
    }
}

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn wide_path(p: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// How the app's own folders are asked for: `KF_FLAG_DONT_VERIFY`, so Windows hands the path
/// over without touching the folder, which has no time limit (the user can point `AppData` or
/// `Local AppData` at a share that hangs, in HKCU). The folder's first touch is then the app's own
/// file read (settings, journal, seen.json), and one that is not there is created as before.
const KNOWN_FOLDER_FLAGS: u32 = windows_sys::Win32::UI::Shell::KF_FLAG_DONT_VERIFY as u32;

pub fn known_folder(id: &windows_sys::core::GUID) -> Option<PathBuf> {
    known_folder_with(id, KNOWN_FOLDER_FLAGS)
}

fn known_folder_with(id: &windows_sys::core::GUID, flags: u32) -> Option<PathBuf> {
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;
    unsafe {
        let mut p: windows_sys::core::PWSTR = std::ptr::null_mut();
        let ok = SHGetKnownFolderPath(id, flags, std::ptr::null_mut(), &mut p) == 0;
        let out = if ok && !p.is_null() {
            let len = (0..).take_while(|&i| *p.add(i) != 0).count();
            Some(path_from_wide(std::slice::from_raw_parts(p, len)))
        } else {
            None
        };
        CoTaskMemFree(p as *const _);
        out
    }
}

/// Now, as Unix seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// Local time minus UTC at `t` (Unix seconds), in seconds: what a date is shifted by to show it
/// as the PC's clock reads (summer time included).
pub fn local_offset(t: i64) -> i64 {
    use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
    let ft = crate::autostart::dates::filetime_from_unix(t);
    let f = FILETIME { dwLowDateTime: ft as u32, dwHighDateTime: (ft >> 32) as u32 };
    let mut utc: SYSTEMTIME = unsafe { std::mem::zeroed() };
    let mut local: SYSTEMTIME = unsafe { std::mem::zeroed() };
    // SAFETY: plain structs in and out; a null time zone is the current one.
    let ok = unsafe { FileTimeToSystemTime(&f, &mut utc) != 0 && SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) != 0 };
    if !ok {
        return 0;
    }
    let l = crate::autostart::dates::unix_at((i32::from(local.wYear), u32::from(local.wMonth), u32::from(local.wDay), u32::from(local.wHour), u32::from(local.wMinute), u32::from(local.wSecond)), 0);
    l - t.max(0)
}

/// The window the user is working in (the UAC prompt and Save As sit over it).
pub fn active_window() -> isize {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::GetActiveWindow;
    // SAFETY: no arguments.
    unsafe { GetActiveWindow() as isize }
}

/// Save As for the report: the path picked, or None. Modal (the system dialog); no start folder
/// is set, so it never opens on a dead share.
pub fn save_dialog(default_name: &str) -> Option<PathBuf> {
    use windows_sys::Win32::UI::Controls::Dialogs::{GetSaveFileNameW, OFN_EXPLORER, OFN_NOCHANGEDIR, OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST, OPENFILENAMEW};
    let filter: Vec<u16> = "Text report (*.txt)\0*.txt\0\0".encode_utf16().collect();
    let mut file = vec![0u16; 1024];
    for (i, c) in default_name.encode_utf16().take(1000).enumerate() {
        file[i] = c;
    }
    let ext = wide("txt");
    let title = wide("Save report");
    let mut ofn: OPENFILENAMEW = unsafe { std::mem::zeroed() };
    ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    ofn.hwndOwner = active_window() as *mut _;
    ofn.lpstrFilter = filter.as_ptr();
    ofn.nFilterIndex = 1;
    ofn.lpstrFile = file.as_mut_ptr();
    ofn.nMaxFile = file.len() as u32;
    ofn.lpstrDefExt = ext.as_ptr();
    ofn.lpstrTitle = title.as_ptr();
    ofn.Flags = OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    // SAFETY: every pointer in `ofn` points at a live buffer of the size given; the call is modal
    // and returns before any of them go away.
    if unsafe { GetSaveFileNameW(&mut ofn) } == 0 {
        return None;
    }
    let len = file.iter().position(|&c| c == 0).unwrap_or(file.len());
    Some(path_from_wide(&file[..len]))
}

/// A web page in the default browser (About's link). https only: nothing else is ever handed
/// to the shell from here.
pub fn open_url(url: &str) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err(format!("Not a web address: {url}"));
    }
    shell_open(url)
}

/// A folder in Explorer (or a file shown selected in its folder, with `select`).
pub fn reveal(path: &Path, select: bool) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    explorer_command()?.raw_arg(reveal_arg(path, select)).spawn().map(|_| ()).map_err(|e| format!("Could not open Explorer: {e}"))
}

/// Explorer by its full path (`<Windows>\explorer.exe`), started in System32. Every program the
/// app starts goes by its full path: a bare "explorer.exe" is looked for in this exe's own folder
/// (and the current one) first, Rust's std as CreateProcess, so on a stick or in the per-user
/// install folder anyone's file of that name would run. Started in System32, the child neither
/// searches nor holds the exe's folder.
pub fn explorer_command() -> Result<std::process::Command, String> {
    let win = windows_dir(false).ok_or("Could not open Explorer: the Windows folder is not known")?;
    let sys = windows_dir(true).ok_or("Could not open Explorer: System32 is not known")?;
    let mut c = std::process::Command::new(win.join("explorer.exe"));
    c.current_dir(sys);
    Ok(c)
}

/// Windows' own folder (`GetSystemWindowsDirectoryW`) or System32 (`GetSystemDirectoryW`), as
/// Windows names them: never from the environment, never relative.
pub fn windows_dir(system: bool) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::{GetSystemDirectoryW, GetSystemWindowsDirectoryW};
    let mut buf = [0u16; 1024];
    // SAFETY: a buffer and its length in units.
    let n = unsafe { if system { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } else { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } } as usize;
    (n > 0 && n < buf.len()).then(|| PathBuf::from(std::ffi::OsString::from_wide(&buf[..n]))).filter(|p| p.is_absolute())
}

/// Explorer parses its own command line: the path goes in quotes (after /select, when
/// selecting). Built from the path's exact units, never a lossy string (a name with a lone
/// surrogate must still be found: VibeRename RR-7); `"` cannot be in a Windows name.
pub fn reveal_arg(path: &Path, select: bool) -> std::ffi::OsString {
    let mut arg = std::ffi::OsString::from(if select { "/select,\"" } else { "\"" });
    arg.push(path.as_os_str());
    arg.push("\"");
    arg
}

/// A path Windows handed over as UTF-16 units, kept exactly (a lone surrogate included).
pub fn path_from_wide(units: &[u16]) -> PathBuf {
    use std::os::windows::ffi::OsStringExt;
    PathBuf::from(std::ffi::OsString::from_wide(units))
}

/// ShellExecuteEx with the shell's own error dialogs suppressed: a failure comes back as an
/// error here, it never parks a modal box on the UI.
fn shell_open(target: &str) -> Result<(), String> {
    use windows_sys::Win32::System::Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx};
    use windows_sys::Win32::UI::Shell::{SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let file = wide(target);
    unsafe {
        CoInitializeEx(std::ptr::null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32);
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
        info.lpFile = file.as_ptr();
        info.nShow = SW_SHOWNORMAL;
        if ShellExecuteExW(&mut info) == 0 {
            return Err(format!("Could not open {target}: {}", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

/// Text onto the clipboard (reports, paths, messages the window cannot let the user select).
pub fn copy_text(text: &str) -> Result<(), String> {
    use windows_sys::Win32::Foundation::GlobalFree;
    use windows_sys::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData};
    use windows_sys::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
    use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
    let w = wide(&clipboard_text(text));
    let fail = |what: &str| format!("Could not copy ({what}): {}", std::io::Error::last_os_error());
    unsafe {
        // Another program (a clipboard manager) may hold it for a moment: a few short tries.
        let mut open = OpenClipboard(std::ptr::null_mut()) != 0;
        for _ in 0..4 {
            if open {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(15));
            open = OpenClipboard(std::ptr::null_mut()) != 0;
        }
        if !open {
            return Err(fail("the clipboard is busy"));
        }
        let put = (|| {
            if EmptyClipboard() == 0 {
                return Err(fail("empty"));
            }
            let h = GlobalAlloc(GMEM_MOVEABLE, w.len() * 2);
            if h.is_null() {
                return Err(fail("memory"));
            }
            let p = GlobalLock(h) as *mut u16;
            if p.is_null() {
                let e = fail("memory"); // before GlobalFree, which may overwrite the last error
                GlobalFree(h);
                return Err(e);
            }
            std::ptr::copy_nonoverlapping(w.as_ptr(), p, w.len());
            GlobalUnlock(h);
            // The clipboard owns the memory once this succeeds; only a failure leaves it ours.
            if SetClipboardData(CF_UNICODETEXT as u32, h).is_null() {
                let e = fail("set");
                GlobalFree(h);
                return Err(e);
            }
            Ok(())
        })();
        CloseClipboard();
        put
    }
}

/// Windows text on the clipboard ends its lines with CRLF (Notepad and others expect it).
pub fn clipboard_text(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\n', "\r\n")
}

/// Windows' app mode (Settings > Personalization > Colors), dark when it cannot be read.
pub fn system_dark() -> bool {
    use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW};
    let key = wide("Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize");
    let value = wide("AppsUseLightTheme");
    let mut data: u32 = 1;
    let mut size = std::mem::size_of::<u32>() as u32;
    let r = unsafe {
        RegGetValueW(HKEY_CURRENT_USER, key.as_ptr(), value.as_ptr(), RRF_RT_REG_DWORD, std::ptr::null_mut(), (&mut data as *mut u32).cast(), &mut size)
    };
    r != 0 || data == 0
}

/// A rectangle in physical pixels, edges as Win32's RECT has them (right and bottom exclusive).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Px {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

/// Where a window's visible frame goes so it fits the monitor's work area (X15A11Y-3): a side
/// longer than the area's shrinks to it, then the frame moves inside the area (left and top edges
/// first). None when it already fits. The window's minimum size still wins: Windows keeps it
/// (WM_GETMINMAXINFO), so a window whose minimum is bigger than the area ends up at its minimum.
pub fn fit_frame(frame: Px, work: Px) -> Option<Px> {
    let w = (frame.right - frame.left).min(work.right - work.left);
    let h = (frame.bottom - frame.top).min(work.bottom - work.top);
    let left = frame.left.min(work.right - w).max(work.left);
    let top = frame.top.min(work.bottom - h).max(work.top);
    let fitted = Px { left, top, right: left + w, bottom: top + h };
    (fitted != frame).then_some(fitted)
}

/// What the fit does with a window in this state (X15RFTP-4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FitWhat {
    /// Not on screen yet, or minimized (a shortcut set to "Run: Minimized"): nothing to fit now,
    /// so the next window event tries again, the one after the user restores it at the latest.
    Later,
    /// Maximized (a shortcut set to "Run: Maximized"): its restore rectangle, the size it comes
    /// back at when the user restores it.
    RestoreRect,
    /// A normal window: its frame.
    Frame,
}

pub fn fit_what(visible: bool, minimized: bool, maximized: bool) -> FitWhat {
    if !visible || minimized {
        FitWhat::Later
    } else if maximized {
        FitWhat::RestoreRect
    } else {
        FitWhat::Frame
    }
}

/// A maximized window's restore rectangle fitted to the work area of its monitor (`fit_frame`).
/// `normal` is GetWindowPlacement's, in workspace coordinates (screen coordinates less `origin`,
/// the primary monitor's work-area top left); `work` is in screen coordinates; the result is in
/// workspace coordinates again. None when it already fits.
pub fn fit_restore(normal: Px, work: Px, origin: (i32, i32)) -> Option<Px> {
    let shift = |r: Px, dx: i32, dy: i32| Px { left: r.left + dx, top: r.top + dy, right: r.right + dx, bottom: r.bottom + dy };
    fit_frame(shift(normal, origin.0, origin.1), work).map(|f| shift(f, -origin.0, -origin.1))
}

/// Fit a window that has just opened into its monitor's work area (X15A11Y-3; `fit_frame`):
/// the window opens at its preferred size, sized for a big screen at 100 %, which on a 1080p
/// laptop at 150 % runs past the taskbar and puts the toasts and the status line out of sight.
/// All in physical pixels (the process is per-monitor DPI aware, so no scaling): the work area of
/// the monitor the window is on, and its visible frame (DWM's, without the invisible resize
/// borders, which go back on around it). A maximized window gets its restore rectangle fitted
/// instead (that one has no DWM frame yet, so its invisible borders count as part of it: it
/// comes back a few pixels inside the area). None while the window is not on screen yet or is
/// minimized (try again later, `fit_what`); else whether it changed.
pub fn fit_to_work_area(hwnd: isize) -> Option<bool> {
    use windows_sys::Win32::Foundation::{POINT, RECT};
    use windows_sys::Win32::Graphics::Dwm::{DWMWA_EXTENDED_FRAME_BOUNDS, DwmGetWindowAttribute};
    use windows_sys::Win32::Graphics::Gdi::{GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITOR_DEFAULTTOPRIMARY, MONITORINFO, MonitorFromPoint, MonitorFromRect, MonitorFromWindow};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetWindowPlacement, GetWindowRect, IsIconic, IsWindowVisible, IsZoomed, SWP_NOACTIVATE, SWP_NOZORDER, SetWindowPlacement, SetWindowPos, WINDOWPLACEMENT,
    };
    let hwnd = hwnd as windows_sys::Win32::Foundation::HWND;
    let px = |r: RECT| Px { left: r.left, top: r.top, right: r.right, bottom: r.bottom };
    let work_of = |m| {
        // SAFETY: a MONITORINFO of its own size for a monitor handle Windows just gave.
        let mut mi: MONITORINFO = unsafe { std::mem::zeroed() };
        mi.cbSize = size_of::<MONITORINFO>() as u32;
        (unsafe { GetMonitorInfoW(m, &mut mi) } != 0).then(|| px(mi.rcWork))
    };
    // SAFETY: plain Win32 calls on the app's own window handle, each with a struct of its own
    // size; a call that fails leaves the window as it is.
    unsafe {
        match fit_what(IsWindowVisible(hwnd) != 0, IsIconic(hwnd) != 0, IsZoomed(hwnd) != 0) {
            FitWhat::Later => return None,
            FitWhat::Frame => {}
            FitWhat::RestoreRect => {
                let mut wp: WINDOWPLACEMENT = std::mem::zeroed();
                wp.length = size_of::<WINDOWPLACEMENT>() as u32;
                if GetWindowPlacement(hwnd, &mut wp) == 0 {
                    return Some(false);
                }
                let Some(primary) = work_of(MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY)) else { return Some(false) };
                let n = wp.rcNormalPosition;
                let on_screen = RECT { left: n.left + primary.left, top: n.top + primary.top, right: n.right + primary.left, bottom: n.bottom + primary.top };
                let Some(work) = work_of(MonitorFromRect(&on_screen, MONITOR_DEFAULTTONEAREST)) else { return Some(false) };
                let Some(to) = fit_restore(px(n), work, (primary.left, primary.top)) else { return Some(false) };
                wp.rcNormalPosition = RECT { left: to.left, top: to.top, right: to.right, bottom: to.bottom };
                return Some(SetWindowPlacement(hwnd, &wp) != 0);
            }
        }
        let mut outer: RECT = std::mem::zeroed();
        if GetWindowRect(hwnd, &mut outer) == 0 {
            return Some(false);
        }
        let mut seen = outer;
        if DwmGetWindowAttribute(hwnd, DWMWA_EXTENDED_FRAME_BOUNDS as u32, (&mut seen as *mut RECT).cast(), size_of::<RECT>() as u32) != 0 {
            seen = outer;
        }
        let Some(work) = work_of(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST)) else { return Some(false) };
        let Some(to) = fit_frame(px(seen), work) else { return Some(false) };
        let (l, t, r, b) = (seen.left - outer.left, seen.top - outer.top, outer.right - seen.right, outer.bottom - seen.bottom);
        Some(SetWindowPos(hwnd, std::ptr::null_mut(), to.left - l, to.top - t, to.right - to.left + l + r, to.bottom - to.top + t + b, SWP_NOZORDER | SWP_NOACTIVATE) != 0)
    }
}
