//! Portable mode (the field-kit stick). At start, before any prefs read, the app is portable when
//! a file named `portable` (exactly, any case, no extension; a folder does not count) sits next to
//! the exe, or the exe's volume is removable: `GetDriveTypeW` says `DRIVE_REMOVABLE`, or the
//! volume's disk reports `BusTypeUsb`, `BusTypeSd` or `BusTypeMmc` (`IOCTL_STORAGE_QUERY_PROPERTY`
//! on the volume opened with no access). A USB SSD is "fixed" to Windows but USB on its bus.
//!
//! Portable: settings in `<exe folder>\VibeBoot-data\config\`, local state (`seen.json`,
//! `journal.json`) in `<exe folder>\VibeBoot-data\local\`, created on the first write. Nothing
//! is written to the PC's profile or registry by the app except the changes the user makes.

use crate::host::Paths;
use std::path::{Path, PathBuf};

pub const DATA: &str = "VibeBoot-data";

/// Why the app runs portable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// A file named `portable` next to the exe.
    Marker,
    /// The exe's drive is removable (or on a USB, SD or MMC bus).
    Removable,
}

/// Where the app keeps its things, and how.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Setup {
    pub paths: Paths,
    /// Portable: the data folder and why.
    pub portable: Option<(PathBuf, Why)>,
}

const DRIVE_REMOVABLE: u32 = 2;
const BUS_USB: u32 = 7;
const BUS_SD: u32 = 0xC;
const BUS_MMC: u32 = 0xD;

/// The rule, pure: the marker file, a removable drive, or a USB/SD/MMC bus.
pub fn decide(marker: bool, drive_type: u32, bus: Option<u32>) -> Option<Why> {
    if marker {
        Some(Why::Marker)
    } else if drive_type == DRIVE_REMOVABLE || bus.is_some_and(|b| matches!(b, BUS_USB | BUS_SD | BUS_MMC)) {
        Some(Why::Removable)
    } else {
        None
    }
}

/// A file (not a folder) named `portable`, any case, no extension, in `dir`.
pub fn has_marker(dir: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else { return false };
    rd.take(10_000).flatten().any(|e| e.file_name().to_str().is_some_and(|n| n.eq_ignore_ascii_case("portable")) && e.file_type().is_ok_and(|t| t.is_file()))
}

/// The portable folders beside the exe.
pub fn portable_paths(exe_dir: &Path) -> Paths {
    let data = exe_dir.join(DATA);
    Paths { config: data.join("config"), local_data: data.join("local") }
}

/// The exe's volume: its drive type and its disk's bus type (None when it cannot be asked).
#[cfg(windows)]
fn volume_of(exe: &Path) -> (u32, Option<u32>) {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, GetDriveTypeW, GetVolumeNameForVolumeMountPointW, GetVolumePathNameW, OPEN_EXISTING};
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::{IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery, STORAGE_DEVICE_DESCRIPTOR, STORAGE_PROPERTY_QUERY, StorageDeviceProperty};
    let p = crate::host::wide_path(exe);
    let mut root = vec![0u16; 1024];
    // SAFETY: a NUL-terminated path, a buffer and its length.
    if unsafe { GetVolumePathNameW(p.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
        return (0, None);
    }
    // SAFETY: the NUL-terminated root from above.
    let drive = unsafe { GetDriveTypeW(root.as_ptr()) };
    let mut vol = vec![0u16; 64];
    // SAFETY: the root, a buffer of 64 units (a volume GUID path is 49).
    if unsafe { GetVolumeNameForVolumeMountPointW(root.as_ptr(), vol.as_mut_ptr(), vol.len() as u32) } == 0 {
        return (drive, None);
    }
    let n = vol.iter().position(|&u| u == 0).unwrap_or(0);
    let mut dev: Vec<u16> = vol[..n].to_vec();
    if dev.last() == Some(&u16::from(b'\\')) {
        dev.pop();
    }
    dev.push(0);
    // SAFETY: the volume device, opened with no access (enough for this query).
    let h = unsafe { CreateFileW(dev.as_ptr(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, std::ptr::null(), OPEN_EXISTING, 0, std::ptr::null_mut()) };
    if h == INVALID_HANDLE_VALUE {
        return (drive, None);
    }
    let q = STORAGE_PROPERTY_QUERY { PropertyId: StorageDeviceProperty, QueryType: PropertyStandardQuery, AdditionalParameters: [0] };
    let mut out = vec![0u64; 128];
    let mut got = 0u32;
    // SAFETY: the query struct in, a u64-aligned buffer of 1 KB out.
    let ok = unsafe { DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, (&q as *const STORAGE_PROPERTY_QUERY).cast(), size_of::<STORAGE_PROPERTY_QUERY>() as u32, out.as_mut_ptr().cast(), (out.len() * 8) as u32, &mut got, std::ptr::null_mut()) } != 0;
    unsafe { CloseHandle(h) };
    if !ok || (got as usize) < size_of::<STORAGE_DEVICE_DESCRIPTOR>() {
        return (drive, None);
    }
    // SAFETY: the buffer holds a STORAGE_DEVICE_DESCRIPTOR of `got` bytes.
    let d = unsafe { &*(out.as_ptr() as *const STORAGE_DEVICE_DESCRIPTOR) };
    (drive, Some(d.BusType as u32))
}

/// Where the app keeps its things, decided at start. `dev_home` (dev-hooks builds only) wins over
/// both modes.
pub fn setup(exe: Option<&Path>, installed: Paths, dev_home: Option<PathBuf>) -> Setup {
    if let Some(home) = dev_home {
        return Setup { paths: Paths { config: home.join("config"), local_data: home.join("local") }, portable: None };
    }
    let Some(exe) = exe else { return Setup { paths: installed, portable: None } };
    let Some(dir) = exe.parent() else { return Setup { paths: installed, portable: None } };
    let marker = has_marker(dir);
    let (drive, bus) = if marker { (0, None) } else { volume_of(exe) };
    match decide(marker, drive, bus) {
        Some(why) => Setup { paths: portable_paths(dir), portable: Some((dir.join(DATA), why)) },
        None => Setup { paths: installed, portable: None },
    }
}

/// Whether the portable data folder can be written (a read-only stick cannot): a probe file made
/// create-new and removed again, in the data folder when it is there, else beside the exe. Never
/// on the window's thread (the stick may be slow).
pub fn writable(data: &Path) -> bool {
    let dir = if data.is_dir() { data.to_path_buf() } else { data.parent().map(Path::to_path_buf).unwrap_or_default() };
    let probe = dir.join(format!(".vibeboot-probe-{}.tmp", std::process::id()));
    match std::fs::OpenOptions::new().write(true).create_new(true).open(&probe) {
        Ok(f) => {
            drop(f);
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// The exe's final path: a junction, symbolic link or subst drive on the way resolved (the
/// `\\?\` prefix dropped again). The path as given when it cannot be resolved. About's install
/// check reads the exe and the uninstaller beside it by this path (the template's).
pub fn final_path(exe: &Path) -> PathBuf {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_NAME_NORMALIZED, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFinalPathNameByHandleW, OPEN_EXISTING, VOLUME_NAME_DOS};
    let w = crate::host::wide_path(exe);
    // SAFETY: a NUL-terminated path; no access rights asked; closed below.
    let h = unsafe { CreateFileW(w.as_ptr(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, std::ptr::null(), OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, std::ptr::null_mut()) };
    if h == INVALID_HANDLE_VALUE {
        return exe.to_path_buf();
    }
    let mut buf = vec![0u16; 32 * 1024];
    // SAFETY: a buffer of the length given; the handle is open.
    let n = unsafe { GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as u32, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) } as usize;
    // SAFETY: opened above, closed once.
    unsafe { CloseHandle(h) };
    if n == 0 || n >= buf.len() {
        return exe.to_path_buf();
    }
    strip_verbatim(&buf[..n])
}

/// `\\?\C:\x` as `C:\x`, `\\?\UNC\s\x` as `\\s\x`; other forms as they are.
pub fn strip_verbatim(units: &[u16]) -> PathBuf {
    let pre = |p: &str| p.encode_utf16().collect::<Vec<u16>>();
    if units.starts_with(&pre("\\\\?\\UNC\\")) {
        let mut v = pre("\\\\");
        v.extend_from_slice(&units[8..]);
        crate::host::path_from_wide(&v)
    } else if units.starts_with(&pre("\\\\?\\")) && units.get(5) == Some(&(b':' as u16)) {
        crate::host::path_from_wide(&units[4..])
    } else {
        crate::host::path_from_wide(units)
    }
}
