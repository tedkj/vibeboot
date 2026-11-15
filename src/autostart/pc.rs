//! The PC as the scanner sees it: registry, folders, shortcuts, files, services, tasks, signers.
//! `sys::SystemPc` is the real one; `fake::FakePc` a scripted one. Every call may block (a share,
//! the service manager, Task Scheduler): call them from a worker, never the window's thread.

use super::{FileKey, FileState, Hive, SignInfo};
use std::path::{Path, PathBuf};

/// A registry value: its name's exact units, its type and its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegVal {
    pub name: Vec<u16>,
    pub kind: u32,
    pub data: Vec<u8>,
    /// Its data could not be read ("value too large to read: 2 MB", "could not be read (...)"):
    /// `data` is empty. One value like that never hides the others in its key.
    pub problem: Option<String>,
}

pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;

/// The most bytes of one value read (a Run value is a command line).
pub const MAX_VALUE: usize = 1 << 20;

/// "value too large to read: 2 MB" for a value of `bytes`.
pub fn too_large(bytes: usize) -> String {
    format!("value too large to read: {} MB", (bytes + (1 << 19)) >> 20)
}

impl RegVal {
    /// The value as text: REG_SZ and REG_EXPAND_SZ up to the first NUL (data of odd length or
    /// without a NUL is taken as far as it goes); None for other types and unread values.
    pub fn text(&self) -> Option<String> {
        if self.problem.is_some() {
            return None;
        }
        reg_text(self.kind, &self.data)
    }
}

/// REG_SZ / REG_EXPAND_SZ bytes as text (lossy for lone surrogates; it is shown and parsed, never
/// handed back to Windows).
pub fn reg_text(kind: u32, data: &[u8]) -> Option<String> {
    if kind != REG_SZ && kind != REG_EXPAND_SZ {
        return None;
    }
    let units: Vec<u16> = data.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
    Some(String::from_utf16_lossy(&units))
}

/// One value by its whole name (RB2-1). A name holding a NUL (hidden from Registry Editor, written
/// with `NtSetValueKey`) is cut there by `Pc::reg_value` and would read another value (`Vis\0x`
/// reads `Vis`, `\0Hid` the key's default): it is found in the key's listing instead, by all its
/// units. Every side reads a value through this, so they read it alike.
pub fn value(pc: &dyn Pc, hive: Hive, path: &str, name: &[u16]) -> Result<Option<(u32, Vec<u8>)>, String> {
    if !name.contains(&0) {
        return pc.reg_value(hive, path, name);
    }
    let Some(k) = pc.reg_key(hive, path)? else { return Ok(None) };
    match k.values.into_iter().find(|v| v.name == name) {
        None => Ok(None),
        Some(RegVal { problem: Some(why), .. }) => Err(why),
        Some(v) => Ok(Some((v.kind, v.data))),
    }
}

/// A key: its values and its last write (FILETIME).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegKey {
    pub values: Vec<RegVal>,
    pub last_write: Option<u64>,
}

/// A file in a folder listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirItem {
    pub name: Vec<u16>,
    pub dir: bool,
    pub hidden: bool,
    pub created: Option<u64>,
}

/// A shortcut, read without resolving it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Lnk {
    /// `GetPath` with `SLGP_RAWPATH` (variables not expanded); empty for an installer
    /// (advertised) shortcut.
    pub path: String,
    pub args: String,
}

/// A file's facts.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct FileFacts {
    pub state: FileState,
    pub created: Option<u64>,
    pub key: Option<FileKey>,
}

/// The most bytes of a startup file hashed for its definition (`def::file`; 64 MiB is about 0.3 s
/// from the cache); a bigger one is known by its identity, size and last write alone.
pub const MAX_CONTENT: usize = 64 << 20;

/// What a startup file holds, as its definition takes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Content {
    /// The SHA-256 of all its bytes, read through the handle its identity comes from.
    Digest([u8; 32]),
    /// Bigger than `MAX_CONTENT`: its identity, size and last write stand for it.
    OverCap,
    /// It could not be opened for reading or read (another process holds it, its ACL allows
    /// execute only, a range of it is locked), and why; its identity, size and last write stand
    /// for it (read through a handle that asks for its attributes only).
    Unreadable(String),
}

/// Why the bytes of a file are `Content::Unreadable` when they are not handed over within their
/// time, local or on a share (RB3-3, RB4-2; `sys::FILE_WAIT`): a share too slow, another program
/// holding an oplock on it, an earlier read of it that has not returned.
pub const SLOW: &str = "not read within 3 s (its share is slow, or another program holds it)";

/// Why a file's identity is unknown when it is not read within its time (`sys::FILE_WAIT`).
pub const LATE_IDENTITY: &str = "it did not answer within 3 s";

/// Why a file was not read when its step's wait ran out (RB5-1, `sys::Step`): one location's
/// scan, one change or one batch of signer checks charges at most its wait (`sys::STEP_WAIT`; a
/// signer batch's `sys::SIGN_STEP`) in all to reads of one kind, five times that in time with
/// the grace (RB7-5); once it is used up, the rest of that kind are not read one by one. (RB6-2: it
/// says whose wait ran out, never that others did not answer: slow reads that all answered can
/// use it up too, past their grace.)
pub const SPENT: &str = "could not be read in time (VibeBoot's wait for files here ran out)";

/// Whether `why` says a read was not made (or cut short) because its step's wait ran out
/// (`SPENT`): the file itself was never asked to the end.
pub fn spent(why: &str) -> bool {
    why.contains(SPENT)
}

/// Why a file was not read when too many of its kind are held up already (RB5-3, `sys::MAX_LATE`).
pub const HELD: &str = "not read: too many files are held up by other programs";

/// A file's identity and what it holds (`Content`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileBytes {
    pub key: Option<FileKey>,
    pub content: Content,
}

/// A service as the service manager has it.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Service {
    pub name: String,
    pub display: String,
    /// SERVICE_KERNEL_DRIVER 1, SERVICE_FILE_SYSTEM_DRIVER 2, Win32 0x10 / 0x20 (and user
    /// services' flags).
    pub kind: u32,
    /// 0 boot, 1 system, 2 automatic, 3 manual, 4 disabled.
    pub start: u32,
    pub delayed: bool,
    pub binary: String,
    pub account: String,
    /// SERVICE_STOPPED 1 .. SERVICE_PAUSED 7.
    pub state: u32,
}

pub const SERVICE_DRIVER: u32 = 0x1 | 0x2;

impl Service {
    pub fn driver(&self) -> bool {
        self.kind & SERVICE_DRIVER != 0
    }
}

/// A scheduled task as Task Scheduler gives it.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct TaskRaw {
    pub path: String,
    pub enabled: bool,
    /// TASK_STATE: 0 unknown, 1 disabled, 2 queued, 3 ready, 4 running.
    pub state: i32,
    /// OLE automation date (local time); 0 or below 1 is "never".
    pub last_run: f64,
    pub last_result: i32,
    pub xml: String,
}

/// The service manager's list, and the services whose settings could not be read (name, why).
pub type ServiceList = (Vec<Service>, Vec<(String, String)>);

/// Who this process runs as: the account's name (DOMAIN\user) and SID string, and how its own
/// tasks run (`Elevation`).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Account {
    pub name: String,
    pub sid: String,
    pub elevation: Elevation,
}

/// Whether this account's tasks run elevated, from this process's token (its elevation type and
/// integrity level): an elevated process's COM ignores per-user classes (RB3-2,
/// `def::class_keys`). The app (its token filtered) and the helper (elevated) read it alike.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Elevation {
    /// It could not be told.
    #[default]
    Unknown,
    /// A standard account: its tasks run unelevated, with the highest privileges too.
    Standard,
    /// An administrator under UAC: its tasks run unelevated, elevated with the highest privileges.
    Split,
    /// An administrator without UAC's split (UAC off, or the built-in Administrator): elevated.
    Always,
}

pub trait Pc: Send + Sync {
    /// A key's values and last write; None when the key does not exist.
    fn reg_key(&self, hive: Hive, path: &str) -> Result<Option<RegKey>, String>;
    /// One value by name; None when it (or its key) does not exist. The name ends at its first NUL,
    /// as Windows' by-name calls take it (`RegQueryValueExW`): read a value whose name holds one
    /// through `value`, never through this.
    fn reg_value(&self, hive: Hive, path: &str, name: &[u16]) -> Result<Option<(u32, Vec<u8>)>, String>;
    /// A key's last write; None when the key does not exist.
    fn reg_last_write(&self, hive: Hive, path: &str) -> Result<Option<u64>, String>;
    /// Write a REG_BINARY value (the key is created if needed).
    fn reg_set_binary(&self, hive: Hive, path: &str, name: &[u16], data: &[u8]) -> Result<(), String>;
    /// The startup folder: the user's (`FOLDERID_Startup`) or everyone's (`FOLDERID_CommonStartup`).
    fn startup_folder(&self, common: bool) -> Option<PathBuf>;
    /// A folder's files; None when the folder does not exist.
    fn list_dir(&self, dir: &Path) -> Result<Option<Vec<DirItem>>, String>;
    fn lnk(&self, path: &Path) -> Result<Lnk, String>;
    fn file(&self, path: &Path) -> FileFacts;
    /// A file's identity and what it holds from one open handle (`FileBytes`, `Content`: unreadable
    /// bytes are their own answer, with the identity a handle for its attributes reads); None when
    /// it is not there.
    fn file_bytes(&self, path: &Path) -> Result<Option<FileBytes>, String>;
    /// Whether a file exists (for resolving command lines); false when unsure.
    fn exists(&self, path: &Path) -> bool;
    /// Every Win32 service and driver; the second list names those whose settings could not be
    /// read (never silently left out).
    fn services(&self) -> Result<ServiceList, String>;
    fn service(&self, name: &str) -> Result<Option<Service>, String>;
    fn set_service_start(&self, name: &str, start: u32, delayed: bool) -> Result<(), String>;
    /// Every task this account can see; the second list says what could not be read.
    fn tasks(&self) -> Result<(Vec<TaskRaw>, Vec<String>), String>;
    fn task(&self, path: &str) -> Result<Option<TaskRaw>, String>;
    fn set_task_enabled(&self, path: &str, on: bool) -> Result<(), String>;
    /// Who signed the file, and the identity, size and last write of the file that answer is for
    /// (from the same open handle; None when no file was opened): the signer cache keeps an
    /// answer only under that key.
    fn sign(&self, path: &Path) -> (SignInfo, Option<FileKey>);
    /// An environment variable (case-insensitive), for `%VAR%` in commands.
    fn env(&self, name: &str) -> Option<String>;
    /// System32 and the Windows folder: where a bare program name is looked for.
    fn sys_dirs(&self) -> Vec<PathBuf>;
    /// `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`.
    fn machine_guid(&self) -> Option<String>;
    fn account(&self) -> Account;
    /// Now, as a FILETIME (UTC).
    fn now(&self) -> u64;
    /// A local wall-clock time (a task's registration date) as Unix seconds UTC.
    fn local_to_unix(&self, y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> Option<i64>;
}
