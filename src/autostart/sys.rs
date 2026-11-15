//! The real PC (`SystemPc`): the registry (HKLM in its 64-bit view), the known folders, files
//! (every read of one under a time limit, local or on a share: a file another program holds
//! with an oplock, or one on a disconnected share, is "unknown" or "not read" after its time,
//! never "missing", and never holds the scan, a change or a signer for long: `within`), the
//! service manager, Task Scheduler and Authenticode. Reads only, except the three writes a
//! switch makes (`reg_set_binary`, `set_service_start`, `set_task_enabled`).

use super::pc::{Account, DirItem, FileFacts, Lnk, Pc, RegKey, RegVal, Service, TaskRaw};
use super::{FileKey, FileState, Hive, SignInfo, text};
use std::path::{Path, PathBuf};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, FILETIME};
use windows_sys::Win32::System::Registry::*;

/// How long a file may take to answer, wherever it is (RB3-3, RB4-2): its identity and bytes, a
/// folder's listing, whether it is there.
pub const FILE_WAIT: Duration = Duration::from_secs(3);
/// How long a shortcut may take to be read through the shell.
const LNK_WAIT: Duration = Duration::from_secs(10);
/// How long a signature check may take (it reads the whole file, and maybe a catalog).
pub const SIGN_WAIT: Duration = Duration::from_secs(20);
/// How long one step (one location's scan, one change, one batch's late binds: `step`) waits
/// in all on reads of one kind (RB5-1): each read waits at most what is left; once it is used
/// up, the step's remaining reads of that kind are late at once (`pc::SPENT`). What answered
/// reads take inside their grace is not charged (`GRACE`, at most `GRACE_IN_ALL` times this per
/// kind), so the real worst case is 25 s per kind of read per step (5 s charged, 20 s of grace;
/// RB7-5), never one limit per entry.
pub const STEP_WAIT: Duration = Duration::from_secs(5);
/// What a read that answers may take before it costs its step anything (RB6-2): a healthy read,
/// however slow the disk, spends none of the wait; a read given up on costs all of its wait.
pub const GRACE: Duration = Duration::from_millis(250);
/// How much grace a step gives one kind of read in all (`GRACE_IN_ALL` times its wait, RB6-2):
/// past it, an answered read costs all it took, so files that each answer just inside the grace
/// (an oplock acknowledged after 240 ms) cost a bounded time too, never N graces.
const GRACE_IN_ALL: u32 = 4;
/// The same for one batch of signer checks, across the window's four signer workers (RB5-3):
/// this PC's 233 targets take about 6 s of checks in all, so a slow disk has ten times that.
/// With the grace, about 300 s of checks per batch (60 s charged, 240 s of grace, which takes 960
/// answered checks of 250 ms; RB7-5), spread over the four workers. Each worker asks what is
/// left before its check starts, so the three others' last checks can each run on to their
/// `SIGN_WAIT` after the wait is used up: at most 360 s of checks, about 90 s on the clock
/// (RB8-4).
pub const SIGN_STEP: Duration = Duration::from_secs(60);

#[derive(Default)]
pub struct SystemPc;

fn root(h: Hive) -> HKEY {
    match h {
        Hive::User => HKEY_CURRENT_USER,
        Hive::Machine => HKEY_LOCAL_MACHINE,
        Hive::Users => HKEY_USERS,
    }
}

/// An open registry key, closed once.
struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: opened by RegOpenKeyExW / RegCreateKeyExW, closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

fn open(hive: Hive, path: &str, access: u32) -> Result<Option<Key>, String> {
    let w = text::wide(path);
    let mut k: HKEY = std::ptr::null_mut();
    // SAFETY: a NUL-terminated path; the handle is ours.
    let r = unsafe { RegOpenKeyExW(root(hive), w.as_ptr(), 0, access | KEY_WOW64_64KEY, &mut k) };
    match r {
        ERROR_SUCCESS => Ok(Some(Key(k))),
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(None),
        e => Err(text::os_words(e)),
    }
}

fn last_write(k: &Key) -> Option<u64> {
    let mut ft = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    // SAFETY: only the last-write time is asked for.
    let r = unsafe { RegQueryInfoKeyW(k.0, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), &mut ft) };
    let v = (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime);
    (r == ERROR_SUCCESS && v != 0).then_some(v)
}

/// A string stored without its NUL is handed over (and sized) with room for one: two bytes over
/// the cap are that NUL, not data (R-BOOT-7). Both registry reads (`value_at`, `reg_value`) take
/// this rule.
const ROOM: usize = super::pc::MAX_VALUE + 2;

fn fits(kind: u32, n: usize) -> bool {
    n <= super::pc::MAX_VALUE || (matches!(kind, super::pc::REG_SZ | super::pc::REG_EXPAND_SZ) && n <= ROOM)
}

/// The value at index `i` of `k` (its name, type and size already read): its data, at most
/// `MAX_VALUE` bytes; a bigger or unreadable one comes back with its problem and no data.
fn value_at(k: &Key, i: u32, name: Vec<u16>, kind: u32, size: usize) -> RegVal {
    use super::pc::{MAX_VALUE, too_large};
    let problem = |why: String| RegVal { name: name.clone(), kind, data: Vec::new(), problem: Some(why) };
    let room = ROOM;
    if !fits(kind, size) {
        return problem(too_large(size));
    }
    let mut nbuf = vec![0u16; 16_384];
    let mut data = vec![0u8; size.max(16)];
    loop {
        let mut nlen = nbuf.len() as u32;
        let mut dlen = data.len() as u32;
        let mut kind2 = 0u32;
        // SAFETY: buffers and their sizes (units for the name, bytes for the data).
        let r = unsafe { RegEnumValueW(k.0, i, nbuf.as_mut_ptr(), &mut nlen, std::ptr::null(), &mut kind2, data.as_mut_ptr(), &mut dlen) };
        match r {
            ERROR_SUCCESS if !fits(kind2, dlen as usize) => return problem(too_large(dlen as usize)),
            ERROR_SUCCESS => return RegVal { name: nbuf[..nlen as usize].to_vec(), kind: kind2, data: data[..dlen as usize].to_vec(), problem: None },
            // It grew between the two reads.
            ERROR_MORE_DATA if (dlen as usize) <= room && data.len() < room => data = vec![0u8; (dlen as usize).max(data.len() * 2).min(room)],
            ERROR_MORE_DATA => return problem(too_large((dlen as usize).max(MAX_VALUE + 1))),
            e => return problem(format!("could not be read ({})", text::os_words(e))),
        }
    }
}

/// Reads given up on that have not returned yet, by kind and path, and how many (RB4-2, RB4-7).
/// A path with a read of a kind out is not read that way again until it returns: the late
/// answer comes at once, so a file held for good (an oplock that is never acknowledged, a share
/// that hangs) keeps one thread and handle per kind of read however often it is scanned, never
/// one more per scan. At most `MAX_LATE` reads of a kind are out at a time; past that, reads of
/// that kind are late at once (switched off only or unknown, never a hang).
static LATE: Mutex<BTreeMap<(&'static str, String), usize>> = Mutex::new(BTreeMap::new());

/// The most reads of one kind given up on and still out (`LATE`).
const MAX_LATE: usize = 64;

fn late_reads() -> MutexGuard<'static, BTreeMap<(&'static str, String), usize>> {
    LATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Why a read did not answer (`within`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Late {
    /// Not within its own time limit, or an earlier read of it that was not is still out.
    Slow,
    /// Its step's wait for reads of its kind ran out (RB5-1, `Step`): not read one by one.
    Spent,
    /// `MAX_LATE` reads of its kind are held up already (RB5-3): not started.
    Full,
}

impl Late {
    /// In words: `slow` for a read past its own limit, `pc::SPENT`, `pc::HELD`.
    pub(super) fn words(self, slow: &str) -> String {
        match self {
            Late::Slow => slow.into(),
            Late::Spent => super::pc::SPENT.into(),
            Late::Full => super::pc::HELD.into(),
        }
    }
}

/// One step's wait budget (RB5-1): one location's scan, one change, one batch of signer checks.
/// Each kind of read may wait `each` in all within it, however many entries it has, so N held or
/// unreachable files cost one budget per kind, never N limits one after another. Shared by the
/// threads that `run` in it (the signer workers).
pub struct Step {
    each: Duration,
    /// Per kind: the wait spent, and the grace given (RB6-2).
    used: Mutex<BTreeMap<&'static str, (Duration, Duration)>>,
}

thread_local! {
    /// The step this thread's reads count against (`Step::run`); none: each read its own limit.
    static STEP: RefCell<Option<Arc<Step>>> = const { RefCell::new(None) };
}

impl Step {
    pub fn new(each: Duration) -> Arc<Step> {
        Arc::new(Step { each, used: Mutex::new(BTreeMap::new()) })
    }

    /// Run `f` on this thread with its reads counted against this step (the thread's earlier
    /// step comes back after, a panic included).
    pub fn run<T>(self: &Arc<Self>, f: impl FnOnce() -> T) -> T {
        struct Back(Option<Arc<Step>>);
        impl Drop for Back {
            fn drop(&mut self) {
                let prev = self.0.take();
                STEP.with(|s| *s.borrow_mut() = prev);
            }
        }
        let _back = Back(STEP.with(|s| s.borrow_mut().replace(self.clone())));
        f()
    }

    fn used(&self) -> MutexGuard<'_, BTreeMap<&'static str, (Duration, Duration)>> {
        self.used.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What is left of kind `what`'s wait.
    fn left(&self, what: &'static str) -> Duration {
        self.each.saturating_sub(self.used().get(what).map(|u| u.0).unwrap_or_default())
    }

    /// A read of kind `what` took `d` (RB6-2): one that answered costs only what it took past
    /// `GRACE`, while the step's grace for the kind lasts; one given up on costs all of it.
    fn spend(&self, what: &'static str, d: Duration, answered: bool) {
        let mut used = self.used();
        let (spent, graced) = used.entry(what).or_default();
        let free = if answered { d.min(GRACE).min((self.each * GRACE_IN_ALL).saturating_sub(*graced)) } else { Duration::ZERO };
        *graced += free;
        *spent += d - free;
    }
}

/// Whether this thread's reads count against a step now (`FakePc` counts signer checks outside one).
pub(super) fn in_step() -> bool {
    STEP.with(|s| s.borrow().is_some())
}

/// Run `f` as one step of its own (`STEP_WAIT` per kind of read): a location's scan, a change.
pub fn step<T>(f: impl FnOnce() -> T) -> T {
    Step::new(STEP_WAIT).run(f)
}

/// Run `f`, one change's signer check, as a step of its own (RB6-4): the whole `SIGN_WAIT` it
/// asks for, never what is left of the change's own step.
pub fn sign_step<T>(f: impl FnOnce() -> T) -> T {
    Step::new(SIGN_WAIT).run(f)
}

/// Run `f`, a read of kind `what` of `path`, on a thread of its own and wait at most `limit` for
/// it (RB4-2: every file read, local or on a share), and at most what is left of this thread's
/// step for that kind (`Step`, RB5-1). Err: it did not answer in time, or an earlier read of it
/// that was given up on has not returned yet (`LATE`), or why it was not started.
pub(super) fn within<T: Send + 'static>(what: &'static str, path: &Path, limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> Result<T, Late> {
    let key = (what, path.to_string_lossy().to_lowercase());
    {
        let late = late_reads();
        if late.contains_key(&key) {
            return Err(Late::Slow);
        }
        if late.iter().filter(|((w, _), _)| *w == what).map(|(_, n)| n).sum::<usize>() >= MAX_LATE {
            return Err(Late::Full);
        }
    }
    let step = STEP.with(|s| s.borrow().clone());
    let left = step.as_ref().map_or(limit, |s| s.left(what));
    if left.is_zero() {
        return Err(Late::Spent);
    }
    // Cut short by the step: late for its sake, not the file's own limit.
    let (wait, cut) = if left < limit { (left, true) } else { (limit, false) };
    let t0 = std::time::Instant::now();
    let r = wait_for(key, wait, f);
    if let Some(s) = &step {
        s.spend(what, t0.elapsed(), r.is_some());
    }
    r.ok_or(if cut { Late::Spent } else { Late::Slow })
}

/// `within`'s wait: `f` on its own thread, at most `limit`; None when it was given up on (then
/// counted in `LATE` until it returns).
fn wait_for<T: Send + 'static>(key: (&'static str, String), limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    const RUNNING: u8 = 0;
    const RETURNED: u8 = 1;
    const GIVEN_UP: u8 = 2;
    // Moved on only under `LATE`'s lock: a read that returns just as it is given up on is
    // counted once or not at all, never left in it.
    let state = Arc::new(AtomicU8::new(RUNNING));
    let (tx, rx) = std::sync::mpsc::channel();
    let (k, st) = (key.clone(), state.clone());
    let spawned = std::thread::Builder::new().spawn(move || {
        let _ = tx.send(f());
        let mut late = late_reads();
        if st.swap(RETURNED, Ordering::SeqCst) == GIVEN_UP
            && let Some(n) = late.get_mut(&k)
        {
            *n -= 1;
            if *n == 0 {
                late.remove(&k);
            }
        }
    });
    if spawned.is_err() {
        return None;
    }
    match rx.recv_timeout(limit) {
        Ok(v) => Some(v),
        Err(_) => {
            let mut late = late_reads();
            if state.compare_exchange(RUNNING, GIVEN_UP, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                *late.entry(key).or_insert(0) += 1;
                None
            } else {
                drop(late);
                rx.try_recv().ok()
            }
        }
    }
}

/// A file's identity, size and last write, by its open handle.
pub fn file_key(f: &std::fs::File) -> Option<FileKey> {
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, FILE_ID_INFO, FileIdInfo, GetFileInformationByHandle, GetFileInformationByHandleEx};
    let m = f.metadata().ok()?;
    let h = f.as_raw_handle();
    // SAFETY: plain structs filled by the calls, sizes given.
    let (serial, id) = unsafe {
        let mut info: FILE_ID_INFO = std::mem::zeroed();
        if GetFileInformationByHandleEx(h, FileIdInfo, (&mut info as *mut FILE_ID_INFO).cast(), size_of::<FILE_ID_INFO>() as u32) != 0 {
            (info.VolumeSerialNumber, info.FileId.Identifier)
        } else {
            let mut bh: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
            if GetFileInformationByHandle(h, &mut bh) == 0 {
                return None;
            }
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&((u64::from(bh.nFileIndexHigh) << 32) | u64::from(bh.nFileIndexLow)).to_le_bytes());
            (u64::from(bh.dwVolumeSerialNumber), id)
        }
    };
    let k = FileKey { serial, id, size: m.file_size(), written: m.last_write_time() };
    k.usable().then_some(k)
}

/// What the scan says of a startup target that is not on a disk of this PC (X15PRV-1,
/// X15R2BC-4): it is never opened. Opening it could contact another computer by itself (SMB, or
/// WebDAV through WebClient) with this account's sign-in, right as the scan runs; a scammer's
/// planted entry would learn the PC is being looked at. Windows contacts it only when the entry
/// runs.
pub const NOT_LOCAL: &str = "on a network or device path, not opened";

/// Whether a path is anything but a file on a local disk (X15PRV-1, X15R2BC-4): an allowlist.
/// Only a drive letter path (`C:\...`, also as `\\?\C:\`, `\\.\C:\` or `\??\C:\`) on a local
/// drive (fixed, removable, CD or RAM disk: `local_letter`) is opened. Anything else may reach
/// another computer or a device when opened, however it is spelled (`\\server\share`, WebDAV,
/// `\\?\UNC\`, `\\?\GLOBALROOT\...`, `\GLOBAL??\...`, `\Device\...`, a volume GUID path, a pipe,
/// a mapped network drive), so it is not. Told by the letters and `GetDriveTypeW`: nothing is
/// opened to tell.
pub(crate) fn not_local(p: &Path) -> bool {
    let s = p.as_os_str().to_string_lossy().replace('/', "\\");
    let rest = [r"\\?\", r"\\.\", r"\??\"].iter().find_map(|x| s.strip_prefix(x)).unwrap_or(&s); // offpc-ok: a pattern, nothing opened
    let b = rest.as_bytes();
    let letter = b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b.len() == 2 || b[2] == b'\\');
    !(letter && local_letter(b[0]))
}

/// Whether the scan leaves `path` unopened (`not_local`), except a file right in a startup
/// folder (X15R2A-2): the startup folders and their files are the user's own setup, read where
/// they are (Windows reads them at every sign-in), also when the folder is redirected to a share.
fn left_unopened(pc: &SystemPc, path: &Path) -> bool {
    use std::path::Component;
    not_local(path)
        && !(matches!(path.components().next_back(), Some(Component::Normal(_)))
            && [false, true].into_iter().any(|common| pc.startup_folder(common).is_some_and(|f| path.parent() == Some(f.as_path()))))
}

/// Whether drive `letter` is a local drive: fixed, removable, CD or RAM disk (not a network drive,
/// and not a letter with nothing behind it). Asked of the drive type, which opens nothing on it.
fn local_letter(letter: u8) -> bool {
    let root: Vec<u16> = format!("{}:\\", letter as char).encode_utf16().chain([0]).collect(); // offpc-ok: a drive type only, nothing opened
    // SAFETY: a NUL-terminated root path.
    let kind = unsafe { windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(root.as_ptr()) };
    // DRIVE_REMOVABLE, DRIVE_FIXED, DRIVE_CDROM, DRIVE_RAMDISK.
    matches!(kind, 2 | 3 | 5 | 6)
}

/// A file's facts now, through a handle for its attributes alone (no time limit: the caller adds
/// one, `within`).
fn file_now(p: &Path) -> FileFacts {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    match std::fs::OpenOptions::new().access_mode(FILE_READ_ATTRIBUTES).share_mode(7).open(p) {
        Ok(f) => match f.metadata() {
            Ok(m) if m.is_dir() => FileFacts { state: FileState::Unknown("a folder, not a file".into()), ..FileFacts::default() },
            Ok(m) => FileFacts { state: FileState::Present, created: (m.creation_time() != 0).then(|| m.creation_time()), key: file_key(&f) },
            Err(e) => FileFacts { state: FileState::Unknown(text::clean(&e.to_string())), ..FileFacts::default() },
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => FileFacts { state: absent(p), ..FileFacts::default() },
        Err(e) => FileFacts { state: FileState::Unknown(text::clean(&e.to_string())), ..FileFacts::default() },
    }
}

/// Why a file's bytes cannot be read while its attributes can: access denied (an ACL with
/// execute but no read), a sharing violation (another process holds it with share mode 0), a
/// lock violation (a range of it locked). Its owner can arrange each of these (RB2-2).
fn unreadable(e: &std::io::Error) -> bool {
    // ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION.
    matches!(e.raw_os_error(), Some(5 | 32 | 33))
}

/// A file's identity and content through one handle opened for reading: the SHA-256 of all its
/// bytes up to `MAX_CONTENT`, read in pieces (`digest`). One whose bytes cannot be opened for
/// reading (`unreadable`) is known by the identity a handle for its attributes alone reads.
fn bytes_now(p: &Path, stop: &AtomicBool) -> Result<Option<super::pc::FileBytes>, String> {
    use super::pc::{Content, FileBytes, MAX_CONTENT};
    use std::os::windows::fs::OpenOptionsExt;
    let words = |e: &std::io::Error| text::clean(&e.to_string());
    let f = match std::fs::OpenOptions::new().read(true).share_mode(7).open(p) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) if unreadable(&e) => {
            let why = words(&e);
            let facts = file_now(p);
            return match facts.state {
                FileState::Present => Ok(Some(FileBytes { key: facts.key, content: Content::Unreadable(why) })),
                FileState::Missing => Ok(None),
                FileState::Unknown(w) => Err(format!("{why}; its identity could not be read either ({w})")),
                FileState::NoTarget => Err(why),
            };
        }
        Err(e) => return Err(words(&e)),
    };
    let m = f.metadata().map_err(|e| words(&e))?;
    if m.is_dir() {
        return Err("a folder, not a file".into());
    }
    let key = file_key(&f);
    if m.len() > MAX_CONTENT as u64 {
        return Ok(Some(FileBytes { key, content: Content::OverCap }));
    }
    Ok(Some(FileBytes { key, content: digest(&mut &f, stop) }))
}

/// What `r` hands over (RB2-8, RB3-3): the SHA-256 of all of it, read in 64 KiB pieces; more than
/// `MAX_CONTENT` (it grew during the read) is `OverCap`, never a part taken for the whole. A read
/// that fails partway (a locked range, an ACL, a share gone) or is told to `stop` (its time is
/// up) is `Unreadable`: the identity read through the same handle stands for it, and the
/// entry switches off only.
fn digest(r: &mut dyn std::io::Read, stop: &AtomicBool) -> super::pc::Content {
    use super::pc::{Content, MAX_CONTENT};
    let mut sha = super::def::Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0usize;
    loop {
        if stop.load(Ordering::Relaxed) {
            return Content::Unreadable(super::pc::SLOW.into());
        }
        match r.read(&mut buf) {
            Ok(0) => return Content::Digest(sha.finish()),
            Ok(n) => {
                total += n;
                if total > MAX_CONTENT {
                    return Content::OverCap;
                }
                sha.update(&buf[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Content::Unreadable(text::clean(&e.to_string())),
        }
    }
}

/// A file, local or on a share (RB3-3, RB4-2): its identity first (`ident`: a handle for its
/// attributes alone, which an oplock does not hold up), then its bytes (`bytes`), all within
/// `limit`. Bytes not handed over in time (a share too slow, another program holding an oplock
/// on the file) are `Content::Unreadable` (`pc::SLOW`: switched off only, never a lost switch or
/// a hang), and the read left behind is told to stop; an identity not read in time is unknown
/// (which file it is cannot be told). Each read is one `within`, so a file held for good costs
/// one thread per kind of read, never one per scan.
pub(super) fn bytes_within(path: &Path, limit: Duration, ident: impl FnOnce() -> FileFacts + Send + 'static, bytes: impl FnOnce(&AtomicBool) -> Result<Option<super::pc::FileBytes>, String> + Send + 'static) -> Result<Option<super::pc::FileBytes>, String> {
    use super::pc::{Content, FileBytes};
    let t0 = std::time::Instant::now();
    let facts = within("identity", path, limit, ident).map_err(|l| l.words(super::pc::LATE_IDENTITY))?;
    match facts.state {
        FileState::Present => {}
        FileState::Missing => return Ok(None),
        FileState::Unknown(why) => return Err(why),
        FileState::NoTarget => return Err("not a file".into()),
    }
    let stop = Arc::new(AtomicBool::new(false));
    let told = stop.clone();
    match within("bytes", path, limit.saturating_sub(t0.elapsed()), move || bytes(&told)) {
        Ok(r) => r,
        Err(l) => {
            stop.store(true, Ordering::Relaxed);
            Ok(Some(FileBytes { key: facts.key, content: Content::Unreadable(l.words(super::pc::SLOW)) }))
        }
    }
}

/// Who signed a file (`check`, `signer::check` for `SystemPc`), within `limit` (RB4-2): a check
/// that does not answer in time (an oplock on the file, a share that hangs), or is not started
/// (its step's wait is used up, too many are held up: RB5-3), is `Signer::Unknown` with its
/// reason, never a signer thread held for good. The window then refuses a service on it, and
/// switches a task it could be Windows' own of off only (`switch::unchecked_task`, RB6-1).
pub(super) fn sign_within(path: &Path, limit: Duration, check: impl FnOnce() -> (SignInfo, Option<FileKey>) + Send + 'static) -> (SignInfo, Option<FileKey>) {
    within("signature", path, limit, check).unwrap_or_else(|l| {
        let why = match l {
            Late::Slow if limit.as_secs() > 0 => format!("its signature was not checked within {} s", limit.as_secs()),
            Late::Slow => format!("its signature was not checked within {} ms", limit.as_millis()),
            Late::Spent => "its signature was not checked in time (VibeBoot's wait for signer checks here ran out)".into(),
            Late::Full => format!("its signature was not checked ({})", super::pc::HELD),
        };
        (SignInfo { signer: super::Signer::Unknown(why), company: None }, None)
    })
}

/// A path that was not found: Missing when the nearest folder above it that exists answers (the
/// volume is there and says "not here"); Unknown when a folder above it cannot be asked or no
/// folder up to the root is there (a drive that is not there).
pub(super) fn absent(p: &Path) -> FileState {
    let mut cur = p.parent();
    while let Some(d) = cur {
        if d.as_os_str().is_empty() {
            break;
        }
        match std::fs::metadata(d) {
            Ok(m) if m.is_dir() => return FileState::Missing,
            Ok(_) => return FileState::Missing, // a file where a folder would be: not there either
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => cur = d.parent(),
            Err(e) => return FileState::Unknown(format!("its folder could not be read ({})", text::clean(&e.to_string()))),
        }
    }
    FileState::Unknown("its drive or share is not there".into())
}

fn ft_now() -> u64 {
    let mut ft = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    // SAFETY: an out struct.
    unsafe { windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime(&mut ft) };
    (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime)
}

fn sys_dir(windows: bool) -> Option<PathBuf> {
    use windows_sys::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};
    let mut buf = vec![0u16; 1024];
    // SAFETY: a buffer and its length in units.
    let n = unsafe { if windows { GetWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } else { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } } as usize;
    use std::os::windows::ffi::OsStringExt;
    (n > 0 && n < buf.len()).then(|| PathBuf::from(std::ffi::OsString::from_wide(&buf[..n])))
}

/// How a known folder is asked for (RB5-2): `KF_FLAG_DONT_VERIFY`, so Windows hands over its
/// path without checking the folder is there, which has no time limit (a Startup folder
/// redirected to a share that hangs, which the user can set in HKCU). The folder's one touch is
/// then the bounded listing (`list_dir`), and a change's the bounded file read.
const KNOWN_FOLDER_FLAGS: u32 = windows_sys::Win32::UI::Shell::KF_FLAG_DONT_VERIFY as u32;

fn known_folder(id: &windows_sys::core::GUID) -> Option<PathBuf> {
    known_folder_with(id, KNOWN_FOLDER_FLAGS)
}

fn known_folder_with(id: &windows_sys::core::GUID, flags: u32) -> Option<PathBuf> {
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;
    // SAFETY: the shell allocates the string; it is freed here.
    unsafe {
        let mut p: windows_sys::core::PWSTR = std::ptr::null_mut();
        let ok = SHGetKnownFolderPath(id, flags, std::ptr::null_mut(), &mut p) == 0;
        let out = if ok && !p.is_null() {
            let len = (0..).take_while(|&i| *p.add(i) != 0).count();
            use std::os::windows::ffi::OsStringExt;
            Some(PathBuf::from(std::ffi::OsString::from_wide(std::slice::from_raw_parts(p, len))))
        } else {
            None
        };
        CoTaskMemFree(p as *const _);
        out
    }
}

/// How this account's tasks run (RB3-2), from a token's elevation type and, for Default, its
/// integrity level's RID: Full (the helper) or Limited (the app under UAC) is an administrator
/// under UAC; Default is no split token, so the integrity level tells: medium (0x2000, medium
/// plus 0x2100) a standard account, high (0x3000) or system (0x4000) one that always runs
/// elevated. Anything else: unknown (RB4-6 pins the table).
pub(super) fn elevation_of(kind: i32, rid: Option<u32>) -> super::pc::Elevation {
    use super::pc::Elevation;
    use windows_sys::Win32::Security::{TokenElevationTypeDefault, TokenElevationTypeFull, TokenElevationTypeLimited};
    if kind == TokenElevationTypeFull || kind == TokenElevationTypeLimited {
        return Elevation::Split;
    }
    match rid {
        Some(0x2000..0x3000) if kind == TokenElevationTypeDefault => Elevation::Standard,
        Some(0x3000..=0x4FFF) if kind == TokenElevationTypeDefault => Elevation::Always,
        _ => Elevation::Unknown,
    }
}

/// How this account's tasks run (RB3-2), from this process's token (`elevation_of`); a token
/// that cannot be read: unknown.
fn elevation(tok: windows_sys::Win32::Foundation::HANDLE) -> super::pc::Elevation {
    use super::pc::Elevation;
    use windows_sys::Win32::Security::{GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TOKEN_MANDATORY_LABEL, TokenElevationType, TokenElevationTypeDefault, TokenIntegrityLevel};
    let mut kind = 0i32;
    let mut need = 0u32;
    // SAFETY: an i32 out value of its size.
    if unsafe { GetTokenInformation(tok, TokenElevationType, (&mut kind as *mut i32).cast(), 4, &mut need) } == 0 {
        return Elevation::Unknown;
    }
    if kind != TokenElevationTypeDefault {
        return elevation_of(kind, None);
    }
    // SAFETY: a size query, then a buffer of that size (u64-aligned) holding a
    // TOKEN_MANDATORY_LABEL whose SID points into the same buffer.
    unsafe { GetTokenInformation(tok, TokenIntegrityLevel, std::ptr::null_mut(), 0, &mut need) };
    let mut buf = vec![0u64; (need as usize).div_ceil(8).max(4)];
    if unsafe { GetTokenInformation(tok, TokenIntegrityLevel, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut need) } == 0 {
        return Elevation::Unknown;
    }
    let rid = unsafe {
        let sid = (*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL)).Label.Sid;
        let n = *GetSidSubAuthorityCount(sid);
        if n == 0 {
            return Elevation::Unknown;
        }
        *GetSidSubAuthority(sid, u32::from(n) - 1)
    };
    elevation_of(kind, Some(rid))
}

/// This process's account: DOMAIN\user and its SID string.
pub fn account() -> Account {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, LookupAccountSidW, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut out = Account::default();
    let mut tok: HANDLE = std::ptr::null_mut();
    // SAFETY: the current process's token, query only; closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) } == 0 {
        return out;
    }
    let mut need = 0u32;
    // SAFETY: a size query, then a buffer of that size (u64-aligned).
    unsafe { GetTokenInformation(tok, TokenUser, std::ptr::null_mut(), 0, &mut need) };
    let mut tu = vec![0u64; (need as usize).div_ceil(8).max(8)];
    let ok = unsafe { GetTokenInformation(tok, TokenUser, tu.as_mut_ptr().cast(), (tu.len() * 8) as u32, &mut need) } != 0;
    out.elevation = elevation(tok);
    unsafe { CloseHandle(tok) };
    if !ok {
        return out;
    }
    // SAFETY: the buffer holds a TOKEN_USER written above.
    let sid = unsafe { (*(tu.as_ptr() as *const TOKEN_USER)).User.Sid };
    let mut s: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: the SID above; the string is LocalFree'd.
    if unsafe { ConvertSidToStringSidW(sid, &mut s) } != 0 && !s.is_null() {
        unsafe {
            let len = (0..).take_while(|&i| *s.add(i) != 0).count();
            out.sid = String::from_utf16_lossy(std::slice::from_raw_parts(s, len));
            LocalFree(s.cast());
        }
    }
    let (mut name, mut dom) = (vec![0u16; 256], vec![0u16; 256]);
    let (mut nn, mut dn) = (256u32, 256u32);
    let mut use_: SID_NAME_USE = 0;
    // SAFETY: buffers and their sizes in units.
    if unsafe { LookupAccountSidW(std::ptr::null(), sid, name.as_mut_ptr(), &mut nn, dom.as_mut_ptr(), &mut dn, &mut use_) } != 0 {
        out.name = format!("{}\\{}", String::from_utf16_lossy(&dom[..dn as usize]), String::from_utf16_lossy(&name[..nn as usize]));
    }
    out
}

impl Pc for SystemPc {
    fn reg_key(&self, hive: Hive, path: &str) -> Result<Option<RegKey>, String> {
        let Some(k) = open(hive, path, KEY_READ)? else { return Ok(None) };
        let mut out = RegKey { values: Vec::new(), last_write: last_write(&k) };
        let mut name = vec![0u16; 16_384];
        // Value by value: first its name, type and size (no data), then its data. A value too
        // large or unreadable is listed with its problem; it never hides the others. Only a key
        // whose values cannot be listed at all fails as a whole.
        for i in 0..=10_000u32 {
            let mut nlen = name.len() as u32;
            let mut kind = 0u32;
            let mut size = 0u32;
            // SAFETY: a name buffer and its size in units; no data buffer, its size asked for.
            let r = unsafe { RegEnumValueW(k.0, i, name.as_mut_ptr(), &mut nlen, std::ptr::null(), &mut kind, std::ptr::null_mut(), &mut size) };
            match r {
                ERROR_SUCCESS => {}
                ERROR_NO_MORE_ITEMS => return Ok(Some(out)),
                e => return Err(text::os_words(e)),
            }
            out.values.push(value_at(&k, i, name[..nlen as usize].to_vec(), kind, size as usize));
        }
        Ok(Some(out))
    }

    fn reg_value(&self, hive: Hive, path: &str, name: &[u16]) -> Result<Option<(u32, Vec<u8>)>, String> {
        use super::pc::{MAX_VALUE, too_large};
        let Some(k) = open(hive, path, KEY_QUERY_VALUE)? else { return Ok(None) };
        let n = text::nul(name);
        let mut data = vec![0u8; 4096];
        loop {
            let mut kind = 0u32;
            let mut len = data.len() as u32;
            // SAFETY: a NUL-terminated name; a buffer and its size in bytes.
            let r = unsafe { RegQueryValueExW(k.0, n.as_ptr(), std::ptr::null(), &mut kind, data.as_mut_ptr(), &mut len) };
            match r {
                // The scan's size rule (`fits`), so a value the scan reads is one a change reads.
                ERROR_SUCCESS if !fits(kind, len as usize) => return Err(too_large(len as usize)),
                ERROR_SUCCESS => return Ok(Some((kind, data[..len as usize].to_vec()))),
                ERROR_MORE_DATA if (len as usize) <= ROOM && data.len() < ROOM => data = vec![0u8; (len as usize).max(data.len() * 2).min(ROOM)],
                ERROR_MORE_DATA => return Err(too_large((len as usize).max(MAX_VALUE + 1))),
                ERROR_FILE_NOT_FOUND => return Ok(None),
                e => return Err(text::os_words(e)),
            }
        }
    }

    fn reg_last_write(&self, hive: Hive, path: &str) -> Result<Option<u64>, String> {
        Ok(open(hive, path, KEY_QUERY_VALUE)?.and_then(|k| last_write(&k)))
    }

    fn reg_set_binary(&self, hive: Hive, path: &str, name: &[u16], data: &[u8]) -> Result<(), String> {
        let w = text::wide(path);
        let mut k: HKEY = std::ptr::null_mut();
        // SAFETY: a NUL-terminated path; the handle is ours.
        let r = unsafe { RegCreateKeyExW(root(hive), w.as_ptr(), 0, std::ptr::null(), 0, KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_WOW64_64KEY, std::ptr::null(), &mut k, std::ptr::null_mut()) };
        if r != ERROR_SUCCESS {
            return Err(text::os_words(r));
        }
        let k = Key(k);
        let n = text::nul(name);
        // SAFETY: a NUL-terminated name and the bytes with their length.
        let r = unsafe { RegSetValueExW(k.0, n.as_ptr(), 0, REG_BINARY, data.as_ptr(), data.len() as u32) };
        if r == ERROR_SUCCESS { Ok(()) } else { Err(text::os_words(r)) }
    }

    fn startup_folder(&self, common: bool) -> Option<PathBuf> {
        use windows_sys::Win32::UI::Shell::{FOLDERID_CommonStartup, FOLDERID_Startup};
        known_folder(if common { &FOLDERID_CommonStartup } else { &FOLDERID_Startup })
    }

    fn list_dir(&self, dir: &Path) -> Result<Option<Vec<DirItem>>, String> {
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::fs::MetadataExt;
        let d = dir.to_path_buf();
        let read = move || -> Result<Option<Vec<DirItem>>, String> {
            let rd = match std::fs::read_dir(&d) {
                Ok(r) => r,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(text::clean(&e.to_string())),
            };
            let mut out = Vec::new();
            for e in rd.take(5_000) {
                let e = e.map_err(|e| text::clean(&e.to_string()))?;
                let m = e.metadata().ok();
                out.push(DirItem {
                    name: e.file_name().encode_wide().collect(),
                    dir: m.as_ref().is_some_and(|m| m.is_dir()),
                    hidden: m.as_ref().is_some_and(|m| m.file_attributes() & 0x2 != 0),
                    created: m.as_ref().map(|m| m.creation_time()).filter(|&c| c != 0),
                });
            }
            Ok(Some(out))
        };
        within("folder", dir, FILE_WAIT, read).unwrap_or_else(|l| Err(l.words("the folder did not answer within 3 s")))
    }

    fn lnk(&self, path: &Path) -> Result<Lnk, String> {
        let p = path.to_path_buf();
        within("shortcut", path, LNK_WAIT, move || super::lnk::read(&p)).unwrap_or_else(|l| Err(l.words("the shortcut did not answer within 10 s")))
    }

    fn file(&self, path: &Path) -> FileFacts {
        if !path.is_absolute() {
            return FileFacts { state: FileState::Unknown("not a full path (Windows looks for it on its search path)".into()), ..FileFacts::default() };
        }
        if left_unopened(self, path) {
            return FileFacts { state: FileState::Unknown(NOT_LOCAL.into()), ..FileFacts::default() };
        }
        let p = path.to_path_buf();
        within("identity", path, FILE_WAIT, move || file_now(&p)).unwrap_or_else(|l| FileFacts { state: FileState::Unknown(l.words(super::pc::LATE_IDENTITY)), ..FileFacts::default() })
    }

    fn file_bytes(&self, path: &Path) -> Result<Option<super::pc::FileBytes>, String> {
        if !path.is_absolute() {
            return Err("not a full path".into());
        }
        if left_unopened(self, path) {
            return Err(NOT_LOCAL.into());
        }
        let (a, b) =(path.to_path_buf(), path.to_path_buf());
        bytes_within(path, FILE_WAIT, move || file_now(&a), move |stop| bytes_now(&b, stop))
    }

    fn exists(&self, path: &Path) -> bool {
        // Not asked of another computer (X15PRV-1): as a share that does not answer.
        if left_unopened(self, path) {
            return false;
        }
        let p = path.to_path_buf();
        within("exists", path, FILE_WAIT, move || p.is_file()).unwrap_or(false)
    }

    fn services(&self) -> Result<super::pc::ServiceList, String> {
        super::services::sys::all()
    }

    fn service(&self, name: &str) -> Result<Option<Service>, String> {
        super::services::sys::one(name)
    }

    fn set_service_start(&self, name: &str, start: u32, delayed: bool) -> Result<(), String> {
        super::services::sys::set_start(name, start, delayed)
    }

    fn tasks(&self) -> Result<(Vec<TaskRaw>, Vec<String>), String> {
        super::tasks::sys::all()
    }

    fn task(&self, path: &str) -> Result<Option<TaskRaw>, String> {
        super::tasks::sys::one(path)
    }

    fn set_task_enabled(&self, path: &str, on: bool) -> Result<(), String> {
        super::tasks::sys::set_enabled(path, on)
    }

    fn sign(&self, path: &Path) -> (SignInfo, Option<FileKey>) {
        if left_unopened(self, path) {
            return (SignInfo { signer: super::Signer::Unknown(NOT_LOCAL.into()), company: None }, None);
        }
        let p = path.to_path_buf();
        sign_within(path, SIGN_WAIT, move || super::signer::check(&p))
    }

    fn env(&self, name: &str) -> Option<String> {
        std::env::var_os(name).map(|v| v.to_string_lossy().into_owned())
    }

    fn sys_dirs(&self) -> Vec<PathBuf> {
        [sys_dir(false), sys_dir(true)].into_iter().flatten().collect()
    }

    fn machine_guid(&self) -> Option<String> {
        let name: Vec<u16> = "MachineGuid".encode_utf16().collect();
        let (kind, data) = self.reg_value(Hive::Machine, r"SOFTWARE\Microsoft\Cryptography", &name).ok()??;
        let g = super::pc::reg_text(kind, &data)?.trim().to_ascii_lowercase();
        (g.len() >= 8 && g.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')).then_some(g)
    }

    fn account(&self) -> Account {
        account()
    }

    fn now(&self) -> u64 {
        ft_now()
    }

    fn local_to_unix(&self, y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> Option<i64> {
        use windows_sys::Win32::Foundation::SYSTEMTIME;
        use windows_sys::Win32::System::Time::{SystemTimeToFileTime, TzSpecificLocalTimeToSystemTime};
        let local = SYSTEMTIME { wYear: y as u16, wMonth: mo as u16, wDayOfWeek: 0, wDay: d as u16, wHour: h as u16, wMinute: mi as u16, wSecond: s as u16, wMilliseconds: 0 };
        let mut utc: SYSTEMTIME = unsafe { std::mem::zeroed() };
        let mut ft = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        // SAFETY: plain structs in and out.
        let ok = unsafe { TzSpecificLocalTimeToSystemTime(std::ptr::null(), &local, &mut utc) != 0 && SystemTimeToFileTime(&utc, &mut ft) != 0 };
        if !ok {
            return None;
        }
        super::dates::unix_from_filetime((u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime))
    }
}
