//! A scripted PC: registry, files, shortcuts, services, tasks and signers in memory. The scan and
//! the switches run on it in the unit tests and the window tests (nothing on the PC the tests run
//! on is read or changed). In the library, not under `cfg(test)`, so the window tests (a separate
//! crate) can use it; LTO drops it from the exe.

use super::pc::{Account, DirItem, FileBytes, FileFacts, Lnk, Pc, RegKey, RegVal, Service, TaskRaw};
use super::{FileKey, FileState, Hive, SignInfo, Signer};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// How long a held file's bytes are waited for (`hold_bytes`): `sys::FILE_WAIT`, shortened so
/// the tests stay quick.
pub const HELD_WAIT: Duration = Duration::from_millis(300);

#[derive(Clone, Debug, Default)]
struct Key {
    values: Vec<RegVal>,
    last_write: u64,
}

#[derive(Clone, Debug)]
struct File {
    created: u64,
    key: FileKey,
    /// Its bytes; None for a file over `pc::MAX_CONTENT`.
    data: Option<Vec<u8>>,
    /// Its bytes cannot be read, and why (it can be listed and its attributes read, not opened for
    /// reading: `deny_bytes`, `hold_exclusive`).
    unreadable: Option<String>,
}

/// What `on` runs when its event comes: the event, how many of them to let pass first, the action.
type Hook = (&'static str, usize, Box<dyn FnOnce(&FakePc) + Send>);

#[derive(Default)]
pub struct FakePc {
    keys: Mutex<HashMap<(Hive, String), Key>>,
    key_errors: Mutex<HashMap<(Hive, String), String>>,
    files: Mutex<HashMap<String, (PathBuf, File)>>,
    dirs: Mutex<HashMap<String, PathBuf>>,
    /// Paths under these prefixes answer nothing: Unknown, after `slow` (a dead share).
    dead: Mutex<Vec<String>>,
    slow: Mutex<Duration>,
    lnks: Mutex<HashMap<String, Result<Lnk, String>>>,
    /// Files whose bytes cannot be opened while their flag is set (`hold_bytes`).
    held: Mutex<HashMap<String, std::sync::Arc<std::sync::atomic::AtomicBool>>>,
    /// Files whose bytes each open waits this long for (`lag_bytes`).
    lag: Mutex<HashMap<String, Duration>>,
    /// Files whose identity each read waits this long for (`lag_identity`).
    lag_ident: Mutex<HashMap<String, Duration>>,
    /// Files whose signer check takes this long (`lag_sign`).
    lag_sign: Mutex<HashMap<String, Duration>>,
    services:Mutex<Vec<Service>>,
    services_error: Mutex<Option<String>>,
    /// Services the list names but whose settings could not be read.
    pub unread_services: Mutex<Vec<(String, String)>>,
    tasks: Mutex<Vec<TaskRaw>>,
    /// What the task walk could not read (a folder's list, a task).
    pub unread_tasks: Mutex<Vec<String>>,
    tasks_error: Mutex<Option<String>>,
    signers: Mutex<HashMap<String, SignInfo>>,
    pub startup_user: Mutex<Option<PathBuf>>,
    pub startup_common: Mutex<Option<PathBuf>>,
    pub guid: Mutex<Option<String>>,
    pub now: Mutex<u64>,
    pub account: Mutex<Account>,
    /// Local time minus UTC, seconds (a task's registration date is local time).
    pub tz: Mutex<i64>,
    fail_writes: Mutex<Option<String>>,
    writes: AtomicUsize,
    /// The signer reports another file identity than the scan read (a file swapped between).
    pub swap_on_sign: std::sync::atomic::AtomicBool,
    /// A service write's second half (the delayed flag) fails with this.
    pub fail_delayed: Mutex<Option<String>>,
    /// How many signer checks were asked for.
    pub signs: AtomicUsize,
    /// How many of them were asked for outside any step (`sys::Step`, RB5-3: the window's batch
    /// of signer checks and a change's lock each wait one step's budget in all).
    pub signs_outside_step: AtomicUsize,
    /// Every change made, in order ("set HKCU ...\Run\Updater", "task \Up off").
    pub log: Mutex<Vec<String>>,
    next_id: AtomicUsize,
    /// Registry strings come back as Windows' two calls hand them over into `SystemPc`'s buffers
    /// (RB-1, RB2-7): `reg_key` into `enum_buf`, `reg_value` into `query_buf` (`read_shape`).
    pub windows_reads: std::sync::atomic::AtomicBool,
    hooks: Mutex<Vec<Hook>>,
}

fn low(s: &str) -> String {
    s.to_lowercase()
}

fn lowp(p: &Path) -> String {
    low(&p.to_string_lossy()).trim_end_matches('\\').to_string()
}

fn eq_name(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| fold(*x) == fold(*y))
}

fn fold(u: u16) -> u16 {
    if (u16::from(b'A')..=u16::from(b'Z')).contains(&u) { u + 32 } else { u }
}

/// A task's XML after its switch, as Task Scheduler writes it: `Settings/Enabled` says the new
/// state (put in, on its own indented line, where there was none). A task without `<Settings>`
/// is left as it is.
fn with_enabled(xml: &str, on: bool) -> String {
    let Some(i) = xml.find("<Settings>") else { return xml.to_string() };
    let at = i + "<Settings>".len();
    let mut rest = xml[at..].to_string();
    for old in ["\n    <Enabled>true</Enabled>", "\n    <Enabled>false</Enabled>"] {
        if rest.starts_with(old) {
            rest = rest[old.len()..].to_string();
        }
    }
    format!("{}\n    <Enabled>{on}</Enabled>{rest}", &xml[..at])
}

fn text_kind(kind: u32) -> bool {
    kind == super::pc::REG_SZ || kind == super::pc::REG_EXPAND_SZ
}

/// A string's bytes as Windows' reads hand them over into a buffer of `buf` bytes (measured live
/// by the reviewer on 26200, rev-boot2 RB2-7): as stored, except that an odd length's last byte
/// comes back zeroed when the buffer has room for a whole NUL after the data (`buf >= len + 2`),
/// whichever call it is. Neither call adds a missing NUL: `RegSetValueExW` adds one when it
/// stores a string, not a read (the fake stores bytes as `NtSetValueKey` does, as given).
pub fn read_shape(kind: u32, data: &[u8], buf: usize) -> Vec<u8> {
    let mut d = data.to_vec();
    if text_kind(kind) && !d.len().is_multiple_of(2) && buf >= d.len() + 2 {
        *d.last_mut().unwrap() = 0;
    }
    d
}

/// The buffer `SystemPc::reg_key` reads a value's data into: the size the listing reported, at
/// least 16 bytes (`sys::value_at`).
pub fn enum_buf(len: usize) -> usize {
    len.max(16)
}

/// The buffer `SystemPc::reg_value` ends with: 4096 bytes, grown to the size asked for or twice
/// as much, at most the cap and the room for a NUL (`sys::reg_value`).
pub fn query_buf(len: usize) -> usize {
    let room = super::pc::MAX_VALUE + 2;
    let mut b = 4096;
    while b < len && b < room {
        b = len.max(b * 2).min(room);
    }
    b
}

/// A value's name as Windows' by-name calls take it: up to its first NUL (RB2-1).
fn c_name(name: &[u16]) -> &[u16] {
    &name[..name.iter().position(|&u| u == 0).unwrap_or(name.len())]
}

pub fn sz(s: &str) -> Vec<u8> {
    s.encode_utf16().chain([0]).flat_map(|u| u.to_le_bytes()).collect()
}

impl FakePc {
    pub fn new() -> FakePc {
        let pc = FakePc::default();
        *pc.startup_user.lock().unwrap() = Some(PathBuf::from(r"C:\Users\ted\Startup"));
        *pc.startup_common.lock().unwrap() = Some(PathBuf::from(r"C:\ProgramData\Startup"));
        *pc.guid.lock().unwrap() = Some("6f1c2a3e-0000-4000-8000-00000000c0de".into());
        // 2026-10-22 12:00 UTC.
        *pc.now.lock().unwrap() = super::dates::filetime_from_unix(1_792_670_400);
        *pc.account.lock().unwrap() = Account { name: r"DESK\ted".into(), sid: "S-1-5-21-1-2-3-1001".into(), elevation: super::pc::Elevation::Split };
        pc.add_dir(r"C:\Users\ted\Startup");
        pc.add_dir(r"C:\ProgramData\Startup");
        pc.add_dir(r"C:\Windows\System32");
        // SYSTEM's hive is always loaded (HKEY_USERS\S-1-5-18).
        pc.reg_key_time(Hive::Users, "S-1-5-18", 1);
        pc
    }

    // ---------- registry ----------

    pub fn reg_put(&self, hive: Hive, path: &str, name: &str, kind: u32, data: Vec<u8>) {
        self.reg_put_units(hive, path, name.encode_utf16().collect(), kind, data);
    }

    pub fn reg_put_units(&self, hive: Hive, path: &str, name: Vec<u16>, kind: u32, data: Vec<u8>) {
        let mut keys = self.keys.lock().unwrap();
        let k = keys.entry((hive, low(path))).or_default();
        k.values.retain(|v| !eq_name(&v.name, &name));
        k.values.push(RegVal { name, kind, data, problem: None });
    }

    /// A value whose data cannot be read (too large, denied): listed with its problem.
    pub fn reg_put_problem(&self, hive: Hive, path: &str, name: &str, kind: u32, why: &str) {
        let name: Vec<u16> = name.encode_utf16().collect();
        let mut keys = self.keys.lock().unwrap();
        let k = keys.entry((hive, low(path))).or_default();
        k.values.retain(|v| !eq_name(&v.name, &name));
        k.values.push(RegVal { name, kind, data: Vec::new(), problem: Some(why.into()) });
    }

    pub fn set_reg_sz(&self, hive: Hive, path: &str, name: &str, text: &str) {
        self.reg_put(hive, path, name, super::pc::REG_SZ, sz(text));
    }

    pub fn reg_get(&self, hive: Hive, path: &str, name: &str) -> Option<(u32, Vec<u8>)> {
        let n: Vec<u16> = name.encode_utf16().collect();
        let keys = self.keys.lock().unwrap();
        keys.get(&(hive, low(path)))?.values.iter().find(|v| eq_name(&v.name, &n)).map(|v| (v.kind, v.data.clone()))
    }

    pub fn reg_delete(&self, hive: Hive, path: &str, name: &str) {
        let n: Vec<u16> = name.encode_utf16().collect();
        if let Some(k) = self.keys.lock().unwrap().get_mut(&(hive, low(path))) {
            k.values.retain(|v| !eq_name(&v.name, &n));
        }
    }

    pub fn reg_key_time(&self, hive: Hive, path: &str, ft: u64) {
        self.keys.lock().unwrap().entry((hive, low(path))).or_default().last_write = ft;
    }

    /// The key cannot be read: every read of it is this error.
    pub fn fail_key(&self, hive: Hive, path: &str, why: &str) {
        self.key_errors.lock().unwrap().insert((hive, low(path)), why.into());
    }

    // ---------- files ----------

    pub fn add_dir(&self, p: &str) {
        let mut dirs = self.dirs.lock().unwrap();
        let mut cur = PathBuf::from(p);
        loop {
            dirs.insert(lowp(&cur), cur.clone());
            if !cur.pop() || cur.as_os_str().is_empty() {
                break;
            }
        }
    }

    pub fn add_file(&self, p: &str) {
        self.add_file_at(p, super::dates::filetime_from_unix(1_700_000_000));
    }

    /// A file created at `created` (FILETIME).
    pub fn add_file_at(&self, p: &str, created: u64) {
        let path = PathBuf::from(p);
        if let Some(parent) = path.parent() {
            self.add_dir(&parent.to_string_lossy());
        }
        let n = self.next_id.fetch_add(1, Ordering::SeqCst) as u8 + 1;
        let key = FileKey { serial: 0xC0DE, id: [n; 16], size: 100, written: created };
        let data = Some(format!("file {n}").into_bytes());
        self.files.lock().unwrap().insert(lowp(&path), (path, File { created, key, data, unreadable: None }));
    }

    /// A file rewritten in place with its identity, size and times put back (only its bytes
    /// change); None: bigger than `pc::MAX_CONTENT`.
    pub fn rewrite_file(&self, p: &str, data: Option<Vec<u8>>) {
        if let Some((_, f)) = self.files.lock().unwrap().get_mut(&lowp(Path::new(p))) {
            f.data = data;
        }
    }

    /// The file can be listed and its facts read, not its bytes: an ACL with execute but no read
    /// (as `SystemPc` reads it: access denied, its identity from a handle for its attributes).
    pub fn deny_bytes(&self, p: &str) {
        self.unreadable(p, Some("Access is denied. (os error 5)"));
    }

    /// Another process holds the file open with share mode 0 (RB2-2): as `deny_bytes`, a sharing
    /// violation. None: it lets go.
    pub fn hold_exclusive(&self, p: &str, held: bool) {
        self.unreadable(p, held.then_some("The process cannot access the file because it is being used by another process. (os error 32)"));
    }

    /// Another program holds an oplock on the file and never acknowledges the break, or it sits
    /// on a share that does not hand its bytes over (RB3-3, RB4-2): every open for its bytes (its
    /// signer check's too) blocks until it lets go (`held` false), whatever it is told; its
    /// attributes still answer. It is read as `SystemPc` reads every file, through
    /// `sys::bytes_within` (`sys::sign_within`), within `HELD_WAIT` and its step's wait.
    pub fn hold_bytes(&self, p: &str, held: bool) {
        let mut all = self.held.lock().unwrap();
        all.entry(lowp(Path::new(p))).or_insert_with(|| std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false))).store(held, Ordering::SeqCst);
    }

    /// As `hold_bytes`, but the holder lets go `lag` after each open (RB5-1: it acknowledges the
    /// break just after VibeBoot gave up on it, so no read of it stays out).
    pub fn lag_bytes(&self, p: &str, lag: Duration) {
        self.lag.lock().unwrap().insert(lowp(Path::new(p)), lag);
    }

    /// Every read of the file's identity (alone, or before its bytes) answers after `lag`, read as
    /// `SystemPc` reads it: through `sys::within`, within `HELD_WAIT` and its step's wait (RB6-2:
    /// a slow share; `Duration::ZERO`: a file that answers at once, but is read that way).
    pub fn lag_identity(&self, p: &str, lag: Duration) {
        self.lag_ident.lock().unwrap().insert(lowp(Path::new(p)), lag);
    }

    /// The file's signer check answers after `lag`, as `SystemPc` checks it: through
    /// `sys::sign_within`, within `sys::SIGN_WAIT` and its step's wait (RB6-4).
    pub fn lag_sign(&self, p: &str, lag: Duration) {
        self.lag_sign.lock().unwrap().insert(lowp(Path::new(p)), lag);
    }

    fn unreadable(&self, p: &str, why: Option<&str>) {
        if let Some((_, f)) = self.files.lock().unwrap().get_mut(&lowp(Path::new(p))) {
            f.unreadable = why.map(str::to_string);
        }
    }

    /// Run `f` when the `skip + 1`-th `event` comes ("sign", "task", "service": at the start of
    /// that call), as something else on the PC would at that moment.
    pub fn on(&self, event: &'static str, skip: usize, f: impl FnOnce(&FakePc) + Send + 'static) {
        self.hooks.lock().unwrap().push((event, skip, Box::new(f)));
    }

    fn hook(&self, event: &str) {
        let due = {
            let mut hooks = self.hooks.lock().unwrap();
            match hooks.iter().position(|h| h.0 == event) {
                Some(i) if hooks[i].1 == 0 => Some(hooks.remove(i).2),
                Some(i) => {
                    hooks[i].1 -= 1;
                    None
                }
                None => None,
            }
        };
        if let Some(f) = due {
            f(self);
        }
    }

    pub fn remove_file(&self, p: &str) {
        self.files.lock().unwrap().remove(&lowp(Path::new(p)));
    }

    /// Paths under `prefix` do not answer (a disconnected share): Unknown after `slow`.
    pub fn dead_prefix(&self, prefix: &str, slow: Duration) {
        self.dead.lock().unwrap().push(low(prefix));
        *self.slow.lock().unwrap() = slow;
    }

    fn dead(&self, p: &Path) -> bool {
        let l = lowp(p);
        let dead = self.dead.lock().unwrap().iter().any(|d| l.starts_with(d.as_str()));
        if dead {
            std::thread::sleep(*self.slow.lock().unwrap());
        }
        dead
    }

    /// A read of a dead path as `SystemPc` makes it (RB5-1): on its own thread through
    /// `sys::within`, within `HELD_WAIT` and its step's wait; it answers after `slow`.
    fn dead_read<T: Send + 'static>(&self, what: &'static str, p: &Path, answer: T, late: impl FnOnce(super::sys::Late) -> T) -> Option<T> {
        let l = lowp(p);
        if !self.dead.lock().unwrap().iter().any(|d| l.starts_with(d.as_str())) {
            return None;
        }
        let slow = *self.slow.lock().unwrap();
        Some(super::sys::within(what, p, HELD_WAIT, move || {
            std::thread::sleep(slow);
            answer
        }).unwrap_or_else(late))
    }

    pub fn set_lnk(&self, p: &str, l: Result<Lnk, String>) {
        self.add_file(p);
        self.lnks.lock().unwrap().insert(lowp(Path::new(p)), l);
    }

    /// A shortcut rewritten in place with its identity, size and times put back (only what it
    /// says changes).
    pub fn rewrite_lnk(&self, p: &str, l: Result<Lnk, String>) {
        self.lnks.lock().unwrap().insert(lowp(Path::new(p)), l);
    }

    /// A file's identity reads as zero (a file system that has none): unknown.
    pub fn zero_file_id(&self, p: &str) {
        if let Some((_, f)) = self.files.lock().unwrap().get_mut(&lowp(Path::new(p))) {
            f.key.id = [0; 16];
        }
    }

    pub fn set_signer(&self, p: &str, s: Signer) {
        self.set_sign(p, SignInfo { signer: s, company: None });
    }

    pub fn set_sign(&self, p: &str, s: SignInfo) {
        self.signers.lock().unwrap().insert(lowp(Path::new(p)), s);
    }

    // ---------- services and tasks ----------

    pub fn add_service(&self, s: Service) {
        let mut v = self.services.lock().unwrap();
        v.retain(|x| !x.name.eq_ignore_ascii_case(&s.name));
        v.push(s);
    }

    pub fn remove_service(&self, name: &str) {
        self.services.lock().unwrap().retain(|x| !x.name.eq_ignore_ascii_case(name));
    }

    pub fn fail_services(&self, why: &str) {
        *self.services_error.lock().unwrap() = Some(why.into());
    }

    pub fn add_task(&self, t: TaskRaw) {
        let mut v = self.tasks.lock().unwrap();
        v.retain(|x| !x.path.eq_ignore_ascii_case(&t.path));
        v.push(t);
    }

    pub fn fail_tasks(&self, why: &str) {
        *self.tasks_error.lock().unwrap() = Some(why.into());
    }

    // ---------- writes ----------

    /// Every write from now on fails with `why`.
    pub fn fail_writes(&self, why: &str) {
        *self.fail_writes.lock().unwrap() = Some(why.into());
    }

    pub fn allow_writes(&self) {
        *self.fail_writes.lock().unwrap() = None;
    }

    pub fn writes(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }

    fn write(&self, what: String) -> Result<(), String> {
        if let Some(e) = self.fail_writes.lock().unwrap().clone() {
            return Err(e);
        }
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.log.lock().unwrap().push(what);
        Ok(())
    }

    /// A file's facts as the fake keeps them (no lag, no dead share).
    fn file_now(&self, path: &Path) -> FileFacts {
        if !path.is_absolute() && !path.to_string_lossy().starts_with(r"\\") { // offpc-ok: the fake tells shares from local paths
            return FileFacts { state: FileState::Unknown("not a full path".into()), ..FileFacts::default() };
        }
        if let Some((_, f)) = self.files.lock().unwrap().get(&lowp(path)) {
            return FileFacts { state: FileState::Present, created: Some(f.created), key: Some(f.key) };
        }
        // As SystemPc: missing when the nearest folder above that exists answers; unknown when no
        // folder up to the root is there (a drive that is not there).
        let dirs = self.dirs.lock().unwrap();
        let answers = path.ancestors().skip(1).any(|p| !p.as_os_str().is_empty() && dirs.contains_key(&lowp(p)));
        FileFacts { state: if answers { FileState::Missing } else { FileState::Unknown("its drive or share is not there".into()) }, ..FileFacts::default() }
    }

    /// A file's bytes as the fake keeps them (no lagged identity).
    fn bytes_now(&self, path: &Path) -> Result<Option<FileBytes>, String> {
        if self.dead(path) {
            return Err("its folder did not answer".into());
        }
        use super::pc::Content;
        let held = self.held.lock().unwrap().get(&lowp(path)).cloned().filter(|h| h.load(Ordering::SeqCst));
        if let Some(h) = held {
            // As `SystemPc` reads it: the identity answers, the open for its bytes waits for the
            // holder (told to stop or not), all within the time limit.
            let facts = self.file(path);
            let key = facts.key;
            return super::sys::bytes_within(path, HELD_WAIT, move || facts, move |_| {
                while h.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(Some(FileBytes { key, content: Content::Unreadable("let go".into()) }))
            });
        }
        let lag = self.lag.lock().unwrap().get(&lowp(path)).copied();
        if let Some(lag) = lag {
            let facts = self.file(path);
            let key = facts.key;
            return super::sys::bytes_within(path, HELD_WAIT, move || facts, move |_| {
                std::thread::sleep(lag);
                Ok(Some(FileBytes { key, content: Content::Unreadable("let go".into()) }))
            });
        }
        Ok(self.files.lock().unwrap().get(&lowp(path)).map(|(_, f)| {
            let content = match (&f.unreadable, &f.data) {
                (Some(why), _) => Content::Unreadable(why.clone()),
                (None, None) => Content::OverCap,
                (None, Some(b)) => {
                    let mut sha = super::def::Sha256::new();
                    sha.update(b);
                    Content::Digest(sha.finish())
                }
            };
            FileBytes { key: Some(f.key), content }
        }))
    }
}

impl Pc for FakePc {
    fn reg_key(&self, hive: Hive, path: &str) -> Result<Option<RegKey>, String> {
        if let Some(e) = self.key_errors.lock().unwrap().get(&(hive, low(path))) {
            return Err(e.clone());
        }
        let windows = self.windows_reads.load(Ordering::SeqCst);
        Ok(self.keys.lock().unwrap().get(&(hive, low(path))).map(|k| RegKey {
            values: k.values.iter().map(|v| if windows && v.problem.is_none() { RegVal { data: read_shape(v.kind, &v.data, enum_buf(v.data.len())), ..v.clone() } } else { v.clone() }).collect(),
            last_write: (k.last_write != 0).then_some(k.last_write),
        }))
    }

    fn reg_value(&self, hive: Hive, path: &str, name: &[u16]) -> Result<Option<(u32, Vec<u8>)>, String> {
        if let Some(e) = self.key_errors.lock().unwrap().get(&(hive, low(path))) {
            return Err(e.clone());
        }
        let windows = self.windows_reads.load(Ordering::SeqCst);
        // As `RegQueryValueExW`: the name ends at its first NUL.
        let name = c_name(name);
        let keys = self.keys.lock().unwrap();
        let Some(v) = keys.get(&(hive, low(path))).and_then(|k| k.values.iter().find(|v| eq_name(&v.name, name))) else { return Ok(None) };
        // A value that cannot be read is an error, as `SystemPc::reg_value` says one past its cap.
        if let Some(why) = &v.problem {
            return Err(why.clone());
        }
        Ok(Some((v.kind, if windows { read_shape(v.kind, &v.data, query_buf(v.data.len())) } else { v.data.clone() })))
    }

    fn reg_last_write(&self, hive: Hive, path: &str) -> Result<Option<u64>, String> {
        if let Some(e) = self.key_errors.lock().unwrap().get(&(hive, low(path))) {
            return Err(e.clone());
        }
        Ok(self.keys.lock().unwrap().get(&(hive, low(path))).map(|k| k.last_write))
    }

    fn reg_set_binary(&self, hive: Hive, path: &str, name: &[u16], data: &[u8]) -> Result<(), String> {
        // As `RegSetValueExW`: the name ends at its first NUL.
        let name = c_name(name);
        self.write(format!("set {} {path}\\{}", hive.name(), String::from_utf16_lossy(name)))?;
        self.reg_put_units(hive, path, name.to_vec(), super::approved::REG_BINARY, data.to_vec());
        Ok(())
    }

    fn startup_folder(&self, common: bool) -> Option<PathBuf> {
        if common { self.startup_common.lock().unwrap().clone() } else { self.startup_user.lock().unwrap().clone() }
    }

    fn list_dir(&self, dir: &Path) -> Result<Option<Vec<DirItem>>, String> {
        if self.dead(dir) {
            return Err("the folder did not answer".into());
        }
        let d = lowp(dir);
        if !self.dirs.lock().unwrap().contains_key(&d) {
            return Ok(None);
        }
        use std::os::windows::ffi::OsStrExt;
        let mut out: Vec<DirItem> = Vec::new();
        for (l, (p, f)) in self.files.lock().unwrap().iter() {
            if Path::new(l).parent().map(lowp) == Some(d.clone()) {
                out.push(DirItem { name: p.file_name().unwrap().encode_wide().collect(), dir: false, hidden: false, created: Some(f.created) });
            }
        }
        for (l, p) in self.dirs.lock().unwrap().iter() {
            if Path::new(l).parent().map(lowp) == Some(d.clone()) && *l != d {
                out.push(DirItem { name: p.file_name().unwrap_or_default().encode_wide().collect(), dir: true, hidden: false, created: None });
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Some(out))
    }

    fn lnk(&self, path: &Path) -> Result<Lnk, String> {
        self.lnks.lock().unwrap().get(&lowp(path)).cloned().unwrap_or_else(|| Err("not a shortcut Windows can read".into()))
    }

    fn file(&self, path: &Path) -> FileFacts {
        let gone = FileFacts { state: FileState::Unknown("its folder did not answer (a share or drive that is not there)".into()), ..FileFacts::default() };
        if let Some(f) = self.dead_read("identity", path, gone, |l| FileFacts { state: FileState::Unknown(l.words(super::pc::LATE_IDENTITY)), ..FileFacts::default() }) {
            return f;
        }
        let lag = self.lag_ident.lock().unwrap().get(&lowp(path)).copied();
        if let Some(lag) = lag {
            let facts = self.file_now(path);
            return super::sys::within("identity", path, HELD_WAIT, move || {
                std::thread::sleep(lag);
                facts
            })
            .unwrap_or_else(|l| FileFacts { state: FileState::Unknown(l.words(super::pc::LATE_IDENTITY)), ..FileFacts::default() });
        }
        self.file_now(path)
    }

    fn file_bytes(&self, path: &Path) -> Result<Option<FileBytes>, String> {
        let lag = self.lag_ident.lock().unwrap().get(&lowp(path)).copied();
        if let Some(lag) = lag {
            // As `SystemPc` reads it: its identity first (late: unknown), then its bytes.
            let facts = self.file_now(path);
            let bytes = self.bytes_now(path);
            return super::sys::bytes_within(
                path,
                HELD_WAIT,
                move || {
                    std::thread::sleep(lag);
                    facts
                },
                move |_| bytes,
            );
        }
        self.bytes_now(path)
    }

    fn exists(&self, path: &Path) -> bool {
        if let Some(b) = self.dead_read("exists", path, false, |_| false) {
            return b;
        }
        self.files.lock().unwrap().contains_key(&lowp(path))
    }

    fn services(&self) -> Result<super::pc::ServiceList, String> {
        if let Some(e) = self.services_error.lock().unwrap().clone() {
            return Err(e);
        }
        Ok((self.services.lock().unwrap().clone(), self.unread_services.lock().unwrap().clone()))
    }

    fn service(&self, name: &str) -> Result<Option<Service>, String> {
        self.hook("service");
        if let Some(e) = self.services_error.lock().unwrap().clone() {
            return Err(e);
        }
        Ok(self.services.lock().unwrap().iter().find(|s| s.name.eq_ignore_ascii_case(name)).cloned())
    }

    fn set_service_start(&self, name: &str, start: u32, delayed: bool) -> Result<(), String> {
        self.write(format!("service {name} {start} {delayed}"))?;
        let half = self.fail_delayed.lock().unwrap().clone();
        match self.services.lock().unwrap().iter_mut().find(|s| s.name.eq_ignore_ascii_case(name)) {
            Some(s) => {
                // ChangeServiceConfigW writes Start under the service's key: its last write moves.
                let now = *self.now.lock().unwrap();
                self.reg_key_time(Hive::Machine, &format!(r"{}\{}", super::services::SERVICES_KEY, s.name), now);
                s.start = start;
                // The second of the two writes (the delayed flag) fails: the start type changed.
                if let Some(e) = half {
                    return Err(e);
                }
                s.delayed = delayed;
            }
            None => return Err("The specified service does not exist as an installed service.".into()),
        }
        Ok(())
    }

    fn tasks(&self) -> Result<(Vec<TaskRaw>, Vec<String>), String> {
        if let Some(e) = self.tasks_error.lock().unwrap().clone() {
            return Err(e);
        }
        Ok((self.tasks.lock().unwrap().clone(), self.unread_tasks.lock().unwrap().clone()))
    }

    fn task(&self, path: &str) -> Result<Option<TaskRaw>, String> {
        self.hook("task");
        if let Some(e) = self.tasks_error.lock().unwrap().clone() {
            return Err(e);
        }
        Ok(self.tasks.lock().unwrap().iter().find(|t| t.path.eq_ignore_ascii_case(path)).cloned())
    }

    fn set_task_enabled(&self, path: &str, on: bool) -> Result<(), String> {
        self.write(format!("task {path} {}", if on { "on" } else { "off" }))?;
        match self.tasks.lock().unwrap().iter_mut().find(|t| t.path.eq_ignore_ascii_case(path)) {
            Some(t) => {
                t.enabled = on;
                t.state = if on { 3 } else { 1 };
                t.xml = with_enabled(&t.xml, on);
            }
            None => return Err("The system cannot find the file specified.".into()),
        }
        Ok(())
    }

    fn sign(&self, path: &Path) -> (SignInfo, Option<FileKey>) {
        self.hook("sign");
        self.signs.fetch_add(1, Ordering::SeqCst);
        if !super::sys::in_step() {
            self.signs_outside_step.fetch_add(1, Ordering::SeqCst);
        }
        let held = self.held.lock().unwrap().get(&lowp(path)).cloned().filter(|h| h.load(Ordering::SeqCst));
        if let Some(h) = held {
            // A held file's signer check opens it for its bytes too (RB5-3): as `SystemPc` checks
            // it, within `HELD_WAIT` and its step's wait; it answers once let go.
            return super::sys::sign_within(path, HELD_WAIT, move || {
                while h.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                (SignInfo { signer: Signer::NotSigned, company: None }, None)
            });
        }
        let facts = self.file(path);
        // The file a signer opens may have been replaced since the scan: `swap_on_sign` hands
        // back another identity, as a file swapped between the two would.
        let key = if self.swap_on_sign.load(Ordering::SeqCst) { facts.key.map(|k| FileKey { written: k.written + 1, ..k }) } else { facts.key };
        let lag = self.lag_sign.lock().unwrap().get(&lowp(path)).copied();
        if let Some(lag) = lag {
            let s = self.signers.lock().unwrap().get(&lowp(path)).cloned().unwrap_or(SignInfo { signer: Signer::NotSigned, company: None });
            return super::sys::sign_within(path, super::sys::SIGN_WAIT, move || {
                std::thread::sleep(lag);
                (s, key)
            });
        }
        if let Some(s) = self.signers.lock().unwrap().get(&lowp(path)) {
            return (s.clone(), key);
        }
        let signer = match facts.state {
            FileState::Present => Signer::NotSigned,
            FileState::Missing => Signer::Missing,
            FileState::Unknown(e) => Signer::Unknown(e),
            FileState::NoTarget => Signer::Unknown("no file".into()),
        };
        (SignInfo { signer, company: None }, key)
    }

    fn env(&self, name: &str) -> Option<String> {
        Some(
            match name.to_ascii_lowercase().as_str() {
                "systemroot" | "windir" => r"C:\Windows",
                "programfiles" => r"C:\Program Files",
                "programfiles(x86)" => r"C:\Program Files (x86)",
                "programdata" => r"C:\ProgramData",
                "appdata" => r"C:\Users\ted\AppData\Roaming",
                "localappdata" => r"C:\Users\ted\AppData\Local",
                "userprofile" => r"C:\Users\ted",
                _ => return None,
            }
            .to_string(),
        )
    }

    fn sys_dirs(&self) -> Vec<PathBuf> {
        vec![PathBuf::from(r"C:\Windows\System32"), PathBuf::from(r"C:\Windows")]
    }

    fn machine_guid(&self) -> Option<String> {
        self.guid.lock().unwrap().clone()
    }

    fn account(&self) -> Account {
        self.account.lock().unwrap().clone()
    }

    fn now(&self) -> u64 {
        *self.now.lock().unwrap()
    }

    fn local_to_unix(&self, y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> Option<i64> {
        Some(super::dates::unix_at((y, mo, d, h, mi, s), *self.tz.lock().unwrap()))
    }
}
