//! The admin steps, in a short-lived helper (VibeLink's pattern). The app never runs elevated
//! (started elevated anyway, every admin step still goes through here: there is no second code
//! path). Each step is one named job:
//!
//! | job            | items (at most 64)                                   | limit |
//! |----------------|------------------------------------------------------|-------|
//! | `scan-tasks`   | none: every task's path, state, last run and XML     | 60 s  |
//! | `startup-set`  | HKLM Run / Run32 value or common startup file        | 20 s  |
//! | `task-set`     | a task's enabled flag                                | 20 s  |
//! | `service-start`| a non-Microsoft service's start type (Auto ↔ Manual) | 20 s  |
//! | `task-undo`    | the Journal Undo of a task's change (`records`)      | 20 s  |
//!
//! The app creates the pipe first: `\\.\pipe\vibeboot-<128-bit random, lower-case hex>`, duplex,
//! overlapped, first instance only, byte mode, remote clients rejected, one instance, a DACL with
//! the current user's SID only. Then it relaunches its own exe from its final path
//! (`GetFinalPathNameByHandleW`, VibeLink R-LINK-1) with `ShellExecuteExW` verb `runas`, the window
//! as owner: `VibeBoot.exe --helper <job> <pipe>`. One UAC prompt per job; declining changes
//! nothing. Both ends check each other: the client must be the PID ShellExecuteEx returned,
//! running this exe (compared by `FILE_ID_INFO`, a zero identity never "the same"); the helper
//! connects with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` and checks the server the
//! same way.
//!
//! The helper refuses to run unelevated (exit 3), with a job not in the table or a malformed pipe
//! or request (exit 2), or with the wrong server (exit 5); its watchdog ends it at the job's hard
//! limit (exit 4); a broken pipe ends it at once. It reads one request, checks every item against
//! its own fresh read (`autostart::switch::apply`), does the job and sends a result per item.
//! It records every task switch-off it makes in its own admin-only records (`crate::records`,
//! `HKLM\SOFTWARE\VibeBoot`); only such a record lets a `task-undo` switch back on a task that
//! reads as Windows' own.
//! Every item carries the entry's definition digest as the app's list read it (32 bytes,
//! `autostart::def`): an entry replaced under the same name since is refused, never changed.
//! Wire: kind (1 byte), length (u32 LE, capped per kind), payload; strict on both ends, and the
//! app treats every byte from the pipe as untrusted. Every message after Hello carries the job's
//! epoch; one for another epoch breaks the stream. No job takes a free path or command.

use crate::autostart::def::Def;
use crate::autostart::pc::{Pc, TaskRaw};
use crate::autostart::switch::{self, Data, Outcome, Request};
use crate::autostart::taskxml::MAX_XML;
use crate::autostart::tasks::{MAX_TASKS, MAX_UNREAD};
use crate::autostart::{Ident, Location};
use crate::records::{self, Store};
use std::time::Duration;

pub const PIPE_PREFIX: &str = r"\\.\pipe\vibeboot-";
/// How long the app waits for the helper to connect (the UAC prompt may sit there).
pub const CONNECT_WAIT: Duration = Duration::from_secs(120);
pub const MAX_ITEMS: usize = 64;
/// The longest result text.
pub const MAX_TEXT: usize = 512;

/// `Job`, `Job::ALL` and each job's `--helper` name from one list (review RRC-2), so `ALL` can't
/// miss a job: `from_name`, `from_code` and the tests all go through it. A variant outside the
/// list does not compile (`name` has no arm for it).
macro_rules! jobs {
    ($($(#[$doc:meta])* $job:ident => $name:literal,)+) => {
        /// The jobs, and nothing else.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum Job {
            $($(#[$doc])* $job,)+
        }

        impl Job {
            pub const ALL: [Job; [$(stringify!($job)),+].len()] = [$(Job::$job),+];

            pub fn name(self) -> &'static str {
                match self {
                    $(Job::$job => $name,)+
                }
            }
        }
    };
}

jobs! {
    ScanTasks => "scan-tasks",
    StartupSet => "startup-set",
    TaskSet => "task-set",
    ServiceStart => "service-start",
    /// The Journal Undo of VibeBoot's own recorded change of a task (RB7-1): as `TaskSet`, except
    /// that switching a task back on that reads as Windows' own since is done by `switch::undo`
    /// (the lock lifted) when the helper holds its own record of switching that task off
    /// (RB8-1, `records`: admin-only, the same task with the same whole definition, used once,
    /// 30 days). The journal is the app's, in a folder the user can write: its word alone never
    /// lifts the lock. Without a record the item is done as `TaskSet` does it.
    TaskUndo => "task-undo",
}

impl Job {
    pub fn from_name(s: &str) -> Option<Job> {
        Job::ALL.into_iter().find(|j| j.name() == s)
    }

    fn code(self) -> u8 {
        match self {
            Job::ScanTasks => 1,
            Job::StartupSet => 2,
            Job::TaskSet => 3,
            Job::ServiceStart => 4,
            Job::TaskUndo => 5,
        }
    }

    fn from_code(c: u8) -> Option<Job> {
        Job::ALL.into_iter().find(|j| j.code() == c)
    }

    /// The helper's hard limit for the job.
    pub fn limit(self) -> Duration {
        match self {
            Job::ScanTasks => Duration::from_secs(60),
            _ => Duration::from_secs(20),
        }
    }

    /// The job a change goes to (None: no admin step for it).
    pub fn for_location(loc: Location) -> Option<Job> {
        match loc {
            Location::RunMachine | Location::RunMachine32 | Location::StartupCommon => Some(Job::StartupSet),
            Location::LogonTask => Some(Job::TaskSet),
            Location::Service => Some(Job::ServiceStart),
            _ => None,
        }
    }

    /// The job a Journal Undo goes to: a task's is `TaskUndo` (RB7-1), any other its change's.
    pub fn for_undo(loc: Location) -> Option<Job> {
        match loc {
            Location::LogonTask => Some(Job::TaskUndo),
            loc => Job::for_location(loc),
        }
    }

    /// Whether the job's items are changes of `loc` (`TaskUndo`'s are a task's).
    fn takes(self, loc: Location) -> bool {
        Job::for_location(loc) == Some(if self == Job::TaskUndo { Job::TaskSet } else { self })
    }

    /// One item of the job, checked and done: a `TaskUndo` that switches its task back on by
    /// `records::undo_on` (the lock lifted only with the helper's own record of that off), every
    /// other item by `switch::apply`. A task switch-off the helper made (either job) is recorded
    /// in `kept` once done; a record that cannot be kept leaves the off done, and its Undo says
    /// there is no record.
    pub fn act(self, pc: &dyn Pc, kept: &dyn Store, r: &Request) -> Outcome {
        if self == Job::TaskUndo && r.new.on() == Some(true) {
            return records::undo_on(pc, kept, r);
        }
        let o = switch::apply(pc, r);
        if matches!(self, Job::TaskSet | Job::TaskUndo) && o == Outcome::Done && r.new.on() == Some(false) {
            let _ = records::keep_off(pc, kept, r);
        }
        o
    }
}

// ---------- the wire ----------

const KIND_HELLO: u8 = 1;
const KIND_REQUEST: u8 = 2;
const KIND_TASK: u8 = 3;
const KIND_ITEM: u8 = 4;
const KIND_DONE: u8 = 5;
const KIND_UNREAD: u8 = 6;

/// Done's codes.
pub mod done {
    pub const OK: u8 = 0;
    pub const BAD_REQUEST: u8 = 1;
    pub const FAILED: u8 = 2;
}

const MAX_PATH_BYTES: usize = 4096;
const CAP_REQUEST: usize = 8 + 1 + 2 + MAX_ITEMS * (1 + 2 + 2 * 1024 + 1 + 12 + 12 + 32);
const CAP_TASK: usize = 8 + 1 + 4 + 8 + 4 + 2 + MAX_PATH_BYTES + 4 + MAX_XML;
const CAP_ITEM: usize = 8 + 2 + 1 + 2 + MAX_TEXT;
const CAP_UNREAD: usize = 8 + 2 + MAX_TEXT;
/// The most bytes one job's stream may bring (10 000 tasks of 256 KiB would be 2.5 GB): the
/// app's memory is bounded whatever the other end does. A PC's tasks take a few MB.
pub const MAX_STREAM: usize = 64 << 20;

/// What the helper says, in order: Hello, then Task records and what it could not read
/// (scan-tasks) or Item results, then Done.
#[derive(Clone, Debug, PartialEq)]
pub enum Msg {
    Hello { pid: u32 },
    Task { epoch: u64, task: TaskRaw },
    /// Something the task walk could not read (scan-tasks): a row in the app, never dropped.
    Unread { epoch: u64, text: String },
    Item { epoch: u64, index: u16, outcome: Outcome },
    Done { epoch: u64, code: u8 },
}

fn frame(kind: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&payload);
    out
}

/// Text cut to `max` bytes at a character boundary.
fn cut(s: &str, max: usize) -> &str {
    let mut n = s.len().min(max);
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    &s[..n]
}

pub fn encode(m: &Msg) -> Vec<u8> {
    match m {
        Msg::Hello { pid } => frame(KIND_HELLO, pid.to_le_bytes().to_vec()),
        Msg::Task { epoch, task } => {
            let mut p = epoch.to_le_bytes().to_vec();
            p.push(u8::from(task.enabled));
            p.extend_from_slice(&task.state.to_le_bytes());
            p.extend_from_slice(&task.last_run.to_bits().to_le_bytes());
            p.extend_from_slice(&task.last_result.to_le_bytes());
            let path = cut(&task.path, MAX_PATH_BYTES).as_bytes();
            p.extend_from_slice(&(path.len() as u16).to_le_bytes());
            p.extend_from_slice(path);
            // An XML over the cap goes as empty: the app's parser says so.
            let xml = if task.xml.len() > MAX_XML { "" } else { task.xml.as_str() };
            p.extend_from_slice(&(xml.len() as u32).to_le_bytes());
            p.extend_from_slice(xml.as_bytes());
            frame(KIND_TASK, p)
        }
        Msg::Item { epoch, index, outcome } => {
            let mut p = epoch.to_le_bytes().to_vec();
            p.extend_from_slice(&index.to_le_bytes());
            let (code, text) = match outcome {
                Outcome::Done => (0u8, ""),
                Outcome::Refused(t) => (1, t.as_str()),
                Outcome::Failed(t) => (2, t.as_str()),
            };
            p.push(code);
            let t = cut(text, MAX_TEXT).as_bytes();
            p.extend_from_slice(&(t.len() as u16).to_le_bytes());
            p.extend_from_slice(t);
            frame(KIND_ITEM, p)
        }
        Msg::Done { epoch, code } => {
            let mut p = epoch.to_le_bytes().to_vec();
            p.push(*code);
            frame(KIND_DONE, p)
        }
        Msg::Unread { epoch, text } => {
            let mut p = epoch.to_le_bytes().to_vec();
            let t = cut(text, MAX_TEXT).as_bytes();
            p.extend_from_slice(&(t.len() as u16).to_le_bytes());
            p.extend_from_slice(t);
            frame(KIND_UNREAD, p)
        }
    }
}

/// A strict reader over bytes: every read checks what is left.
struct Rd<'a>(&'a [u8]);

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err("a message ends early".into());
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap_or([0; 2])))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap_or([0; 4])))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap_or([0; 8])))
    }
    /// An entry's definition digest (`autostart::def::Def`).
    fn def(&mut self) -> Result<Def, String> {
        Ok(Def(self.take(32)?.try_into().unwrap_or([0; 32])))
    }
    fn text(&mut self, len: usize, max: usize) -> Result<String, String> {
        if len > max {
            return Err(format!("a text of {len} bytes (at most {max})"));
        }
        String::from_utf8(self.take(len)?.to_vec()).map_err(|_| "a text that is not UTF-8".to_string())
    }
    fn units(&mut self, max: usize) -> Result<Vec<u16>, String> {
        let n = self.u16()? as usize;
        if n == 0 || n > max {
            return Err(format!("a name of {n} units (1 to {max})"));
        }
        let b = self.take(n * 2)?;
        let u: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        if u.contains(&0) {
            return Err("a name with a NUL".into());
        }
        Ok(u)
    }
    fn end(&self) -> Result<(), String> {
        if self.0.is_empty() { Ok(()) } else { Err("a message with bytes left over".into()) }
    }
}

/// Reads the helper's messages out of the byte stream. Strict: an unknown kind, a size over its
/// cap, a malformed payload, a message out of order, another epoch, too many tasks or items end
/// the stream as broken (the helper is ours, so anything else means someone else).
pub struct Decoder {
    buf: Vec<u8>,
    epoch: u64,
    hello: bool,
    done: bool,
    tasks: usize,
    /// "Could not be read" notes so far (at most MAX_UNREAD, apart from the tasks).
    unread: usize,
    items: usize,
    /// Bytes taken in so far (at most MAX_STREAM).
    bytes: usize,
    max_items: usize,
    broken: bool,
}

impl Decoder {
    /// A decoder for the job with this epoch and this many request items.
    pub fn new(epoch: u64, items: usize) -> Decoder {
        Decoder { buf: Vec::new(), epoch, hello: false, done: false, tasks: 0, unread: 0, items: 0, bytes: 0, max_items: items, broken: false }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Msg>, String> {
        if self.broken {
            return Err("the helper's stream was already broken".into());
        }
        self.bytes += bytes.len();
        if self.bytes > MAX_STREAM {
            return self.fail(format!("more than {} MB from the helper", MAX_STREAM >> 20));
        }
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        while self.buf.len() >= 5 {
            let kind = self.buf[0];
            let len = u32::from_le_bytes(self.buf[1..5].try_into().unwrap_or([0; 4])) as usize;
            let cap = match kind {
                KIND_HELLO => 4,
                KIND_TASK => CAP_TASK,
                KIND_ITEM => CAP_ITEM,
                KIND_DONE => 9,
                KIND_UNREAD => CAP_UNREAD,
                k => return self.fail(format!("an unknown message ({k})")),
            };
            if len > cap {
                return self.fail(format!("a message of {len} bytes (at most {cap})"));
            }
            if self.buf.len() < 5 + len {
                break;
            }
            let p: Vec<u8> = self.buf[5..5 + len].to_vec();
            self.buf.drain(..5 + len);
            let m = match self.parse(kind, &p) {
                Ok(m) => m,
                Err(e) => return self.fail(e),
            };
            match &m {
                Msg::Hello { .. } if self.hello => return self.fail("a second hello".into()),
                Msg::Hello { .. } => self.hello = true,
                _ if !self.hello => return self.fail("a message before hello".into()),
                _ if self.done => return self.fail("a message after done".into()),
                Msg::Task { epoch, .. } | Msg::Unread { epoch, .. } | Msg::Item { epoch, .. } | Msg::Done { epoch, .. } if *epoch != self.epoch => return self.fail("a message for another job".into()),
                Msg::Task { .. } => {
                    self.tasks += 1;
                    if self.tasks > MAX_TASKS {
                        return self.fail(format!("more than {MAX_TASKS} tasks"));
                    }
                }
                // Counted apart from the tasks: a note after a full list of tasks is not one
                // task too many.
                Msg::Unread { .. } => {
                    self.unread += 1;
                    if self.unread > MAX_UNREAD {
                        return self.fail(format!("more than {MAX_UNREAD} notes of what could not be read"));
                    }
                }
                Msg::Item { index, .. } => {
                    if *index as usize != self.items || self.items >= self.max_items {
                        return self.fail(format!("a result for item {index} (expected {})", self.items));
                    }
                    self.items += 1;
                }
                Msg::Done { .. } => self.done = true,
            }
            out.push(m);
        }
        Ok(out)
    }

    fn parse(&self, kind: u8, p: &[u8]) -> Result<Msg, String> {
        let mut r = Rd(p);
        let m = match kind {
            KIND_HELLO => Msg::Hello { pid: r.u32()? },
            KIND_TASK => {
                let epoch = r.u64()?;
                let enabled = match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err("a task's enabled flag that is neither".into()),
                };
                let state = r.u32()? as i32;
                let last_run = f64::from_bits(r.u64()?);
                let last_result = r.u32()? as i32;
                let plen = r.u16()? as usize;
                let path = r.text(plen, MAX_PATH_BYTES)?;
                if !switch::valid_task_path(&path) {
                    return Err("a task path that is not one".into());
                }
                let xlen = r.u32()? as usize;
                let xml = r.text(xlen, MAX_XML)?;
                Msg::Task { epoch, task: TaskRaw { path, enabled, state, last_run, last_result, xml } }
            }
            KIND_ITEM => {
                let epoch = r.u64()?;
                let index = r.u16()?;
                let code = r.u8()?;
                let tlen = r.u16()? as usize;
                let text = crate::autostart::text::clean_max(&r.text(tlen, MAX_TEXT)?, 300);
                let outcome = match code {
                    0 => Outcome::Done,
                    1 => Outcome::Refused(text),
                    2 => Outcome::Failed(text),
                    _ => return Err("an item result of no known kind".into()),
                };
                Msg::Item { epoch, index, outcome }
            }
            KIND_DONE => Msg::Done { epoch: r.u64()?, code: r.u8()? },
            KIND_UNREAD => {
                let epoch = r.u64()?;
                let tlen = r.u16()? as usize;
                Msg::Unread { epoch, text: crate::autostart::text::clean_max(&r.text(tlen, MAX_TEXT)?, 300) }
            }
            _ => return Err("an unknown message".into()),
        };
        r.end()?;
        Ok(m)
    }

    fn fail(&mut self, why: String) -> Result<Vec<Msg>, String> {
        self.broken = true;
        self.buf.clear();
        Err(format!("the helper sent {why}"))
    }
}

/// The location's code in a `startup-set` item.
fn startup_code(loc: Location) -> Option<u8> {
    match loc {
        Location::RunMachine => Some(1),
        Location::RunMachine32 => Some(2),
        Location::StartupCommon => Some(3),
        _ => None,
    }
}

fn startup_loc(c: u8) -> Option<Location> {
    match c {
        1 => Some(Location::RunMachine),
        2 => Some(Location::RunMachine32),
        3 => Some(Location::StartupCommon),
        _ => None,
    }
}

fn put_units(p: &mut Vec<u8>, u: &[u16]) {
    p.extend_from_slice(&(u.len() as u16).to_le_bytes());
    for x in u {
        p.extend_from_slice(&x.to_le_bytes());
    }
}

fn put_str(p: &mut Vec<u8>, s: &str) {
    put_units(p, &s.encode_utf16().collect::<Vec<u16>>());
}

/// The app's request: the job, its epoch and its items. Err for anything the job does not take.
pub fn encode_request(epoch: u64, job: Job, items: &[Request]) -> Result<Vec<u8>, String> {
    if items.len() > MAX_ITEMS || (job == Job::ScanTasks) != items.is_empty() {
        return Err("not a request the helper takes".into());
    }
    let mut p = epoch.to_le_bytes().to_vec();
    p.push(job.code());
    p.extend_from_slice(&(items.len() as u16).to_le_bytes());
    for r in items {
        switch::well_formed(r)?;
        if !job.takes(r.location) {
            return Err("a change for another job".into());
        }
        match (&r.ident, &r.old, &r.new) {
            (Ident::Value { name } | Ident::File { name, .. }, Data::Approved(old), Data::Approved(Some(new))) => {
                p.push(startup_code(r.location).ok_or("not an all-users startup entry")?);
                put_units(&mut p, name);
                match old {
                    None => p.push(0),
                    Some(o) => {
                        p.push(1);
                        p.extend_from_slice(o);
                    }
                }
                p.extend_from_slice(new);
                p.extend_from_slice(&r.def.0);
            }
            (Ident::Task { path }, Data::TaskEnabled(old), Data::TaskEnabled(new)) => {
                put_str(&mut p, path);
                p.push(u8::from(*old));
                p.push(u8::from(*new));
                p.extend_from_slice(&r.def.0);
            }
            (Ident::Service { name }, Data::ServiceStart { start: os, delayed: od }, Data::ServiceStart { start: ns, delayed: nd }) => {
                put_str(&mut p, name);
                p.extend_from_slice(&[*os as u8, u8::from(*od), *ns as u8, u8::from(*nd)]);
                p.extend_from_slice(&r.def.0);
            }
            _ => return Err("not a request the helper takes".into()),
        }
    }
    Ok(frame(KIND_REQUEST, p))
}

/// The helper reads the request: every parameter bound and checked here, and again (against the
/// PC) by `switch::apply`. A startup file's path is never taken from the request.
pub fn decode_request(bytes: &[u8], want: Job) -> Result<(u64, Vec<Request>), String> {
    if bytes.len() < 5 || bytes[0] != KIND_REQUEST {
        return Err("not a request".into());
    }
    let len = u32::from_le_bytes(bytes[1..5].try_into().unwrap_or([0; 4])) as usize;
    if len > CAP_REQUEST || bytes.len() != 5 + len {
        return Err("a request of the wrong size".into());
    }
    let mut r = Rd(&bytes[5..]);
    let epoch = r.u64()?;
    let job = Job::from_code(r.u8()?).ok_or("an unknown job")?;
    if job != want {
        return Err("a request for another job".into());
    }
    let n = r.u16()? as usize;
    if n > MAX_ITEMS || (job == Job::ScanTasks) != (n == 0) {
        return Err(format!("{n} items"));
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let req = match job {
            Job::StartupSet => {
                let loc = startup_loc(r.u8()?).ok_or("not an all-users startup location")?;
                let name = r.units(260)?;
                let old = match r.u8()? {
                    0 => None,
                    1 => Some(r.take(12)?.to_vec()),
                    _ => return Err("an old value that is neither there nor absent".into()),
                };
                let new = r.take(12)?.to_vec();
                let def = r.def()?;
                let ident = if loc == Location::StartupCommon { Ident::File { name, path: Default::default() } } else { Ident::Value { name } };
                Request { location: loc, ident, def, old: Data::Approved(old), new: Data::Approved(Some(new)) }
            }
            Job::TaskSet | Job::TaskUndo => {
                let path = String::from_utf16(&r.units(1024)?).map_err(|_| "a task path that is not text")?;
                let flag = |b: u8| match b {
                    0 => Ok(false),
                    1 => Ok(true),
                    _ => Err("a flag that is neither".to_string()),
                };
                let old = flag(r.u8()?)?;
                let new = flag(r.u8()?)?;
                Request { location: Location::LogonTask, ident: Ident::Task { path }, def: r.def()?, old: Data::TaskEnabled(old), new: Data::TaskEnabled(new) }
            }
            Job::ServiceStart => {
                let name = String::from_utf16(&r.units(256)?).map_err(|_| "a service name that is not text")?;
                let b = r.take(4)?;
                let flag = |x: u8| if x <= 1 { Ok(x == 1) } else { Err("a flag that is neither".to_string()) };
                let (old, new) = (Data::ServiceStart { start: u32::from(b[0]), delayed: flag(b[1])? }, Data::ServiceStart { start: u32::from(b[2]), delayed: flag(b[3])? });
                Request { location: Location::Service, ident: Ident::Service { name }, def: r.def()?, old, new }
            }
            Job::ScanTasks => unreachable!("no items"),
        };
        switch::well_formed(&req)?;
        out.push(req);
    }
    r.end()?;
    Ok((epoch, out))
}

/// Items checked and done by `switch::apply` alone, on `pc` (a fake one in tests, the real PC in
/// the Sandbox test): no job's own way and no records. The helper's work is `Job::act`
/// (`sys::work`), which a `task-undo` must go through.
pub fn execute(pc: &dyn Pc, items: &[Request]) -> Vec<Outcome> {
    items.iter().map(|r| switch::apply(pc, r)).collect()
}

/// The helper's command line, `--helper <job> <pipe>`: the one copy of its shape. The elevated
/// relaunch passes it (joined with spaces: no part has one) and the pe test starts the exe with
/// it, so the two can't drift apart (review RRC-1).
pub fn args(job: Job, pipe: &str) -> [String; 3] {
    ["--helper".into(), job.name().into(), pipe.into()]
}

/// The helper's arguments: `--helper <job> <pipe>`, the pipe exactly as the app makes it.
pub fn parse_args(args: &[String]) -> Option<(Job, String)> {
    let [flag, job, pipe] = args else { return None };
    if flag != "--helper" {
        return None;
    }
    let job = Job::from_name(job)?;
    let hex = pipe.strip_prefix(PIPE_PREFIX)?;
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    Some((job, pipe.clone()))
}

/// The pipe's name: 128 random bits from the system's generator, lower-case hex.
pub fn pipe_name(random: &[u8; 16]) -> String {
    format!("{PIPE_PREFIX}{}", random.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// A file identity: the volume serial and the 128-bit file id.
pub(crate) type FileIdent = (u64, [u8; 16]);

/// Two identities are one file: equal, and neither the serial nor the id is zero.
pub(crate) fn same_id(a: FileIdent, b: FileIdent) -> bool {
    a == b && a.0 != 0 && a.1 != [0; 16]
}

/// The identity where a file system has no `FILE_ID_INFO` (FAT, exFAT): the 32-bit serial and the
/// 64-bit index in the low 8 bytes, the high 8 bytes zero.
pub(crate) fn fallback_id(serial: u32, index_high: u32, index_low: u32) -> FileIdent {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&((u64::from(index_high) << 32) | u64::from(index_low)).to_le_bytes());
    (u64::from(serial), id)
}

/// A verbatim path's plain form: `\\?\C:\x` → `C:\x`, `\\?\UNC\srv\share\x` → `\\srv\share\x`.
pub(crate) fn strip_verbatim(p: &[u16]) -> Option<Vec<u16>> {
    let s = String::from_utf16(p).ok()?;
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return Some(format!(r"\\{rest}").encode_utf16().collect());
    }
    let rest = s.strip_prefix(r"\\?\")?;
    let b = rest.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\').then(|| rest.encode_utf16().collect())
}

// ---------- running a job (the app's side) ----------

/// What a job brought back.
#[derive(Clone, Debug, PartialEq)]
pub enum Answer {
    /// One result per item, in order; None where the helper ended before it answered that item
    /// (whether it happened is unknown: the journal settles it against the live data).
    Items(Vec<Option<Outcome>>),
    /// Every task, and what could not be read on the way.
    Tasks(Vec<TaskRaw>, Vec<String>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ElevError {
    /// The user said no at the UAC prompt: nothing was done.
    Declined,
    /// It did not get as far as the request (no pipe, the helper did not start or connect, a
    /// stranger on the pipe): nothing was done.
    NotStarted(String),
    /// The request went out and the helper failed on the way: the items without a result are
    /// unknown.
    Broken(String),
}

impl ElevError {
    pub fn words(&self) -> String {
        match self {
            ElevError::Declined => "Not done: administrator rights were declined.".into(),
            ElevError::NotStarted(w) => format!("Not done: {w}."),
            ElevError::Broken(w) => format!("The administrator step failed: {w}."),
        }
    }
}

/// Runs admin jobs. `connected` is called once the helper proved to be ours, right before the
/// request goes out (the journal's pending records are written there).
pub trait Elevator: Send + Sync {
    fn run(&self, job: Job, epoch: u64, items: &[Request], hwnd: isize, connected: &dyn Fn()) -> Result<Answer, ElevError>;
}

/// The real one: this exe, relaunched elevated.
pub struct SystemElevator;

impl Elevator for SystemElevator {
    fn run(&self, job: Job, epoch: u64, items: &[Request], hwnd: isize, connected: &dyn Fn()) -> Result<Answer, ElevError> {
        sys::run_job(job, epoch, items, hwnd, connected)
    }
}

/// A scripted elevator for tests: the job runs on a fake PC (no UAC prompt, no process), and can
/// be declined or broken off after some items.
pub struct FakeElevator {
    pub pc: std::sync::Arc<dyn Pc>,
    pub decline: std::sync::atomic::AtomicBool,
    /// Break off after this many items (the helper dies mid-job).
    pub break_after: std::sync::Mutex<Option<usize>>,
    /// Every job asked for, in order.
    pub asked: std::sync::Mutex<Vec<(Job, usize)>>,
    /// Tasks only an elevated read sees (restrictive security): `scan-tasks` adds them.
    pub hidden_tasks: std::sync::Mutex<Vec<TaskRaw>>,
    /// The helper's own records of its task switch-offs (in memory: never HKLM).
    pub records: records::Memory,
}

impl FakeElevator {
    pub fn new(pc: std::sync::Arc<dyn Pc>) -> FakeElevator {
        FakeElevator { pc, decline: Default::default(), break_after: Default::default(), asked: Default::default(), hidden_tasks: Default::default(), records: Default::default() }
    }
}

impl Elevator for FakeElevator {
    fn run(&self, job: Job, _epoch: u64, items: &[Request], _hwnd: isize, connected: &dyn Fn()) -> Result<Answer, ElevError> {
        self.asked.lock().unwrap().push((job, items.len()));
        if self.decline.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ElevError::Declined);
        }
        connected();
        if job == Job::ScanTasks {
            let hidden = self.hidden_tasks.lock().unwrap().clone();
            return self.pc.tasks().map(|(mut t, unread)| {
                t.extend(hidden);
                Answer::Tasks(t, unread)
            }).map_err(ElevError::Broken);
        }
        let stop = *self.break_after.lock().unwrap();
        let mut out = Vec::new();
        for (i, r) in items.iter().enumerate() {
            if stop.is_some_and(|n| i >= n) {
                out.push(None);
            } else {
                out.push(Some(job.act(&*self.pc, &self.records, r)));
            }
        }
        Ok(Answer::Items(out))
    }
}

#[cfg(windows)]
pub mod sys {
    use super::*;
    use std::time::Instant;
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::Storage::FileSystem::*;
    use windows_sys::Win32::System::IO::*;
    use windows_sys::Win32::System::Pipes::*;
    use windows_sys::Win32::System::Threading::*;

    /// This exe's path, as Windows has it (exact UTF-16 units).
    pub fn own_exe() -> Option<Vec<u16>> {
        use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
        let mut buf = vec![0u16; 32_768];
        // SAFETY: a buffer and its length in units.
        let n = unsafe { GetModuleFileNameW(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) } as usize;
        (n > 0 && n < buf.len()).then(|| buf[..n].to_vec())
    }

    /// The image path of process `pid` (None when it cannot be opened or asked).
    pub fn image_of(pid: u32) -> Option<Vec<u16>> {
        // SAFETY: a query-only open of a process by id; closed below.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 32_768];
        let mut n = buf.len() as u32;
        // SAFETY: a buffer and its length in units.
        let ok = unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut n) } != 0;
        unsafe { CloseHandle(h) };
        ok.then(|| buf[..n as usize].to_vec())
    }

    fn file_id(path: &[u16]) -> Option<FileIdent> {
        let mut p = path.to_vec();
        p.push(0);
        // SAFETY: a NUL-terminated path, attributes only, sharing everything; closed below.
        let h = unsafe { CreateFileW(p.as_ptr(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, std::ptr::null(), OPEN_EXISTING, 0, std::ptr::null_mut()) };
        if h == INVALID_HANDLE_VALUE {
            return None;
        }
        // SAFETY: plain structs filled by the calls, sizes given.
        let id = unsafe {
            let mut info: FILE_ID_INFO = std::mem::zeroed();
            if GetFileInformationByHandleEx(h, FileIdInfo, (&mut info as *mut FILE_ID_INFO).cast(), size_of::<FILE_ID_INFO>() as u32) != 0 {
                Some((info.VolumeSerialNumber, info.FileId.Identifier))
            } else {
                let mut bh: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
                (GetFileInformationByHandle(h, &mut bh) != 0).then(|| fallback_id(bh.dwVolumeSerialNumber, bh.nFileIndexHigh, bh.nFileIndexLow))
            }
        };
        unsafe { CloseHandle(h) };
        id
    }

    /// Two paths name the same file, compared by identity (never by name).
    pub fn same_file(a: &[u16], b: &[u16]) -> bool {
        match (file_id(a), file_id(b)) {
            (Some(x), Some(y)) => same_id(x, y),
            _ => false,
        }
    }

    /// The path the elevated helper is started from: this exe's final path (R-LINK-1: the
    /// elevated token has its own drive letters, so a subst or mapped letter is resolved away).
    pub fn launch_path() -> Option<Vec<u16>> {
        own_exe().map(|p| launch_path_of(&p))
    }

    pub(super) fn launch_path_of(p: &[u16]) -> Vec<u16> {
        final_path(p).map(plain_if_valid).unwrap_or_else(|| p.to_vec())
    }

    fn final_path(path: &[u16]) -> Option<Vec<u16>> {
        let mut p = path.to_vec();
        p.push(0);
        // SAFETY: a NUL-terminated path, attributes only, sharing everything; closed below.
        let h = unsafe { CreateFileW(p.as_ptr(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, std::ptr::null(), OPEN_EXISTING, 0, std::ptr::null_mut()) };
        if h == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut buf = vec![0u16; 32_768];
        // SAFETY: a buffer and its length in units.
        let n = unsafe { GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as u32, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) } as usize;
        unsafe { CloseHandle(h) };
        (n > 0 && n < buf.len()).then(|| buf[..n].to_vec())
    }

    fn plain_if_valid(verbatim: Vec<u16>) -> Vec<u16> {
        let Some(plain) = super::strip_verbatim(&verbatim) else { return verbatim };
        let mut z = plain.clone();
        z.push(0);
        let mut buf = vec![0u16; 32_768];
        // SAFETY: a NUL-terminated path, a buffer and its length in units.
        let n = unsafe { GetFullPathNameW(z.as_ptr(), buf.len() as u32, buf.as_mut_ptr(), std::ptr::null_mut()) } as usize;
        if plain.len() < MAX_PATH as usize && n > 0 && n < buf.len() && buf[..n] == plain[..] { plain } else { verbatim }
    }

    pub fn random16() -> Option<[u8; 16]> {
        use windows_sys::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};
        let mut b = [0u8; 16];
        // SAFETY: a 16-byte buffer; the system's preferred generator.
        (unsafe { BCryptGenRandom(std::ptr::null_mut(), b.as_mut_ptr(), 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG) } == 0).then_some(b)
    }

    /// The process runs elevated (its token's TokenElevation).
    pub fn elevated() -> bool {
        let mut tok: HANDLE = std::ptr::null_mut();
        // SAFETY: the current process's token, query only; closed below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) } == 0 {
            return false;
        }
        let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut n = 0u32;
        let ok = unsafe { GetTokenInformation(tok, TokenElevation, (&mut e as *mut TOKEN_ELEVATION).cast(), size_of::<TOKEN_ELEVATION>() as u32, &mut n) } != 0;
        unsafe { CloseHandle(tok) };
        ok && e.TokenIsElevated != 0
    }

    /// A security descriptor whose DACL allows only the current user (read and write).
    struct UserOnly {
        _token_user: Vec<u64>,
        _acl: Vec<u64>,
        sd: Box<SECURITY_DESCRIPTOR>,
    }

    fn user_only() -> Option<UserOnly> {
        let mut tok: HANDLE = std::ptr::null_mut();
        // SAFETY: the current process's token, query only; closed below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) } == 0 {
            return None;
        }
        let mut need = 0u32;
        unsafe { GetTokenInformation(tok, TokenUser, std::ptr::null_mut(), 0, &mut need) };
        let mut tu = vec![0u64; (need as usize).div_ceil(8).max(8)];
        let ok = unsafe { GetTokenInformation(tok, TokenUser, tu.as_mut_ptr().cast(), (tu.len() * 8) as u32, &mut need) } != 0;
        unsafe { CloseHandle(tok) };
        if !ok {
            return None;
        }
        // SAFETY: the buffer holds a TOKEN_USER written by the call above.
        let sid = unsafe { (*(tu.as_ptr() as *const TOKEN_USER)).User.Sid };
        let sid_len = unsafe { GetLengthSid(sid) } as usize;
        let acl_len = size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() + sid_len;
        let mut acl = vec![0u64; acl_len.div_ceil(8)];
        let pacl = acl.as_mut_ptr() as *mut ACL;
        // SAFETY: an ACL buffer of `acl_len` bytes; one ACE for the user's SID.
        unsafe {
            if InitializeAcl(pacl, acl_len as u32, ACL_REVISION) == 0 || AddAccessAllowedAce(pacl, ACL_REVISION, GENERIC_READ | GENERIC_WRITE, sid) == 0 {
                return None;
            }
        }
        let mut sd: Box<SECURITY_DESCRIPTOR> = Box::new(unsafe { std::mem::zeroed() });
        let psd = (&mut *sd as *mut SECURITY_DESCRIPTOR).cast();
        // SAFETY: a descriptor in our memory, the DACL above (both outlive the pipe's creation).
        unsafe {
            if InitializeSecurityDescriptor(psd, 1 /* SECURITY_DESCRIPTOR_REVISION */) == 0 || SetSecurityDescriptorDacl(psd, 1, pacl, 0) == 0 {
                return None;
            }
        }
        Some(UserOnly { _token_user: tu, _acl: acl, sd })
    }

    /// The app's end of the pipe: one instance, overlapped, user-only, no remote clients.
    pub struct Server {
        pub h: HANDLE,
        pub name: String,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            // SAFETY: created in `create`, closed once.
            unsafe { CloseHandle(self.h) };
        }
    }

    // SAFETY: the handle is used by one thread at a time (the job's worker).
    unsafe impl Send for Server {}

    pub fn create() -> Result<Server, String> {
        let r = random16().ok_or("no random numbers from the system")?;
        let name = pipe_name(&r);
        let sec = user_only().ok_or("the pipe's access rules could not be made")?;
        let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: (&*sec.sd as *const SECURITY_DESCRIPTOR) as *mut _, bInheritHandle: 0 };
        let w = crate::host::wide(&name);
        // SAFETY: a NUL-terminated name and attributes that live through the call.
        let h = unsafe {
            CreateNamedPipeW(
                w.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                64 * 1024,
                64 * 1024,
                0,
                &sa,
            )
        };
        drop(sec);
        if h == INVALID_HANDLE_VALUE {
            return Err(format!("the pipe did not open ({})", std::io::Error::last_os_error()));
        }
        Ok(Server { h, name })
    }

    /// How an overlapped wait ended.
    pub enum End {
        Done(u32),
        Deadline,
        ProcessGone,
        Error(u32),
    }

    /// Wait for an overlapped operation in 100 ms steps until done, `deadline`, or `process`
    /// ends; anything but done cancels it first.
    fn wait(h: HANDLE, ov: &mut OVERLAPPED, deadline: Instant, process: HANDLE) -> End {
        loop {
            let mut n = 0u32;
            // SAFETY: the operation started on `h` with `ov`; a 100 ms wait.
            if unsafe { GetOverlappedResultEx(h, ov, &mut n, 100, 0) } != 0 {
                return End::Done(n);
            }
            let e = unsafe { GetLastError() };
            if e != WAIT_TIMEOUT && e != WAIT_IO_COMPLETION && e != ERROR_IO_INCOMPLETE {
                return End::Error(e);
            }
            let why = if Instant::now() >= deadline {
                Some(End::Deadline)
            } else if !process.is_null() && unsafe { WaitForSingleObject(process, 0) } == WAIT_OBJECT_0 {
                Some(End::ProcessGone)
            } else {
                None
            };
            if let Some(w) = why {
                // SAFETY: cancel our own operation, then wait for it to finish with `ov`.
                unsafe {
                    CancelIoEx(h, ov);
                    let mut n = 0u32;
                    GetOverlappedResult(h, ov, &mut n, 1);
                }
                return w;
            }
        }
    }

    pub struct Event(pub HANDLE);
    impl Drop for Event {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    pub fn event() -> Event {
        // SAFETY: an unnamed manual-reset event.
        Event(unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) })
    }

    pub fn overlapped(ev: &Event) -> OVERLAPPED {
        // SAFETY: all-zero is a valid OVERLAPPED.
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = ev.0;
        ov
    }

    /// The relaunch: this exe (from its final path), elevated, with the job's arguments. Blocks
    /// until the UAC prompt is answered. Ok(process handle), or Err(Win32 code): 1223 is "no".
    pub fn relaunch(job: Job, pipe: &str, hwnd: isize) -> Result<HANDLE, u32> {
        use windows_sys::Win32::System::Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx};
        use windows_sys::Win32::UI::Shell::{SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
        let mut file = launch_path().ok_or(2u32)?;
        file.push(0);
        let params = crate::host::wide(&super::args(job, pipe).join(" "));
        let verb = crate::host::wide("runas");
        // SAFETY: COM for the shell on this thread; the struct's strings outlive the call.
        unsafe {
            CoInitializeEx(std::ptr::null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32);
            let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
            info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
            info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
            info.hwnd = hwnd as *mut _;
            info.lpVerb = verb.as_ptr();
            info.lpFile = file.as_ptr();
            info.lpParameters = params.as_ptr();
            info.nShow = 0; // SW_HIDE: the helper has no window anyway
            if ShellExecuteExW(&mut info) == 0 {
                return Err(GetLastError());
            }
            if info.hProcess.is_null() {
                return Err(ERROR_INVALID_HANDLE);
            }
            Ok(info.hProcess)
        }
    }

    struct Proc(HANDLE);
    impl Drop for Proc {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    /// One job, start to end, on the calling (worker) thread.
    pub fn run_job(job: Job, epoch: u64, items: &[Request], hwnd: isize, connected: &dyn Fn()) -> Result<Answer, ElevError> {
        let request = encode_request(epoch, job, items).map_err(ElevError::NotStarted)?;
        let server = create().map_err(ElevError::NotStarted)?;
        let started = Instant::now();
        let process = match relaunch(job, &server.name, hwnd) {
            Ok(p) => Proc(p),
            Err(1223) => return Err(ElevError::Declined),
            Err(e) => return Err(ElevError::NotStarted(format!("the helper did not start ({})", std::io::Error::from_raw_os_error(e as i32)))),
        };
        let pid = unsafe { GetProcessId(process.0) };
        serve(&server, process.0, pid, started + CONNECT_WAIT, job, epoch, items.len(), &request, connected)
    }

    /// Wait for the helper (`pid`, started as `process`) to connect until `deadline`, check it
    /// is that process running this exe, hear its hello, then send the request and read the
    /// answer until Done.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn serve(server: &Server, process: HANDLE, pid: u32, deadline: Instant, job: Job, epoch: u64, n_items: usize, request: &[u8], connected: &dyn Fn()) -> Result<Answer, ElevError> {
        let ev = event();
        let mut ov = overlapped(&ev);
        // SAFETY: an overlapped connect on our pipe.
        let r = unsafe { ConnectNamedPipe(server.h, &mut ov) };
        let err = unsafe { GetLastError() };
        if r == 0 && err != ERROR_PIPE_CONNECTED {
            if err != ERROR_IO_PENDING {
                return Err(ElevError::NotStarted(format!("the pipe did not wait ({})", std::io::Error::from_raw_os_error(err as i32))));
            }
            match wait(server.h, &mut ov, deadline, process) {
                End::Done(_) => {}
                End::Deadline => return Err(ElevError::NotStarted("the helper did not connect within 2 minutes".into())),
                End::ProcessGone => {
                    let mut code = 0u32;
                    // SAFETY: the helper's process handle, still held.
                    let known = unsafe { GetExitCodeProcess(process, &mut code) } != 0;
                    return Err(ElevError::NotStarted(if known && code == 5 {
                        // The pipe admits this user only: an administrator's account typed into the
                        // prompt (over-the-shoulder) cannot reach it.
                        "the helper could not reach VibeBoot (administrator rights from another account do not work: run VibeBoot in an administrator's own session)".into()
                    } else {
                        "the helper ended before it connected".into()
                    }));
                }
                End::Error(e) => return Err(ElevError::NotStarted(format!("the pipe failed ({})", std::io::Error::from_raw_os_error(e as i32)))),
            }
        }
        // Who connected: the process we started, running this exe.
        let mut client = 0u32;
        let ok = unsafe { GetNamedPipeClientProcessId(server.h, &mut client) } != 0;
        let same = match (own_exe(), image_of(client)) {
            (Some(a), Some(b)) => same_file(&a, &b),
            _ => false,
        };
        if !ok || client != pid || !same {
            return Err(ElevError::NotStarted("something else connected to the helper's pipe: it was closed".into()));
        }
        let mut dec = Decoder::new(epoch, n_items);
        let mut buf = vec![0u8; 64 * 1024];
        let hello_by = Instant::now() + Duration::from_secs(15);
        // Hello first.
        let mut pending: Vec<Msg> = Vec::new();
        while !pending.iter().any(|m| matches!(m, Msg::Hello { .. })) {
            let n = read(server, &mut buf, hello_by, process).map_err(|e| ElevError::NotStarted(format!("the helper said nothing ({e})")))?;
            pending.extend(dec.push(&buf[..n]).map_err(ElevError::NotStarted)?);
        }
        connected();
        // The request.
        {
            let ev = event();
            let mut ov = overlapped(&ev);
            // SAFETY: an overlapped write of `request`, waited for below before it is dropped.
            let r = unsafe { WriteFile(server.h, request.as_ptr(), request.len() as u32, std::ptr::null_mut(), &mut ov) };
            let e = unsafe { GetLastError() };
            if r == 0 && e != ERROR_IO_PENDING {
                return Err(ElevError::Broken(format!("the request did not go out ({})", std::io::Error::from_raw_os_error(e as i32))));
            }
            if r == 0 && !matches!(wait(server.h, &mut ov, Instant::now() + Duration::from_secs(10), process), End::Done(_)) {
                return Err(ElevError::Broken("the request did not go out".into()));
            }
        }
        let end = Instant::now() + job.limit() + Duration::from_secs(5);
        let mut items: Vec<Option<Outcome>> = vec![None; n_items];
        let mut tasks: Vec<TaskRaw> = Vec::new();
        let mut unread: Vec<String> = Vec::new();
        loop {
            for m in pending.drain(..) {
                match m {
                    Msg::Hello { .. } => {}
                    Msg::Task { task, .. } => tasks.push(task),
                    Msg::Unread { text, .. } => unread.push(text),
                    Msg::Item { index, outcome, .. } => items[index as usize] = Some(outcome),
                    Msg::Done { code, .. } => {
                        return match (job, code) {
                            (Job::ScanTasks, done::OK) => Ok(Answer::Tasks(tasks, unread)),
                            (_, done::OK) => Ok(Answer::Items(items)),
                            (_, done::BAD_REQUEST) => Err(ElevError::Broken("the helper refused the request".into())),
                            _ => Err(ElevError::Broken("the helper could not do the job".into())),
                        };
                    }
                }
            }
            let n = match read(server, &mut buf, end, process) {
                Ok(n) => n,
                // Gone before Done: a task list is incomplete (no answer); items without a result
                // are unknown (None), settled by the journal against the live data.
                Err(e) => return if job == Job::ScanTasks { Err(ElevError::Broken(e)) } else { Ok(Answer::Items(items)) },
            };
            match dec.push(&buf[..n]) {
                Ok(msgs) => pending.extend(msgs),
                Err(e) => return if job == Job::ScanTasks { Err(ElevError::Broken(e)) } else { Ok(Answer::Items(items)) },
            }
        }
    }

    /// One overlapped read: bytes, or why none came.
    fn read(server: &Server, buf: &mut [u8], deadline: Instant, process: HANDLE) -> Result<usize, String> {
        loop {
            let ev = event();
            let mut ov = overlapped(&ev);
            // SAFETY: an overlapped read into `buf`, waited for below before `buf` is touched.
            let r = unsafe { ReadFile(server.h, buf.as_mut_ptr(), buf.len() as u32, std::ptr::null_mut(), &mut ov) };
            let err = unsafe { GetLastError() };
            let n = if r != 0 {
                let mut n = 0u32;
                unsafe { GetOverlappedResult(server.h, &ov, &mut n, 1) };
                n
            } else if err == ERROR_IO_PENDING {
                match wait(server.h, &mut ov, deadline, process) {
                    End::Done(n) => n,
                    End::Deadline => return Err("the helper ran out of time".into()),
                    End::ProcessGone => return Err("the helper ended".into()),
                    End::Error(_) => return Err("the helper went away".into()),
                }
            } else {
                return Err("the helper went away".into());
            };
            if n > 0 {
                return Ok(n as usize);
            }
        }
    }

    // ---------- the helper's side ----------

    /// The helper's end of the pipe (synchronous: one thread reads and writes).
    pub struct Client(pub HANDLE);
    impl Drop for Client {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    impl Client {
        pub fn send(&self, m: &Msg) -> bool {
            let b = encode(m);
            let mut n = 0u32;
            // SAFETY: a synchronous write of `b`.
            unsafe { WriteFile(self.0, b.as_ptr(), b.len() as u32, &mut n, std::ptr::null_mut()) != 0 && n as usize == b.len() }
        }

        /// The request: one message, read whole (at most its cap).
        pub fn request(&self) -> Option<Vec<u8>> {
            let mut head = [0u8; 5];
            if !self.read_exact(&mut head) || head[0] != KIND_REQUEST {
                return None;
            }
            let len = u32::from_le_bytes(head[1..5].try_into().ok()?) as usize;
            if len > CAP_REQUEST {
                return None;
            }
            let mut body = vec![0u8; len];
            if !self.read_exact(&mut body) {
                return None;
            }
            let mut all = head.to_vec();
            all.extend_from_slice(&body);
            Some(all)
        }

        fn read_exact(&self, buf: &mut [u8]) -> bool {
            let mut got = 0usize;
            while got < buf.len() {
                let mut n = 0u32;
                // SAFETY: a synchronous read into the rest of `buf`.
                if unsafe { ReadFile(self.0, buf[got..].as_mut_ptr(), (buf.len() - got) as u32, &mut n, std::ptr::null_mut()) } == 0 || n == 0 {
                    return false;
                }
                got += n as usize;
            }
            true
        }
    }

    /// Connect to the app's pipe, identification-level only (the app cannot act as us), and
    /// check that its server is this exe.
    pub fn connect(pipe: &str) -> Option<Client> {
        let w = crate::host::wide(pipe);
        for _ in 0..3 {
            // SAFETY: a NUL-terminated name; the handle is ours.
            let h = unsafe { CreateFileW(w.as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, std::ptr::null(), OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, std::ptr::null_mut()) };
            if h == INVALID_HANDLE_VALUE {
                if unsafe { GetLastError() } == ERROR_PIPE_BUSY {
                    unsafe { WaitNamedPipeW(w.as_ptr(), 2000) };
                    continue;
                }
                return None;
            }
            let c = Client(h);
            let mut server = 0u32;
            if unsafe { GetNamedPipeServerProcessId(h, &mut server) } == 0 {
                return None;
            }
            let (mine, theirs) = (own_exe()?, image_of(server)?);
            return same_file(&mine, &theirs).then_some(c);
        }
        None
    }

    /// The helper's work once connected: read the request, do it (`Job::act`, its records in
    /// `kept`), answer, say done.
    pub fn work(client: &Client, job: Job, pc: &dyn Pc, kept: &dyn Store) -> i32 {
        let Some(bytes) = client.request() else { return 2 };
        let (epoch, items) = match decode_request(&bytes, job) {
            Ok(x) => x,
            Err(_) => {
                // The epoch, if it can be read, so the app hears the refusal.
                let epoch = bytes.get(5..13).and_then(|b| b.try_into().ok()).map(u64::from_le_bytes).unwrap_or(0);
                client.send(&Msg::Done { epoch, code: done::BAD_REQUEST });
                return 2;
            }
        };
        if job == Job::ScanTasks {
            let (tasks, unread) = match pc.tasks() {
                Ok(x) => x,
                Err(_) => {
                    client.send(&Msg::Done { epoch, code: done::FAILED });
                    return 0;
                }
            };
            for t in tasks.into_iter().take(MAX_TASKS) {
                if !client.send(&Msg::Task { epoch, task: t }) {
                    return 5;
                }
            }
            for text in unread.into_iter().take(MAX_UNREAD) {
                if !client.send(&Msg::Unread { epoch, text }) {
                    return 5;
                }
            }
        } else {
            for (i, r) in items.iter().enumerate() {
                let outcome = job.act(pc, kept, r);
                if !client.send(&Msg::Item { epoch, index: i as u16, outcome }) {
                    return 5;
                }
            }
        }
        client.send(&Msg::Done { epoch, code: done::OK });
        0
    }
}

#[cfg(windows)]
pub use sys::{elevated, own_exe, same_file};

/// The helper's whole life (`VibeBoot.exe --helper <job> <pipe>`): the exit code.
/// 2: bad arguments or request, 3: not elevated, 4: the hard limit, 5: the pipe or its server was
/// wrong.
#[cfg(windows)]
pub fn run_helper(args: &[String]) -> i32 {
    let Some((job, pipe)) = parse_args(args) else { return 2 };
    if !elevated() {
        return 3;
    }
    let limit = job.limit();
    std::thread::spawn(move || {
        std::thread::sleep(limit);
        // SAFETY: ends this process; Windows closes its handles with it.
        unsafe { windows_sys::Win32::System::Threading::ExitProcess(4) };
    });
    let Some(client) = sys::connect(&pipe) else { return 5 };
    if !client.send(&Msg::Hello { pid: std::process::id() }) {
        return 5;
    }
    sys::work(&client, job, &crate::autostart::sys::SystemPc, &records::Hklm)
}
