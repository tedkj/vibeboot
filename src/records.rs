//! The helper's own records of the task switch-offs it made (RB8-1, AUDIT-1 round 11), kept where
//! only administrators can write: `HKLM\SOFTWARE\VibeBoot` on the real PC, one REG_BINARY JSON
//! value per off, named by its 128-bit id (the family's pattern: VibePath's and VibeScamCheck's
//! undo records). The journal in `%LOCALAPPDATA%\VibeBoot` (or the stick) is for showing and
//! history; it can be written without admin rights, so the elevated `task-undo` never lifts the
//! Windows-own task lock on its word.
//!
//! Every task switch-off the helper makes (`task-set`, or a `task-undo` that switches off), once it
//! reads back as done, is recorded under a fresh id: the task's path and its whole definition as
//! the helper reads it right after the off (`def::Fresh::def`, what an Undo that switches it back
//! on is bound to). A `task-undo` that switches a task back on lifts the lock (`switch::undo`) only
//! with a record of the same task with the same definition, not used and at most 30 days old;
//! once that Undo is done the record is marked used, in the same elevated step. Without one the
//! item is done as `task-set` would do it (`switch::apply`): a task the lock does not hold is
//! switched on as before, a locked one is refused in words that say why (`NOT_RECORDED`, `USED`,
//! `EXPIRED`, `AHEAD`, `NO_RECORDS`). Expired records go on sight, and with the oldest past `KEEP`
//! at every new record. A record stamped more than `SKEW` ahead of the clock (the clock set back
//! after the off) is refused in its own words and kept: it is good again once the clock has caught
//! up, and ages from there. The user's own tasks are switched by the app itself, as the user: no elevated step,
//! no record.
//!
//! The real key is made by the helper with its own security (`SDDL`: owner Administrators, a
//! protected DACL of SYSTEM and Administrators, nobody else), and its owner and DACL are checked
//! before every use (`admin_only`). The helper takes the store as `&dyn Store`: tests keep records
//! in memory (`Memory`), so no test reaches HKLM. The real create, open and owner/DACL check run
//! in one test, on throwaway keys under HKCU (`hklm::tests`, RB9-2).

use crate::autostart::def::{self, Def};
use crate::autostart::pc::Pc;
use crate::autostart::switch::{self, Data, Outcome, Request};
use crate::autostart::{Ident, Location};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

pub type Id = [u8; 16];

pub const KEY: &str = r"SOFTWARE\VibeBoot";
/// The key's security when the helper makes it: owner Administrators (an owner who is a user
/// could rewrite the DACL unelevated), a protected DACL of SYSTEM and Administrators only.
pub const SDDL: &str = "O:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)";
/// The most records kept on a PC (the oldest go first).
pub const KEEP: usize = 500;
/// The largest record read back (a task path is at most 1 024 units).
pub const MAX_BYTES: usize = 16 * 1024;
/// A record's life: 30 days from the off.
pub const MAX_AGE: i64 = 30 * 24 * 60 * 60;
/// How far ahead of the clock a record may be stamped and still be good (a clock set back a
/// little). One further ahead is refused until the clock catches up (RB9-5, RB10-4).
pub const SKEW: i64 = 24 * 60 * 60;

/// Why a locked task's Undo is refused (said after `switch::WINDOWS_TASK`).
pub const NOT_RECORDED: &str = "the helper has no record of switching it off on this PC (an off made before VibeBoot kept such records, or one whose record could not be kept), so the Undo does not switch it back on: Task Scheduler can";
pub const USED: &str = "the helper's record of switching it off was used by an Undo already, so the Undo does not switch it back on again: Task Scheduler can";
pub const EXPIRED: &str = "the helper's record of switching it off is more than 30 days old (records last 30 days), so the Undo does not switch it back on: Task Scheduler can";
pub const AHEAD: &str = "the helper's record of switching it off is dated more than a day after this PC's clock (the clock was set back), so the Undo does not switch it back on until the clock is right: Task Scheduler can";
pub const NO_RECORDS: &str = "the helper's own records (HKLM\\SOFTWARE\\VibeBoot) could not be read or trusted, so the Undo does not switch it back on";

/// One task switch-off the helper made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Unix seconds when it was recorded (the oldest go first).
    pub at: i64,
    /// The task, as the request named it.
    pub path: String,
    /// Its whole definition as the helper read it after the off (`def::Fresh::def`).
    pub def: Def,
    /// Unix seconds when its Undo was done: used, never again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used: Option<i64>,
}

/// Where the records are kept: the values under one key, by name. Err: they cannot be read,
/// written or trusted, in words.
pub trait Store: Send + Sync {
    /// Every value there, by name (none when the key is not there).
    fn list(&self) -> Result<Vec<(String, Vec<u8>)>, String>;
    /// A new value (create-new: a name is never reused).
    fn put(&self, name: &str, bytes: &[u8]) -> Result<(), String>;
    /// A value that is there, rewritten.
    fn replace(&self, name: &str, bytes: &[u8]) -> Result<(), String>;
    fn delete(&self, name: &str) -> Result<(), String>;
}

/// Records in memory: the tests' store (and the scripted helper's, `FakeElevator`).
#[derive(Default)]
pub struct Memory {
    pub values: Mutex<BTreeMap<String, Vec<u8>>>,
    /// Every call fails with this (records that cannot be read or trusted).
    pub broken: Mutex<Option<String>>,
}

impl Memory {
    fn up(&self) -> Result<(), String> {
        match self.broken.lock().unwrap().clone() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// The records kept, decoded.
    pub fn records(&self) -> Vec<Record> {
        self.values.lock().unwrap().values().filter_map(|b| decode(b)).collect()
    }
}

impl Store for Memory {
    fn list(&self) -> Result<Vec<(String, Vec<u8>)>, String> {
        self.up()?;
        Ok(self.values.lock().unwrap().iter().map(|(n, b)| (n.clone(), b.clone())).collect())
    }

    fn put(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        self.up()?;
        let mut v = self.values.lock().unwrap();
        if v.contains_key(name) {
            return Err(format!("the record {name} is there already"));
        }
        v.insert(name.into(), bytes.to_vec());
        Ok(())
    }

    fn replace(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        self.up()?;
        match self.values.lock().unwrap().get_mut(name) {
            Some(b) => {
                *b = bytes.to_vec();
                Ok(())
            }
            None => Err(format!("the record {name} is not there")),
        }
    }

    fn delete(&self, name: &str) -> Result<(), String> {
        self.up()?;
        self.values.lock().unwrap().remove(name);
        Ok(())
    }
}

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// A record made at `at` is past its 30 days at `now`.
pub fn expired(at: i64, now: i64) -> bool {
    now.saturating_sub(at) > MAX_AGE
}

/// A record made at `at` is stamped more than `SKEW` ahead of `now`: the clock was set back
/// after the off. Refused, never deleted for it (RB10-4).
pub fn ahead(at: i64, now: i64) -> bool {
    at.saturating_sub(now) > SKEW
}

/// Which records go, of (made at, name): every expired one, then the oldest past `KEEP`. One
/// stamped ahead of the clock is not expired: it counts as the newest.
pub fn to_prune<N>(mut found: Vec<(i64, N)>, now: i64) -> Vec<N> {
    found.sort_by_key(|(at, _)| *at);
    let (old, live): (Vec<_>, Vec<_>) = found.into_iter().partition(|(at, _)| expired(*at, now));
    let extra = live.len().saturating_sub(KEEP);
    old.into_iter().chain(live.into_iter().take(extra)).map(|(_, n)| n).collect()
}

pub fn encode(r: &Record) -> Vec<u8> {
    serde_json::to_vec(r).unwrap_or_default()
}

/// Anything not exactly one record is None.
pub fn decode(b: &[u8]) -> Option<Record> {
    if b.len() > MAX_BYTES {
        return None;
    }
    serde_json::from_slice(b).ok()
}

pub fn hex(id: &Id) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// An id from its 32 lower-case hex digits (as `hex` writes it); None for anything else.
pub fn parse_hex(s: &str) -> Option<Id> {
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let mut id = [0u8; 16];
    for (i, c) in s.as_bytes().chunks(2).enumerate() {
        id[i] = u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok()?;
    }
    Some(id)
}

/// The values that are records (a name as `hex` writes it, a record's bytes); anything else
/// under the key is left alone.
fn records(s: &dyn Store) -> Result<Vec<(String, Record)>, String> {
    Ok(s.list()?.into_iter().filter_map(|(n, b)| Some((parse_hex(&n).map(|_| n)?, decode(&b)?))).collect())
}

/// Record a task switch-off the helper made, under `id`: the task `path` and its definition
/// `def` as it reads after the off. The expired records and the oldest past `KEEP` go.
pub fn record_off(s: &dyn Store, id: &Id, path: &str, def: Def, now: i64) -> Result<(), String> {
    s.put(&hex(id), &encode(&Record { at: now, path: path.into(), def, used: None }))?;
    let found = records(s)?;
    for n in to_prune(found.into_iter().map(|(n, r)| (r.at, n)).collect(), now) {
        let _ = s.delete(&n);
    }
    Ok(())
}

/// The record that lets the Undo `undo` (a task switched back on) lift the Windows-own lock: one
/// of the same task with the same definition (the Undo's binding, the record's `def`), not used,
/// at most 30 days old (an expired one is deleted here) and not stamped ahead of the clock (kept);
/// the newest of them. Its name and itself, or why there is none, in words. Records that cannot be
/// read or trusted are their own answer, never a yes.
pub fn check_undo(s: &dyn Store, undo: &Request, now: i64) -> Result<(String, Record), String> {
    let path = match (undo.location, &undo.ident, &undo.old, &undo.new) {
        (Location::LogonTask, Ident::Task { path }, Data::TaskEnabled(false), Data::TaskEnabled(true)) => path,
        _ => return Err(NOT_RECORDED.into()),
    };
    let found = records(s).map_err(|e| format!("{NO_RECORDS} ({e})"))?;
    let (mut used, mut old, mut early) = (false, false, false);
    let mut best: Option<(String, Record)> = None;
    for (n, r) in found {
        if r.path != *path || r.def != undo.def {
            continue;
        }
        if expired(r.at, now) {
            let _ = s.delete(&n);
            old = true;
        } else if r.used.is_some() {
            used = true;
        } else if ahead(r.at, now) {
            early = true;
        } else if best.as_ref().is_none_or(|(_, b)| r.at >= b.at) {
            best = Some((n, r));
        }
    }
    match best {
        Some(b) => Ok(b),
        None if used => Err(USED.into()),
        None if early => Err(AHEAD.into()),
        None if old => Err(EXPIRED.into()),
        None => Err(NOT_RECORDED.into()),
    }
}

/// Mark the record `name` used once its Undo is done.
pub fn mark_used(s: &dyn Store, name: &str, r: &Record, now: i64) -> Result<(), String> {
    s.replace(name, &encode(&Record { used: Some(now), ..r.clone() }))
}

/// After a task switch-off the helper made (done): record it, with the task's whole definition
/// as it reads now, only while that reading is still the task the off was bound to (RB9-5: one
/// replaced under its path since the write gets none, so a record never attests a definition
/// the helper did not switch off). Err: no record was kept (its Undo will say so).
pub fn keep_off(pc: &dyn Pc, s: &dyn Store, r: &Request) -> Result<(), String> {
    let Ident::Task { path } = &r.ident else { return Err("not a task".into()) };
    let def = match crate::autostart::sys::step(|| def::read(pc, r.location, &r.ident)) {
        Ok(Some(f)) if f.binds(r.def, Some(false)) => f.def,
        Ok(Some(_)) => return Err("the task was replaced after it was switched off".into()),
        Ok(None) => return Err("the task is gone".into()),
        Err(e) => return Err(e),
    };
    let id = crate::helper::sys::random16().ok_or("no random id")?;
    record_off(s, &id, path, def, now())
}

/// A `task-undo` item that switches its task back on: with the helper's record of that off,
/// `switch::undo` (the lock lifted), the record then used; without one, `switch::apply`, whose
/// lock refusal then says why the Undo could not lift it.
pub fn undo_on(pc: &dyn Pc, s: &dyn Store, r: &Request) -> Outcome {
    let now = now();
    match check_undo(s, r, now) {
        Ok((name, rec)) => {
            let o = switch::undo(pc, r);
            if o == Outcome::Done {
                // Not marked (the key went unwritable in between): it stays good for one more
                // Undo, which the live task then has to match again (VibeScamCheck's rule).
                let _ = mark_used(s, &name, &rec, now);
            }
            o
        }
        Err(why) => match switch::apply(pc, r) {
            Outcome::Refused(w) if w == switch::WINDOWS_TASK => Outcome::Refused(format!("{w}; {why}")),
            o => o,
        },
    }
}

/// Whose an ACE or owner is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Who {
    System,
    Admins,
    Other,
}

/// One ACE as read: its type, flags, access mask and whose it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ace {
    pub kind: u8,
    pub flags: u8,
    pub mask: u32,
    pub who: Who,
}

const ACCESS_DENIED: u8 = 1;
const INHERIT_ONLY: u8 = 8;
/// Every right that changes a key or its values or security: set value, create subkey, create
/// link, delete, write DAC, write owner, generic write, generic all, maximum allowed.
pub const WRITE_RIGHTS: u32 = 0x2 | 0x4 | 0x20 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x4000_0000 | 0x1000_0000 | 0x0200_0000;

/// Only SYSTEM and Administrators can change the key: owned by one of them (an owner can always
/// rewrite the DACL), a DACL (none would let everyone in), and no ACE that applies to the key
/// and is not a deny gives anyone else a write right. An ACE of a type other than allow or deny
/// is judged as an allow (callback and object ACEs are not expected here).
pub fn admin_only(owner: Who, dacl: Option<&[Ace]>) -> bool {
    if owner == Who::Other {
        return false;
    }
    let Some(aces) = dacl else { return false };
    !aces.iter().any(|a| a.kind != ACCESS_DENIED && a.flags & INHERIT_ONLY == 0 && a.mask & WRITE_RIGHTS != 0 && a.who == Who::Other)
}

/// The real records, in `HKLM\SOFTWARE\VibeBoot`: the key made with its own security, owner and
/// DACL checked before every use, one REG_BINARY value per record. Used by `run_helper` only
/// (elevated); never by a test.
#[cfg(windows)]
pub struct Hklm;

#[cfg(windows)]
impl Store for Hklm {
    fn list(&self) -> Result<Vec<(String, Vec<u8>)>, String> {
        hklm::list()
    }

    fn put(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        hklm::put(name, bytes)
    }

    fn replace(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        hklm::replace(name, bytes)
    }

    fn delete(&self, name: &str) -> Result<(), String> {
        hklm::delete(name)
    }
}

#[cfg(windows)]
mod hklm {
    use super::{Ace, KEY, MAX_BYTES, SDDL, Who, admin_only};
    use crate::autostart::text::{os_words, wide};
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, LocalFree};
    use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::Registry::*;

    /// An open key, closed once.
    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: opened by RegOpenKeyExW / RegCreateKeyExW, closed once.
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn words(code: u32) -> String {
        format!("HKLM\\{KEY}: {}", os_words(code))
    }

    /// The key, made with its own security (`SDDL`) when it is not there yet.
    fn create() -> Result<Key, String> {
        create_at(HKEY_LOCAL_MACHINE, KEY, REG_OPTION_NON_VOLATILE)
    }

    /// The key to read: None when it is not there.
    fn open() -> Result<Option<Key>, String> {
        open_at(HKEY_LOCAL_MACHINE, KEY)
    }

    /// `create` under any root, kept or `REG_OPTION_VOLATILE` (the tests use a throwaway volatile
    /// key of HKCU's, never HKLM: RB9-2, VibeScamCheck's RU-6, RB10-2).
    fn create_at(root: HKEY, sub: &str, options: REG_OPEN_CREATE_OPTIONS) -> Result<Key, String> {
        let sddl = wide(SDDL);
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a NUL-terminated SDDL string; the descriptor is freed below.
        if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut psd, std::ptr::null_mut()) } == 0 {
            return Err(format!("HKLM\\{KEY}: its access rules could not be made"));
        }
        let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: psd, bInheritHandle: 0 };
        let name = wide(sub);
        let mut hk: HKEY = std::ptr::null_mut();
        // SAFETY: a NUL-terminated name, attributes that live through the call.
        let r = unsafe { RegCreateKeyExW(root, name.as_ptr(), 0, std::ptr::null(), options, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, &sa, &mut hk, std::ptr::null_mut()) };
        // SAFETY: made by the conversion above.
        unsafe { LocalFree(psd) };
        if r != 0 {
            return Err(words(r));
        }
        let k = Key(hk);
        trusted(&k)?;
        Ok(k)
    }

    /// `open` under any root (as `create_at`).
    fn open_at(root: HKEY, sub: &str) -> Result<Option<Key>, String> {
        let name = wide(sub);
        let mut hk: HKEY = std::ptr::null_mut();
        // SAFETY: a NUL-terminated name.
        let r = unsafe { RegOpenKeyExW(root, name.as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &mut hk) };
        if r == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if r != 0 {
            return Err(words(r));
        }
        let k = Key(hk);
        trusted(&k)?;
        Ok(Some(k))
    }

    fn who(sid: PSID) -> Who {
        // SAFETY: a SID inside a descriptor we hold.
        unsafe {
            if IsWellKnownSid(sid, WinLocalSystemSid) != 0 {
                Who::System
            } else if IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0 {
                Who::Admins
            } else {
                Who::Other
            }
        }
    }

    /// The key's owner and DACL, judged by `judged`.
    fn trusted(k: &Key) -> Result<(), String> {
        let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let mut need = 0u32;
        // SAFETY: a size query.
        let r = unsafe { RegGetKeySecurity(k.0, info, std::ptr::null_mut(), &mut need) };
        if r != ERROR_INSUFFICIENT_BUFFER || need == 0 {
            return Err(words(r));
        }
        let mut buf = vec![0u64; (need as usize).div_ceil(8)];
        let psd: PSECURITY_DESCRIPTOR = buf.as_mut_ptr().cast();
        // SAFETY: a buffer of `need` bytes.
        let r = unsafe { RegGetKeySecurity(k.0, info, psd, &mut need) };
        if r != 0 {
            return Err(words(r));
        }
        judged(psd)
    }

    /// A descriptor's owner and DACL (the owner read and the ACE walk), judged by `admin_only`.
    /// Apart from the key, so tests judge descriptors made from SDDL on any PC (RB10-1).
    fn judged(psd: PSECURITY_DESCRIPTOR) -> Result<(), String> {
        let mut owner: PSID = std::ptr::null_mut();
        let mut dflt = 0;
        let mut present = 0;
        let mut acl: *mut ACL = std::ptr::null_mut();
        // SAFETY: the descriptor read above; the pointers point into it.
        let ok = unsafe { GetSecurityDescriptorOwner(psd, &mut owner, &mut dflt) != 0 && GetSecurityDescriptorDacl(psd, &mut present, &mut acl, &mut dflt) != 0 };
        if !ok || owner.is_null() {
            return Err(format!("HKLM\\{KEY}: its owner could not be read"));
        }
        let owner = who(owner);
        let dacl = if present == 0 || acl.is_null() {
            None
        } else {
            let mut aces = Vec::new();
            // SAFETY: a DACL inside the descriptor; each ACE read through GetAce.
            unsafe {
                for i in 0..u32::from((*acl).AceCount) {
                    let mut p: *mut core::ffi::c_void = std::ptr::null_mut();
                    if GetAce(acl, i, &mut p) == 0 || p.is_null() {
                        return Err(format!("HKLM\\{KEY}: its access rules could not be read"));
                    }
                    let h = &*(p as *const ACE_HEADER);
                    // Allow and deny ACEs have the mask at 4 and the SID at 8; anything else is
                    // judged as someone else's.
                    let mask = std::ptr::read_unaligned((p as *const u8).add(4).cast::<u32>());
                    let who = if matches!(h.AceType, 0 | 1) { who((p as *mut u8).add(8).cast()) } else { Who::Other };
                    aces.push(Ace { kind: h.AceType, flags: h.AceFlags, mask, who });
                }
            }
            Some(aces)
        };
        if admin_only(owner, dacl.as_deref()) { Ok(()) } else { Err(format!("HKLM\\{KEY} can be changed by more than administrators")) }
    }

    /// A value's bytes (None: not there).
    fn read_value(k: &Key, name: &[u16]) -> Result<Option<Vec<u8>>, String> {
        let mut ty = 0u32;
        let mut n = 0u32;
        // SAFETY: a size query of a NUL-terminated name.
        let r = unsafe { RegQueryValueExW(k.0, name.as_ptr(), std::ptr::null(), &mut ty, std::ptr::null_mut(), &mut n) };
        if r == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if r != 0 {
            return Err(words(r));
        }
        if ty != REG_BINARY || n as usize > MAX_BYTES {
            return Err(format!("HKLM\\{KEY}: a record that is not one"));
        }
        let mut b = vec![0u8; n as usize];
        // SAFETY: a buffer of `n` bytes.
        let r = unsafe { RegQueryValueExW(k.0, name.as_ptr(), std::ptr::null(), &mut ty, b.as_mut_ptr(), &mut n) };
        if r != 0 {
            return Err(words(r));
        }
        b.truncate(n as usize);
        Ok(Some(b))
    }

    /// Every REG_BINARY value of a record's size, by name (others are not records: skipped).
    pub fn list() -> Result<Vec<(String, Vec<u8>)>, String> {
        let Some(k) = open()? else { return Ok(Vec::new()) };
        let (mut count, mut max_name, mut max_data) = (0u32, 0u32, 0u32);
        // SAFETY: counts and sizes only.
        let r = unsafe { RegQueryInfoKeyW(k.0, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), &mut count, &mut max_name, &mut max_data, std::ptr::null_mut(), std::ptr::null_mut()) };
        if r != 0 {
            return Err(words(r));
        }
        let mut out = Vec::new();
        let mut name = vec![0u16; max_name as usize + 1];
        let mut data = vec![0u8; max_data as usize];
        for i in 0..count {
            let mut nl = name.len() as u32;
            let mut dl = data.len() as u32;
            let mut ty = 0u32;
            // SAFETY: buffers of the sizes the key reported.
            let r = unsafe { RegEnumValueW(k.0, i, name.as_mut_ptr(), &mut nl, std::ptr::null(), &mut ty, data.as_mut_ptr(), &mut dl) };
            if r != 0 {
                // Changed while it was read (another helper): what was read stands.
                break;
            }
            if ty == REG_BINARY && dl as usize <= MAX_BYTES {
                out.push((String::from_utf16_lossy(&name[..nl as usize]), data[..dl as usize].to_vec()));
            }
        }
        Ok(out)
    }

    pub fn put(name: &str, bytes: &[u8]) -> Result<(), String> {
        let k = create()?;
        let n = wide(name);
        if read_value(&k, &n)?.is_some() {
            return Err(format!("HKLM\\{KEY}: the record {name} is there already"));
        }
        // SAFETY: a NUL-terminated name and `bytes`.
        let r = unsafe { RegSetValueExW(k.0, n.as_ptr(), 0, REG_BINARY, bytes.as_ptr(), bytes.len() as u32) };
        if r != 0 { Err(words(r)) } else { Ok(()) }
    }

    pub fn replace(name: &str, bytes: &[u8]) -> Result<(), String> {
        let k = create()?;
        let n = wide(name);
        if read_value(&k, &n)?.is_none() {
            return Err(format!("HKLM\\{KEY}: the record {name} is not there"));
        }
        // SAFETY: a NUL-terminated name and `bytes`.
        let r = unsafe { RegSetValueExW(k.0, n.as_ptr(), 0, REG_BINARY, bytes.as_ptr(), bytes.len() as u32) };
        if r != 0 { Err(words(r)) } else { Ok(()) }
    }

    pub fn delete(name: &str) -> Result<(), String> {
        let Some(_) = open()? else { return Ok(()) };
        let k = create()?;
        // SAFETY: a NUL-terminated name.
        let r = unsafe { RegDeleteValueW(k.0, wide(name).as_ptr()) };
        if r != 0 && r != ERROR_FILE_NOT_FOUND { Err(words(r)) } else { Ok(()) }
    }

}
