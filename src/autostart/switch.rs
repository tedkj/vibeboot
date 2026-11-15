//! The switches: what each kind writes, and the one way a change is made. Every change reads its
//! value, task or service again right before acting (VIBEWARE "what was read is a plan"): gone
//! since the scan, its definition not the one the list showed (`def`: an entry replaced under the
//! same name is another entry), or its data not what the change expects, and it is refused
//! ("changed since the scan: scan again"). After the write it reads back; anything but the new data is a failure.
//! Undo is the same call with old and new swapped, so it too acts only while the data still
//! equals what the app wrote. Nothing is ever deleted.
//!
//! The elevated helper runs the same `apply` (its own fresh read, its own checks): no change takes
//! a free path or command. A startup file's path is always the startup folder joined with the
//! file's name, never a path from the request.

use super::pc::Pc;
use super::def::{self, Def};
use super::{Hive, Ident, Location, Signer, approved, services, taskxml, text};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A switch's raw data.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Data {
    /// A StartupApproved value's bytes (REG_BINARY), None when there is no value.
    Approved(Option<Vec<u8>>),
    TaskEnabled(bool),
    /// A service's start type (2 automatic, 3 manual) and its delayed-start flag.
    ServiceStart { start: u32, delayed: bool },
}

impl Data {
    /// On, off, or neither (a StartupApproved value of another form).
    pub fn on(&self) -> Option<bool> {
        match self {
            Data::Approved(v) => approved::decode(v.as_deref().map(|b| (approved::REG_BINARY, b))).on(),
            Data::TaskEnabled(e) => Some(*e),
            Data::ServiceStart { start, .. } => match start {
                2 => Some(true),
                3 => Some(false),
                _ => None,
            },
        }
    }

    /// In words, for the journal: "enabled (02 00 00 00 …)", "Automatic (delayed start)".
    pub fn words(&self) -> String {
        match self {
            Data::Approved(None) => "no switch value (on)".into(),
            Data::Approved(Some(b)) => {
                let hex = b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ");
                match self.on() {
                    Some(true) => format!("on ({hex})"),
                    Some(false) => format!("off ({hex})"),
                    None => format!("unknown ({hex})"),
                }
            }
            Data::TaskEnabled(true) => "task enabled".into(),
            Data::TaskEnabled(false) => "task disabled".into(),
            Data::ServiceStart { start, delayed } => start_words(*start, *delayed).into(),
        }
    }
}

impl Data {
    /// In a word or two, for a list: "on", "off", "Manual", "Automatic (delayed start)".
    pub fn short(&self) -> String {
        match self {
            Data::Approved(_) => match self.on() {
                Some(true) => "on".into(),
                Some(false) => "off".into(),
                None => "unknown".into(),
            },
            Data::TaskEnabled(true) => "enabled".into(),
            Data::TaskEnabled(false) => "disabled".into(),
            Data::ServiceStart { start, delayed } => start_words(*start, *delayed).into(),
        }
    }
}

pub fn start_words(start: u32, delayed: bool) -> &'static str {
    match (start, delayed) {
        (0, _) => "Boot",
        (1, _) => "System",
        (2, true) => "Automatic (delayed start)",
        (2, false) => "Automatic",
        (3, _) => "Manual",
        (4, _) => "Disabled",
        _ => "Unknown",
    }
}

/// One change: on what (the entry by its name, and its definition as the list read it, bound as
/// `def::Fresh::bound` binds a change of its direction), from what, to what.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub location: Location,
    pub ident: Ident,
    pub def: Def,
    pub old: Data,
    pub new: Data,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Done,
    /// Not tried: the check before acting said no (changed since the scan, gone, not allowed).
    Refused(String),
    /// Tried, and Windows said no or the result does not read back.
    Failed(String),
}

/// The words for data that is not what the scan read.
pub const CHANGED: &str = "changed since the scan: scan again";
pub const GONE: &str = "gone since the scan: scan again";

/// A name a value or startup file can have: 1 to 260 units, no NUL, and (for files) no folder
/// part.
pub fn valid_name(name: &[u16], file: bool) -> bool {
    if name.is_empty() || name.len() > 260 || name.contains(&0) {
        return false;
    }
    if file {
        let bad = [u16::from(b'\\'), u16::from(b'/'), u16::from(b':')];
        let dots: Vec<u16> = "..".encode_utf16().collect();
        let dot: Vec<u16> = ".".encode_utf16().collect();
        if name.iter().any(|u| bad.contains(u)) || name == dots.as_slice() || name == dot.as_slice() {
            return false;
        }
    }
    true
}

/// The startup file a location's name stands for: the startup folder and the name, nothing else.
pub fn startup_path(pc: &dyn Pc, loc: Location, name: &[u16]) -> Option<PathBuf> {
    let common = match loc {
        Location::StartupUser => false,
        Location::StartupCommon => true,
        _ => return None,
    };
    if !valid_name(name, true) {
        return None;
    }
    use std::os::windows::ffi::OsStringExt;
    Some(pc.startup_folder(common)?.join(std::ffi::OsString::from_wide(name)))
}

/// The switch's data right now, and whether its entry is still there. Err: it could not be read.
pub fn read(pc: &dyn Pc, loc: Location, ident: &Ident) -> Result<(Data, bool), String> {
    match (loc, ident) {
        (Location::RunUser | Location::RunMachine | Location::RunMachine32, Ident::Value { name }) => {
            let (hive, path) = loc.reg().ok_or("no key")?;
            let exists = super::pc::value(pc, hive, path, name)?.is_some();
            Ok((approved_data(pc, loc, name)?, exists))
        }
        (Location::StartupUser | Location::StartupCommon, Ident::File { name, .. }) => {
            let path = startup_path(pc, loc, name).ok_or("not a startup file name")?;
            let exists = match pc.file(&path).state {
                super::FileState::Present => true,
                super::FileState::Missing => false,
                super::FileState::Unknown(e) => return Err(e),
                super::FileState::NoTarget => false,
            };
            Ok((approved_data(pc, loc, name)?, exists))
        }
        (Location::LogonTask, Ident::Task { path }) => match pc.task(path)? {
            Some(t) => Ok((Data::TaskEnabled(t.enabled), true)),
            None => Ok((Data::TaskEnabled(false), false)),
        },
        (Location::Service, Ident::Service { name }) => match pc.service(name)? {
            Some(s) => Ok((Data::ServiceStart { start: s.start, delayed: s.delayed }, true)),
            None => Ok((Data::ServiceStart { start: 0, delayed: false }, false)),
        },
        _ => Err("this entry has no switch".into()),
    }
}

fn approved_data(pc: &dyn Pc, loc: Location, name: &[u16]) -> Result<Data, String> {
    let (hive, sub) = loc.approved().ok_or("no switch")?;
    match pc.reg_value(hive, &sub.path(), name)? {
        None => Ok(Data::Approved(None)),
        Some((approved::REG_BINARY, b)) => Ok(Data::Approved(Some(b))),
        Some((kind, _)) => Err(format!("Windows' switch for it is a value of type {kind}, not one VibeBoot knows")),
    }
}

/// Whether a request has the right shape for its location (the helper's first check, and the
/// app's): the identity's kind, the data's kind, a writable value, a start type the switch uses.
pub fn well_formed(r: &Request) -> Result<(), String> {
    let ok = match (r.location, &r.ident, &r.old, &r.new) {
        (Location::RunUser | Location::RunMachine | Location::RunMachine32, Ident::Value { name }, Data::Approved(old), Data::Approved(Some(new))) => valid_name(name, false) && approved::writable(new) && old.as_ref().is_none_or(|o| o.len() == 12),
        (Location::StartupUser | Location::StartupCommon, Ident::File { name, .. }, Data::Approved(old), Data::Approved(Some(new))) => valid_name(name, true) && approved::writable(new) && old.as_ref().is_none_or(|o| o.len() == 12),
        (Location::LogonTask, Ident::Task { path }, Data::TaskEnabled(_), Data::TaskEnabled(_)) => valid_task_path(path),
        (Location::Service, Ident::Service { name }, Data::ServiceStart { start: os, delayed: od }, Data::ServiceStart { start, delayed }) => {
            valid_service_name(name) && matches!((start, delayed), (2, _) | (3, false)) && matches!((os, od), (2, _) | (3, _))
        }
        _ => false,
    };
    if ok { Ok(()) } else { Err("not a change VibeBoot makes".into()) }
}

/// A task path as the scan returns it: `\`-rooted, 1 to 1024 units, no NUL, no `..` part.
pub fn valid_task_path(p: &str) -> bool {
    let n = p.encode_utf16().count();
    (1..=1024).contains(&n) && p.starts_with('\\') && !p.contains('\0') && !p.split('\\').any(|s| s == "..")
}

/// A service name as `EnumServicesStatusExW` gives it: 1 to 256 units, no NUL, slash or
/// backslash.
pub fn valid_service_name(n: &str) -> bool {
    let c = n.encode_utf16().count();
    (1..=256).contains(&c) && !n.contains(['\0', '\\', '/'])
}

/// Why a service is Windows' own and left alone (the helper refuses it, the window locks it):
/// its program is signed by Microsoft and runs nothing of anyone else's (`borrowed`: no command
/// written into it, no file or URL from outside Windows' own folders handed to it), or its
/// program file is missing and it is on Windows' own service list (a damaged Windows, not a
/// leftover). None: VibeBoot may switch it. A missing file of any other service may be switched
/// off: it does nothing anyway.
pub fn windows_service(name: &str, signer: &Signer, borrowed: bool) -> Option<&'static str> {
    match signer {
        Signer::Microsoft if !borrowed => Some("Windows' own service (signed by Microsoft): left alone"),
        Signer::Missing if services::windows_own(name) => Some("Windows' own service (its program file is missing): left alone"),
        _ => None,
    }
}

/// Why a task is Windows' own and left alone (the helper refuses it, the window locks it): it
/// has one action, that action's program is signed by Microsoft, and it runs nothing of anyone
/// else's (`borrowed`, as for services). Its folder says nothing (anyone with admin rights can
/// register a task under `\Microsoft\`); a task with several actions is never locked, so a
/// Microsoft program in front cannot lock a second action of someone else's.
pub fn windows_task(single_action: bool, signer: Option<&Signer>, borrowed: bool) -> Option<&'static str> {
    if !single_action || borrowed {
        return None;
    }
    match signer {
        Some(Signer::Microsoft) => Some(WINDOWS_TASK),
        _ => None,
    }
}

/// `windows_task`'s words (VibeBoot's helper adds to them why a `task-undo` could not lift the
/// lock, RB8-1).
pub const WINDOWS_TASK: &str = "Windows' own task (its program is signed by Microsoft): left alone";

/// Why a task that would be Windows' own if its signer said Microsoft switches off only
/// (RB6-1, the one rule): its signer could not be checked, whatever the cause (a check held up
/// or cut short, a file held with share mode 0, a bare program name, a folder). Unknown proves
/// nothing, so it never locks: the lock is for a task Windows proves is its own, and a task its
/// own program can make unreadable would otherwise be one nobody can switch off. Switching it
/// off is always safe; switching it on waits for a signer. None: the signer says nothing here
/// (it answered, or the task could never be Windows' own).
pub fn unchecked_task(single_action: bool, signer: Option<&Signer>, borrowed: bool) -> Option<&'static str> {
    (single_action && !borrowed && matches!(signer, Some(Signer::Unknown(_)))).then_some("its program's signer could not be checked")
}

/// What a switch-off of a startup file the scan could not tell apart is bound to (RB6-2): its
/// identity was not read for want of time (its step's wait ran out). No digest is this one, so
/// a request bound to it is never `apply`'d as it is (`binds` never matches it: refused); the
/// change binds it first (`bind_now`).
pub const UNBOUND: Def = Def([0; 32]);

/// A switch-off bound to `UNBOUND`, bound now (RB6-2): to which entry it is as the change reads
/// it (a few reads of one file, each within its own limit). An off never runs anything, so
/// binding it to the file that is there when it is made is safe; an on is never bound this
/// way. The change worker runs the binds of a whole batch in one step (RB7-2, `Ctx::run`): one
/// not read before that step's wait ran out is refused in `LATE_BIND`'s words. Err: the refusal.
pub fn bind_now(pc: &dyn Pc, r: &Request) -> Result<(Request, def::Fresh), Outcome> {
    if r.def != UNBOUND || r.new.on() != Some(false) {
        return Err(Outcome::Refused("not a change VibeBoot makes".into()));
    }
    match def::read(pc, r.location, &r.ident) {
        Ok(Some(f)) => Ok((Request { def: f.bound(false), ..r.clone() }, f)),
        Ok(None) => Err(Outcome::Refused(GONE.into())),
        Err(e) if super::pc::spent(&e) => Err(Outcome::Refused(LATE_BIND.into())),
        Err(e) => Err(Outcome::Refused(format!("could not be read ({e})"))),
    }
}

/// The words for a switch-off bound when it is made whose file was not read before its batch's
/// wait ran out (RB7-2): nothing was written.
pub const LATE_BIND: &str = "which file it is could not be read in time (VibeBoot's wait for files here ran out), so it was not switched off: try again";

/// The words for an Undo whose entry is not as the change left it (its switch moved since, or the
/// entry under the name is another): scanning again never makes it undoable.
pub const UNDO_CHANGED: &str = "changed since this change was made: not undone (switch it in the list instead)";
pub const UNDO_GONE: &str = "gone since this change was made: not undone";

/// An Undo's outcome in an Undo's words (`UNDO_CHANGED`, `UNDO_GONE`); others as they are.
pub fn for_undo(o: Outcome) -> Outcome {
    match o {
        Outcome::Refused(w) if w == CHANGED => Outcome::Refused(UNDO_CHANGED.into()),
        Outcome::Refused(w) if w == GONE => Outcome::Refused(UNDO_GONE.into()),
        o => o,
    }
}

/// The words for a switch-on of an entry part of whose run could not be established
/// (`def::Fresh::off_only`).
pub fn off_only_words(why: &str) -> String {
    format!("{why}, so VibeBoot switches it off, never on")
}

/// The entry is still the one the request was made on: there, its definition the request's (not
/// one put in its place under the same name since; unknown is never a match; `Fresh::binds`), its
/// switch data the request's old. One part of whose run could not be established is switched off
/// only (the one rule, RB3: `def::Fresh::off_only`). Err: the refusal.
fn still(pc: &dyn Pc, r: &Request) -> Result<(), Outcome> {
    let (now, exists) = read(pc, r.location, &r.ident).map_err(|e| Outcome::Refused(format!("could not be read ({e})")))?;
    if !exists {
        return Err(Outcome::Refused(GONE.into()));
    }
    match def::read(pc, r.location, &r.ident) {
        Ok(Some(f)) => same(Ok(f), r)?,
        Ok(None) => return Err(Outcome::Refused(GONE.into())),
        Err(e) => return Err(Outcome::Refused(format!("could not be read ({e})"))),
    }
    if now != r.old {
        return Err(Outcome::Refused(CHANGED.into()));
    }
    Ok(())
}

/// A reading of the entry (the change's own, or the snapshot the Windows-own lock is judged on)
/// is the request's entry, and the request a switch the rule allows on it (RB3: off only, when
/// part of what it runs could not be established), or the refusal.
fn same(f: Result<def::Fresh, String>, r: &Request) -> Result<(), Outcome> {
    match f {
        Ok(f) if f.binds(r.def, r.new.on()) => match f.off_only {
            Some(why) if r.new.on() != Some(false) => Err(Outcome::Refused(off_only_words(&why))),
            _ => Ok(()),
        },
        Ok(_) => Err(Outcome::Refused(CHANGED.into())),
        Err(e) => Err(Outcome::Refused(format!("could not be read ({e})"))),
    }
}

/// A Run value's or startup shortcut's reading as the list reads it (`run::entry`,
/// `folders::entry`): its definition with what its command could not establish
/// (`cmdline::Command::unknown`, past the nesting or the ends VibeBoot follows) folded in as a gap
/// (`run::with_unknown`), both from one read of the entry (RIN1-11). The task and service arms
/// judge on such a reading already (`scan::task_snapshot`, the service's `with_unknown`). Any
/// other startup file runs no command line of its own: its reading is `def::read`'s. None: gone.
fn command_reading(pc: &dyn Pc, loc: Location, ident: &Ident) -> Result<Option<def::Fresh>, String> {
    use super::cmdline;
    match (loc, ident) {
        (Location::RunUser | Location::RunMachine | Location::RunMachine32, Ident::Value { name }) => {
            let (hive, path) = loc.reg().ok_or("no key")?;
            let Some((kind, data)) = super::pc::value(pc, hive, path, name)? else { return Ok(None) };
            let d = def::run_value(kind, &data);
            let unknown = super::pc::reg_text(kind, &data).and_then(|raw| cmdline::resolve(&cmdline::expand(&raw, &|n| pc.env(n)), &pc.sys_dirs(), &|p| pc.exists(p)).unknown);
            Ok(Some(super::run::with_unknown(def::Fresh { def: d, core: d, off_only: None }, unknown)))
        }
        (Location::StartupUser | Location::StartupCommon, Ident::File { name, .. }) if def::is_lnk(name) => {
            let path = startup_path(pc, loc, name).ok_or("not a startup file name")?;
            match pc.file(&path).state {
                super::FileState::Present => {}
                super::FileState::Missing | super::FileState::NoTarget => return Ok(None),
                super::FileState::Unknown(why) => return Err(why),
            }
            let lnk = pc.lnk(&path);
            let unknown = match &lnk {
                Ok(l) if !l.path.trim().is_empty() => {
                    let prog = cmdline::expand(&l.path, &|n| pc.env(n));
                    let args = cmdline::expand(&l.args, &|n| pc.env(n));
                    cmdline::analyze(std::path::Path::new(prog.trim()), &args, &pc.sys_dirs(), &|p| pc.exists(p)).unknown
                }
                _ => None,
            };
            def::startup_file(pc, &path, Some(&lnk)).map(|f| Some(super::run::with_unknown(f, unknown)))
        }
        _ => def::read(pc, loc, ident),
    }
}

/// Make one change: check, act, read back. The check runs first and again right before the write
/// (RB-4): a task's or service's lock needs its signer, which can take seconds on a share. One
/// step (`sys::step`, RB5-1): its file reads wait at most 25 s in all per kind, however many
/// (`sys::STEP_WAIT` and its grace), and its one signer check its own `sys::SIGN_WAIT` (20 s,
/// RB6-4) on top.
pub fn apply(pc: &dyn Pc, r: &Request) -> Outcome {
    super::sys::step(|| apply_now(pc, r, false))
}

/// The Journal Undo of VibeBoot's own recorded change (`journal::Journal::undo_request`): as
/// `apply`, with one difference (RB7-1). A task VibeBoot switched off while its signer was not
/// known (or not Microsoft's), which reads as Windows' own since, is switched back on: putting
/// back what VibeBoot found is VibeBoot undoing its own change, so the Windows-own lock does not
/// refuse it. Only that direction (an Undo that switches a locked task off is refused, as any
/// off of one is), only on the entry the off was made on (bound as every switch-on is, to the
/// task's whole definition as the off's record keeps it: `still`, `same`), and an unknown
/// signer still refuses it (`unchecked_task`). Every other switch-on of a locked task is
/// refused. That the request is such an Undo is the caller's to know: the app's for the user's
/// own task (no elevated step), and VibeBoot's helper calls it only with its own admin-only record
/// of that off (RB8-1); a port's helper must hold the same, never the journal's word.
pub fn undo(pc: &dyn Pc, r: &Request) -> Outcome {
    super::sys::step(|| apply_now(pc, r, true))
}

/// FS8: why a service was not switched to Manual: its note could not be kept.
pub const NOT_NOTED: &str = "VibeBoot could not keep its note of this change in the service's own settings (what lets it show the service and switch it back on later), so it was not switched off: nothing was changed";

fn apply_now(pc: &dyn Pc, r: &Request, undo: bool) -> Outcome {
    let o = apply_once(pc, r, undo);
    // FS8: switched back on: VibeBoot's note in the service's key goes (a failed or half-done
    // switch keeps it, so the service stays listed and switchable).
    if o == Outcome::Done
        && let (Ident::Service { name }, Data::ServiceStart { start: 2, .. }) = (&r.ident, &r.new)
    {
        services::clear_off_note(pc, name);
    }
    o
}

fn apply_once(pc: &dyn Pc, r: &Request, undo: bool) -> Outcome {
    if let Err(e) = well_formed(r) {
        return Outcome::Refused(e);
    }
    if let Err(o) = still(pc, r) {
        return o;
    }
    let wrote = match (&r.ident, &r.new) {
        (Ident::Value { name } | Ident::File { name, .. }, Data::Approved(Some(b))) => {
            // RIN1-11: judged, as tasks and services are, on the reading with what its command
            // could not establish as a gap: a switch-on of a Run value or shortcut nested past
            // what VibeBoot follows is refused whatever the request (or an old record) is bound
            // to; an off goes through, bound to which entry it is. `still` then checks again.
            match command_reading(pc, r.location, &r.ident) {
                Ok(Some(f)) => {
                    if let Err(o) = same(Ok(f), r) {
                        return o;
                    }
                }
                Ok(None) => return Outcome::Refused(GONE.into()),
                Err(e) => return Outcome::Refused(format!("could not be read ({e})")),
            }
            if let Err(o) = still(pc, r) {
                return o;
            }
            let (hive, sub) = r.location.approved().expect("well formed");
            pc.reg_set_binary(hive, &sub.path(), name, b)
        }
        (Ident::Task { path }, Data::TaskEnabled(on)) => {
            let t = match pc.task(path) {
                Ok(Some(t)) => t,
                Ok(None) => return Outcome::Refused(GONE.into()),
                Err(e) => return Outcome::Refused(format!("could not be read ({e})")),
            };
            match taskxml::parse(&t.xml) {
                Ok(d) if d.starts_with_pc() => {}
                Ok(_) => return Outcome::Refused("the task has no logon or boot trigger".into()),
                Err(e) => return Outcome::Refused(format!("the task could not be read ({e})")),
            }
            // Windows' own tasks are left alone, as its services are (the window locks them). The
            // lock is judged on the request's own task (not one put in its place since): the
            // snapshot whose definition, its COM handler's DLL included, was read with it.
            let Some((e, d)) = super::scan::task_snapshot(pc, &t) else {
                return Outcome::Refused("the task has no logon or boot trigger".into());
            };
            if let Err(o) = same(d, r) {
                return o;
            }
            // Its own step (RB6-4): the whole time a signer check may take, not what is left
            // of the change's.
            let sign = e.target.as_ref().map(|tg| super::sys::sign_step(|| pc.sign(tg).0.signer));
            let single = e.task.as_ref().is_some_and(|f| f.actions == 1);
            if let Some(why) = windows_task(single, sign.as_ref(), e.borrowed())
                && !(undo && r.new.on() == Some(true))
            {
                return Outcome::Refused(why.into());
            }
            if let Some(why) = unchecked_task(single, sign.as_ref(), e.borrowed())
                && r.new.on() != Some(false)
            {
                return Outcome::Refused(off_only_words(why));
            }
            if let Err(o) = still(pc, r) {
                return o;
            }
            pc.set_task_enabled(path, *on)
        }
        (Ident::Service { name }, Data::ServiceStart { start, delayed }) => {
            let svc = match pc.service(name) {
                Ok(Some(s)) => s,
                Ok(None) => return Outcome::Refused(GONE.into()),
                Err(e) => return Outcome::Refused(format!("could not be read ({e})")),
            };
            if svc.driver() {
                return Outcome::Refused("a driver: VibeBoot does not switch drivers".into());
            }
            let Some((target, borrowed, hosted, unknown)) = services::target(pc, &svc).and_then(|t| {
                let (b, h, u) = (t.borrowed(), services::hosted(&t), t.cmd.unknown);
                t.target.map(|p| (p, b, h, u))
            }) else {
                return Outcome::Refused("its program could not be told from its settings".into());
            };
            // The lock is judged on the request's own service, not one put in its place since.
            // One part of whose run could not be read is never Windows' own (RB3): its program's
            // signer says nothing of its DLL.
            // What its command could not establish is a gap here too (`run::with_unknown`).
            let fresh = super::run::with_unknown(def::service(pc, &svc, hosted), unknown);
            let partial = fresh.off_only.is_some();
            if let Err(o) = same(Ok(fresh), r) {
                return o;
            }
            match super::sys::sign_step(|| pc.sign(&target).0.signer) {
                Signer::Unknown(e) => return Outcome::Refused(format!("its program's signer could not be checked ({e})")),
                s => {
                    if let Some(why) = windows_service(name, &s, borrowed || partial) {
                        return Outcome::Refused(why.into());
                    }
                }
            }
            if let Err(o) = still(pc, r) {
                return o;
            }
            // FS8: the note first, in the service's own key: no note, no switch to Manual.
            if *start == 3
                && let Data::ServiceStart { start: was, delayed: was_delayed } = &r.old
                && let Err(e) = services::keep_off_note(pc, name, *was, *was_delayed)
            {
                return Outcome::Refused(format!("{NOT_NOTED} ({e})"));
            }
            pc.set_service_start(name, *start, *delayed)
        }
        _ => return Outcome::Refused("not a change VibeBoot makes".into()),
    };
    if let Err(e) = wrote {
        // A change may be two writes (a service's start type, then its delayed flag): what is
        // there now is read back and said, never assumed.
        return match read(pc, r.location, &r.ident) {
            Ok((after, true)) if after == r.new => Outcome::Done,
            Ok((after, true)) if after != r.old => Outcome::Failed(format!("{e}; it is now {}", after.words())),
            _ => Outcome::Failed(e),
        };
    }
    match read(pc, r.location, &r.ident) {
        Ok((after, true)) if after == r.new => Outcome::Done,
        Ok((after, _)) => Outcome::Failed(format!("it reads back as {}", after.words())),
        Err(e) => Outcome::Failed(format!("it could not be read back ({e})")),
    }
}

/// The request that switches an entry `on` or off from `old`, at `now` (FILETIME), bound to the
/// entry's definition as the list read it (`read`) as the one rule binds it (`Fresh::bound`: an
/// off to which entry it is, an on to all of what it runs, RB4-1): None when the entry has no
/// switch or its data has a form VibeBoot does not touch.
pub fn request_for(location: Location, ident: &Ident, read: &def::Fresh, old: &Data, on: bool, now: u64) -> Option<Request> {
    let new = match old {
        Data::Approved(v) => {
            if v.as_ref().is_some_and(|b| b.len() != 12) {
                return None;
            }
            Data::Approved(Some(approved::bytes_for(on, now).to_vec()))
        }
        Data::TaskEnabled(_) => Data::TaskEnabled(on),
        // Off: Manual, recording the delayed flag in the journal (old). On: Automatic, with the
        // delayed flag the service still carries (one a half-done switch left); the journal's own
        // undo puts back exactly what was there.
        Data::ServiceStart { start, delayed } => {
            if on {
                Data::ServiceStart { start: 2, delayed: *start == 3 && *delayed }
            } else if *start == 2 {
                let _ = delayed;
                Data::ServiceStart { start: 3, delayed: false }
            } else {
                return None;
            }
        }
    };
    if old.on() == Some(on) {
        return None;
    }
    let r = Request { location, ident: ident.clone(), def: read.bound(on), old: old.clone(), new };
    well_formed(&r).ok().map(|_| r)
}

/// Which hive a location's switch writes (HKCU needs no admin; HKLM goes to the helper).
pub fn hive(loc: Location) -> Option<Hive> {
    loc.approved().map(|(h, _)| h)
}

/// A name for the journal and messages, cleaned.
pub fn ident_words(i: &Ident) -> String {
    match i {
        Ident::Value { name } | Ident::File { name, .. } => text::units(name),
        Ident::Task { path } => text::clean(path),
        Ident::Service { name } => text::clean(name),
    }
}
