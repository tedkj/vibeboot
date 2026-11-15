//! Switches and the admin queue (pure). Which way a switch goes:
//!
//! - HKCU entries (Run, startup folder) and the user's own tasks change at once, no admin.
//! - HKLM entries (Run, Run32, common startup folder), other tasks and services need the helper:
//!   switching one queues it; the bar says "3 changes need administrator rights: Apply /
//!   Discard". Apply runs one helper job per kind (at most three prompts: startup, tasks,
//!   services).
//! - Services: off is Manual (3) from Automatic (2), the delayed flag kept in the journal; on is
//!   what the journal recorded (the journal's Undo), or Automatic. Windows' own services and
//!   tasks are left alone (`windows_own`; the helper refuses them too). Drivers, RunOnce and
//!   policy entries have no switch.

use crate::autostart::def::Fresh;
use crate::autostart::switch::{self, Request};
use crate::autostart::{Entry, Ident, Location, Signer, Switch};
use crate::groups::Facts;
use crate::helper::Job;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// Made now, by the app.
    Direct(Request),
    /// Queued for the helper's job.
    Admin(Job, Request),
    /// No switch, and why.
    Not(String),
}

/// Where switching `e` on (or off) goes, at `now` (FILETIME, for Task Manager's bytes).
pub fn route(e: &Entry, f: &Facts, on: bool, now: u64) -> Route {
    match &e.switch {
        Switch::Fixed(w) | Switch::Unknown(w) => return Route::Not(w.clone()),
        _ => {}
    }
    let Some(data) = e.data.as_ref() else { return Route::Not("its switch could not be read".into()) };
    // The change is bound to the entry as the list read it (`autostart::def`), as the one rule binds
    // its direction (`Fresh::bound`): never without it (a startup file not read in time: its
    // off is bound when it is made, `reading`).
    let Some(read) = reading(e) else { return Route::Not("what it runs could not be read, so VibeBoot leaves it alone".into()) };
    // Part of it could not be read (a startup file's bytes): switched off, never on (RB2-2).
    if let Some(why) = &e.off_only
        && on
    {
        return Route::Not(switch::off_only_words(why));
    }
    if matches!(e.location, Location::Service | Location::LogonTask) {
        if let Some(why) = windows_own(e, f) {
            return Route::Not(why.replace("left alone", "VibeBoot leaves it alone"));
        }
        if let Some(why) = unchecked(e, f)
            && on
        {
            return Route::Not(switch::off_only_words(why));
        }
        match f.sign.as_ref().map(|s| &s.signer) {
            None => return Route::Not("its signature is still being checked".into()),
            Some(Signer::Unknown(_)) if e.location == Location::Service => return Route::Not("its program's signature could not be checked, so VibeBoot leaves it alone".into()),
            _ => {}
        }
    }
    let Some(req) = switch::request_for(e.location, &e.ident, &read, data, on, now) else {
        return Route::Not(if data.on() == Some(on) { "it is already that way".into() } else { "VibeBoot does not switch this one".into() });
    };
    match e.location {
        Location::RunUser | Location::StartupUser => Route::Direct(req),
        Location::LogonTask if e.task.as_ref().is_some_and(|t| t.own) => Route::Direct(req),
        loc => match Job::for_location(loc) {
            Some(job) => Route::Admin(job, req),
            None => Route::Not("VibeBoot does not switch this one".into()),
        },
    }
}

/// Why an entry is Windows' own and has a lock instead of a switch (the helper refuses the same,
/// `switch::windows_service` and `switch::windows_task`): a service signed by Microsoft that
/// runs nothing of anyone else's, or on Windows' own list with its file missing; a task whose one
/// program is signed by Microsoft and runs nothing of anyone else's. A task whose signer could not
/// be checked is never locked: it switches off only (`unchecked`, RB6-1).
pub fn windows_own(e: &Entry, f: &Facts) -> Option<&'static str> {
    let sig = f.sign.as_ref().map(|s| &s.signer);
    match (e.location, &e.ident) {
        (Location::Service, Ident::Service { name }) => sig.and_then(|s| switch::windows_service(name, s, f.borrowed())),
        (Location::LogonTask, Ident::Task { .. }) => switch::windows_task(single(e), task_signer(e, f), f.borrowed()),
        _ => None,
    }
}

/// Why a task switches off only for want of its signer (`switch::unchecked_task`, RB6-1), as
/// `switch::apply` judges it.
pub fn unchecked(e: &Entry, f: &Facts) -> Option<&'static str> {
    match (e.location, &e.ident) {
        (Location::LogonTask, Ident::Task { .. }) => switch::unchecked_task(single(e), task_signer(e, f), f.borrowed()),
        _ => None,
    }
}

fn single(e: &Entry) -> bool {
    e.task.as_ref().is_some_and(|t| t.actions == 1)
}

/// A task's signer as `switch::apply` asks for it: a task with no program file has none.
fn task_signer<'a>(e: &Entry, f: &'a Facts) -> Option<&'a Signer> {
    e.target.as_ref().and(f.sign.as_ref().map(|s| &s.signer))
}

/// The entry's reading a change is bound to (`Entry::reading`). A startup file whose identity
/// was not read because its step's wait ran out (RB6-2: off only, no definition) reads as
/// `switch::UNBOUND`: its off is bound when it is made (`switch::bind_now`), never its on.
pub fn reading(e: &Entry) -> Option<Fresh> {
    e.reading().or_else(|| {
        let late = matches!(e.location, Location::StartupUser | Location::StartupCommon) && e.def.is_none() && e.data.is_some();
        late.then(|| e.off_only.clone()).flatten().map(|why| Fresh { def: switch::UNBOUND, core: switch::UNBOUND, off_only: Some(why) })
    })
}

/// A change waiting for administrator rights.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Queued {
    pub key: String,
    pub name: String,
    pub job: Job,
    pub req: Request,
    /// The entry as the list read it (`Entry::reading`): its record keeps both of its bindings
    /// for the Undo (RB4-1), and no Undo when it switches off only (RB3-5).
    pub read: crate::autostart::def::Fresh,
}

impl Queued {
    /// The switch as it will be once applied.
    pub fn on(&self) -> Option<bool> {
        self.req.new.on()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Queue {
    pub items: Vec<Queued>,
}

impl Queue {
    /// Queue a change, or take a queued one back (switching the same entry again puts it back as
    /// it is: nothing to apply). True when it is queued now.
    pub fn toggle(&mut self, q: Queued) -> bool {
        if let Some(i) = self.items.iter().position(|x| x.key == q.key) {
            self.items.remove(i);
            return false;
        }
        self.items.push(q);
        true
    }

    pub fn get(&self, key: &str) -> Option<&Queued> {
        self.items.iter().find(|q| q.key == key)
    }

    pub fn remove(&mut self, key: &str) {
        self.items.retain(|q| q.key != key);
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The helper runs, in order (startup, tasks, services), each at most 64 items.
    pub fn jobs(&self) -> Vec<(Job, Vec<Queued>)> {
        let mut out = Vec::new();
        for job in [Job::StartupSet, Job::TaskSet, Job::ServiceStart] {
            let all: Vec<Queued> = self.items.iter().filter(|q| q.job == job).cloned().collect();
            for chunk in all.chunks(crate::helper::MAX_ITEMS) {
                out.push((job, chunk.to_vec()));
            }
        }
        out
    }

    /// "3 changes need administrator rights".
    pub fn bar_text(&self) -> String {
        match self.items.len() {
            0 => String::new(),
            1 => "1 change needs administrator rights".into(),
            n => format!("{n} changes need administrator rights"),
        }
    }
}
