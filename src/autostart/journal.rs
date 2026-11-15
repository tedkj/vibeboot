//! The journal: `journal.json` (a state file, `state::Store`), every change per PC with its
//! exact old and new data and its status. A change is written "pending" before it is made and
//! "done", "failed" (tried) or "refused" (not tried: nothing written) after. Undo puts the old data back only while the current data still
//! equals what the app wrote, on the entry the change was made on (the record keeps the entry's
//! definition, `def` and `core`, and the Undo is bound to the one its direction takes:
//! `switch::apply` with old and new swapped checks exactly that);
//! otherwise "changed since; not undone". A pending record found at start is checked against the
//! live data and settled. Pure: the app reads the PC and keeps the file.

use super::def::Def;
use super::switch::{Data, Request};
use super::{Ident, Location};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The most records kept (the oldest settled ones go first; pending ones always stay).
pub const MAX_RECORDS: usize = 2_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Pending,
    Done,
    /// Tried, and Windows said no or it did not read back: it may have half happened.
    Failed(String),
    /// Not tried: the check before acting said no (changed since the scan, gone, Windows' own).
    /// Nothing was written.
    Refused(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    /// Unix seconds.
    pub time: i64,
    /// The PC's MachineGuid.
    pub pc: String,
    /// The app run that made it ("Undo all from this session").
    pub session: String,
    pub location: Location,
    pub key: String,
    /// The entry's name as shown then (cleaned).
    pub name: String,
    pub ident: Ident,
    /// The entry's definition as the list read it (`def::Fresh::def`, all of what it runs): what
    /// an Undo that switches it on is bound to. None in records from before it was kept: those
    /// are never undone.
    #[serde(default)]
    pub def: Option<Def>,
    /// Which entry it was (`def::Fresh::core`): what an Undo that switches it off is bound to
    /// (RB4-1). None in records from before it was kept: such an Undo is not offered.
    #[serde(default)]
    pub core: Option<Def>,
    /// The version of the encoding `def` was made with (`def::VERSION`); 0 in records from before
    /// it was kept. A record of another version is never undone, except a Run value's
    /// (`def::comparable`, RB2-6).
    #[serde(default)]
    pub def_v: u8,
    /// The change was made while part of what the entry runs could not be established, and why
    /// (`Entry::off_only`: `def` is which entry it is alone). Its Undo would switch it on, which
    /// the rule never does on such a reading (RB3-5): it has none.
    #[serde(default)]
    pub off_only: Option<String>,
    pub old: Data,
    pub new: Data,
    pub status: Status,
    /// This record undoes that one.
    #[serde(default)]
    pub undo_of: Option<String>,
    /// How a pending record found at start was settled.
    #[serde(default)]
    pub settled: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Journal {
    pub records: Vec<Record>,
}

/// Why a record cannot be undone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoUndo {
    NotDone,
    AlreadyUndone,
    IsAnUndo,
    UndoPending,
    /// Recorded without the entry's definition: which entry it was cannot be told.
    NoDefinition,
    /// An on recorded before VibeBoot kept which entry it was apart from what it runs (`core`,
    /// round 7): its Undo, a switch-off, is bound to that alone, which the record lacks (RB5-6).
    NoCore,
    /// Recorded by an earlier VibeBoot that read the entry's definition another way: this one
    /// cannot tell whether it is the same entry.
    OldDefinition,
    /// Switched off while part of what it runs could not be established: switching it back on is
    /// bound to all of what it runs, which this change never read (RB3-5).
    OffOnly,
}

impl NoUndo {
    pub fn words(self) -> &'static str {
        match self {
            NoUndo::NotDone => "it was not done",
            NoUndo::AlreadyUndone => "already undone",
            NoUndo::IsAnUndo => "an undo is not undone (switch the entry instead)",
            NoUndo::UndoPending => "its undo is on its way",
            NoUndo::NoDefinition => "recorded before VibeBoot kept what the entry runs, so which entry it was cannot be told (switch it in the list instead)",
            NoUndo::NoCore => "switched on by an earlier VibeBoot that did not keep which entry it was apart from what it runs, so its switch-off cannot be bound to it (switch it off in the list instead)",
            NoUndo::OldDefinition => "recorded by an earlier VibeBoot that read the entry another way, so this one cannot tell it is the same entry (switch it in the list instead)",
            NoUndo::OffOnly => "switched off while VibeBoot could not tell all of what it runs, and it never switches such an entry on (switch it on in the list once the list shows what it runs)",
        }
    }
}

impl Journal {
    /// Add a record or replace the one with its id (a change re-applied onto a fresh read of the
    /// file lands once).
    pub fn upsert(&mut self, r: Record) {
        match self.records.iter_mut().find(|x| x.id == r.id) {
            Some(x) => *x = r,
            None => self.records.push(r),
        }
        if self.records.len() > MAX_RECORDS {
            let extra = self.records.len() - MAX_RECORDS;
            let mut dropped = 0;
            self.records.retain(|x| {
                if dropped < extra && x.status != Status::Pending {
                    dropped += 1;
                    false
                } else {
                    true
                }
            });
        }
    }

    pub fn get(&self, id: &str) -> Option<&Record> {
        self.records.iter().find(|r| r.id == id)
    }

    /// This PC's records, newest first (by time, then by place in the file: a total order).
    pub fn newest_first(&self, pc: &str) -> Vec<&Record> {
        let mut v: Vec<(usize, &Record)> = self.records.iter().enumerate().filter(|(_, r)| r.pc == pc).collect();
        v.sort_by_key(|(i, r)| (std::cmp::Reverse(r.time), std::cmp::Reverse(*i)));
        v.into_iter().map(|(_, r)| r).collect()
    }

    /// The done record that undid `id`.
    pub fn undone_by(&self, id: &str) -> Option<&Record> {
        self.records.iter().find(|r| r.undo_of.as_deref() == Some(id) && r.status == Status::Done)
    }

    pub fn can_undo(&self, id: &str) -> Result<&Record, NoUndo> {
        let r = self.get(id).ok_or(NoUndo::NotDone)?;
        if r.status != Status::Done {
            return Err(NoUndo::NotDone);
        }
        if r.undo_of.is_some() {
            return Err(NoUndo::IsAnUndo);
        }
        if self.undone_by(id).is_some() {
            return Err(NoUndo::AlreadyUndone);
        }
        if self.records.iter().any(|x| x.undo_of.as_deref() == Some(id) && x.status == Status::Pending) {
            return Err(NoUndo::UndoPending);
        }
        // Its Undo is bound as every change is (`def::Fresh::bound`, RB4-1): one that switches it
        // back on to all of what it ran, one that switches it back off to which entry it was.
        if undo_on(r) && r.def.is_none() {
            return Err(NoUndo::NoDefinition);
        }
        if !undo_on(r) && r.core.is_none() {
            return Err(NoUndo::NoCore);
        }
        if !super::def::comparable(r.location, r.def_v) {
            return Err(NoUndo::OldDefinition);
        }
        // Its Undo would switch it on (back to what was there), bound to a reading that never
        // held all of what it runs: it could never succeed (RB3-5).
        if r.off_only.is_some() && undo_on(r) {
            return Err(NoUndo::OffOnly);
        }
        Ok(r)
    }

    /// The change that undoes `id`: from what the app wrote back to what was there, on the entry
    /// the change was made on (its definition then: `switch::apply` refuses another). Where there
    /// was no StartupApproved value (Windows' "on"), Undo writes Task Manager's "on" bytes: the
    /// same switch, and nothing is ever deleted.
    pub fn undo_request(&self, id: &str) -> Result<Request, NoUndo> {
        let r = self.can_undo(id)?;
        let def = if undo_on(r) { r.def.ok_or(NoUndo::NoDefinition)? } else { r.core.ok_or(NoUndo::NoCore)? };
        let back = match &r.old {
            Data::Approved(None) => Data::Approved(Some(super::approved::enable_bytes().to_vec())),
            other => other.clone(),
        };
        Ok(Request { location: r.location, ident: r.ident.clone(), def, old: r.new.clone(), new: back })
    }

    /// What was there before the newest done change of `key` that left `now`: the data a switch
    /// back puts in place (a service set to Manual returns to its delayed start). None when no
    /// done change of this PC left the entry as it is now.
    pub fn recorded_before(&self, pc: &str, key: &str, now: &Data) -> Option<Data> {
        let r = self.newest_first(pc).into_iter().find(|r| r.key == key && r.status == Status::Done)?;
        (r.new == *now).then(|| r.old.clone())
    }

    /// This PC's records still pending (a crash between "pending" and "done").
    pub fn pending(&self, pc: &str) -> Vec<&Record> {
        self.records.iter().filter(|r| r.pc == pc && r.status == Status::Pending).collect()
    }

    /// Services the app switched to Manual on this PC and nobody switched back: the newest tried
    /// record for the service (done, or failed: a two-step write may have changed it halfway)
    /// was a change to Manual. A refused change was never tried (nothing written): it does not
    /// count. The scan lists those that are Manual now, with their real state.
    pub fn switched_off_services(&self, pc: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let mut seen = BTreeSet::new();
        for r in self.newest_first(pc) {
            if r.location != Location::Service || matches!(r.status, Status::Pending | Status::Refused(_)) || !seen.insert(r.key.clone()) {
                continue;
            }
            if let (Ident::Service { name }, Data::ServiceStart { start: 3, .. }) = (&r.ident, &r.new) {
                out.insert(name.clone());
            }
        }
        out
    }
}

/// Whether undoing `r` switches its entry on (back to what was there): anything but off.
fn undo_on(r: &Record) -> bool {
    r.old.on() != Some(false)
}

/// How a pending record stands against the live data: the new data is there (done), the old
/// data is there (the change did not happen), or something else (changed since by someone
/// else). None while the live data cannot be read (it stays pending: unknown is not settled).
pub fn settle(r: &Record, live: Result<(Data, bool), String>) -> Option<(Status, String)> {
    let (data, exists) = live.ok()?;
    if !exists {
        return Some((Status::Failed("gone since".into()), "settled at start: the entry is gone".into()));
    }
    if data == r.new {
        Some((Status::Done, "settled at start: the change had been made".into()))
    } else if data == r.old {
        Some((Status::Failed("not made: VibeBoot stopped before the change".into()), "settled at start: the change had not been made".into()))
    } else {
        Some((Status::Failed("changed since by something else".into()), "settled at start: neither the old nor the new data is there".into()))
    }
}
