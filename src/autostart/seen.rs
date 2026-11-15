//! First seen: `seen.json` (a state file, `state::Store`), per PC (MachineGuid: one stick serves
//! many PCs), entry key to first and last seen. "New since the last look" marks the entries the
//! previous look at this PC did not have: the look is the newest scan of an earlier run of the
//! app (rescans in one sitting compare with the same baseline). Only locations the previous look
//! read count: an entry from a location that could not be read then is not "new" now. Pure.

use super::{DateFact, DateKind, Location};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The most entries remembered per PC (the oldest last-seen go first).
pub const MAX_ENTRIES: usize = 5_000;

/// The most PCs remembered (X15PRV-5): a stick goes from customer to customer, and each PC's
/// list is that customer's. The PCs looked at longest ago go first, told by the order of the
/// looks, never by a PC's clock (as ScamCheck's `kept::MAX_PCS`). A hundred keeps "new since
/// the last look" for return visits.
pub const MAX_PCS: usize = 100;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Seen {
    pub pcs: BTreeMap<String, PcSeen>,
    /// The PCs by their last look, the newest first, at most `MAX_PCS`. A PC it does not name
    /// (from a file written before it was kept) is older than every PC it names: such PCs go
    /// all together once it holds `MAX_PCS`, never some of them.
    pub recent: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PcSeen {
    /// Unix seconds of this PC's newest look.
    pub last_look: i64,
    /// The locations that look read (`Location::tag`).
    pub answered: Vec<String>,
    /// Entry key to (first seen, last seen), Unix seconds.
    pub entries: BTreeMap<String, (i64, i64)>,
    /// Location tag to the first look that read it (at the latest): an entry first seen after
    /// it was not there then.
    pub read_since: BTreeMap<String, i64>,
}

/// What a scan is compared with: this PC's previous look.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Baseline {
    pub last_look: Option<i64>,
    pub known: BTreeSet<String>,
    pub answered: BTreeSet<String>,
    pub first: BTreeMap<String, i64>,
    pub read_since: BTreeMap<String, i64>,
}

impl Baseline {
    /// New since the last look: there was one, it read this location, and did not have the key.
    pub fn is_new(&self, key: &str, loc: Location) -> bool {
        self.last_look.is_some() && self.answered.contains(loc.tag()) && !self.known.contains(key)
    }

    /// When the entry was first seen on this PC (None: never before).
    pub fn first_seen(&self, key: &str) -> Option<i64> {
        self.first.get(key).copied()
    }

    /// What this app's own looks say about when an entry came (for `dates::added`): Appeared
    /// when a look before the one that first saw it read its location (first seen at that look;
    /// `now` for one new at this look); KnownSince when it was there at the first look that read
    /// its location (it is at least that old, nothing more). None for an entry this PC's looks
    /// say nothing about.
    pub fn evidence(&self, key: &str, loc: Location, now: i64) -> Option<DateFact> {
        self.evidence_in(key, loc.tag(), now)
    }

    /// `evidence` for a task only a Full scan reads (one hidden from this account): judged by
    /// the Full scans' own reads (`FULL_TASKS`), not by this account's view of the tasks. The
    /// first Full scan on a PC says nothing about when such a task came: its own dates
    /// (registration, task file) do.
    pub fn evidence_hidden(&self, key: &str, now: i64) -> Option<DateFact> {
        self.evidence_in(key, FULL_TASKS, now)
    }

    fn evidence_in(&self, key: &str, tag: &str, now: i64) -> Option<DateFact> {
        match self.first.get(key) {
            Some(&first) => {
                let appeared = self.read_since.get(tag).is_some_and(|&r| r < first);
                Some(DateFact { kind: if appeared { DateKind::Appeared } else { DateKind::KnownSince }, at: first })
            }
            None => (self.last_look.is_some() && self.answered.contains(tag) && !self.known.contains(key)).then_some(DateFact { kind: DateKind::Appeared, at: now }),
        }
    }
}

/// The tag a Full scan's read of every task (hidden ones included) is recorded under, beside the
/// locations' tags.
pub const FULL_TASKS: &str = "LogonTaskFull";

impl Seen {
    /// This PC's previous look (empty for a PC never seen, or no PC id).
    pub fn baseline(&self, pc: &str) -> Baseline {
        let Some(p) = self.pcs.get(pc) else { return Baseline::default() };
        Baseline {
            last_look: (p.last_look > 0).then_some(p.last_look),
            known: p.entries.keys().cloned().collect(),
            answered: p.answered.iter().cloned().collect(),
            first: p.entries.iter().map(|(k, v)| (k.clone(), v.0)).collect(),
            read_since: p.read_since.clone(),
        }
    }

    /// A look at `pc` at `now`: every entry it found, and the locations it read.
    pub fn record(&mut self, pc: &str, now: i64, found: &[String], answered: &[Location]) {
        let tags: Vec<&str> = answered.iter().map(|l| l.tag()).collect();
        self.record_tags(pc, now, found, &tags);
    }

    /// `record` for a look that was a Full scan: its read of every task counts as `FULL_TASKS`
    /// too.
    pub fn record_full(&mut self, pc: &str, now: i64, found: &[String], answered: &[Location]) {
        let mut tags: Vec<&str> = answered.iter().map(|l| l.tag()).collect();
        tags.push(FULL_TASKS);
        self.record_tags(pc, now, found, &tags);
    }

    fn record_tags(&mut self, pc: &str, now: i64, found: &[String], answered: &[&str]) {
        let p = self.pcs.entry(pc.to_string()).or_default();
        let before = (p.last_look > 0).then_some(p.last_look);
        for l in answered {
            // A location an older file says was read, with no time: at the latest the last look.
            let was = if p.answered.iter().any(|a| a == l) { before.unwrap_or(now) } else { now };
            let r = p.read_since.entry(l.to_string()).or_insert(was);
            *r = (*r).min(now);
        }
        p.last_look = p.last_look.max(now);
        let mut tags: BTreeSet<String> = p.answered.iter().cloned().collect();
        tags.extend(answered.iter().map(|l| l.to_string()));
        p.answered = tags.into_iter().collect();
        for k in found {
            let e = p.entries.entry(k.clone()).or_insert((now, now));
            e.0 = e.0.min(now);
            e.1 = e.1.max(now);
        }
        if p.entries.len() > MAX_ENTRIES {
            let mut by_last: Vec<(i64, String)> = p.entries.iter().map(|(k, v)| (v.1, k.clone())).collect();
            by_last.sort();
            for (_, k) in by_last.into_iter().take(p.entries.len() - MAX_ENTRIES) {
                p.entries.remove(&k);
            }
        }
        self.recent.retain(|x| x != pc);
        self.recent.insert(0, pc.to_string());
        self.recent.truncate(MAX_PCS);
        if self.recent.len() == MAX_PCS {
            let recent = &self.recent;
            self.pcs.retain(|k, _| recent.contains(k));
        }
    }
}
