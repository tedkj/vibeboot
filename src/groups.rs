//! VibeBoot's face on the scanner: entries grouped by when they run, ranked, filtered, with the
//! Microsoft entries collapsed per group. Pure; the controller hands it what it knows.
//!
//! Groups, in order: "When you sign in" (Run keys, policy Run keys, startup folders), "When you
//! sign in (scheduled tasks)", "Once, at the next sign-in" (RunOnce), "When Windows starts
//! (services)", "When Windows starts (drivers)". Inside a group: not from Microsoft first, then
//! Microsoft's, each by name. The order is a rank made once per entry (group, Microsoft, the
//! name folded, the entry key), sorted as plain tuples: a total order, whatever the names hold.

use crate::autostart::{Entry, Location, SignInfo, Signer, dates};
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Group {
    SignIn,
    Tasks,
    Once,
    Services,
    Drivers,
}

impl Group {
    pub const ALL: [Group; 5] = [Group::SignIn, Group::Tasks, Group::Once, Group::Services, Group::Drivers];

    pub fn of(loc: Location) -> Group {
        match loc {
            Location::RunUser | Location::RunMachine | Location::RunMachine32 | Location::PolicyRunUser | Location::PolicyRunMachine | Location::StartupUser | Location::StartupCommon => Group::SignIn,
            Location::RunOnceUser | Location::RunOnceMachine | Location::RunOnceMachine32 => Group::Once,
            Location::LogonTask => Group::Tasks,
            Location::Service => Group::Services,
            Location::Driver => Group::Drivers,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Group::SignIn => "When you sign in",
            Group::Tasks => "When you sign in (scheduled tasks)",
            Group::Once => "Once, at the next sign-in",
            Group::Services => "When Windows starts (services)",
            Group::Drivers => "When Windows starts (drivers)",
        }
    }

    /// The short name a failure is told under ("Services: could not be read").
    pub fn short(self) -> &'static str {
        match self {
            Group::SignIn => "Run keys and startup folders",
            Group::Tasks => "Scheduled tasks",
            Group::Once => "RunOnce keys",
            Group::Services => "Services",
            Group::Drivers => "Drivers",
        }
    }

    pub fn locations(self) -> Vec<Location> {
        Location::ALL.into_iter().filter(|l| Group::of(*l) == self).collect()
    }

    pub fn index(self) -> usize {
        Group::ALL.iter().position(|g| *g == self).unwrap_or(0)
    }
}

/// What the list knows about an entry besides the entry itself.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Facts {
    /// None while its signer is being checked.
    pub sign: Option<SignInfo>,
    /// New since the last look.
    pub new: bool,
    /// An interpreter runs a command written into the entry itself (no script file): the signer
    /// is the interpreter's, not the command's.
    pub inline: bool,
    /// Its program is handed a file or URL from outside Windows' own folders (`Entry::through`):
    /// "runs C:\Users\x\evil.exe through rundll32.exe".
    pub through: Option<String>,
}

impl Facts {
    /// What the list knows about `e`: its signer (None while checked) and whether it is new.
    pub fn of(e: &Entry, sign: Option<SignInfo>, new: bool) -> Facts {
        Facts { sign, new, inline: inline(e), through: e.through.clone() }
    }

    /// The signer says nothing about what runs (`Entry::borrowed`).
    pub fn borrowed(&self) -> bool {
        self.inline || self.through.is_some()
    }

    /// A Microsoft program runs someone else's file: the words, flagged in the row.
    pub fn launched(&self) -> Option<&str> {
        matches!(self.sign.as_ref().map(|s| &s.signer), Some(Signer::Microsoft)).then_some(self.through.as_deref()).flatten()
    }
}

/// From Microsoft: signed by Microsoft, and running nothing of anyone else's: not an inline
/// command run by Microsoft's interpreter (an encoded PowerShell line is nobody's signed code),
/// not someone else's file handed to a Microsoft program (rundll32, explorer, msiexec…).
pub fn microsoft(f: &Facts) -> bool {
    !f.borrowed() && matches!(f.sign.as_ref().map(|s| &s.signer), Some(Signer::Microsoft))
}

/// Whether an entry runs a command written into itself (`cmdline::inline`, the scanner's rule:
/// the helper's Microsoft guard uses the same).
pub fn inline(e: &Entry) -> bool {
    crate::autostart::cmdline::inline(e.script, e.target.as_deref())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filters {
    /// Added in the last 30 days (by the best date, `dates::added`).
    pub recent: bool,
    pub new_only: bool,
    /// Microsoft's entries folded away per group.
    pub not_ms: bool,
    /// On name, publisher and command, case-insensitive.
    pub text: String,
}

impl Default for Filters {
    fn default() -> Self {
        Filters { recent: false, new_only: false, not_ms: true, text: String::new() }
    }
}

pub const RECENT_DAYS: i64 = 30;

/// One row of the list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Row {
    /// A group's head: its entries shown and in all, and what it could not read.
    Head { group: Group, shown: usize, total: usize, scanning: bool, failed: Option<String> },
    /// An entry (its index in the entries).
    Entry(usize),
    /// "41 from Microsoft: show" (or hide, when shown).
    Microsoft { group: Group, count: usize, open: bool },
}

/// The publisher in words, for the row and the text filter.
pub fn publisher(f: &Facts) -> String {
    if f.inline {
        return "a command (no file of its own)".into();
    }
    if let Some(t) = f.launched() {
        return t.to_string();
    }
    match f.sign.as_ref().map(|s| &s.signer) {
        None => "checking…".into(),
        Some(Signer::Microsoft) => "Microsoft".into(),
        Some(Signer::SignedBy(n)) => n.clone(),
        Some(Signer::NotSigned) => "not signed".into(),
        Some(Signer::Broken(_)) => "signature broken".into(),
        Some(Signer::Missing) => "file missing".into(),
        Some(Signer::Unknown(_)) => "unknown".into(),
    }
}

/// Whether an entry's best date (`dates::added`) is in the last 30 days.
pub fn recent(e: &Entry, now: i64) -> bool {
    dates::added(&e.dates).is_some_and(|d| d.at >= now - RECENT_DAYS * 86_400)
}

/// The 30-day filter's name, tooltip and the list's head: on a first look at a PC (no earlier
/// look to compare with) the filter cannot tell added from changed, and says so until the next
/// visit: "Changed lately (first look)", headed "First look on this PC: N entries changed in the
/// last 30 days". `recent` is how many entries the filter keeps.
pub fn recent_words(first_look: bool, recent: usize) -> (&'static str, &'static str, String) {
    if !first_look {
        return ("Added in the last 30 days", "Entries whose best date (shown with its source) is in the last 30 days", String::new());
    }
    let n = if recent == 1 { "1 entry".to_string() } else { format!("{recent} entries") };
    (
        "Changed lately (first look)",
        "First look on this PC: VibeBoot cannot yet tell what was added. Entries whose best date (a key's last change counts) is in the last 30 days; from the next look on, it tells added from changed",
        format!("First look on this PC: {n} changed in the last 30 days"),
    )
}

/// Whether an entry passes the filters (the Microsoft fold is not a filter: it is the view).
pub fn passes(e: &Entry, f: &Facts, filters: &Filters, now: i64) -> bool {
    if filters.new_only && !f.new {
        return false;
    }
    if filters.recent && !recent(e, now) {
        return false;
    }
    let needle = filters.text.trim().to_lowercase();
    if !needle.is_empty() {
        let hay = [e.name.to_lowercase(), publisher(f).to_lowercase(), e.raw.to_lowercase(), e.expanded.to_lowercase()];
        if !hay.iter().any(|h| h.contains(&needle)) {
            return false;
        }
    }
    true
}

/// The rank: group, Microsoft last, the name folded, the key. Made once per entry.
fn rank(e: &Entry, f: &Facts) -> (usize, bool, String, String) {
    (Group::of(e.location).index(), microsoft(f), e.name.to_lowercase(), e.key.clone())
}

/// The order of `entries`: indices sorted by rank (a total order).
pub fn order(entries: &[Entry], facts: &[Facts]) -> Vec<usize> {
    let mut ranked: Vec<((usize, bool, String, String), usize)> = entries.iter().zip(facts).enumerate().map(|(i, (e, f))| (rank(e, f), i)).collect();
    ranked.sort_unstable();
    ranked.into_iter().map(|(_, i)| i).collect()
}

/// The rows: per group its head, its entries not from Microsoft, then Microsoft's (folded into
/// one row while `filters.not_ms` and the group is not opened).
#[allow(clippy::too_many_arguments)]
pub fn rows(entries: &[Entry], facts: &[Facts], filters: &Filters, opened: &HashSet<Group>, answered: &HashSet<Location>, failed: &[(Location, String)], now: i64) -> Vec<Row> {
    let order = order(entries, facts);
    let mut out = Vec::new();
    for g in Group::ALL {
        let locs = g.locations();
        let in_group: Vec<usize> = order.iter().copied().filter(|&i| Group::of(entries[i].location) == g).collect();
        let shown: Vec<usize> = in_group.iter().copied().filter(|&i| passes(&entries[i], &facts[i], filters, now)).collect();
        let scanning = locs.iter().any(|l| !answered.contains(l));
        let fails: Vec<String> = failed.iter().filter(|(l, _)| locs.contains(l)).map(|(l, w)| format!("{}: {w}", l.label())).collect();
        let failed_text = if fails.is_empty() { None } else { Some(fails.join("; ")) };
        out.push(Row::Head { group: g, shown: shown.len(), total: in_group.len(), scanning, failed: failed_text });
        let (ms, other): (Vec<usize>, Vec<usize>) = shown.into_iter().partition(|&i| microsoft(&facts[i]));
        out.extend(other.into_iter().map(Row::Entry));
        if ms.is_empty() {
            continue;
        }
        if filters.not_ms {
            let open = opened.contains(&g);
            out.push(Row::Microsoft { group: g, count: ms.len(), open });
            if open {
                out.extend(ms.into_iter().map(Row::Entry));
            }
        } else {
            out.extend(ms.into_iter().map(Row::Entry));
        }
    }
    out
}

/// The summary's counts over every entry (filters aside).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub total: usize,
    pub not_ms: usize,
    pub unsigned: usize,
    pub broken: usize,
    pub missing: usize,
    pub checking: usize,
    pub new: usize,
    /// Entries something of which could not be read (a value too large, a task).
    pub unread: usize,
}

pub fn counts(entries: &[Entry], facts: &[Facts]) -> Counts {
    let mut c = Counts { total: entries.len(), ..Counts::default() };
    for (e, f) in entries.iter().zip(facts) {
        match f.sign.as_ref().map(|s| &s.signer) {
            None => c.checking += 1,
            Some(Signer::Microsoft) if !f.borrowed() => {}
            Some(s) => {
                c.not_ms += 1;
                match s {
                    Signer::NotSigned => c.unsigned += 1,
                    Signer::Broken(_) => c.broken += 1,
                    _ => {}
                }
            }
        }
        if e.file == crate::autostart::FileState::Missing {
            c.missing += 1;
        }
        if f.new {
            c.new += 1;
        }
        if e.unread.is_some() {
            c.unread += 1;
        }
    }
    c
}

/// "63 entries start with this PC: 22 not from Microsoft, 2 unsigned, 1 file missing".
pub fn summary(c: &Counts) -> String {
    let plural = |n: usize, one: &str, many: &str| if n == 1 { format!("1 {one}") } else { format!("{n} {many}") };
    let head = if c.total == 1 { "1 entry starts with this PC".to_string() } else { format!("{} entries start with this PC", c.total) };
    if c.checking > 0 {
        return format!("{head} · checking signatures {} of {}", c.total - c.checking, c.total);
    }
    let mut parts = vec![format!("{} not from Microsoft", c.not_ms)];
    if c.unsigned > 0 {
        parts.push(format!("{} unsigned", c.unsigned));
    }
    if c.broken > 0 {
        parts.push(plural(c.broken, "signature broken", "signatures broken"));
    }
    if c.missing > 0 {
        parts.push(plural(c.missing, "file missing", "files missing"));
    }
    if c.new > 0 {
        parts.push(format!("{} new", c.new));
    }
    if c.unread > 0 {
        parts.push(format!("{} could not be read", c.unread));
    }
    format!("{head}: {}", parts.join(", "))
}
