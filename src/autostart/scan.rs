//! The scan, location by location. Each part answers for its locations: entries, or the reason a
//! location could not be read (never an empty list in its place). Signers come after, per target
//! (`signer`), so the list can show what it has meanwhile.

use super::pc::{Account, Pc, Service, TaskRaw};
use super::run::target_facts;
use super::switch::Data;
use super::taskxml::{self, Action, TaskDef};
use super::{DateFact, DateKind, Entry, FileState, Hive, Ident, Location, ServiceFacts, Switch, TaskFacts, cmdline, dates, entry_key, folders, run, services, tasks, text};
use std::path::PathBuf;

/// What one part of the scan found.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Part {
    pub entries: Vec<Entry>,
    /// Locations that could not be read, and why.
    pub failed: Vec<(Location, String)>,
    /// Locations this part answered for (read or failed).
    pub answered: Vec<Location>,
}

impl Part {
    fn take(&mut self, loc: Location, r: Result<Vec<Entry>, String>) {
        self.answered.push(loc);
        match r {
            Ok(mut e) => self.entries.append(&mut e),
            Err(why) => self.failed.push((loc, why)),
        }
    }
}

/// Every Run-style key, each one step (`sys::step`, RB5-1: its file reads wait at most 25 s in
/// all per kind, `sys::STEP_WAIT` and its grace, however many values point at held or
/// unreachable files).
pub fn registry(pc: &dyn Pc) -> Part {
    let mut p = Part::default();
    for loc in Location::RUN_KEYS {
        p.take(loc, super::sys::step(|| run::scan(pc, loc)));
    }
    p
}

/// Both startup folders, each one step (`sys::step`, RB5-1).
pub fn startup_folders(pc: &dyn Pc) -> Part {
    let mut p = Part::default();
    for loc in [Location::StartupUser, Location::StartupCommon] {
        p.take(loc, super::sys::step(|| folders::scan(pc, loc)));
    }
    p
}

/// Tasks as this account sees them, or as the helper read them (a full scan).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TaskPart {
    pub part: Part,
    /// How many tasks were read in all (logon or not).
    pub total: usize,
    /// What could not be read on the way.
    pub unread: Vec<String>,
}

/// The well-known accounts' names.
pub fn account_words(user: &str) -> String {
    let u = user.trim();
    match u.to_ascii_uppercase().as_str() {
        "S-1-5-18" | "SYSTEM" | "NT AUTHORITY\\SYSTEM" => "SYSTEM".into(),
        "S-1-5-19" => "LOCAL SERVICE".into(),
        "S-1-5-20" => "NETWORK SERVICE".into(),
        "S-1-5-32-544" => "Administrators".into(),
        "S-1-5-32-545" => "Users".into(),
        "S-1-5-4" => "INTERACTIVE".into(),
        _ => text::clean(u),
    }
}

/// A task this account may switch without admin rights: it runs as this account (by SID or
/// name) without the highest privileges. Anything else goes to the helper.
pub fn own_task(def: &TaskDef, me: &Account) -> bool {
    is_me(def.user.as_deref().unwrap_or(""), me) && !def.run_level.as_deref().is_some_and(|l| l.eq_ignore_ascii_case("HighestAvailable"))
}

/// A task's account is this one (by SID, DOMAIN\name or name).
pub fn is_me(user: &str, me: &Account) -> bool {
    let user = user.trim();
    !user.is_empty() && (user.eq_ignore_ascii_case(&me.sid) || user.eq_ignore_ascii_case(&me.name) || me.name.rsplit('\\').next().is_some_and(|n| !n.is_empty() && user.eq_ignore_ascii_case(n)))
}

/// A class id as a key name (`{8-4-4-4-12}`, trimmed); None for anything else (never a path).
pub fn clsid(s: &str) -> Option<&str> {
    let c = s.trim();
    (c.starts_with('{') && c.ends_with('}') && c.len() == 38 && c[1..37].bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')).then_some(c)
}

/// One task as an entry, when it starts with the PC (an enabled logon or boot trigger) or its
/// definition cannot be read (unknown is its own answer: it is listed, and left alone).
pub fn task_entry(pc: &dyn Pc, t: &TaskRaw) -> Option<Entry> {
    task_snapshot(pc, t).map(|(e, _)| e)
}

/// `task_entry`, with its definition as read in the same pass (Err: why it could not be): the
/// Windows-own lock is judged on this snapshot, its COM handlers resolved once for what it
/// shows, signs and fingerprints (RB2-3).
pub fn task_snapshot(pc: &dyn Pc, t: &TaskRaw) -> Option<(Entry, Result<super::def::Fresh, String>)> {
    let ident = Ident::Task { path: t.path.clone() };
    let mut e = Entry {
        location: Location::LogonTask,
        key: entry_key(Location::LogonTask, &ident),
        ident,
        name: text::clean(tasks::name_of(&t.path)),
        raw: String::new(),
        expanded: String::new(),
        target: None,
        file: FileState::NoTarget,
        file_key: None,
        script: false,
        hidden: false,
        through: None,
        note: None,
        switch: if t.enabled { Switch::On } else { Switch::Off { since: None } },
        data: Some(Data::TaskEnabled(t.enabled)),
        place: text::clean(&t.path),
        dates: Vec::new(),
        account: None,
        task: None,
        service: None,
        unread: None,
        def: None,
        core: None,
        off_only: None,
    };
    let last_run = dates::ole_parts(t.last_run).and_then(|p| pc.local_to_unix(p.0, p.1, p.2, p.3, p.4, p.5));
    let mut facts = TaskFacts { enabled: t.enabled, state: tasks::state_words(t.state).into(), last_run, last_result: if last_run.is_some() || t.last_result != 0x41303 { tasks::result_words(t.last_result) } else { "never run".into() }, ..TaskFacts::default() };
    let def = match taskxml::parse(&t.xml) {
        Ok(d) => d,
        Err(why) => {
            // Windows never hands over an empty definition: empty is one VibeBoot did not get (over
            // its size limit, or Windows would not give it).
            let why = if t.xml.is_empty() { format!("its definition could not be read (over {} KB, or Windows would not hand it over)", taskxml::MAX_XML / 1024) } else { format!("its definition could not be read: {why}") };
            e.note = Some(format!("{why}; whether it starts with this PC is not known"));
            e.unread = Some(why.clone());
            e.switch = Switch::Fixed("its definition could not be read, so VibeBoot cannot tell what it runs: left alone".into());
            e.data = None;
            e.task = Some(facts);
            return Some((e, Err(why)));
        }
    };
    if !def.starts_with_pc() {
        return None;
    }
    let (fingerprint, mut coms) = match super::def::task_read(pc, &t.xml) {
        Ok((d, c)) => (Ok(d), c.into_iter()),
        Err(why) => (Err(why), Vec::new().into_iter()),
    };
    // Cleaned and capped when built, as the author is (IN-VibeBoot-6): the trigger's account
    // and the run level are the task's own text.
    facts.when = text::clean(&def.when());
    facts.author = def.author.as_deref().map(text::clean);
    facts.run_level = def.run_level.as_deref().map(|l| text::clean_max(l, 40));
    facts.own = own_task(&def, &pc.account());
    facts.actions = def.actions.len();
    e.account = def.user.as_deref().map(account_words);
    let mut shown: Vec<String> = Vec::new();
    // What the command it shows could not establish (`cmdline::Command::unknown`).
    let mut unknown = None;
    for a in &def.actions {
        match a {
            Action::Exec { command, args } => {
                let raw = if args.is_empty() { command.clone() } else { format!("{command} {args}") };
                shown.push(raw.clone());
                if e.target.is_none() && e.raw.is_empty() {
                    e.raw = raw.clone();
                    e.expanded = cmdline::expand(&raw, &|n| pc.env(n));
                    let c = cmdline::resolve(&e.expanded, &pc.sys_dirs(), &|p| pc.exists(p));
                    e.through = run::through_of(pc, &c);
                    e.target = c.target;
                    e.script = c.script;
                    e.hidden = c.hidden;
                    e.note = c.note.map(str::to_string);
                    unknown = c.unknown;
                }
            }
            Action::ComHandler { clsid } => {
                // What COM loads for it, as the definition read it (`def::Com`); none when that
                // could not be established (switched off only: `def::bind` says why) or the
                // definition could not be read (no switch, the reason in the note).
                let com = coms.next();
                let com = com.as_ref().and_then(|c| c.as_ref().ok());
                let words = com.map(|c| c.words()).unwrap_or_else(|| format!("COM handler {}", text::clean(clsid)));
                shown.push(words.clone());
                // Its signer says nothing about what runs: never Windows' own (as `through`).
                if e.through.is_none() {
                    e.through = com.and_then(|c| c.borrowed.clone());
                }
                if e.target.is_none() && e.raw.is_empty() {
                    e.raw = words;
                    match (com, &fingerprint) {
                        (Some(c), _) => {
                            let x = cmdline::expand(&c.dll, &|n| pc.env(n));
                            e.expanded = x.clone();
                            e.target = Some(PathBuf::from(x));
                        }
                        (None, Err(why)) => e.note = Some(why.clone()),
                        (None, Ok(_)) => {}
                    }
                }
            }
            Action::Other(kind) => shown.push(format!("a {kind} action")),
        }
    }
    if def.actions.is_empty() {
        e.note = Some("it has no actions".into());
    }
    if shown.len() > 1 {
        e.raw = shown.join("  ·  ");
    }
    if let Some((p, off)) = def.date.as_deref().and_then(dates::parse_xml_date) {
        let at = match off {
            Some(o) => Some(dates::unix_at(p, o)),
            None => pc.local_to_unix(p.0, p.1, p.2, p.3, p.4, p.5),
        };
        if let Some(at) = at {
            e.dates.push(DateFact { kind: DateKind::Registered, at });
        }
    }
    if let Some(win) = pc.env("SystemRoot") {
        let file = PathBuf::from(format!(r"{win}\System32\Tasks{}", t.path));
        if let Some(at) = pc.file(&file).created.and_then(dates::unix_from_filetime) {
            e.dates.push(DateFact { kind: DateKind::TaskFile, at });
        }
    }
    // Bound last, so the row's reasons are added to what it says already (the one rule, RB3).
    // What its command could not establish is a gap of the snapshot too, so the change's own
    // check (`switch::apply`, on this snapshot) refuses a switch-on as the list does.
    let fingerprint = fingerprint.map(|f| run::with_unknown(f, unknown));
    super::def::bind(&mut e, fingerprint.clone());
    let target = e.target.clone();
    target_facts(pc, target.as_deref(), &mut e, DateKind::ProgramCreated);
    e.task = Some(facts);
    Some((e, fingerprint))
}

/// The logon and boot tasks among `list` (this account's view, or the helper's full read), one
/// step (`sys::step`, RB5-1).
pub fn tasks(pc: &dyn Pc, list: Result<(Vec<TaskRaw>, Vec<String>), String>) -> TaskPart {
    super::sys::step(|| tasks_now(pc, list))
}

fn tasks_now(pc: &dyn Pc, list: Result<(Vec<TaskRaw>, Vec<String>), String>) -> TaskPart {
    let mut out = TaskPart::default();
    out.part.answered.push(Location::LogonTask);
    match list {
        Err(why) => out.part.failed.push((Location::LogonTask, why)),
        Ok((all, unread)) => {
            out.total = all.len();
            out.part.entries = all.iter().filter_map(|t| task_entry(pc, t)).collect();
            // What could not be read on the way is a row each: counted, never dropped.
            out.part.entries.extend(unread.iter().enumerate().map(|(n, why)| unread_task(n, why)));
            out.unread = unread;
        }
    }
    out
}

/// A task that could not be read at all (its folder's list, the task itself, its path): a row of
/// its own, flagged, with no switch. It has no identity (its path is not known), so it is never
/// recorded as seen and never "new".
pub fn unread_task(n: usize, why: &str) -> Entry {
    let why = text::clean(why);
    Entry {
        location: Location::LogonTask,
        key: format!("{}|?unread {n}", Location::LogonTask.tag()),
        ident: Ident::Task { path: String::new() },
        name: "A scheduled task VibeBoot could not read".into(),
        raw: String::new(),
        expanded: String::new(),
        target: None,
        file: FileState::NoTarget,
        file_key: None,
        script: false,
        hidden: false,
        through: None,
        note: Some(format!("{why}; whether it starts with this PC is not known")),
        switch: Switch::Fixed("it could not be read, so VibeBoot cannot tell what it runs: left alone".into()),
        data: None,
        place: "Task Scheduler".into(),
        dates: Vec::new(),
        account: None,
        task: None,
        service: None,
        unread: Some(why),
        def: None,
        core: None,
        off_only: None,
    }
}

/// What a Windows-named service whose settings could not be read all runs through (RB5-4,
/// RB6-5): its publisher in the list, flagged.
pub const UNREAD_HOSTED: &str = "Microsoft's program, with what it loads not read";

/// One service or driver as an entry, when it starts with Windows: drivers with start boot,
/// system or automatic; services automatic (delayed included), and services this app switched
/// to Manual, so they can be switched back on: by its helper's note in the service's own key
/// (FS8: machine-wide, whatever became of the journal), or by the journal (`switched_off`: one
/// switched before the notes, or a note that could not be read).
pub fn service_entry(pc: &dyn Pc, s: &Service, switched_off: &dyn Fn(&str) -> bool) -> Option<Entry> {
    let driver = s.driver();
    let note = if !driver && s.start == 3 { services::switched_off_note(pc, &s.name) } else { None };
    let listed = if driver { s.start <= 2 } else { s.start == 2 || (s.start == 3 && (note.is_some() || switched_off(&s.name))) };
    if !listed {
        return None;
    }
    let loc = if driver { Location::Driver } else { Location::Service };
    let ident = Ident::Service { name: s.name.clone() };
    let t = services::target(pc, s).unwrap_or_default();
    let (switch, data) = if driver {
        (Switch::Fixed(loc.no_switch().unwrap_or("").into()), None)
    } else {
        (if s.start == 2 { Switch::On } else { Switch::Off { since: None } }, Some(Data::ServiceStart { start: s.start, delayed: s.delayed }))
    };
    let mut e = Entry {
        location: loc,
        key: entry_key(loc, &ident),
        ident,
        name: services::shown_name(s),
        raw: s.binary.clone(),
        expanded: t.expanded.clone(),
        target: t.target.clone(),
        file: FileState::NoTarget,
        file_key: None,
        script: t.cmd.script,
        hidden: t.cmd.hidden,
        through: t.through.clone(),
        note: t.note.clone(),
        switch,
        data,
        place: format!(r"HKEY_LOCAL_MACHINE\{}\{}", services::SERVICES_KEY, text::clean(&s.name)),
        dates: Vec::new(),
        account: (!s.account.is_empty()).then(|| account_words(&s.account)),
        task: None,
        service: Some(ServiceFacts { name: s.name.clone(), start: s.start, delayed: s.delayed, state: services::state_words(s.state).into(), kind: s.kind, was_delayed: note }),
        unread: None,
        def: None,
        core: None,
        off_only: None,
    };
    if !driver {
        let fresh = super::def::service(pc, s, services::hosted(&t));
        match &fresh.off_only {
            // RB4-3, RB5-4: Windows' own service by its name, part of whose settings this account
            // cannot read (`nsi`'s Parameters key grants read to SYSTEM, Administrators and the
            // service alone). No switch here: offered as off only, the helper (which reads it
            // whole) would refuse it as Windows' own when it is. But not folded with Microsoft's
            // either: some of these keys are writable by others than administrators (Network
            // Configuration Operators, other services' accounts), so what it hides may be theirs.
            // Its own row, unknown, never locked or folded as Windows' own (`through`). The
            // reason is the switch's words; `through` reads as a publisher (RB6-5: the list's
            // publisher column and the detail's flag show it), never the reason in its place.
            Some(why) if services::windows_own(&s.name) => {
                e.switch = Switch::Unknown(format!("Windows' own service by its name, but {why}, so VibeBoot cannot tell what it runs: left alone"));
                e.data = None;
                e.through = Some(UNREAD_HOSTED.into());
            }
            // What its command could not establish switches it off only (`run::with_unknown`).
            _ => super::def::bind(&mut e, Ok(run::with_unknown(fresh, t.cmd.unknown))),
        }
    }
    if let Ok(Some(ft)) = pc.reg_last_write(Hive::Machine, &format!(r"{}\{}", services::SERVICES_KEY, s.name))
        && let Some(at) = dates::unix_from_filetime(ft) {
            e.dates.push(DateFact { kind: DateKind::ServiceChanged, at });
        }
    let target = e.target.clone();
    target_facts(pc, target.as_deref(), &mut e, DateKind::BinaryCreated);
    Some(e)
}

/// Services and drivers that start with Windows, one step (`sys::step`, RB5-1).
pub fn services(pc: &dyn Pc, switched_off: &dyn Fn(&str) -> bool) -> Part {
    super::sys::step(|| services_now(pc, switched_off))
}

fn services_now(pc: &dyn Pc, switched_off: &dyn Fn(&str) -> bool) -> Part {
    let mut p = Part { answered: vec![Location::Service, Location::Driver], ..Part::default() };
    match pc.services() {
        Err(why) => {
            p.failed.push((Location::Service, why.clone()));
            p.failed.push((Location::Driver, why));
        }
        Ok((all, unread)) => {
            p.entries = all.iter().filter_map(|s| service_entry(pc, s, switched_off)).collect();
            if !unread.is_empty() {
                let names: Vec<String> = unread.iter().take(5).map(|(n, _)| text::clean(n)).collect();
                let more = if unread.len() > 5 { format!(" and {} more", unread.len() - 5) } else { String::new() };
                p.failed.push((Location::Service, format!("{} could not be read ({}{more}): {}", unread.len(), names.join(", "), text::clean(&unread[0].1))));
            }
        }
    }
    p
}
