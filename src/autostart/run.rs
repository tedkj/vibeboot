//! The Run-style keys: Run and RunOnce (HKCU, HKLM, HKLM's 32-bit WOW6432Node) and the policy
//! Run keys. Each text value is an entry; its switch is the StartupApproved value of the same
//! name (Run keys only: RunOnce runs once and is gone, a policy is changed where it is set).
//!
//! `HKCU\Software\WOW6432Node\...\Run` is not read: HKCU\Software is shared between the 32- and
//! 64-bit views since Windows 7 (only HKCU\Software\Classes is redirected), Explorer reads only
//! the native key, and the key does not exist on the PC this was built on.

use super::pc::{Pc, RegVal};
use super::{DateFact, DateKind, Entry, FileState, Ident, Location, Switch, approved, cmdline, dates, def, entry_key, switch::Data, text};
use std::collections::HashMap;

/// One StartupApproved value: its type and bytes, or why it could not be read.
pub type Approved = Result<(u32, Vec<u8>), String>;

/// The StartupApproved values of one key, by lower-cased name.
pub fn approved_values(pc: &dyn Pc, loc: Location) -> Result<HashMap<String, Approved>, String> {
    let Some((hive, sub)) = loc.approved() else { return Ok(HashMap::new()) };
    let key = pc.reg_key(hive, &sub.path())?;
    Ok(key
        .map(|k| {
            k.values
                .into_iter()
                .map(|v| {
                    let a = match v.problem {
                        Some(why) => Err(why),
                        None => Ok((v.kind, v.data)),
                    };
                    (fold(&v.name), a)
                })
                .collect()
        })
        .unwrap_or_default())
}

/// An entry's switch from its StartupApproved value as read: one that could not be read leaves
/// the switch unknown, never "on".
pub fn switch_read(loc: Location, value: Option<&Approved>) -> (Switch, Option<Data>) {
    match value {
        Some(Err(why)) if loc.no_switch().is_none() => (Switch::Unknown(format!("Windows' switch for it could not be read ({why}): left alone")), None),
        v => switch_of(loc, v.and_then(|r| r.as_ref().ok())),
    }
}

/// A registry name for matching (registry names are case-insensitive).
pub fn fold(name: &[u16]) -> String {
    String::from_utf16_lossy(name).to_lowercase()
}

/// An entry's switch from its StartupApproved value (or its location's lack of one).
pub fn switch_of(loc: Location, value: Option<&(u32, Vec<u8>)>) -> (Switch, Option<Data>) {
    if let Some(why) = loc.no_switch() {
        return (Switch::Fixed(why.into()), None);
    }
    let state = approved::decode(value.map(|(k, b)| (*k, b.as_slice())));
    match state {
        approved::State::Absent => (Switch::On, Some(Data::Approved(None))),
        approved::State::Enabled => (Switch::On, Some(Data::Approved(value.map(|v| v.1.clone())))),
        approved::State::Disabled { at } => (Switch::Off { since: at }, Some(Data::Approved(value.map(|v| v.1.clone())))),
        approved::State::Unknown { len, kind } => (Switch::Unknown(format!("Windows' switch for it has a form VibeBoot does not know ({len} bytes, type {kind}): left alone")), None),
    }
}

/// What the command's program is handed from outside Windows' own folders (`cmdline::through`).
pub fn through_of(pc: &dyn Pc, c: &cmdline::Command) -> Option<String> {
    cmdline::through(c, &cmdline::Owned::from_env(&|n| pc.env(n)), &pc.sys_dirs(), &|p| pc.exists(p))
}

/// An entry's reading with what its command could not establish (`cmdline::Command::unknown`,
/// IN-VibeBoot-1/2) as one more gap, as `def`'s own gaps are (the one rule, RB3): it then
/// switches off only, bound to which entry it is (`core`).
pub fn with_unknown(f: def::Fresh, unknown: Option<&str>) -> def::Fresh {
    let Some(why) = unknown else { return f };
    let off_only = match f.off_only {
        Some(o) if o.split("; ").any(|x| x == why) => o,
        Some(o) => format!("{o}; {why}"),
        None => why.to_string(),
    };
    def::Fresh { def: f.core, core: f.core, off_only: Some(off_only) }
}

/// The file facts and dates of a command's target.
pub fn target_facts(pc: &dyn Pc, target: Option<&std::path::Path>, e: &mut Entry, created_kind: DateKind) {
    let Some(t) = target else {
        e.file = FileState::NoTarget;
        return;
    };
    let f = pc.file(t);
    e.file = f.state;
    e.file_key = f.key;
    if let Some(at) = f.created.and_then(dates::unix_from_filetime) {
        e.dates.push(DateFact { kind: created_kind, at });
    }
}

/// One Run-style value as an entry.
pub fn entry(pc: &dyn Pc, loc: Location, v: &RegVal, key_time: Option<u64>, approved: &HashMap<String, Approved>) -> Option<Entry> {
    if let Some(why) = &v.problem {
        return Some(unread_value(loc, v, why, key_time));
    }
    let (hive, path) = loc.reg()?;
    // The value as a change reads it (`def::read`: `pc::value`): the listing's call hands some
    // strings over otherwise (an odd length, RB-1), and what is shown and bound is one read. By
    // its whole name: one holding a NUL is never read as another value (RB2-1).
    let nul = v.name.contains(&0);
    let v = &match super::pc::value(pc, hive, path, &v.name) {
        Ok(Some((kind, data))) => RegVal { kind, data, ..v.clone() },
        Ok(None) => return Some(unread_value(loc, v, "it went away while it was read", key_time)),
        Err(why) => return Some(unread_value(loc, v, &format!("could not be read ({why})"), key_time)),
    };
    let raw = v.text()?;
    let expanded = cmdline::expand(&raw, &|n| pc.env(n));
    let cmd = cmdline::resolve(&expanded, &pc.sys_dirs(), &|p| pc.exists(p));
    let ident = Ident::Value { name: v.name.clone() };
    let (switch, data) = match switch_read(loc, approved.get(&fold(&v.name))) {
        // Windows' by-name calls cannot reach a name holding a NUL (Explorer's own StartupApproved
        // lookup among them, it is not known how): its switch cannot be told, and none is
        // written (`switch::valid_name`).
        (Switch::Fixed(w), d) => (Switch::Fixed(w), d),
        _ if nul => (Switch::Unknown("its name holds a NUL, which Windows' by-name calls cannot reach, so its switch cannot be told: left alone".into()), None),
        s => s,
    };
    let name = if v.name.is_empty() { "(default)".to_string() } else { text::units(&v.name) };
    // A Run value is its type and bytes, nothing more: which entry it is and all of what it runs.
    let def = Some(super::def::run_value(v.kind, &v.data));
    let mut e = Entry {
        location: loc,
        key: entry_key(loc, &ident),
        ident,
        name,
        raw: raw.clone(),
        expanded,
        target: cmd.target.clone(),
        file: FileState::NoTarget,
        file_key: None,
        script: cmd.script,
        hidden: cmd.hidden,
        through: through_of(pc, &cmd),
        note: match (nul, cmd.note) {
            (true, n) => Some(format!("its name holds a NUL: hidden from Registry Editor, a known way to hide a Run value{}", n.map(|n| format!("; {n}")).unwrap_or_default())),
            (false, n) => n.map(str::to_string),
        },
        switch,
        data,
        place: format!(r"{}\{path}", hive.name()),
        dates: Vec::new(),
        account: Some(match hive {
            super::Hive::User => pc.account().name,
            super::Hive::Machine | super::Hive::Users => "every user who signs in".into(),
        }),
        task: None,
        service: None,
        unread: None,
        def,
        core: def,
        off_only: None,
    };
    if let Switch::Off { since: Some(ft) } = e.switch
        && let Some(at) = dates::unix_from_filetime(ft) {
            e.dates.push(DateFact { kind: DateKind::Disabled, at });
        }
    if let Some(at) = key_time.and_then(dates::unix_from_filetime) {
        e.dates.push(DateFact { kind: DateKind::RunKeyChanged, at });
    }
    // What its command runs could not be established: off only, its row says why (`def::bind`).
    if let (Some(d), Some(_)) = (def, cmd.unknown) {
        def::bind(&mut e, Ok(with_unknown(def::Fresh { def: d, core: d, off_only: None }, cmd.unknown)));
    }
    let t = e.target.clone();
    target_facts(pc, t.as_deref(), &mut e, DateKind::ProgramCreated);
    Some(e)
}

/// A value whose data could not be read (too large, denied): its own entry, flagged, never
/// toggled (what it runs cannot be told); the others in its key are listed as ever.
fn unread_value(loc: Location, v: &RegVal, why: &str, key_time: Option<u64>) -> Entry {
    let (hive, path) = loc.reg().unwrap_or((super::Hive::User, ""));
    let ident = Ident::Value { name: v.name.clone() };
    let text_kind = v.kind == super::pc::REG_SZ || v.kind == super::pc::REG_EXPAND_SZ;
    let mut e = Entry {
        location: loc,
        key: entry_key(loc, &ident),
        ident,
        name: if v.name.is_empty() { "(default)".to_string() } else { text::units(&v.name) },
        raw: String::new(),
        expanded: String::new(),
        target: None,
        file: FileState::NoTarget,
        file_key: None,
        script: false,
        hidden: false,
        through: None,
        note: Some(format!("{why}{}", if text_kind { "" } else { " (not a text value: Explorer does not run it)" })),
        switch: match loc.no_switch() {
            Some(w) => Switch::Fixed(w.into()),
            None => Switch::Unknown("its value could not be read, so VibeBoot cannot tell what it runs: left alone".into()),
        },
        data: None,
        place: format!(r"{}\{path}", hive.name()),
        dates: Vec::new(),
        account: None,
        task: None,
        service: None,
        unread: Some(why.to_string()),
        def: None,
        core: None,
        off_only: None,
    };
    if let Some(at) = key_time.and_then(dates::unix_from_filetime) {
        e.dates.push(DateFact { kind: DateKind::RunKeyChanged, at });
    }
    e
}

/// Every entry of one Run-style key. Err: the key could not be read (never "empty").
pub fn scan(pc: &dyn Pc, loc: Location) -> Result<Vec<Entry>, String> {
    let (hive, path) = loc.reg().ok_or("not a registry location")?;
    let Some(key) = pc.reg_key(hive, path)? else { return Ok(Vec::new()) };
    // The switches: a key that cannot be read leaves every switch unknown, never "on".
    let approved = approved_values(pc, loc).ok();
    let empty = HashMap::new();
    let mut out = Vec::new();
    for v in &key.values {
        if let Some(mut e) = entry(pc, loc, v, key.last_write, approved.as_ref().unwrap_or(&empty)) {
            if approved.is_none() && loc.no_switch().is_none() {
                e.switch = Switch::Unknown("Windows' switch for it could not be read".into());
                e.data = None;
            }
            out.push(e);
        }
    }
    Ok(out)
}
