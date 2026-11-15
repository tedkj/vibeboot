//! The startup folders: the user's (`FOLDERID_Startup`) and everyone's (`FOLDERID_CommonStartup`).
//! Every file there runs at sign-in except `desktop.ini` (the folder's own settings). A `.lnk` is
//! read through `IShellLinkW` (never resolved); other files (`.bat`, `.vbs`, `.url`, `.exe`) are
//! their own target. The switch is StartupApproved\StartupFolder, the value named as the file.

use super::pc::{DirItem, Pc};
use super::run::{Approved, approved_values, fold, switch_read, target_facts};
use super::{DateFact, DateKind, Entry, FileState, Ident, Location, Switch, cmdline, dates, def, entry_key, text};
use std::path::Path;

const SCRIPTS: [&str; 10] = ["bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1", "hta"];

fn ext(name: &str) -> String {
    name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default()
}

/// What a startup file whose identity was not read in time runs through (RB7-7): its publisher
/// in the list when its program is Microsoft's, flagged.
pub const UNREAD_FILE: &str = "Microsoft's program, from a startup file not read in time";

/// One file in a startup folder as an entry (None for what Windows does not run there).
pub fn entry(pc: &dyn Pc, loc: Location, folder: &Path, item: &DirItem, approved: &std::collections::HashMap<String, Approved>) -> Option<Entry> {
    if item.dir {
        return None;
    }
    let shown = text::units(&item.name);
    let lossy = String::from_utf16_lossy(&item.name);
    if lossy.eq_ignore_ascii_case("desktop.ini") {
        return None;
    }
    use std::os::windows::ffi::OsStringExt;
    let path = folder.join(std::ffi::OsString::from_wide(&item.name));
    let ident = Ident::File { name: item.name.clone(), path: path.clone() };
    let (switch, data) = switch_read(loc, approved.get(&fold(&item.name)));
    let mut e = Entry {
        location: loc,
        key: entry_key(loc, &ident),
        ident,
        name: shown,
        raw: path.to_string_lossy().into_owned(),
        expanded: path.to_string_lossy().into_owned(),
        target: Some(path.clone()),
        file: FileState::NoTarget,
        file_key: None,
        script: false,
        hidden: false,
        through: None,
        note: None,
        switch,
        data,
        place: folder.to_string_lossy().into_owned(),
        dates: Vec::new(),
        account: Some(match loc {
            Location::StartupCommon => "every user who signs in".into(),
            _ => pc.account().name,
        }),
        task: None,
        service: None,
        unread: None,
        def: None,
        core: None,
        off_only: None,
    };
    if let Some(at) = item.created.and_then(dates::unix_from_filetime) {
        e.dates.push(DateFact { kind: DateKind::Added, at });
    }
    if let Switch::Off { since: Some(ft) } = e.switch
        && let Some(at) = dates::unix_from_filetime(ft) {
            e.dates.push(DateFact { kind: DateKind::Disabled, at });
        }
    let fresh = match ext(&lossy).as_str() {
        "lnk" => {
            let lnk = pc.lnk(&path);
            // The shortcut file itself (its identity and bytes) and what it says are the entry's
            // definition (`def`).
            let mut fresh = def::startup_file(pc, &path, Some(&lnk));
            match lnk {
                Ok(l) if l.path.trim().is_empty() => {
                    e.raw = String::new();
                    e.expanded = String::new();
                    e.target = None;
                    e.note = Some("an installer shortcut: Windows finds its program when it runs".into());
                }
                Ok(l) => {
                    e.raw = if l.args.is_empty() { format!("\"{}\"", l.path) } else { format!("\"{}\" {}", l.path, l.args) };
                    let prog = cmdline::expand(&l.path, &|n| pc.env(n));
                    let args = cmdline::expand(&l.args, &|n| pc.env(n));
                    e.expanded = if args.is_empty() { format!("\"{prog}\"") } else { format!("\"{prog}\" {args}") };
                    let c = cmdline::analyze(Path::new(prog.trim()), &args, &pc.sys_dirs(), &|p| pc.exists(p));
                    // What its command could not establish switches it off only.
                    fresh = fresh.map(|f| super::run::with_unknown(f, c.unknown));
                    e.through = super::run::through_of(pc, &c);
                    e.target = c.target;
                    e.script = c.script;
                    e.hidden = c.hidden;
                    let t = e.target.clone();
                    target_facts(pc, t.as_deref(), &mut e, DateKind::ProgramCreated);
                }
                Err(why) => {
                    e.target = None;
                    e.file = FileState::Unknown(format!("the shortcut could not be read ({why})"));
                    e.note = Some("a shortcut Windows cannot read".into());
                }
            }
            fresh
        }
        x => {
            e.script = SCRIPTS.contains(&x);
            let f = pc.file(&path);
            e.file = f.state;
            e.file_key = f.key;
            def::startup_file(pc, &path, None)
        }
    };
    // Bound last (the one rule, RB3): bytes another process holds, an ACL with execute only, a
    // slow share or a shortcut that cannot be read keep its switch-off, and its row says why on
    // top of what it says already.
    match fresh {
        // RB6-2: which file it is was not read because the folder's wait ran out (the file was
        // never asked to the end): off only all the same, never a lost switch. Its off is bound
        // when it is made (`switch::bind_now`), its on refused.
        // RB7-4: a read cut short by the folder's wait counts as spent too (it was asked, but
        // waited only what was left of the folder's wait, not its own limit). A shortcut's
        // identity is read once (with its bytes), so a cut-short read leaves it off only; any
        // other file's is read twice (alone, then with its bytes), and after a cut-short first
        // read the second finds it still out (`Late::Slow`): no switch. A read never started is
        // off only for both. Either way is safe (the off is bound when it is made).
        Err(why) if super::pc::spent(&why) && e.data.is_some() => {
            let why = format!("which file it is was not read in time ({})", super::pc::SPENT);
            let said = format!("{why}: VibeBoot can switch it off, not on");
            e.note = Some(match e.note.take() {
                Some(n) => format!("{n}; {said}"),
                None => said,
            });
            // RB7-7: a publisher's words where the list shows it as one (`groups::launched`),
            // the reason staying in the note and the switch's words.
            e.through.get_or_insert(UNREAD_FILE.into());
            e.off_only = Some(why);
        }
        fresh => def::bind(&mut e, fresh),
    }
    Some(e)
}

/// Every entry in one startup folder. Err: the folder could not be read (never "empty").
pub fn scan(pc: &dyn Pc, loc: Location) -> Result<Vec<Entry>, String> {
    let common = match loc {
        Location::StartupUser => false,
        Location::StartupCommon => true,
        _ => return Err("not a startup folder".into()),
    };
    let folder = pc.startup_folder(common).ok_or("Windows did not say where the startup folder is")?;
    let Some(items) = pc.list_dir(&folder)? else { return Ok(Vec::new()) };
    let approved = approved_values(pc, loc).ok();
    let empty = std::collections::HashMap::new();
    let mut out = Vec::new();
    for item in &items {
        if let Some(mut e) = entry(pc, loc, &folder, item, approved.as_ref().unwrap_or(&empty)) {
            if approved.is_none() {
                e.switch = Switch::Unknown("Windows' switch for it could not be read".into());
                e.data = None;
            }
            out.push(e);
        }
    }
    Ok(out)
}
