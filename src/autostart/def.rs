//! What an entry is, apart from its switch: the Run value's type and bytes, the startup file's
//! identity and bytes (and its shortcut's program and arguments), the task's definition and its
//! COM handler's DLL, the service's type, program, account, DLL and recovery program. The scan reads it with the entry; a change carries it and acts
//! only while the entry still has it (VIBEWARE "what was read is a plan"): an entry replaced
//! under the same name between the list and the change is another entry, and the change is
//! refused ("changed since the scan: scan again").
//!
//! **The one rule (RB3):** when VibeBoot cannot fully establish what an entry will run, the entry
//! is switched off only, its row says why, and switching it on (an Undo that would switch it on
//! included) is refused, in the app and in the helper alike (`Fresh::off_only`, enforced by
//! `changes::route`, `switch::apply` and `journal::Journal::can_undo`). Switching off never runs
//! anything, so it is always safe. Every kind's definition is read through `Enc`, which keeps
//! two digests: which entry it is (`core`: a Run value's type and bytes, a startup file's
//! identity, a task's XML, a service's type, program and account) and all of what it runs. A
//! part of what it runs that cannot be established (`Enc::gap`: a file's bytes, a shortcut, a
//! COM class, a service's DLL) leaves only the first. An entry that cannot be told at all (its
//! value, identity, XML or service settings unreadable) has no switch. A switch-off is bound to
//! the first digest alone, a switch-on to the second (`Fresh::bound`, RB4-1): what an entry runs
//! can never refuse its switch-off.
//!
//! The definition is kept as a SHA-256 of a tagged encoding (`Def`), so a request to the helper
//! and a journal record stay small: one digest per change, whatever the size of the command or
//! the task's XML.

use super::pc::{Account, Content, Elevation, Lnk, Pc, Service};
use super::{FileKey, FileState, Hive, Ident, Location, scan, services, switch, taskxml, text};
use std::path::Path;

/// The version of the encoding this build fingerprints with, kept with each journal record
/// (`journal::Record::def_v`). Bumped whenever the encoding of any kind but a Run value changes:
/// a record of another version cannot be compared with a fresh read (RB2-6). 2: a task's COM
/// handler is its whole `TreatAs` chain, read where its account's COM reads (RB3-1, RB3-2).
pub const VERSION: u8 = 2;

/// The version that last changed `loc`'s encoding of a whole entry: a Run value's never did, a
/// startup file's and a service's in 1, a task's in 2.
fn since(loc: Location) -> u8 {
    match loc {
        Location::RunUser | Location::RunMachine | Location::RunMachine32 => 0,
        Location::LogonTask => 2,
        _ => 1,
    }
}

/// Whether a record's definition of version `v` at `loc` can be compared with this build's: made
/// with this kind's encoding as this build reads it (RB2-6).
pub fn comparable(loc: Location, v: u8) -> bool {
    (since(loc)..=VERSION).contains(&v)
}

/// A definition as read now (the one rule, RB3). `def` is what a switch-on is bound to: all of
/// what the entry runs; or, when part of that could not be established (`off_only`, and why),
/// only which entry it is (`core`), and then it switches off only. A switch-off is bound to
/// `core`, always (`bound`, RB4-1): turning an entry off is harmless whatever it runs; turning
/// one on stays bound to all of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fresh {
    pub def: Def,
    /// Which entry it is, apart from what it runs (`Enc`'s first part).
    pub core: Def,
    pub off_only: Option<String>,
}

impl Fresh {
    fn whole(def: Def) -> Fresh {
        Fresh { def, core: def, off_only: None }
    }

    /// What a change that switches the entry `on` (or off) is bound to, the one binding rule
    /// (RB4-1): a switch-off to which entry it is (`core`) alone, never to what it runs, so that
    /// whoever controls what it runs (a hijacker cycling its DLL, a share near its time limit)
    /// cannot refuse it; a switch-on to all of what it runs (`def`).
    pub fn bound(&self, on: bool) -> Def {
        if on { self.def } else { self.core }
    }

    /// Whether a change bound to `def` that switches the entry to `on` may act on this reading
    /// (`bound`): an off when this is the same entry, an on when it is the same entry running
    /// the same. A switch whose new state is neither on nor off is held to all of it.
    pub fn binds(&self, def: Def, on: Option<bool>) -> bool {
        self.bound(on != Some(false)) == def
    }
}

/// An entry's definition, as a SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Def(pub [u8; 32]);

impl Def {
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn from_hex(s: &str) -> Option<Def> {
        let b = s.as_bytes();
        if b.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, pair) in b.chunks(2).enumerate() {
            let s = std::str::from_utf8(pair).ok()?;
            out[i] = u8::from_str_radix(s, 16).ok()?;
        }
        Some(Def(out))
    }
}

impl std::fmt::Debug for Def {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Def({})", &self.hex()[..16])
    }
}

impl serde::Serialize for Def {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.hex())
    }
}

impl<'de> serde::Deserialize<'de> for Def {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Def, D::Error> {
        let s = String::deserialize(d)?;
        Def::from_hex(&s).ok_or_else(|| serde::de::Error::custom("not a definition digest"))
    }
}

/// A tagged encoding fed to SHA-256: every field with its length, so no two encodings meet. It
/// keeps two digests: of every field (all of what the entry runs) and of the fields before
/// `payload` (which entry it is), the second tagged "core" so it never meets the first. What of
/// the payload cannot be established is a `gap` (the one rule, RB3): `done` then hands over the
/// core as the definition, with the reasons as `Fresh::off_only`.
struct Enc {
    full: Sha256,
    core: Sha256,
    payload: bool,
    gaps: Vec<String>,
}

impl Enc {
    fn new(kind: &str) -> Enc {
        let mut e = Enc { full: Sha256::new(), core: Sha256::new(), payload: false, gaps: Vec::new() };
        Enc::put(&mut e.core, b"core");
        e.field(kind.as_bytes());
        e
    }

    fn put(h: &mut Sha256, b: &[u8]) {
        h.update(&(b.len() as u64).to_le_bytes());
        h.update(b);
    }

    fn field(&mut self, b: &[u8]) {
        Enc::put(&mut self.full, b);
        if !self.payload {
            Enc::put(&mut self.core, b);
        }
    }

    /// What follows is what the entry runs, not which entry it is.
    fn payload(&mut self) {
        self.payload = true;
    }

    /// Part of what the entry runs could not be established, and why: it switches off only.
    fn gap(&mut self, why: String) {
        debug_assert!(self.payload, "which entry it is is never a gap");
        if !self.gaps.contains(&why) {
            self.gaps.push(why);
        }
    }

    fn done(self) -> Fresh {
        let core = Def(self.core.finish());
        if self.gaps.is_empty() { Fresh { def: Def(self.full.finish()), core, off_only: None } } else { Fresh { def: core, core, off_only: Some(self.gaps.join("; ")) } }
    }
}

/// A Run-style value: its type and its exact bytes.
pub fn run_value(kind: u32, data: &[u8]) -> Def {
    let mut e = Enc::new("run");
    e.field(&kind.to_le_bytes());
    e.field(data);
    e.done().def
}

/// Whether a startup file's name is a shortcut's (read through `IShellLinkW`).
pub fn is_lnk(name: &[u16]) -> bool {
    String::from_utf16_lossy(name).rsplit_once('.').is_some_and(|(_, x)| x.eq_ignore_ascii_case("lnk"))
}

/// A startup file: which file it is (its identity, size and last write; a zero identity is
/// unknown, no switch), what it holds (`Content`: the SHA-256 of all its bytes, read through the
/// same handle; over `pc::MAX_CONTENT`, its identity, size and last write stand for it, tagged),
/// and for a shortcut its program and arguments as read. Bytes that could not be read (held, an
/// execute-only ACL, a share too slow, a read that failed partway) or a shortcut that could not
/// be read are a `gap`: switched off only (RB2-2, RB3-3).
pub fn file(key: Option<FileKey>, content: &Content, lnk: Option<&Result<Lnk, String>>) -> Result<Fresh, String> {
    let k = key.filter(FileKey::usable).ok_or("the startup file's identity could not be read")?;
    let mut e = Enc::new("file");
    e.field(&k.serial.to_le_bytes());
    e.field(&k.id);
    e.field(&k.size.to_le_bytes());
    e.field(&k.written.to_le_bytes());
    e.payload();
    match content {
        Content::Digest(d) => {
            e.field(b"sha256");
            e.field(d);
        }
        Content::OverCap => e.field(b"over the cap"),
        Content::Unreadable(why) => e.gap(format!("its bytes could not be read ({why})")),
    }
    match lnk {
        None => e.field(b"not a shortcut"),
        Some(Ok(l)) => {
            e.field(b"shortcut");
            e.field(l.path.as_bytes());
            e.field(l.args.as_bytes());
        }
        // Held so that its bytes cannot be read, it cannot be read as a shortcut either: one
        // reason.
        Some(Err(_)) if matches!(content, Content::Unreadable(_)) => {}
        Some(Err(why)) => e.gap(format!("the shortcut could not be read ({why})")),
    }
    Ok(e.done())
}

/// A startup file's definition read now: its identity and content through one handle (`file`).
pub fn startup_file(pc: &dyn Pc, path: &Path, lnk: Option<&Result<Lnk, String>>) -> Result<Fresh, String> {
    match pc.file_bytes(path) {
        Ok(Some(b)) => file(b.key, &b.content, lnk),
        Ok(None) => Err("the startup file went away while it was read".into()),
        Err(why) => Err(format!("the startup file could not be read ({why})")),
    }
}

/// A task: its XML as Task Scheduler hands it over, event by event, less what its own switch
/// writes (`Task/Settings/Enabled`) and the whitespace between elements (an element added or
/// taken away re-indents nothing else). Whitespace that is an element's whole text stays. For
/// each COM handler action, what COM loads for it (`com_handler`): the XML names only the class.
/// The XML is which task it is; a COM handler that cannot be resolved is a `gap`.
pub fn task(pc: &dyn Pc, xml: &str) -> Result<Fresh, String> {
    task_read(pc, xml).map(|(d, _)| d)
}

/// A task's definition and its COM handlers as resolved in the same read (`Com`, one per
/// ComHandler action; Err: why what it runs could not be established): the list shows, signs and
/// locks what it fingerprints (RB2-3).
pub fn task_read(pc: &dyn Pc, xml: &str) -> Result<(Fresh, Vec<Result<Com, String>>), String> {
    use quick_xml::events::Event;
    if xml.len() > taskxml::MAX_XML {
        return Err(format!("the task's XML is more than VibeBoot reads ({} KB)", taskxml::MAX_XML / 1024));
    }
    let mut r = quick_xml::Reader::from_str(xml);
    r.config_mut().trim_text(false);
    let mut e = Enc::new("task");
    let mut stack: Vec<Vec<u8>> = Vec::new();
    // Whitespace-only text, held until the next event says whether it is text or layout; and
    // whether the event before it was a start tag or text.
    let mut gap: Option<(Vec<u8>, bool, bool)> = None;
    let (mut after_start, mut after_text) = (false, false);
    let mut root = false;
    // Inside Task/Settings/Enabled (the switch), from its start to its end.
    let switch_at = |stack: &[Vec<u8>]| stack.len() >= 3 && stack[0] == b"Task" && stack[1] == b"Settings" && stack[2] == b"Enabled";
    loop {
        let ev = r.read_event().map_err(|x| format!("the task's XML is malformed ({x})"))?;
        if let Event::Text(t) = &ev
            && t.iter().all(|c| c.is_ascii_whitespace())
        {
            let g = gap.get_or_insert_with(|| (Vec::new(), after_start, after_text));
            g.0.extend_from_slice(t);
            continue;
        }
        let tag: u8 = match &ev {
            Event::Start(_) => b'S',
            Event::End(_) => b'E',
            Event::Empty(_) => b'M',
            Event::Text(_) => b'T',
            Event::CData(_) => b'C',
            Event::Comment(_) => b'c',
            Event::Decl(_) => b'D',
            Event::PI(_) => b'P',
            Event::DocType(_) => b'd',
            Event::GeneralRef(_) => b'R',
            Event::Eof => b'Z',
        };
        if let Event::Start(s) | Event::Empty(s) = &ev {
            root |= stack.is_empty();
            stack.push(s.local_name().as_ref().to_vec());
        }
        let skip = switch_at(&stack);
        if let Some((ws, s, t)) = gap.take() {
            let text = matches!(tag, b'T' | b'C' | b'R');
            if !skip && (text || t || (s && tag == b'E')) {
                e.field(b"T");
                e.field(&ws);
            }
        }
        if !skip {
            e.field(&[tag]);
            e.field(&ev);
        }
        after_start = tag == b'S';
        after_text = matches!(tag, b'T' | b'C' | b'R');
        match ev {
            Event::End(_) | Event::Empty(_) => {
                stack.pop();
            }
            Event::Eof => break,
            _ => {}
        }
    }
    // As the scan's reader: a document that ends early, or has no root, is not a definition.
    if !stack.is_empty() || !root {
        return Err("the task's XML ends early".into());
    }
    let parsed = taskxml::parse(xml)?;
    e.payload();
    let mut coms = Vec::new();
    if parsed.actions.iter().any(|a| matches!(a, taskxml::Action::ComHandler { .. })) {
        let keys = class_keys(pc, parsed.user.as_deref(), parsed.run_level.as_deref(), &pc.account());
        for a in &parsed.actions {
            if let taskxml::Action::ComHandler { clsid } = a {
                let com = keys.clone().and_then(|k| com_handler(pc, clsid, &k, &mut e));
                if let Err(why) = &com {
                    e.gap(why.clone());
                }
                coms.push(com);
            }
        }
    }
    Ok((e.done(), coms))
}

/// The machine's classes (`HKLM\SOFTWARE\Classes\CLSID`), which COM always reads.
const MACHINE_CLASSES: &str = r"SOFTWARE\Classes\CLSID";

/// Where COM looks a task's classes up (`class_keys`): the per-user classes of the account it
/// runs as, then the machine's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassKeys {
    /// The per-user classes COM reads first; None when the task runs elevated (an elevated
    /// process's COM ignores per-user classes: RB3-2) and COM reads the machine's alone.
    pub own: Option<(Hive, String)>,
    /// Whether the task runs elevated could not be told, and why: what it runs is established
    /// only when the per-user classes change nothing of it (else it switches off only).
    pub maybe: Option<String>,
}

impl ClassKeys {
    /// The per-user classes in words: "HKCU\Software\Classes", "HKU\S-1-5-21-…_Classes".
    fn own_words(&self) -> String {
        match &self.own {
            Some((Hive::User, base)) => format!(r"HKCU\{}", base.trim_end_matches(r"\CLSID")),
            Some((_, base)) => format!(r"HKU\{}", base.trim_end_matches(r"\CLSID")),
            None => String::new(),
        }
    }
}

/// A service account a task may run as, by its SID or its names: its SID.
fn service_account(user: &str) -> Option<&'static str> {
    match user.to_ascii_uppercase().as_str() {
        "S-1-5-18" | "SYSTEM" | "LOCALSYSTEM" | "NT AUTHORITY\\SYSTEM" => Some("S-1-5-18"),
        "S-1-5-19" | "LOCAL SERVICE" | "LOCALSERVICE" | "NT AUTHORITY\\LOCAL SERVICE" | "NT AUTHORITY\\LOCALSERVICE" => Some("S-1-5-19"),
        "S-1-5-20" | "NETWORK SERVICE" | "NETWORKSERVICE" | "NT AUTHORITY\\NETWORK SERVICE" | "NT AUTHORITY\\NETWORKSERVICE" => Some("S-1-5-20"),
        _ => None,
    }
}

/// A SID string (`S-1-` and digits and dashes only: it becomes a key name, never a path).
/// Bytes, never a `str` slice: an account name with a multi-byte character at byte 4 is no SID,
/// never a panic (IN-VibeBoot-3).
fn sid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() <= 184 && b.len() > 4 && b[..4].eq_ignore_ascii_case(b"S-1-") && b[4..].iter().all(|&b| b.is_ascii_digit() || b == b'-')
}

/// Where COM looks a task's classes up (RB2-4, RB3-2). An elevated process's COM ignores
/// per-user classes (measured: at High IL an HKCU-only class is REGDB_E_CLASSNOTREG, the same
/// class activates at Medium IL), so a task that runs elevated is looked up in the machine's
/// classes alone, and one that does not in its account's first.
/// - SYSTEM, LOCAL SERVICE, NETWORK SERVICE: elevated, the machine's alone.
/// - This account, or no account named (a group's task: it runs as whoever signs in; the list
///   shows this account's view of it, as it does every other entry): HKCU, unless it runs
///   elevated as this account's token says (`Account::elevation`: an administrator with UAC
///   runs the highest privileges elevated). A group's task with the highest privileges runs
///   elevated or not as whoever signs in is: `maybe`. The helper is this same account (its pipe
///   admits this account's SID only), so it reads the same hive and decides the same.
/// - Another account by SID: its classes hive, when it is loaded and can be read; whether it
///   runs elevated is known only for least privilege under UAC (not the built-in
///   Administrator's: RB4-5), else `maybe`.
/// - Err (what it runs cannot be established: switched off only): another account by name, or
///   one whose hive is not loaded or cannot be read.
pub fn class_keys(pc: &dyn Pc, user: Option<&str>, run_level: Option<&str>, me: &Account) -> Result<ClassKeys, String> {
    let highest = run_level.is_some_and(|l| l.trim().eq_ignore_ascii_case("HighestAvailable"));
    let user = user.map(str::trim).filter(|u| !u.is_empty());
    if user.and_then(service_account).is_some() {
        return Ok(ClassKeys { own: None, maybe: None });
    }
    // Whether it runs elevated (Err: that cannot be told, and why), and its account's classes.
    let (elevated, own): (Result<bool, String>, (Hive, String)) = match user {
        Some(u) if !scan::is_me(u, me) => {
            let who = scan::account_words(u);
            if !sid(u) {
                return Err(format!("it runs as {}, whose registry VibeBoot does not look up", text::clean(u)));
            }
            let root = format!("{u}_Classes");
            match pc.reg_last_write(Hive::Users, &root) {
                Ok(Some(_)) => {}
                Ok(None) => return Err(format!("it runs as {who}, whose registry is not loaded")),
                Err(why) => return Err(format!("it runs as {who}, whose registry could not be read ({why})")),
            }
            // Least privilege under UAC runs unelevated, except for the built-in Administrator
            // (RID 500), whom UAC filters only when its Admin Approval Mode is on (off by
            // default): its least privilege is elevated or not as that setting says (RB4-5).
            let elevated = if !highest && me.elevation == Elevation::Split && !u.ends_with("-500") { Ok(false) } else { Err(format!("it runs as {who}, elevated or not as that account is")) };
            (elevated, (Hive::Users, format!(r"{root}\CLSID")))
        }
        _ => {
            let elevated = match (me.elevation, highest) {
                (_, true) if user.is_none() => Err("it runs with the highest privileges of whoever signs in, elevated or not as that account is".to_string()),
                (Elevation::Standard, _) => Ok(false),
                (Elevation::Split, h) => Ok(h),
                (Elevation::Always, _) => Ok(true),
                (Elevation::Unknown, _) => Err("whether this account runs it elevated could not be told".to_string()),
            };
            (elevated, (Hive::User, r"Software\Classes\CLSID".to_string()))
        }
    };
    Ok(match elevated {
        Ok(true) => ClassKeys { own: None, maybe: None },
        Ok(false) => ClassKeys { own: Some(own), maybe: None },
        Err(why) => ClassKeys { own: Some(own), maybe: Some(why) },
    })
}

/// What COM loads for a task's ComHandler action, resolved once for the list, the signer check,
/// the Windows-own lock and the fingerprint (RB2-3, `com_handler`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Com {
    /// The task's class.
    pub class: String,
    /// The classes COM hands it on to (`TreatAs`), in order: the last one's DLL is what loads.
    pub chain: Vec<String>,
    /// The `InprocServer32` DLL as registered (variables not expanded, quotes trimmed).
    pub dll: String,
    /// Why the DLL's signature says nothing about the handler (it then is never Windows' own, as
    /// `Entry::through`): a registration of the account it runs as (that account can write it),
    /// a `TreatAs`, a runtime loading someone else's code (scrobj.dll's scriptlet). None: the
    /// machine's own registration of the class's own DLL.
    pub borrowed: Option<String>,
}

impl Com {
    /// "COM handler {C}", "COM handler {C}, handed to {T}", "…, handed to {T}, then {U}".
    pub fn words(&self) -> String {
        let mut w = format!("COM handler {}", self.class);
        for (i, t) in self.chain.iter().enumerate() {
            w.push_str(&if i == 0 { format!(", handed to {t}") } else { format!(", then {t}") });
        }
        w
    }
}

/// The most `TreatAs` hand-offs followed (RB3-1); COM's own limit is not documented, and a
/// longer chain is never what a vendor registers.
pub const MAX_TREAT_AS: usize = 8;

/// One value under a class's key in each place COM reads it (`keys`: the account's classes when
/// COM reads them, then the machine's), each fed to `e` tagged by whether it is there (RB3-6):
/// the first non-empty text, and whether it is the account's.
fn class_value(pc: &dyn Pc, keys: &ClassKeys, class: &str, sub: &str, value: &str, e: &mut Enc) -> Result<Option<(bool, String)>, String> {
    let n: Vec<u16> = value.encode_utf16().collect();
    let mut first = None;
    let machine = (Hive::Machine, MACHINE_CLASSES.to_string());
    for (own, (hive, base)) in keys.own.iter().map(|k| (true, k)).chain([(false, &machine)]) {
        let path = if sub.is_empty() { format!(r"{base}\{class}") } else { format!(r"{base}\{class}\{sub}") };
        match pc.reg_value(*hive, &path, &n).map_err(|why| format!("its COM class {class} could not be read ({why})"))? {
            None => e.field(&[0]),
            Some((kind, data)) => {
                e.field(&[&[1u8][..], &kind.to_le_bytes()].concat());
                e.field(&data);
                if first.is_none()
                    && let Some(t) = super::pc::reg_text(kind, &data)
                {
                    let t = t.trim().trim_matches('"').trim().to_string();
                    if !t.is_empty() {
                        first = Some((own, t));
                    }
                }
            }
        }
    }
    Ok(first)
}

/// What COM loads for a ComHandler of class `clsid`, every value read fed to `e` (RB2-3, RB3-1).
/// COM follows `TreatAs` from class to class until one has none (measured: A to B to C activates
/// C, even when B has an `InprocServer32` of its own), so each class's `TreatAs` is read and only
/// the last class's `InprocServer32` is what loads, with its `LocalServer32`, its .NET values and
/// its scriptlet (`ScriptletURL`, what `scrobj.dll` loads). Err, why what it runs cannot be
/// established (switched off only): a class id VibeBoot cannot look up; a `TreatAs` that is no
/// class id, comes back to a class already passed (handed to itself, COM loads nothing:
/// REGDB_E_INVALIDVALUE) or hands on more than `MAX_TREAT_AS` times; a last class with no
/// `InprocServer32` DLL (a missing class); a value that cannot be read; the account's own
/// classes, where whether COM reads them cannot be told (`ClassKeys::maybe`); the .NET runtime,
/// which also reads versions of the class VibeBoot does not read.
fn com_handler(pc: &dyn Pc, clsid: &str, keys: &ClassKeys, e: &mut Enc) -> Result<Com, String> {
    let c = scan::clsid(clsid).ok_or_else(|| format!("its COM handler names no class id VibeBoot can look up ({})", text::clean(clsid)))?;
    e.field(b"com");
    let mut why: Vec<String> = Vec::new();
    // Whether any value COM uses came from the account's own classes.
    let mut used_own = false;
    let mut chain: Vec<String> = Vec::new();
    let mut class = c.to_string();
    while let Some((mine, t)) = class_value(pc, keys, &class, "TreatAs", "", e)? {
        let t = scan::clsid(&t).map(str::to_string).ok_or_else(|| format!("its COM class {class} is handed to {}, which is no class id", text::clean(&t)))?;
        if t.eq_ignore_ascii_case(c) || chain.iter().any(|x| x.eq_ignore_ascii_case(&t)) {
            return Err(format!("its COM class {class} is handed back to {t}, so COM loads nothing it can be told"));
        }
        if chain.len() == MAX_TREAT_AS {
            return Err(format!("its COM class {c} is handed on more than {MAX_TREAT_AS} times"));
        }
        used_own |= mine;
        e.field(b"treat as");
        why.push(if mine { format!("COM hands class {class} to {t} through {}, the registration of the account it runs as", keys.own_words()) } else { format!("COM hands class {class} to {t} (TreatAs)") });
        chain.push(t.clone());
        class = t;
    }
    let Some((mine, dll)) = class_value(pc, keys, &class, "InprocServer32", "", e)? else {
        return Err(format!("its COM class {class} names no InprocServer32 DLL"));
    };
    used_own |= mine;
    if mine {
        why.push(format!("COM finds its DLL through {}, the registration of the account it runs as, not the machine's", keys.own_words()));
    }
    let mut more = Vec::new();
    for (sub, v) in [("LocalServer32", ""), ("InprocServer32", "Assembly"), ("InprocServer32", "Class"), ("InprocServer32", "CodeBase"), ("InprocServer32", "RuntimeVersion"), ("ScriptletURL", "")] {
        if let Some((mine, s)) = class_value(pc, keys, &class, sub, v, e)? {
            used_own |= mine;
            more.push((if v.is_empty() { sub } else { v }, s));
        }
    }
    if let Some(maybe) = &keys.maybe
        && used_own
    {
        return Err(format!("{maybe}, and that account's own classes change what COM loads for it"));
    }
    let named = |k: &str| more.iter().find(|(x, _)| *x == k).map(|(_, s)| text::clean(s));
    let file = dll.rsplit(['\\', '/']).next().unwrap_or(&dll);
    if file.eq_ignore_ascii_case("mscoree.dll") {
        let what = named("CodeBase").or_else(|| named("Assembly")).unwrap_or_else(|| "an assembly".into());
        return Err(format!("the .NET runtime (mscoree.dll) loads {what} for it, choosing among registered versions VibeBoot does not read"));
    }
    if file.eq_ignore_ascii_case("scrobj.dll") {
        let what = named("ScriptletURL").unwrap_or_else(|| "a scriptlet".into());
        why.push(format!("the script component runtime (scrobj.dll) loads {what} for it"));
    }
    Ok(Com { class: c.to_string(), chain, dll, borrowed: (!why.is_empty()).then(|| why.join("; ")) })
}

/// Values of a service's own key, and with `parameters` of its `Parameters` key first (type and
/// bytes, absent ones too).
fn service_values(pc: &dyn Pc, name: &str, values: &[&str], parameters: bool, e: &mut Enc) -> Result<(), String> {
    let own = format!(r"{}\{name}", services::SERVICES_KEY);
    let keys = if parameters { vec![format!(r"{own}\Parameters"), own] } else { vec![own] };
    for v in values {
        let n: Vec<u16> = v.encode_utf16().collect();
        for key in &keys {
            match pc.reg_value(Hive::Machine, key, &n)? {
                None => e.field(b"none"),
                Some((kind, data)) => {
                    e.field(&kind.to_le_bytes());
                    e.field(&data);
                }
            }
        }
    }
    Ok(())
}

/// A service: its type, program (the binary path as the service manager has it), account, its
/// recovery program and actions (`FailureCommand`, `FailureActions`: run as its account when it
/// fails), and for a svchost-hosted one its `ServiceDll` and `ServiceMain` (the DLL and its entry
/// are what runs). Not its start type: that is its switch. Its type, program and account are
/// which service it is; recovery settings or a ServiceDll that cannot be read are a `gap`.
pub fn service(pc: &dyn Pc, s: &Service, hosted: bool) -> Fresh {
    let mut e = Enc::new("service");
    e.field(&s.kind.to_le_bytes());
    e.field(s.binary.as_bytes());
    e.field(s.account.as_bytes());
    e.payload();
    if let Err(why) = service_values(pc, &s.name, &["FailureCommand", "FailureActions"], false, &mut e) {
        e.gap(format!("its recovery settings could not be read ({why})"));
    }
    if hosted && let Err(why) = service_values(pc, &s.name, &["ServiceDll", "ServiceMain"], true, &mut e) {
        e.gap(format!("its ServiceDll could not be read ({why})"));
    }
    e.done()
}

/// The entry's definition right now (the change's own read), with what of it could not be read
/// (`Fresh::off_only`). None: the entry is gone. Err: it could not be read (unknown, never a
/// match).
pub fn read(pc: &dyn Pc, loc: Location, ident: &Ident) -> Result<Option<Fresh>, String> {
    match (loc, ident) {
        (Location::RunUser | Location::RunMachine | Location::RunMachine32, Ident::Value { name }) => {
            let (hive, path) = loc.reg().ok_or("no key")?;
            Ok(super::pc::value(pc, hive, path, name)?.map(|(kind, data)| Fresh::whole(run_value(kind, &data))))
        }
        (Location::StartupUser | Location::StartupCommon, Ident::File { name, .. }) => {
            let path = switch::startup_path(pc, loc, name).ok_or("not a startup file name")?;
            let facts = pc.file(&path);
            match facts.state {
                FileState::Present => {}
                FileState::Missing | FileState::NoTarget => return Ok(None),
                FileState::Unknown(why) => return Err(why),
            }
            let lnk = is_lnk(name).then(|| pc.lnk(&path));
            startup_file(pc, &path, lnk.as_ref()).map(Some)
        }
        (Location::LogonTask, Ident::Task { path }) => match pc.task(path)? {
            Some(t) => task(pc, &t.xml).map(Some),
            None => Ok(None),
        },
        (Location::Service, Ident::Service { name }) => match pc.service(name)? {
            Some(s) => {
                let hosted = services::target(pc, &s).is_some_and(|t| services::hosted(&t));
                Ok(Some(service(pc, &s, hosted)))
            }
            None => Ok(None),
        },
        _ => Err("this entry has no switch".into()),
    }
}

/// An entry of any kind takes its definition as the scan read it (the one rule, RB3). Read
/// whole, it switches both ways. With part of what it runs not established (`Fresh::off_only`),
/// it switches off only (`Entry::off_only`), its row says why (added to its note, never in place
/// of it), and it is never Windows' own or folded as Microsoft's (`through`: its signer says
/// nothing of what runs). Not read at all, its switch is unknown (never toggled), as an
/// unreadable switch is.
pub fn bind(e: &mut super::Entry, r: Result<Fresh, String>) {
    match r {
        Ok(f) => {
            e.def = Some(f.def);
            e.core = Some(f.core);
            e.off_only = f.off_only.clone();
            if let Some(why) = f.off_only {
                let said = format!("{why}: VibeBoot can switch it off, not on");
                e.note = Some(match e.note.take() {
                    Some(n) => format!("{n}; {said}"),
                    None => said,
                });
                e.through.get_or_insert(why);
            }
        }
        Err(why) => {
            e.def = None;
            e.core = None;
            e.off_only = None;
            if e.data.is_some() {
                e.switch = super::Switch::Unknown(format!("{why}, so VibeBoot cannot tell what it is: left alone"));
                e.data = None;
            }
        }
    }
}

// ---------- SHA-256 (FIPS 180-4), std only ----------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    len: usize,
    total: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Sha256::new()
    }
}

impl Sha256 {
    pub fn new() -> Sha256 {
        Sha256 { h: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19], buf: [0; 64], len: 0, total: 0 }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        while !data.is_empty() {
            let n = (64 - self.len).min(data.len());
            self.buf[self.len..self.len + n].copy_from_slice(&data[..n]);
            self.len += n;
            data = &data[n..];
            if self.len == 64 {
                let block = self.buf;
                self.block(&block);
                self.len = 0;
            }
        }
    }

    pub fn finish(mut self) -> [u8; 32] {
        let bits = self.total.wrapping_mul(8);
        self.update(&[0x80]);
        while self.len != 56 {
            self.update(&[0]);
        }
        let mut last = self.buf;
        last[56..].copy_from_slice(&bits.to_be_bytes());
        self.block(&last);
        let mut out = [0u8; 32];
        for (i, w) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn block(&mut self, b: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b2, mut c, mut d, mut e, mut f, mut g, mut h] = self.h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b2) ^ (a & c) ^ (b2 & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b2;
            b2 = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in self.h.iter_mut().zip([a, b2, c, d, e, f, g, h]) {
            *x = x.wrapping_add(y);
        }
    }
}
