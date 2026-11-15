//! The autostart scanner: everything that starts with this PC, from every hiding place (Run keys,
//! startup folders, logon and boot tasks, auto-start services and drivers), with its switch,
//! target, signer and dates; the switches themselves (re-read before acting), the journal and
//! undo, and first-seen. Shared with VibeScamCheck word for word (spec section 1): this folder
//! uses nothing of the app around it (std, serde, serde_json, quick-xml and windows-sys only),
//! so it can be copied as it is. A fix goes to both repos.
//!
//! Everything that touches Windows goes through the `Pc` trait (`pc.rs`): `SystemPc` is the real
//! one, `fake::FakePc` a scripted PC for tests. The scan and the switches are written against the
//! trait, so their rules are tested without touching the PC the tests run on.

pub mod approved;
pub mod cmdline;
pub mod dates;
pub mod def;
pub mod fake;
pub mod folders;
pub mod journal;
pub mod lnk;
pub mod pc;
pub mod run;
pub mod scan;
pub mod seen;
pub mod services;
pub mod signer;
pub mod state;
pub mod switch;
pub mod sys;
pub mod tasks;
pub mod taskxml;
pub mod text;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The registry hives the scanner reads: this account's, the machine's, and `HKEY_USERS` (another
/// account's classes, for a task that runs as that account: `def::class_keys`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Hive {
    User,
    Machine,
    Users,
}

impl Hive {
    pub fn name(self) -> &'static str {
        match self {
            Hive::User => "HKEY_CURRENT_USER",
            Hive::Machine => "HKEY_LOCAL_MACHINE",
            Hive::Users => "HKEY_USERS",
        }
    }
}

/// Where an entry was found. Every entry carries one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Location {
    RunUser,
    RunOnceUser,
    RunMachine,
    RunOnceMachine,
    RunMachine32,
    RunOnceMachine32,
    PolicyRunUser,
    PolicyRunMachine,
    StartupUser,
    StartupCommon,
    LogonTask,
    Service,
    Driver,
}

impl Location {
    pub const ALL: [Location; 13] = [
        Location::RunUser,
        Location::RunOnceUser,
        Location::RunMachine,
        Location::RunOnceMachine,
        Location::RunMachine32,
        Location::RunOnceMachine32,
        Location::PolicyRunUser,
        Location::PolicyRunMachine,
        Location::StartupUser,
        Location::StartupCommon,
        Location::LogonTask,
        Location::Service,
        Location::Driver,
    ];

    /// The Run-style registry locations: hive and key path (HKLM read in its 64-bit view; the
    /// 32-bit programs' key is named by its WOW6432Node path).
    pub const RUN_KEYS: [Location; 8] = [
        Location::RunUser,
        Location::RunOnceUser,
        Location::RunMachine,
        Location::RunOnceMachine,
        Location::RunMachine32,
        Location::RunOnceMachine32,
        Location::PolicyRunUser,
        Location::PolicyRunMachine,
    ];

    pub fn reg(self) -> Option<(Hive, &'static str)> {
        Some(match self {
            Location::RunUser => (Hive::User, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            Location::RunOnceUser => (Hive::User, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            Location::RunMachine => (Hive::Machine, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            Location::RunOnceMachine => (Hive::Machine, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            Location::RunMachine32 => (Hive::Machine, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            Location::RunOnceMachine32 => (Hive::Machine, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
            Location::PolicyRunUser => (Hive::User, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            Location::PolicyRunMachine => (Hive::Machine, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            _ => return None,
        })
    }

    /// Where the entry's StartupApproved switch lives, for the locations that have one.
    pub fn approved(self) -> Option<(Hive, approved::Sub)> {
        Some(match self {
            Location::RunUser => (Hive::User, approved::Sub::Run),
            Location::RunMachine => (Hive::Machine, approved::Sub::Run),
            Location::RunMachine32 => (Hive::Machine, approved::Sub::Run32),
            Location::StartupUser => (Hive::User, approved::Sub::StartupFolder),
            Location::StartupCommon => (Hive::Machine, approved::Sub::StartupFolder),
            _ => return None,
        })
    }

    /// Why an entry here has no switch (None: it has one).
    pub fn no_switch(self) -> Option<&'static str> {
        match self {
            Location::RunOnceUser | Location::RunOnceMachine | Location::RunOnceMachine32 => Some("Runs once at the next sign-in and Windows removes it then: there is nothing to switch"),
            Location::PolicyRunUser | Location::PolicyRunMachine => Some("Set by a policy: change it where the policy is set"),
            Location::Driver => Some("Drivers are read only here: switching one off can stop Windows from starting"),
            _ => None,
        }
    }

    /// A short name for the location, in the detail panel and the report.
    pub fn label(self) -> &'static str {
        match self {
            Location::RunUser => "Run key (this user)",
            Location::RunOnceUser => "RunOnce key (this user)",
            Location::RunMachine => "Run key (all users)",
            Location::RunOnceMachine => "RunOnce key (all users)",
            Location::RunMachine32 => "Run key (all users, 32-bit)",
            Location::RunOnceMachine32 => "RunOnce key (all users, 32-bit)",
            Location::PolicyRunUser => "Policy Run key (this user)",
            Location::PolicyRunMachine => "Policy Run key (all users)",
            Location::StartupUser => "Startup folder (this user)",
            Location::StartupCommon => "Startup folder (all users)",
            Location::LogonTask => "Scheduled task",
            Location::Service => "Service",
            Location::Driver => "Driver",
        }
    }

    /// The location's stable name in keys and files ("RunUser").
    pub fn tag(self) -> &'static str {
        match self {
            Location::RunUser => "RunUser",
            Location::RunOnceUser => "RunOnceUser",
            Location::RunMachine => "RunMachine",
            Location::RunOnceMachine => "RunOnceMachine",
            Location::RunMachine32 => "RunMachine32",
            Location::RunOnceMachine32 => "RunOnceMachine32",
            Location::PolicyRunUser => "PolicyRunUser",
            Location::PolicyRunMachine => "PolicyRunMachine",
            Location::StartupUser => "StartupUser",
            Location::StartupCommon => "StartupCommon",
            Location::LogonTask => "LogonTask",
            Location::Service => "Service",
            Location::Driver => "Driver",
        }
    }
}

/// What a change acts on, exactly as Windows names it (never a cleaned or lossy string).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ident {
    /// A Run-style value: its name's UTF-16 units.
    Value { name: Vec<u16> },
    /// A startup-folder file: its name's units (the StartupApproved value name) and its path.
    File { name: Vec<u16>, path: PathBuf },
    /// A task's full path ("\Vendor\Updater").
    Task { path: String },
    /// A service's key name.
    Service { name: String },
}

impl Ident {
    /// The entry key part that names this (seen.json, the journal).
    pub fn key_part(&self) -> String {
        match self {
            Ident::Value { name } | Ident::File { name, .. } => text::units_key(name),
            Ident::Task { path } => path.clone(),
            Ident::Service { name } => name.to_ascii_lowercase(),
        }
    }
}

/// The entry key: location and identity ("RunUser|Steam", "Service|wuauserv").
pub fn entry_key(loc: Location, ident: &Ident) -> String {
    format!("{}|{}", loc.tag(), ident.key_part())
}

/// An entry's switch as it stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Switch {
    On,
    /// Off; for StartupApproved the FILETIME it was switched off, when Windows recorded one.
    Off { since: Option<u64> },
    /// The switch's data has a form this app does not know: shown, never toggled.
    Unknown(String),
    /// No switch here, and why.
    Fixed(String),
}

impl Switch {
    pub fn on(&self) -> Option<bool> {
        match self {
            Switch::On => Some(true),
            Switch::Off { .. } => Some(false),
            _ => None,
        }
    }
}

/// The target file, as the scan found it.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum FileState {
    Present,
    /// NotFound, with its folder answering.
    Missing,
    /// Anything else (access denied, a share that does not answer, a bare name).
    Unknown(String),
    /// No target to look at (an empty command, a ComHandler without a DLL).
    #[default]
    NoTarget,
}

/// Who signed a file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signer {
    /// Trusted, signed by Microsoft Windows, Microsoft Windows Publisher or Microsoft Corporation
    /// (system catalogs included).
    Microsoft,
    /// Trusted, signed by someone else (Microsoft's hardware compatibility publisher included:
    /// it signs other makers' drivers).
    SignedBy(String),
    NotSigned,
    /// A signature that does not check out (changed since signing, revoked, untrusted root).
    Broken(String),
    /// NotFound, with its folder answering.
    Missing,
    /// Could not be checked.
    Unknown(String),
}

impl Signer {
    /// A definite answer about the file's bytes (one a cache may keep: never a failure).
    pub fn definite(&self) -> bool {
        matches!(self, Signer::Microsoft | Signer::SignedBy(_) | Signer::NotSigned | Signer::Broken(_))
    }
}

/// A signer check: the kind and the version resource's CompanyName ("says it is from",
/// unverified).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignInfo {
    pub signer: Signer,
    pub company: Option<String>,
}

/// One date about an entry, with where it comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DateKind {
    /// A startup-folder file's creation time.
    Added,
    /// A task's RegistrationInfo/Date.
    Registered,
    /// A task file's creation time.
    TaskFile,
    /// The target file's creation time.
    ProgramCreated,
    /// A service binary's creation time.
    BinaryCreated,
    /// The Run key's last write (shared by every value in it).
    RunKeyChanged,
    /// The service key's last write.
    ServiceChanged,
    /// StartupApproved's time of switching off.
    Disabled,
    /// First seen by this app on this PC, at a look after an earlier one that read its location
    /// and did not have it.
    Appeared,
    /// Seen by this app on this PC since its first look at the location: there then, nothing
    /// more is known.
    KnownSince,
}

impl DateKind {
    pub fn words(self) -> &'static str {
        match self {
            DateKind::Added => "added",
            DateKind::Registered => "registered",
            DateKind::TaskFile => "task file created",
            DateKind::ProgramCreated => "program file created",
            DateKind::BinaryCreated => "program file created",
            DateKind::RunKeyChanged => "Run key last changed",
            DateKind::ServiceChanged => "service settings changed",
            DateKind::Disabled => "disabled",
            DateKind::Appeared => "first seen by VibeBoot",
            DateKind::KnownSince => "seen by VibeBoot since",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateFact {
    pub kind: DateKind,
    /// Unix seconds (UTC).
    pub at: i64,
}

/// A scheduled task's run facts.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct TaskFacts {
    pub enabled: bool,
    pub state: String,
    pub last_run: Option<i64>,
    pub last_result: String,
    pub when: String,
    pub author: Option<String>,
    pub run_level: Option<String>,
    /// Runs as this account without the highest privileges: switched without admin rights.
    pub own: bool,
    /// How many actions it has (the entry's target is the first's).
    pub actions: usize,
}

/// A service's facts.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ServiceFacts {
    pub name: String,
    pub start: u32,
    pub delayed: bool,
    pub state: String,
    pub kind: u32,
    /// FS8: VibeBoot's own note in the service's key says it switched it to Manual from
    /// Automatic: its delayed flag then (switching it back on puts that back).
    pub was_delayed: Option<bool>,
}

/// One autostart entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub location: Location,
    pub ident: Ident,
    /// `entry_key(location, ident)`.
    pub key: String,
    /// Shown: the Run value's name, the file's name, the task's name, the service's display name
    /// (cleaned).
    pub name: String,
    /// The command as stored (raw: REG_SZ text, a shortcut's target and arguments, a task's
    /// Exec, a service's binary path).
    pub raw: String,
    /// The command with its variables expanded.
    pub expanded: String,
    /// The file it is about (the program, the DLL, the script), when one could be told.
    pub target: Option<PathBuf>,
    pub file: FileState,
    /// The target's identity, size and last write (the signer cache's key).
    pub file_key: Option<FileKey>,
    /// An interpreter runs a script or command.
    pub script: bool,
    /// An encoded command or a hidden window.
    pub hidden: bool,
    /// Its program is handed a file or URL from outside Windows' own folders, in words: "runs
    // offpc-ok: prose
    /// C:\Users\x\evil.exe through rundll32.exe" (`cmdline::through`). A Microsoft signature on
    /// the program then says nothing about what runs.
    pub through: Option<String>,
    /// Something odd about the command itself ("empty", "an unbalanced quote").
    pub note: Option<String>,
    pub switch: Switch,
    /// The switch's raw data as read (StartupApproved bytes or none, a task's enabled flag, a
    /// service's start type): what a change compares with right before acting.
    pub data: Option<switch::Data>,
    /// Where: the full registry path, the folder, the task's path, the service's key.
    pub place: String,
    pub dates: Vec<DateFact>,
    /// The account it runs as or for.
    pub account: Option<String>,
    pub task: Option<TaskFacts>,
    pub service: Option<ServiceFacts>,
    /// What could not be read about it (a registry value too large to read, a task whose
    /// definition or path could not be read): flagged for attention, never toggled.
    pub unread: Option<String>,
    /// What the entry is, apart from its switch, as the scan read it (`def`): a change carries
    /// it and is made only while the entry still has it. None: it could not be read (no switch).
    pub def: Option<def::Def>,
    /// Which entry it is, apart from what it runs (`def::Fresh::core`): what a switch-off is
    /// bound to (RB4-1). None with `def`.
    pub core: Option<def::Def>,
    /// Part of what it runs could not be established, and why (the one rule, RB3: a startup
    /// file's bytes or shortcut, a COM handler, a service's DLL): `def` is then which entry it is
    /// alone, and VibeBoot switches it off, never on (`def::Fresh::off_only`, `def::bind`).
    pub off_only: Option<String>,
}

impl Entry {
    /// Its definition as the scan read it (`def::Fresh`), which a change is bound to
    /// (`switch::request_for`); None: it could not be read (no switch).
    pub fn reading(&self) -> Option<def::Fresh> {
        Some(def::Fresh { def: self.def?, core: self.core?, off_only: self.off_only.clone() })
    }

    /// A row with no identity of its own (a task that could not be read at all, its path not
    /// known): never recorded as seen, never "new".
    pub fn anonymous(&self) -> bool {
        matches!(&self.ident, Ident::Task { path } if path.is_empty())
    }

    /// It runs a command written into itself (`cmdline::inline`).
    pub fn inline(&self) -> bool {
        cmdline::inline(self.script, self.target.as_deref())
    }

    /// Its program's signature says nothing about what it runs: a command written into it, or a
    /// file or URL from outside Windows' own folders handed to its program (`through`). Never
    /// "from Microsoft", never one of Windows' own.
    pub fn borrowed(&self) -> bool {
        self.inline() || self.through.is_some()
    }
}

/// A file's identity for caching: volume serial, 128-bit id, size and last write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileKey {
    pub serial: u64,
    pub id: [u8; 16],
    pub size: u64,
    pub written: u64,
}

impl FileKey {
    /// Zero serial or id: unknown, never a key (VIBEWARE "Identity, not names").
    pub fn usable(&self) -> bool {
        self.serial != 0 && self.id != [0; 16]
    }
}
