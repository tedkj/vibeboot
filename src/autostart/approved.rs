//! StartupApproved: Windows' own on/off switch for Run values and startup-folder files, the one
//! Task Manager's Startup tab and Settings > Apps > Startup write. Pure: the codec and the key
//! names; the registry calls are the `Pc`'s.
//!
//! `Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`, `\Run32` and
//! `\StartupFolder`, under HKCU or HKLM. The value name is the Run value's name or the startup
//! file's name; REG_BINARY, 12 bytes. Byte 0 odd is disabled (Task Manager writes 0x03), even is
//! enabled (0x02; 0x06 seen); no value is enabled. Bytes 4..12 of a disabled value are the
//! FILETIME (UTC) it was disabled (zero seen too: "disabled, date not recorded"). A value of
//! another length or type is unknown and never toggled.

use serde::{Deserialize, Serialize};

pub const BASE: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";
pub const REG_BINARY: u32 = 3;

/// Which StartupApproved key a location's switch lives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Sub {
    Run,
    Run32,
    StartupFolder,
}

impl Sub {
    pub fn name(self) -> &'static str {
        match self {
            Sub::Run => "Run",
            Sub::Run32 => "Run32",
            Sub::StartupFolder => "StartupFolder",
        }
    }

    /// The key's path under its hive.
    pub fn path(self) -> String {
        format!(r"{BASE}\{}", self.name())
    }
}

/// What a StartupApproved value says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// No value: enabled (Windows' default).
    Absent,
    /// An even byte 0.
    Enabled,
    /// An odd byte 0; the FILETIME it was disabled, when one was recorded (nonzero).
    Disabled { at: Option<u64> },
    /// Another length or type: shown as it is, never toggled.
    Unknown { len: usize, kind: u32 },
}

impl State {
    pub fn on(&self) -> Option<bool> {
        match self {
            State::Absent | State::Enabled => Some(true),
            State::Disabled { .. } => Some(false),
            State::Unknown { .. } => None,
        }
    }
}

/// A value as read: its registry type and bytes (None: no value).
pub fn decode(v: Option<(u32, &[u8])>) -> State {
    let Some((kind, b)) = v else { return State::Absent };
    if kind != REG_BINARY || b.len() != 12 {
        return State::Unknown { len: b.len(), kind };
    }
    if b[0] & 1 == 0 {
        return State::Enabled;
    }
    let t = u64::from_le_bytes(b[4..12].try_into().unwrap_or([0; 8]));
    State::Disabled { at: (t != 0).then_some(t) }
}

/// Task Manager's "disable": `03 00 00 00` and the FILETIME now.
pub fn disable_bytes(now: u64) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0] = 0x03;
    b[4..].copy_from_slice(&now.to_le_bytes());
    b
}

/// Task Manager's "enable": `02 00 00 00` and 8 zero bytes.
pub fn enable_bytes() -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0] = 0x02;
    b
}

/// The bytes a switch writes: Task Manager's, for on or off.
pub fn bytes_for(on: bool, now: u64) -> [u8; 12] {
    if on { enable_bytes() } else { disable_bytes(now) }
}

/// A value this app may write (the helper checks it too): 12 bytes. A switch writes Task
/// Manager's two forms; Undo puts back whatever 12-byte value was there before (an odd one
/// such as `02 01 00 00 …` included), so any 12 bytes may be written back.
pub fn writable(b: &[u8]) -> bool {
    b.len() == 12
}
