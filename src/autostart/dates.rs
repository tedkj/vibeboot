//! Dates: Windows' FILETIME and OLE dates as Unix seconds, a task's XML date, the calendar, and
//! which of an entry's dates says best when it was added. Pure.

use super::{DateFact, DateKind};

/// 100-ns ticks between 1601-01-01 and 1970-01-01.
const EPOCH_DIFF: u64 = 116_444_736_000_000_000;

/// A FILETIME (UTC) as Unix seconds; None for zero or a time before 1970.
pub fn unix_from_filetime(ft: u64) -> Option<i64> {
    (ft > EPOCH_DIFF).then(|| ((ft - EPOCH_DIFF) / 10_000_000) as i64)
}

pub fn filetime_from_unix(secs: i64) -> u64 {
    (secs.max(0) as u64) * 10_000_000 + EPOCH_DIFF
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
pub fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y as i64 - 1 } else { y as i64 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The civil date of a day number.
pub fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    ((if m <= 2 { y + 1 } else { y }) as i32, m, d)
}

/// "12.10.2026" for local seconds (Unix seconds shifted to local time by the caller).
pub fn day_text(local: i64) -> String {
    let (y, m, d) = civil_from_days(local.div_euclid(86_400));
    format!("{d:02}.{m:02}.{y}")
}

// offpc-ok: a time
/// "12.10.2026 14:02" for local seconds.
pub fn time_text(local: i64) -> String {
    let s = local.rem_euclid(86_400);
    format!("{} {:02}:{:02}", day_text(local), s / 3600, (s / 60) % 60)
}

/// Wall-clock parts: year, month, day, hour, minute, second.
pub type Wall = (i32, u32, u32, u32, u32, u32);

/// A task's RegistrationInfo/Date: `2026-09-14T10:22:31.5551234`, maybe with `Z` or an offset.
/// Returns the wall-clock parts and, when the text names one, its offset from UTC in seconds.
pub fn parse_xml_date(s: &str) -> Option<(Wall, Option<i64>)> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() < 10 || !s.is_ascii() {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> { s.get(r)?.parse().ok() };
    if b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let (y, mo, d) = (num(0..4)? as i32, num(5..7)?, num(8..10)?);
    let (mut h, mut mi, mut se) = (0, 0, 0);
    let mut rest = &s[10..];
    if let Some(t) = rest.strip_prefix('T') {
        let tb = t.as_bytes();
        if tb.len() < 5 || tb[2] != b':' {
            return None;
        }
        h = t.get(0..2)?.parse().ok()?;
        mi = t.get(3..5)?.parse().ok()?;
        rest = &t[5..];
        if let Some(r) = rest.strip_prefix(':') {
            se = r.get(0..2)?.parse().ok()?;
            rest = &r[2..];
        }
        if let Some(r) = rest.strip_prefix('.') {
            let n = r.bytes().take_while(u8::is_ascii_digit).count();
            rest = &r[n..];
        }
    }
    let off = match rest {
        "" => None,
        "Z" => Some(0),
        r if (r.starts_with('+') || r.starts_with('-')) && r.len() == 6 && r.as_bytes()[3] == b':' => {
            let sign = if r.starts_with('-') { -1 } else { 1 };
            let oh: i64 = r.get(1..3)?.parse().ok()?;
            let om: i64 = r.get(4..6)?.parse().ok()?;
            Some(sign * (oh * 3600 + om * 60))
        }
        _ => return None,
    };
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 || !(1970..=9999).contains(&y) {
        return None;
    }
    Some(((y, mo, d, h, mi, se), off))
}

/// Wall-clock parts at a known offset from UTC, as Unix seconds.
pub fn unix_at(p: Wall, offset: i64) -> i64 {
    days_from_civil(p.0, p.1, p.2) * 86_400 + (p.3 * 3600 + p.4 * 60 + p.5) as i64 - offset
}

/// An OLE automation date (days since 1899-12-30, local wall clock) as its wall-clock parts;
/// None for "never" (0 or below 1).
pub fn ole_parts(v: f64) -> Option<Wall> {
    if !v.is_finite() || v < 1.0 || v > 2_958_465.0 {
        return None;
    }
    let days = v.floor() as i64;
    let secs = ((v - v.floor()) * 86_400.0).round() as i64;
    let (y, m, d) = civil_from_days(days - 25_569 + secs.div_euclid(86_400));
    let s = secs.rem_euclid(86_400);
    Some((y, m, d, (s / 3600) as u32, ((s / 60) % 60) as u32, (s % 60) as u32))
}

/// Evidence of the entry itself, each good on its own: first seen by this app after an earlier
/// look without it, a startup file's creation, a task's registration and its task file's
/// creation. Not a service key's last write: an updater rewriting the program path, or any
/// switch of its start type (VibeBoot's own too), changes it.
pub fn sure(kind: DateKind) -> bool {
    matches!(kind, DateKind::Appeared | DateKind::Added | DateKind::Registered | DateKind::TaskFile)
}

/// The date that says when an entry was added, and which it is. "Added" never claims old when
/// any evidence says new: the newest sure evidence of the entry itself (`sure`); never the
/// program file's creation (an old interpreter or system program says nothing about the entry
/// that runs it) and never a switch-off. With no sure evidence, its key's last write (a Run-style
/// key's, shared by every value in it; a service's, changed by updates and switches) when the
/// entry could be that change (this app has not seen it before then): weak, said as "added: not
/// known, key changed <date>" (`weak`).
pub fn added(dates: &[DateFact]) -> Option<DateFact> {
    if let Some(d) = dates.iter().filter(|d| sure(d.kind)).max_by_key(|d| d.at) {
        return Some(*d);
    }
    let key = dates.iter().filter(|d| matches!(d.kind, DateKind::RunKeyChanged | DateKind::ServiceChanged)).max_by_key(|d| d.at)?;
    let there_before = dates.iter().any(|d| d.kind == DateKind::KnownSince && d.at < key.at);
    (!there_before).then_some(*key)
}

/// Whether an `added` date is only the key's last change (the entry may be older).
pub fn weak(d: &DateFact) -> bool {
    !sure(d.kind)
}
