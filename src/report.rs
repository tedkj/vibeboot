//! Copy report / Save report: plain text, English, every entry (the window's filters and folds
//! aside) with its location, command, signer, dates and state; footer "VibeBoot 0.1.0". Every
//! text from outside is cleaned (bidi and invisible characters gone).

use crate::autostart::{DateFact, Entry, FileState, Signer, Switch, dates, switch, text};
use crate::groups::{self, Facts, Group};

/// What the report says about the scan as a whole.
pub struct Head<'a> {
    pub scanned: &'a str,
    pub summary: &'a str,
    /// Locations that could not be read, as the window says them.
    pub failed: Vec<String>,
    pub notes: Vec<String>,
}

pub fn date_line(d: &DateFact, offset: &dyn Fn(i64) -> i64) -> String {
    format!("{} {}", d.kind.words(), dates::day_text(d.at + offset(d.at)))
}

pub fn signer_words(f: &Facts) -> String {
    match f.sign.as_ref().map(|s| &s.signer) {
        None => "not checked".into(),
        Some(Signer::Microsoft) => "Microsoft".into(),
        Some(Signer::SignedBy(n)) => format!("signed by {}", text::clean(n)),
        Some(Signer::NotSigned) => "not signed".into(),
        Some(Signer::Broken(w)) => format!("signature broken ({w})"),
        Some(Signer::Missing) => "file missing".into(),
        Some(Signer::Unknown(w)) => format!("unknown ({w})"),
    }
}

pub fn state_words(s: &Switch) -> String {
    match s {
        Switch::On => "on".into(),
        Switch::Off { .. } => "off".into(),
        Switch::Unknown(w) => format!("unknown: {w}"),
        Switch::Fixed(_) => "no switch".into(),
    }
}

pub fn file_words(f: &FileState) -> String {
    match f {
        FileState::Present => "there".into(),
        FileState::Missing => "missing".into(),
        FileState::Unknown(w) => format!("unknown ({w})"),
        FileState::NoTarget => "none".into(),
    }
}

pub fn build(head: &Head, entries: &[Entry], facts: &[Facts], offset: &dyn Fn(i64) -> i64) -> String {
    let mut out = String::new();
    out.push_str("VibeBoot report\n");
    out.push_str(&format!("Scanned {}\n", head.scanned));
    out.push_str(&format!("{}\n", head.summary));
    for f in &head.failed {
        out.push_str(&format!("Could not be read: {}\n", text::clean(f)));
    }
    for n in &head.notes {
        out.push_str(&format!("{}\n", text::clean(n)));
    }
    let order = groups::order(entries, facts);
    for g in Group::ALL {
        let mine: Vec<usize> = order.iter().copied().filter(|&i| Group::of(entries[i].location) == g).collect();
        out.push_str(&format!("\n== {} ({}) ==\n", g.title(), mine.len()));
        for i in mine {
            let (e, f) = (&entries[i], &facts[i]);
            out.push_str(&format!("\n[{}] {}\n", state_words(&e.switch), text::clean(&e.name)));
            out.push_str(&format!("  Location: {} · {}\n", e.location.label(), text::clean(&e.place)));
            if !e.raw.is_empty() {
                out.push_str(&format!("  Command: {}\n", text::clean(&e.raw)));
            }
            if !e.expanded.is_empty() && e.expanded != e.raw {
                out.push_str(&format!("  Expanded: {}\n", text::clean(&e.expanded)));
            }
            if let Some(t) = &e.target {
                out.push_str(&format!("  Target: {} ({})\n", text::clean(&t.to_string_lossy()), file_words(&e.file)));
            }
            let mut sig = signer_words(f);
            if let Some(c) = f.sign.as_ref().and_then(|s| s.company.as_deref()) {
                sig.push_str(&format!(" · says it is from {}", text::clean(c)));
            }
            out.push_str(&format!("  Signer: {sig}\n"));
            let mut flags: Vec<String> = Vec::new();
            if e.script {
                flags.push("runs a script or command".into());
            }
            if e.hidden {
                flags.push("hidden command".into());
            }
            if f.inline {
                flags.push("a command written into the entry (the signer is its interpreter's)".into());
            }
            if let Some(t) = f.launched() {
                flags.push(format!("{} (the signer is its program's)", text::clean(t)));
            }
            if f.new {
                flags.push("new since the last look".into());
            }
            if e.unread.is_some() {
                flags.push("could not be read".into());
            }
            if !flags.is_empty() {
                out.push_str(&format!("  Flags: {}\n", flags.join(", ")));
            }
            let added = match dates::added(&e.dates) {
                Some(d) if dates::weak(&d) => format!("not known, key changed {} ({})", dates::day_text(d.at + offset(d.at)), if d.kind == crate::autostart::DateKind::ServiceChanged { "an update or a switch changes it too" } else { "shared by every value in the key" }),
                Some(d) => date_line(&d, offset),
                None => "not known".into(),
            };
            out.push_str(&format!("  Added: {added}\n"));
            if !e.dates.is_empty() {
                let d: Vec<String> = e.dates.iter().map(|d| date_line(d, offset)).collect();
                out.push_str(&format!("  Dates: {}\n", d.join("; ")));
            }
            if let Some(a) = &e.account {
                out.push_str(&format!("  Account: {}\n", text::clean(a)));
            }
            if let Some(t) = &e.task {
                if !t.when.is_empty() {
                    out.push_str(&format!("  Runs: {}\n", t.when));
                }
                let last = t.last_run.map(|r| dates::time_text(r + offset(r))).unwrap_or_else(|| "never".into());
                out.push_str(&format!("  Last run: {last} · result: {}\n", text::clean(&t.last_result)));
            }
            if let Some(s) = &e.service {
                out.push_str(&format!("  Start type: {} · {}\n", switch::start_words(s.start, s.delayed), s.state));
            }
            if let Switch::Fixed(w) | Switch::Unknown(w) = &e.switch {
                out.push_str(&format!("  Switch: {}\n", text::clean(w)));
            }
            if let Some(n) = &e.note {
                out.push_str(&format!("  Note: {}\n", text::clean(n)));
            }
        }
    }
    out.push_str(&format!("\nVibeBoot {}\n", crate::VERSION));
    out
}
