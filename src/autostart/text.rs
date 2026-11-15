//! Text from outside (Run value names and data, file names, task XML, service names, signer
//! names) as it may be shown: in the window, toasts, the status line and reports. Cleaned at
//! display only: what is handed to Windows (a value name, a task path) stays raw, as the exact
//! UTF-16 units Windows gave (a lone surrogate included: VibeRename RR-7).

/// Characters that change how the text around them reads without showing themselves: controls,
/// bidirectional embeddings, overrides, isolates and marks, zero-width spaces and line
/// separators, the soft hyphen and the Unicode tag characters (VibeLink LINK-5). The joiners
/// U+200C (ZWNJ) and U+200D (ZWJ) stay: emoji and Persian or Indic names need them.
pub fn invisible(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}' | '\u{200E}' | '\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}' | '\u{E0000}'..='\u{E007F}')
}

/// Outside text as it may be shown: invisible characters gone, runs of whitespace one space,
/// trimmed, at most `max` characters (an ellipsis marks a cut; cut by character, never by byte).
pub fn clean_max(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max.saturating_mul(4)));
    let mut space = false;
    let mut n = 0usize;
    let mut cut = false;
    for c in s.chars() {
        if c.is_whitespace() || c == '\u{2028}' || c == '\u{2029}' {
            space = !out.is_empty();
            continue;
        }
        if invisible(c) {
            continue;
        }
        if space {
            if n + 1 >= max {
                cut = true;
                break;
            }
            out.push(' ');
            n += 1;
            space = false;
        }
        if n >= max {
            cut = true;
            break;
        }
        out.push(c);
        n += 1;
    }
    if cut && max > 0 {
        out.pop();
        out.push('…');
    }
    out
}

/// Outside text, at most 400 characters (a command line can be long; the window elides).
pub fn clean(s: &str) -> String {
    clean_max(s, 400)
}

/// UTF-16 units from Windows as text to show: lossy (a lone surrogate shows as U+FFFD), cleaned.
pub fn units(u: &[u16]) -> String {
    clean(&String::from_utf16_lossy(u))
}

/// UTF-16 from Windows as shown text, at most `max` characters: a lone surrogate becomes U+FFFD,
/// then cleaned (the template's `text::clean_wide`, for About's install check).
pub fn clean_wide(w: &[u16], max: usize) -> String {
    clean_max(&String::from_utf16_lossy(w), max)
}

/// UTF-16 units as a key that names exactly these units: the text itself where it is valid
/// UTF-16 (a backslash doubled), a lone surrogate as `\uD800`. Two different unit strings never
/// share a key (seen.json and the journal key entries by it).
pub fn units_key(u: &[u16]) -> String {
    let mut out = String::with_capacity(u.len());
    for r in char::decode_utf16(u.iter().copied()) {
        match r {
            Ok('\\') => out.push_str("\\\\"),
            Ok(c) => out.push(c),
            Err(e) => out.push_str(&format!("\\u{:04X}", e.unpaired_surrogate())),
        }
    }
    out
}

/// The units a `units_key` was made from (None for a string no `units_key` makes).
pub fn units_from_key(k: &str) -> Option<Vec<u16>> {
    let mut out = Vec::with_capacity(k.len());
    let mut chars = k.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            let mut b = [0u16; 2];
            out.extend_from_slice(c.encode_utf16(&mut b));
            continue;
        }
        match chars.next()? {
            '\\' => out.push(u16::from(b'\\')),
            'u' => {
                let hex: String = chars.by_ref().take(4).collect();
                if hex.len() != 4 || !hex.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_lowercase()) {
                    return None;
                }
                let v = u16::from_str_radix(&hex, 16).ok()?;
                if !(0xD800..=0xDFFF).contains(&v) {
                    return None;
                }
                out.push(v);
            }
            _ => return None,
        }
    }
    Some(out)
}

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Units with a NUL at the end, for a Windows call.
pub fn nul(u: &[u16]) -> Vec<u16> {
    u.iter().copied().chain(std::iter::once(0)).collect()
}

/// A 32-bit Windows error or HRESULT in Windows' own words ("Access is denied."), or its number.
pub fn os_words(code: u32) -> String {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Diagnostics::Debug::{FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS, FormatMessageW};
        let mut buf = [0u16; 512];
        // SAFETY: a buffer and its length in units; no inserts.
        let n = unsafe { FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, std::ptr::null(), code, 0x0409, buf.as_mut_ptr(), buf.len() as u32, std::ptr::null()) } as usize;
        let s = clean(&String::from_utf16_lossy(&buf[..n.min(buf.len())]));
        if !s.is_empty() {
            return format!("{} (0x{code:08X})", s.trim_end_matches('.'));
        }
    }
    format!("error 0x{code:08X}")
}
