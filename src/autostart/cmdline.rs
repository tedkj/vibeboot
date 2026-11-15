//! Command lines as Windows runs them (pure: the file system comes in as `exists`).
//!
//! - `%VAR%` is expanded where the variable exists (REG_EXPAND_SZ, and `%VAR%` in REG_SZ too);
//!   an unknown variable stays as written (as `ExpandEnvironmentStringsW` leaves it). The raw
//!   text is kept and shown beside the expanded one.
//! - A quoted program path is the program. An unquoted one with spaces is resolved the way
//!   `CreateProcess` does: each prefix ending at a space in turn, `.exe` added when it has no
//!   extension, the first existing file wins. A bare name (`ctfmon.exe`) is looked for in the
//!   system folders.
//! - `rundll32.exe x.dll,Entry` and `regsvr32 /s x.dll` target the DLL.
//! - Interpreters (`powershell`, `pwsh`, `cmd`, `wscript`, `cscript`, `mshta`,
//!   `conhost --headless`) mark the entry "runs a script or command"; the target is the script
//!   file when an argument names one. `-EncodedCommand` (and its short forms) or a hidden window
//!   flag it "hidden command".
//! - An argument naming a file or URL outside Windows' own folders (`foreign`) is what the
//!   program runs too: "runs C:\Users\x\evil.exe through rundll32.exe" (`through`), so a
//!   Microsoft signature on the program says nothing about the entry.

use std::path::{Path, PathBuf};

/// The longest command line Windows starts (`CreateProcess`), in UTF-16 units: an expansion
/// stops there, and no path longer is ever looked up (IN-VibeBoot-2, IN-VibeBoot-4).
pub const MAX_UNITS: usize = 32_767;

/// The most command lines nested in one another (`cmd /c`, `conhost --headless`) that are
/// followed; one nested deeper is not established (IN-VibeBoot-1).
pub const MAX_NESTING: usize = 8;

/// The most places a program's name may end at (an unquoted line's spaces) that are looked up,
/// and the most bare file names among its arguments looked for in the system folders
/// (IN-VibeBoot-2).
pub const MAX_TRIES: usize = 64;

/// Why what a command runs is not established: it nests deeper than VibeBoot follows.
pub const TOO_DEEP: &str = "its command is nested more than 8 deep (cmd /c, conhost --headless), deeper than VibeBoot follows";

/// Why what a command runs is not established: its program's name may end at more places than
/// VibeBoot looks up.
pub const TOO_MANY_ENDS: &str = "its program's name could end at more than 64 of its spaces, more than VibeBoot looks up";

/// `push` onto `out` while it stays within `MAX_UNITS` (`units` counts them); false once full.
fn push_capped(out: &mut String, units: &mut usize, push: &str) -> bool {
    for ch in push.chars() {
        if *units + ch.len_utf16() > MAX_UNITS {
            return false;
        }
        *units += ch.len_utf16();
        out.push(ch);
    }
    true
}

/// `%VAR%` replaced by its value where `env` knows the name (case-insensitive is `env`'s job);
/// anything else as written. Never slices at a byte offset from another string: it walks chars.
/// At most `MAX_UNITS` long, as `ExpandEnvironmentStringsW`'s output is (IN-VibeBoot-4): no
/// longer line can be started anyway.
pub fn expand(s: &str, env: &dyn Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_UNITS));
    let mut units = 0usize;
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        if !push_capped(&mut out, &mut units, &rest[..start]) {
            return out;
        }
        let after = &rest[start + 1..];
        let (push, next) = match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                match (!name.is_empty()).then(|| env(name)).flatten() {
                    Some(v) => (v, &after[end + 1..]),
                    // Not a variable: the first % stays, the second may open the next one.
                    None => ("%".to_string(), after),
                }
            }
            None => ("%".to_string(), after),
        };
        if !push_capped(&mut out, &mut units, &push) {
            return out;
        }
        rest = next;
    }
    push_capped(&mut out, &mut units, rest);
    out
}

/// What a command line runs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Command {
    /// The program as started (expanded), when one could be told.
    pub program: Option<PathBuf>,
    /// The file the entry is really about: the program, the DLL rundll32 or regsvr32 loads, or
    /// the script an interpreter runs. A bare name nobody found stays bare (relative).
    pub target: Option<PathBuf>,
    /// The program's arguments, as written.
    pub args: String,
    /// An interpreter runs a script or command.
    pub script: bool,
    /// An encoded command or a hidden window.
    pub hidden: bool,
    /// Something odd about the line itself ("empty", "an unbalanced quote").
    pub note: Option<&'static str>,
    /// What it runs could not be established, and why (`TOO_DEEP`, `TOO_MANY_ENDS`): the entry
    /// switches off only (the one rule, RB3).
    pub unknown: Option<&'static str>,
}

/// The interpreters whose own signature says nothing about the command they are handed.
pub const INTERPRETERS: [&str; 7] = ["powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "conhost"];

/// Whether an entry runs a command written into itself: it runs a script or command, and its
/// target is the interpreter (no script file was named). Its signer is then the interpreter's,
/// not the command's: never "from Microsoft".
pub fn inline(script: bool, target: Option<&Path>) -> bool {
    script
        && target.and_then(|t| t.file_name()).is_some_and(|n| {
            let n = n.to_string_lossy().to_ascii_lowercase();
            let stem = n.strip_suffix(".exe").unwrap_or(&n);
            INTERPRETERS.contains(&stem)
        })
}

/// Folders under the Windows folder that any user may write to (lower-case, from the Windows
/// folder, each ending in `\`): a file there is nobody's.
const WRITABLE_UNDER_WINDOWS: [&str; 15] = [
    r"temp\",
    r"tasks\",
    r"tracing\",
    r"debug\",
    r"pla\",
    r"registration\crmlog\",
    r"system32\tasks\",
    r"system32\tasks_migrated\",
    r"system32\spool\",
    r"system32\microsoft\crypto\",
    r"system32\com\dmp\",
    r"system32\fxstmp\",
    r"syswow64\tasks\",
    r"syswow64\com\dmp\",
    r"syswow64\fxstmp\",
];

/// Windows' and Microsoft's own folders, where only administrators and Windows write: the
/// Windows folder (less `WRITABLE_UNDER_WINDOWS`), and under each Program Files folder those of
/// Microsoft and Windows (`Microsoft*`, `Windows*`) and `Common Files\Microsoft Shared`, and
/// Defender's folder in ProgramData.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Owned {
    windows: Option<String>,
    prefixes: Vec<String>,
}

impl Owned {
    pub fn from_env(env: &dyn Fn(&str) -> Option<String>) -> Owned {
        let norm = |s: String| s.trim().replace('/', "\\").trim_end_matches('\\').to_lowercase();
        let windows = env("SystemRoot").or_else(|| env("windir")).map(norm).filter(|w| w.len() >= 3);
        let mut prefixes = Vec::new();
        for v in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
            if let Some(pf) = env(v).map(norm).filter(|p| p.len() >= 3) {
                for p in [format!(r"{pf}\microsoft"), format!(r"{pf}\windows"), format!(r"{pf}\common files\microsoft shared\")] {
                    if !prefixes.contains(&p) {
                        prefixes.push(p);
                    }
                }
            }
        }
        if let Some(pd) = env("ProgramData").map(norm).filter(|p| p.len() >= 3) {
            prefixes.push(format!(r"{pd}\microsoft\windows defender\"));
        }
        Owned { windows, prefixes }
    }

    /// Whether a full path lies in one of the folders (no `..` part, no stream name).
    pub fn contains(&self, path: &str) -> bool {
        let p = path.trim().replace('/', "\\").to_lowercase();
        let p = p.strip_prefix(r"\\?\").unwrap_or(&p);
        let b = p.as_bytes();
        if !(b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\') || p[2..].contains(':') || p.split('\\').any(|s| s == ".." || s == ".") {
            return false;
        }
        if let Some(rest) = self.windows.as_deref().and_then(|w| p.strip_prefix(w)).and_then(|r| r.strip_prefix('\\')) {
            let rest = format!("{rest}\\");
            return rest.len() > 1 && !WRITABLE_UNDER_WINDOWS.iter().any(|x| rest.starts_with(x));
        }
        self.prefixes.iter().any(|x| p.starts_with(x.as_str()))
    }
}

/// Extensions of files a program runs or loads: a bare name with one names a file.
const FILE_EXTS: [&str; 28] = ["exe", "dll", "sys", "ocx", "cpl", "com", "scr", "pif", "msi", "msp", "msc", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "sct", "lnk", "inf", "jar", "url", "xll"];

/// Whether one argument (or a part of one) names a file or URL outside Windows' own folders: any
/// URL, a share, a relative path, a full path outside `owned`, a bare file name not found in the
/// system folders. A switch (`/x`, `-x`) names nothing (its value is looked at on its own).
/// `tries` is how many bare names may still be looked for (`MAX_TRIES` per line): once none
/// may, a bare file name counts as outside, since it was not found (IN-VibeBoot-2).
fn outside(c: &str, owned: &Owned, sys_dirs: &[PathBuf], exists: &dyn Fn(&Path) -> bool, tries: &mut usize) -> bool {
    if c.starts_with(['/', '-']) {
        return false;
    }
    if c.contains("://") {
        return true;
    }
    let b = c.as_bytes();
    if (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')) || c.starts_with(r"\\?\") {
        return !owned.contains(c);
    }
    if has_dir(c) {
        return true;
    }
    match ext(c) {
        Some(e) if FILE_EXTS.contains(&e.as_str()) => {
            if *tries == 0 {
                return true;
            }
            *tries -= 1;
            search(c, sys_dirs, exists).is_none_or(|p| !owned.contains(&p.to_string_lossy()))
        }
        _ => false,
    }
}

/// The first argument naming a file or URL outside Windows' own folders, as written: each
/// argument, a switch's value (`/i:x`, `--x=y`), and the parts of `a,b` (`url.dll,Handler x`).
pub fn foreign(args: &str, owned: &Owned, sys_dirs: &[PathBuf], exists: &dyn Fn(&Path) -> bool) -> Option<String> {
    let mut tries = MAX_TRIES;
    for tok in split_args(args) {
        let mut cands = vec![tok.as_str()];
        if tok.starts_with(['/', '-'])
            && let Some(i) = tok.find([':', '='])
        {
            cands.push(&tok[i + 1..]);
        }
        for c in cands.into_iter().flat_map(|c| c.split(',')) {
            let c = c.trim().trim_matches('"');
            if !c.is_empty() && outside(c, owned, sys_dirs, exists, &mut tries) {
                return Some(c.to_string());
            }
        }
    }
    None
}

/// What a program is handed from outside Windows' own folders, in words: "runs
/// C:\Users\x\evil.exe through rundll32.exe". A Microsoft signature on the program (rundll32,
/// explorer, msiexec…) then says nothing about what runs: never "from Microsoft", never locked.
pub fn through(c: &Command, owned: &Owned, sys_dirs: &[PathBuf], exists: &dyn Fn(&Path) -> bool) -> Option<String> {
    let prog = c.program.as_ref()?;
    let thing = foreign(&c.args, owned, sys_dirs, exists)?;
    let name = prog.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| prog.to_string_lossy().into_owned());
    Some(format!("runs {thing} through {name}"))
}

/// Split arguments the way `CommandLineToArgvW` does (quotes group; `\"` is a quote; `2n`
/// backslashes before a quote are `n` and the quote toggles).
pub fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut any = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let mut n = 1;
                while chars.peek() == Some(&'\\') {
                    chars.next();
                    n += 1;
                }
                if chars.peek() == Some(&'"') {
                    cur.extend(std::iter::repeat_n('\\', n / 2));
                    if n % 2 == 1 {
                        chars.next();
                        cur.push('"');
                    }
                } else {
                    cur.extend(std::iter::repeat_n('\\', n));
                }
                any = true;
            }
            '"' => {
                if quoted && chars.peek() == Some(&'"') {
                    chars.next();
                    cur.push('"');
                } else {
                    quoted = !quoted;
                }
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(cur);
    }
    out
}

/// A file name's extension, lower-case ("exe"), from the last component only.
fn ext(p: &str) -> Option<String> {
    let name = p.rsplit(['\\', '/']).next().unwrap_or(p);
    let (stem, e) = name.rsplit_once('.')?;
    (!stem.is_empty() && !e.is_empty() && !e.contains(' ')).then(|| e.to_ascii_lowercase())
}

const RUNNABLE: [&str; 9] = ["exe", "com", "bat", "cmd", "scr", "pif", "lnk", "msc", "cpl"];

/// A bare name (no folder) in the system folders, as `CreateProcess` searches them (System32,
/// then the Windows folder); `.exe` added when it has no extension.
fn search(name: &str, sys_dirs: &[PathBuf], exists: &dyn Fn(&Path) -> bool) -> Option<PathBuf> {
    let with = if ext(name).is_none() { format!("{name}.exe") } else { name.to_string() };
    sys_dirs.iter().map(|d| d.join(&with)).find(|p| probe(p, exists))
}

/// `exists`, for a path Windows could start: one longer than `MAX_UNITS` is never looked up.
fn probe(p: &Path, exists: &dyn Fn(&Path) -> bool) -> bool {
    p.to_string_lossy().encode_utf16().take(MAX_UNITS + 1).count() <= MAX_UNITS && exists(p)
}

fn has_dir(p: &str) -> bool {
    p.contains('\\') || p.contains('/')
}

/// A path as written becomes a target: with a folder as it is; a bare name found in the system
/// folders there; else the bare name.
fn locate(p: &str, sys_dirs: &[PathBuf], exists: &dyn Fn(&Path) -> bool) -> PathBuf {
    if has_dir(p) {
        return PathBuf::from(p);
    }
    search(p, sys_dirs, exists).unwrap_or_else(|| PathBuf::from(p))
}

/// The program at the start of `line`, the arguments after it, something odd about the line
/// (`Command::note`), and why the program is not established (`Command::unknown`).
type Program = (Option<PathBuf>, String, Option<&'static str>, Option<&'static str>);

/// The program at the start of `line` and the arguments after it.
fn program(line: &str, sys_dirs: &[PathBuf], exists: &dyn Fn(&Path) -> bool) -> Program {
    let line = line.trim();
    if line.is_empty() {
        return (None, String::new(), Some("empty"), None);
    }
    if let Some(rest) = line.strip_prefix('"') {
        return match rest.find('"') {
            Some(end) => {
                let p = rest[..end].trim();
                let args = rest[end + 1..].trim_start().to_string();
                if p.is_empty() { (None, args, Some("empty"), None) } else { (Some(locate(p, sys_dirs, exists)), args, None, None) }
            }
            // No closing quote: CreateProcess takes the rest as the name.
            None => {
                let p = rest.trim();
                if p.is_empty() { (None, String::new(), Some("an unbalanced quote"), None) } else { (Some(locate(p, sys_dirs, exists)), String::new(), Some("an unbalanced quote"), None) }
            }
        };
    }
    // Unquoted: each prefix ending at a space or a tab (CreateProcess splits on both), in order;
    // the first existing file wins. A run of them is one end (the prefix is the same), and at
    // most `MAX_TRIES` ends are looked up (IN-VibeBoot-2): past those, the program is not
    // established.
    let mut cuts: Vec<usize> = Vec::new();
    let mut more = false;
    let mut after_space = false;
    for (i, c) in line.char_indices() {
        let space = c == ' ' || c == '\t';
        if space && !after_space {
            if cuts.len() == MAX_TRIES {
                more = true;
                break;
            }
            cuts.push(i);
        }
        after_space = space;
    }
    if !more {
        cuts.push(line.len());
    }
    for &i in &cuts {
        let cand = line[..i].trim_end();
        if cand.is_empty() {
            continue;
        }
        if !has_dir(cand) {
            if let Some(found) = search(cand, sys_dirs, exists) {
                return (Some(found), line[i..].trim_start().to_string(), None, None);
            }
            continue;
        }
        let tries: Vec<String> = if ext(cand).is_none() { vec![format!("{cand}.exe"), cand.to_string()] } else { vec![cand.to_string()] };
        for t in tries {
            if probe(Path::new(&t), exists) {
                return (Some(PathBuf::from(t)), line[i..].trim_start().to_string(), None, None);
            }
        }
    }
    let unknown = more.then_some(TOO_MANY_ENDS);
    // Nothing exists: the first prefix that ends in a runnable extension, else the first word.
    for &i in &cuts {
        let cand = line[..i].trim_end();
        if ext(cand).is_some_and(|e| RUNNABLE.contains(&e.as_str())) {
            return (Some(locate(cand, sys_dirs, exists)), line[i..].trim_start().to_string(), None, unknown);
        }
    }
    let first = cuts[0];
    (Some(locate(&line[..first], sys_dirs, exists)), line[first..].trim_start().to_string(), None, unknown)
}

/// The program's file name without `.exe`, lower-case.
fn stem(p: &Path) -> String {
    let name = p.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    name.strip_suffix(".exe").map(str::to_string).unwrap_or(name)
}

/// Whether `arg` is PowerShell parameter `full` written as any prefix of it at least `min`
/// characters long (`-e`, `-enc`, `-EncodedCommand`), with `-` or `/`.
fn ps_param(arg: &str, full: &str, min: usize) -> bool {
    let a = arg.to_ascii_lowercase();
    let Some(name) = a.strip_prefix('-').or_else(|| a.strip_prefix('/')) else { return false };
    let name = name.split(':').next().unwrap_or(name);
    name.len() >= min && full.starts_with(name)
}

/// A command line: what it runs, and what that means.
pub fn resolve(line: &str, sys_dirs: &[PathBuf], exists: &dyn Fn(&Path) -> bool) -> Command {
    let (prog, args, note, unknown) = program(line, sys_dirs, exists);
    let Some(prog) = prog else { return Command { note, ..Command::default() } };
    let mut c = analyze(&prog, &args, sys_dirs, exists);
    c.note = c.note.or(note);
    c.unknown = unknown.or(c.unknown);
    c
}

/// A program and its arguments (a command line split already, or a shortcut's target and
/// arguments): which file it is really about.
pub fn analyze(prog: &Path, args: &str, sys_dirs: &[PathBuf], exists: &dyn Fn(&Path) -> bool) -> Command {
    analyze_at(prog, args, sys_dirs, exists, 0)
}

/// `analyze` of a command line nested `depth` deep in another (`cmd /c`, `conhost --headless`).
/// One nested deeper than `MAX_NESTING` is not followed (IN-VibeBoot-1): the interpreter that
/// hands it on stays the target, and what it runs is not established (`TOO_DEEP`). So the
/// recursion is bounded and the work per line stays linear (each level splits the rest once).
fn analyze_at(prog: &Path, args: &str, sys_dirs: &[PathBuf], exists: &dyn Fn(&Path) -> bool, depth: usize) -> Command {
    let mut c = Command { program: Some(prog.to_path_buf()), target: Some(prog.to_path_buf()), args: args.to_string(), ..Command::default() };
    let argv = split_args(args);
    let script_file = |s: &str| locate(s, &[], exists);
    match stem(prog).as_str() {
        "rundll32" => {
            // `x.dll,Entry` (the path may be quoted: split_args took the quotes away).
            if let Some(first) = argv.first() {
                let dll = first.split(',').next().unwrap_or(first).trim();
                if !dll.is_empty() {
                    c.target = Some(locate(dll, sys_dirs, exists));
                }
            }
        }
        "regsvr32" => {
            if let Some(dll) = argv.iter().find(|a| !a.starts_with('/') && !a.starts_with('-')) {
                c.target = Some(locate(dll, sys_dirs, exists));
            }
        }
        "powershell" | "pwsh" => {
            c.script = true;
            let mut i = 0;
            while i < argv.len() {
                let a = &argv[i];
                if ps_param(a, "encodedcommand", 2) || ps_param(a, "ec", 2) || a.eq_ignore_ascii_case("-e") || a.eq_ignore_ascii_case("/e") {
                    c.hidden = true;
                    i += 2;
                    continue;
                }
                if ps_param(a, "windowstyle", 1) {
                    if argv.get(i + 1).is_some_and(|v| v.eq_ignore_ascii_case("hidden")) {
                        c.hidden = true;
                    }
                    i += 2;
                    continue;
                }
                if ps_param(a, "file", 1) {
                    if let Some(f) = argv.get(i + 1) {
                        c.target = Some(script_file(f));
                    }
                    break;
                }
                if ps_param(a, "command", 1) {
                    break; // the rest is the command
                }
                if ps_param(a, "executionpolicy", 2) || ps_param(a, "configurationname", 4) || ps_param(a, "workingdirectory", 2) || ps_param(a, "settingsfile", 2) || ps_param(a, "outputformat", 1) || ps_param(a, "inputformat", 2) || ps_param(a, "psconsolefile", 3) || ps_param(a, "version", 1) || ps_param(a, "custompipename", 2) {
                    i += 2;
                    continue;
                }
                if a.starts_with('-') || a.starts_with('/') {
                    i += 1;
                    continue;
                }
                // The first positional: pwsh's is -File; Windows PowerShell's is -Command (a
                // .ps1 named there is run as a script either way).
                if ext(a).as_deref() == Some("ps1") {
                    c.target = Some(script_file(a));
                }
                break;
            }
        }
        "cmd" => {
            c.script = true;
            if let Some(i) = argv.iter().position(|a| a.eq_ignore_ascii_case("/c") || a.eq_ignore_ascii_case("/k") || a.eq_ignore_ascii_case("/r")) {
                // What follows /c is a command line of its own.
                let rest: Vec<&String> = argv[i + 1..].iter().collect();
                if let Some(first) = rest.first() {
                    if depth == MAX_NESTING {
                        c.unknown = Some(TOO_DEEP);
                        return c;
                    }
                    let inner = analyze_at(&locate(first, sys_dirs, exists), &rest[1..].iter().map(|s| quote(s)).collect::<Vec<_>>().join(" "), sys_dirs, exists, depth + 1);
                    if ext(first).is_some() || has_dir(first) {
                        c.target = inner.target;
                    }
                    c.hidden |= inner.hidden;
                    c.unknown = inner.unknown;
                }
            }
        }
        "wscript" | "cscript" => {
            c.script = true;
            if let Some(f) = argv.iter().find(|a| !a.starts_with('/') && !a.starts_with("//")) {
                c.target = Some(script_file(f));
            }
            if argv.iter().any(|a| a.eq_ignore_ascii_case("//b")) {
                c.hidden = true;
            }
        }
        "mshta" => {
            c.script = true;
            if let Some(f) = argv.first() {
                let l = f.to_ascii_lowercase();
                if l.starts_with("javascript:") || l.starts_with("vbscript:") || l.starts_with("about:") {
                    c.hidden = true; // a script written into the command line itself
                } else if !l.contains("://") {
                    c.target = Some(script_file(f));
                }
            }
        }
        "conhost" if argv.iter().any(|a| a.eq_ignore_ascii_case("--headless")) => {
            c.script = true;
            c.hidden = true;
            let rest: Vec<&String> = argv.iter().skip_while(|a| a.starts_with("--")).collect();
            if let Some(first) = rest.first() {
                if depth == MAX_NESTING {
                    c.unknown = Some(TOO_DEEP);
                    return c;
                }
                let inner = analyze_at(&locate(first, sys_dirs, exists), &rest[1..].iter().map(|s| quote(s)).collect::<Vec<_>>().join(" "), sys_dirs, exists, depth + 1);
                c.target = inner.target;
                c.unknown = inner.unknown;
            }
        }
        _ => {}
    }
    c
}

/// An argument quoted back for `split_args` when it holds a space.
fn quote(s: &str) -> String {
    if s.contains(' ') || s.is_empty() { format!("\"{s}\"") } else { s.to_string() }
}
