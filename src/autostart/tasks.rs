//! Scheduled tasks through the Task Scheduler's COM API (`ITaskService`, `ITaskFolder`,
//! `ITaskFolderCollection`, `IRegisteredTaskCollection`, `IRegisteredTask`) with hand-written
//! vtables over windows-sys (it has the constants, not the interfaces; the slot numbers are
//! taskschd.h's, checked against the windows crate's bindings). Every folder is walked and its
//! tasks read with `TASK_ENUM_HIDDEN`; per task its path, enabled flag, state, last run, last
//! result and XML (parsed in `taskxml`, in the app, never here).
//!
//! Unelevated, tasks with restrictive security are invisible; the helper's `scan-tasks` reads
//! them all. The registry's TaskCache count cannot be read unelevated on 26200 (spiked
//! 2026-10-22: access denied on `...\Schedule\TaskCache\Tree`), so how many are hidden is known
//! only once a full scan has run.

/// A task's last result in words: 0 ok, 0x41300 ready, 0x41301 running, 0x41303 never run,
/// otherwise the HRESULT's text.
pub fn result_words(code: i32) -> String {
    match code as u32 {
        0 => "ok".into(),
        0x41300 => "ready (not run yet)".into(),
        0x41301 => "running".into(),
        0x41303 => "never run".into(),
        0x41306 => "ended by the user".into(),
        c => super::text::os_words(c),
    }
}

pub fn state_words(state: i32) -> &'static str {
    match state {
        1 => "disabled",
        2 => "queued",
        3 => "ready",
        4 => "running",
        _ => "unknown",
    }
}

/// The task's name: its path's last part.
pub fn name_of(path: &str) -> &str {
    path.rsplit('\\').next().filter(|n| !n.is_empty()).unwrap_or(path)
}

/// The most tasks read (a PC has a few hundred), and the deepest folder.
pub const MAX_TASKS: usize = 10_000;
const MAX_DEPTH: usize = 32;
/// The most "could not be read" notes kept from one walk (counted apart from the tasks).
pub const MAX_UNREAD: usize = 1_000;

/// The walk's notes as handed on: at most `MAX_UNREAD`, the last saying the walk stopped at
/// `MAX_TASKS` when it did (never silent).
pub fn notes(mut errors: Vec<String>, stopped: bool) -> Vec<String> {
    let room = if stopped { MAX_UNREAD - 1 } else { MAX_UNREAD };
    errors.truncate(room);
    if stopped {
        errors.push(format!("more than {MAX_TASKS} tasks: the rest were not read"));
    }
    errors
}

#[cfg(windows)]
pub mod sys {
    use super::super::pc::TaskRaw;
    use super::super::taskxml::MAX_XML;
    use super::super::text;
    use super::{MAX_DEPTH, MAX_TASKS, MAX_UNREAD};
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{SysAllocString, SysFreeString, VARIANT_BOOL};
    use windows_sys::Win32::System::Com::{CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize};
    use windows_sys::Win32::System::Variant::{VARIANT, VT_I4};
    use windows_sys::core::{BSTR, GUID, HRESULT};

    const CLSID_TASK_SCHEDULER: GUID = GUID::from_u128(0x0f87369f_a4e5_4cfc_bd3e_73e6154572dd);
    const IID_ITASK_SERVICE: GUID = GUID::from_u128(0x2faba4c7_4da9_4013_9697_20cc3fd40f85);
    const TASK_ENUM_HIDDEN: i32 = 1;
    /// HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), (ERROR_PATH_NOT_FOUND): no such task or folder.
    const NOT_FOUND: [u32; 2] = [0x8007_0002, 0x8007_0003];

    // Vtable slots (0-based: IUnknown 0..2, IDispatch 3..6).
    mod slot {
        pub const RELEASE: usize = 2;
        // ITaskService
        pub const SERVICE_GET_FOLDER: usize = 7;
        pub const SERVICE_CONNECT: usize = 10;
        // ITaskFolder
        pub const FOLDER_GET_FOLDERS: usize = 10;
        pub const FOLDER_GET_TASK: usize = 13;
        pub const FOLDER_GET_TASKS: usize = 14;
        // ITaskFolderCollection and IRegisteredTaskCollection
        pub const COLL_COUNT: usize = 7;
        pub const COLL_ITEM: usize = 8;
        // IRegisteredTask
        pub const TASK_PATH: usize = 8;
        pub const TASK_STATE: usize = 9;
        pub const TASK_ENABLED: usize = 10;
        pub const TASK_PUT_ENABLED: usize = 11;
        pub const TASK_LAST_RUN: usize = 15;
        pub const TASK_LAST_RESULT: usize = 16;
        pub const TASK_XML: usize = 20;
    }

    /// A COM interface pointer we own one reference to.
    struct Obj(*mut c_void);

    impl Obj {
        /// # Safety
        /// `n` is a slot this object's interface has; the caller casts it to that slot's type.
        unsafe fn f(&self, n: usize) -> *const c_void {
            // SAFETY: a live COM object starts with its vtable pointer.
            unsafe { *(*(self.0 as *const *const *const c_void)).add(n) }
        }
    }

    impl Drop for Obj {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: IUnknown::Release, slot 2 of every interface.
                unsafe {
                    let f: extern "system" fn(*mut c_void) -> u32 = std::mem::transmute(self.f(slot::RELEASE));
                    f(self.0);
                }
            }
        }
    }

    struct Bstr(BSTR);

    impl Bstr {
        fn new(s: &str) -> Bstr {
            let w = text::wide(s);
            // SAFETY: a NUL-terminated string; the copy is ours to free.
            Bstr(unsafe { SysAllocString(w.as_ptr()) })
        }

        /// The text, at most `max` units read (a longer one is Err with its length).
        fn text(&self, max: usize) -> Result<String, usize> {
            if self.0.is_null() {
                return Ok(String::new());
            }
            // SAFETY: a BSTR carries its length in bytes before its first unit.
            let n = unsafe { *(self.0 as *const u32).sub(1) } as usize / 2;
            if n > max {
                return Err(n);
            }
            // SAFETY: `n` units of the BSTR.
            Ok(String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(self.0, n) }))
        }
    }

    impl Drop for Bstr {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: allocated by SysAllocString or handed to us by the API.
                unsafe { SysFreeString(self.0) };
            }
        }
    }

    /// COM for this thread while it lives (an apartment already there is used as it is).
    pub struct Com(bool);

    impl Com {
        pub fn init() -> Com {
            // SAFETY: balanced in Drop when it succeeded.
            let hr = unsafe { CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED as u32) };
            Com(hr >= 0)
        }
    }

    impl Drop for Com {
        fn drop(&mut self) {
            if self.0 {
                // SAFETY: this thread's successful CoInitializeEx.
                unsafe { CoUninitialize() };
            }
        }
    }

    fn check(hr: HRESULT, what: &str) -> Result<(), String> {
        if hr >= 0 { Ok(()) } else { Err(format!("{what} ({})", text::os_words(hr as u32))) }
    }

    fn variant_i4(v: i32) -> VARIANT {
        // SAFETY: all-zero is VT_EMPTY; then the type and the value.
        let mut x: VARIANT = unsafe { std::mem::zeroed() };
        x.Anonymous.Anonymous.vt = VT_I4;
        x.Anonymous.Anonymous.Anonymous.lVal = v;
        x
    }

    /// The Task Scheduler, connected to this PC.
    fn service() -> Result<Obj, String> {
        let mut p: *mut c_void = std::ptr::null_mut();
        // SAFETY: an out pointer for the interface asked for.
        let hr = unsafe { CoCreateInstance(&CLSID_TASK_SCHEDULER, std::ptr::null_mut(), CLSCTX_INPROC_SERVER, &IID_ITASK_SERVICE, &mut p) };
        check(hr, "the Task Scheduler could not be reached")?;
        let s = Obj(p);
        // SAFETY: ITaskService::Connect(VARIANT x4), all empty: this PC, this user.
        let hr = unsafe {
            let f: extern "system" fn(*mut c_void, VARIANT, VARIANT, VARIANT, VARIANT) -> HRESULT = std::mem::transmute(s.f(slot::SERVICE_CONNECT));
            f(s.0, std::mem::zeroed(), std::mem::zeroed(), std::mem::zeroed(), std::mem::zeroed())
        };
        check(hr, "the Task Scheduler did not connect")?;
        Ok(s)
    }

    fn folder(s: &Obj, path: &str) -> Result<Option<Obj>, String> {
        let b = Bstr::new(path);
        let mut p: *mut c_void = std::ptr::null_mut();
        // SAFETY: ITaskService::GetFolder(BSTR, ITaskFolder**).
        let hr = unsafe {
            let f: extern "system" fn(*mut c_void, BSTR, *mut *mut c_void) -> HRESULT = std::mem::transmute(s.f(slot::SERVICE_GET_FOLDER));
            f(s.0, b.0, &mut p)
        };
        if NOT_FOUND.contains(&(hr as u32)) {
            return Ok(None);
        }
        check(hr, "a task folder could not be read")?;
        Ok(Some(Obj(p)))
    }

    fn count(c: &Obj) -> Result<i32, String> {
        let mut n = 0i32;
        // SAFETY: get_Count(LONG*), the same slot in both collections.
        let hr = unsafe {
            let f: extern "system" fn(*mut c_void, *mut i32) -> HRESULT = std::mem::transmute(c.f(slot::COLL_COUNT));
            f(c.0, &mut n)
        };
        check(hr, "a task list could not be counted")?;
        Ok(n)
    }

    fn item(c: &Obj, i: i32) -> Result<Obj, String> {
        let mut p: *mut c_void = std::ptr::null_mut();
        // SAFETY: get_Item(VARIANT, I**) with a 1-based VT_I4 index.
        let hr = unsafe {
            let f: extern "system" fn(*mut c_void, VARIANT, *mut *mut c_void) -> HRESULT = std::mem::transmute(c.f(slot::COLL_ITEM));
            f(c.0, variant_i4(i), &mut p)
        };
        check(hr, "a task could not be read")?;
        Ok(Obj(p))
    }

    fn bstr_of(o: &Obj, n: usize) -> Result<Bstr, HRESULT> {
        let mut b: BSTR = std::ptr::null_mut();
        // SAFETY: a get_X(BSTR*) slot.
        let hr = unsafe {
            let f: extern "system" fn(*mut c_void, *mut BSTR) -> HRESULT = std::mem::transmute(o.f(n));
            f(o.0, &mut b)
        };
        let b = Bstr(b);
        if hr >= 0 { Ok(b) } else { Err(hr) }
    }

    fn read_task(t: &Obj) -> Result<TaskRaw, String> {
        let path = bstr_of(t, slot::TASK_PATH).map_err(|hr| text::os_words(hr as u32))?.text(1024).map_err(|_| "a task path over 1024 units".to_string())?;
        let mut raw = TaskRaw { path, ..TaskRaw::default() };
        // SAFETY: the IRegisteredTask getters, each with its own out type.
        unsafe {
            let mut st = 0i32;
            let f: extern "system" fn(*mut c_void, *mut i32) -> HRESULT = std::mem::transmute(t.f(slot::TASK_STATE));
            if f(t.0, &mut st) >= 0 {
                raw.state = st;
            }
            let mut en: VARIANT_BOOL = 0;
            let f: extern "system" fn(*mut c_void, *mut VARIANT_BOOL) -> HRESULT = std::mem::transmute(t.f(slot::TASK_ENABLED));
            if f(t.0, &mut en) >= 0 {
                raw.enabled = en != 0;
            }
            let mut d = 0f64;
            let f: extern "system" fn(*mut c_void, *mut f64) -> HRESULT = std::mem::transmute(t.f(slot::TASK_LAST_RUN));
            if f(t.0, &mut d) >= 0 {
                raw.last_run = d;
            }
            let mut r = 0i32;
            let f: extern "system" fn(*mut c_void, *mut i32) -> HRESULT = std::mem::transmute(t.f(slot::TASK_LAST_RESULT));
            if f(t.0, &mut r) >= 0 {
                raw.last_result = r;
            }
        }
        // The XML, capped: a bigger one is read as empty (the parser then says so).
        raw.xml = match bstr_of(t, slot::TASK_XML) {
            Ok(b) => b.text(MAX_XML / 2).unwrap_or_default(),
            Err(_) => String::new(),
        };
        Ok(raw)
    }

    fn walk(f: &Obj, depth: usize, out: &mut Vec<TaskRaw>, errors: &mut Vec<String>, stopped: &mut bool) {
        if depth > MAX_DEPTH || *stopped {
            return;
        }
        let mut tasks: *mut c_void = std::ptr::null_mut();
        // SAFETY: ITaskFolder::GetTasks(LONG, IRegisteredTaskCollection**).
        let hr = unsafe {
            let g: extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> HRESULT = std::mem::transmute(f.f(slot::FOLDER_GET_TASKS));
            g(f.0, TASK_ENUM_HIDDEN, &mut tasks)
        };
        if hr >= 0 {
            let tasks = Obj(tasks);
            for i in 1..=count(&tasks).unwrap_or(0) {
                if out.len() >= MAX_TASKS {
                    // One more task than the cap: the walk stops here and says so.
                    *stopped = true;
                    return;
                }
                match item(&tasks, i).and_then(|t| read_task(&t)) {
                    Ok(t) => out.push(t),
                    Err(e) if errors.len() < MAX_UNREAD => errors.push(e),
                    Err(_) => {}
                }
            }
        } else {
            errors.push(format!("a task folder's tasks could not be listed ({})", text::os_words(hr as u32)));
        }
        let mut subs: *mut c_void = std::ptr::null_mut();
        // SAFETY: ITaskFolder::GetFolders(LONG, ITaskFolderCollection**).
        let hr = unsafe {
            let g: extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> HRESULT = std::mem::transmute(f.f(slot::FOLDER_GET_FOLDERS));
            g(f.0, 0, &mut subs)
        };
        if hr < 0 {
            errors.push(format!("a task folder's subfolders could not be listed ({})", text::os_words(hr as u32)));
            return;
        }
        let subs = Obj(subs);
        for i in 1..=count(&subs).unwrap_or(0) {
            match item(&subs, i) {
                Ok(sub) => walk(&sub, depth + 1, out, errors, stopped),
                Err(e) => errors.push(e),
            }
        }
    }

    /// Every task this account can see, in every folder (hidden ones included). The second list
    /// names what could not be read.
    pub fn all() -> Result<(Vec<TaskRaw>, Vec<String>), String> {
        let _com = Com::init();
        let s = service()?;
        let root = folder(&s, "\\")?.ok_or("the task root folder is missing")?;
        let mut out = Vec::new();
        let mut errors = Vec::new();
        let mut stopped = false;
        walk(&root, 0, &mut out, &mut errors, &mut stopped);
        Ok((out, super::notes(errors, stopped)))
    }

    fn split(path: &str) -> (&str, &str) {
        match path.rfind('\\') {
            Some(0) => ("\\", &path[1..]),
            Some(i) => (&path[..i], &path[i + 1..]),
            None => ("\\", path),
        }
    }

    fn get(s: &Obj, path: &str) -> Result<Option<Obj>, String> {
        let (dir, name) = split(path);
        let Some(f) = folder(s, dir)? else { return Ok(None) };
        let b = Bstr::new(name);
        let mut p: *mut c_void = std::ptr::null_mut();
        // SAFETY: ITaskFolder::GetTask(BSTR, IRegisteredTask**).
        let hr = unsafe {
            let g: extern "system" fn(*mut c_void, BSTR, *mut *mut c_void) -> HRESULT = std::mem::transmute(f.f(slot::FOLDER_GET_TASK));
            g(f.0, b.0, &mut p)
        };
        if NOT_FOUND.contains(&(hr as u32)) {
            return Ok(None);
        }
        check(hr, "the task could not be read")?;
        Ok(Some(Obj(p)))
    }

    /// One task by its full path; None when there is none.
    pub fn one(path: &str) -> Result<Option<TaskRaw>, String> {
        let _com = Com::init();
        let s = service()?;
        match get(&s, path)? {
            Some(t) => read_task(&t).map(Some),
            None => Ok(None),
        }
    }

    /// Enable or disable a task (`IRegisteredTask::put_Enabled`).
    pub fn set_enabled(path: &str, on: bool) -> Result<(), String> {
        let _com = Com::init();
        let s = service()?;
        let t = get(&s, path)?.ok_or("the task is gone")?;
        // SAFETY: put_Enabled(VARIANT_BOOL).
        let hr = unsafe {
            let f: extern "system" fn(*mut c_void, VARIANT_BOOL) -> HRESULT = std::mem::transmute(t.f(slot::TASK_PUT_ENABLED));
            f(t.0, if on { -1 } else { 0 })
        };
        check(hr, "the task could not be changed")
    }

}
