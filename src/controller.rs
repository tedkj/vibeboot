//! The window's brain. It lives on the UI thread: it keeps the prefs (in memory, saved on the
//! prefs thread), the toasts, the theme, the scan, the switches and the journal. The .slint files
//! lay out what it hands them; every word and choice is made here.
//!
//! A scan: four workers read the Run keys, the startup folders, the tasks and the services; each
//! answers for its locations (entries, or why a location could not be read). The signers follow
//! on four workers, the list filling as they answer (one wake-up per batch). Every answer carries
//! the scan's epoch; an answer for an older scan does nothing. Changes run on a worker too, one
//! batch at a time: journal "pending", the change (re-read right before), journal "done" or
//! "failed"; the admin ones through the elevated helper, one Windows prompt per kind.

use crate::autostart::journal::{self, Journal, Record, Status};
use crate::autostart::pc::{Pc, TaskRaw};
use crate::autostart::scan::{self, Part, TaskPart};
use crate::autostart::seen::{Baseline, Seen};
use crate::autostart::switch::{self, Data, Outcome, Request};
use crate::autostart::{DateFact, Entry, FileKey, FileState, Location, SignInfo, Signer, Switch, approved, dates, run, text};
use crate::changes::{self, Queue, Queued, Route};
use crate::check::{Dot, Fetched, Local, Release, Rows};
use crate::groups::{self, Facts, Filters, Group, Row};
use crate::helper::{Answer, ElevError, Elevator, Job};
use crate::portable::Setup;
use crate::prefs::{Change, Store};
use crate::{AppWindow, CheckDot, CheckRow, ChipItem, DetailInfo, DetailPair, EntryRow, JournalRow, Prefs, Theme, ToastItem, ToastKind};
use slint::{ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode, VecModel, Weak};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, TryRecvError, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Save As: the name offered, the path picked (None: cancelled).
pub type SaveDialog = Box<dyn Fn(&str) -> Option<PathBuf>>;

/// What the controller needs from the outside world; the tests hand it fakes.
pub struct Services {
    pub copy: Box<dyn Fn(&str) -> bool>,
    /// A file shown selected in Explorer (a toast's "Show").
    pub reveal: Box<dyn Fn(&Path)>,
    pub save_dialog: SaveDialog,
    pub pc: Arc<dyn Pc>,
    pub elevator: Arc<dyn Elevator>,
    pub setup: Setup,
    /// Unix seconds now.
    pub now: Arc<dyn Fn() -> i64 + Send + Sync>,
    /// Local time minus UTC at a moment (seconds).
    pub offset: Arc<dyn Fn(i64) -> i64 + Send + Sync>,
    /// The window to put the UAC prompt over.
    pub hwnd: Box<dyn Fn() -> isize>,
    /// Whether the portable data folder can be written (asked on a worker at start).
    pub writable: Arc<dyn Fn(&Path) -> bool + Send + Sync>,
    /// Tests: work runs on the UI thread, at once or held (`hold`) until `release`.
    pub manual: bool,
    pub hold: Cell<bool>,
    /// A web page in the browser (About's link).
    pub open_url: Box<dyn Fn(&str)>,
    /// The install check's offline half, on its worker: this copy's files, their signatures and
    /// hashes (`trust::inspect_from`; true: installed, so the uninstaller too).
    pub inspect: Fetcher<bool, Local>,
    /// The install check's online half, on its worker: the release list at a path on the site,
    /// waited for at most `release.wait`. Only `main` hands in the real one (the exe's
    /// `net::fetch_release_list`, in no test build); the tests hand in fakes.
    pub fetch: Fetcher<str, Fetched>,
    /// What the check holds the list to: the app, its version, the list's key, the code signer.
    pub release: Release,
}

/// A blocking call the check's worker makes.
pub type Fetcher<A, R> = Arc<dyn Fn(&A) -> R + Send + Sync>;

impl Services {
    /// The real services. `fetch` is the release-list fetcher: `main` hands in the exe's
    /// `net::fetch_release_list`, and is the only place that names it.
    pub fn system(setup: Setup, fetch: Fetcher<str, Fetched>) -> Services {
        // The exe's identity as this process started from it, taken now, before an install
        // could replace it, and handed to every check (FED3, RVD7).
        let started = crate::trust::exe_identity();
        Services {
            copy: Box::new(|t| crate::host::copy_text(t).is_ok()),
            reveal: Box::new(|p| {
                let _ = crate::host::reveal(p, true);
            }),
            save_dialog: Box::new(crate::host::save_dialog),
            pc: Arc::new(crate::autostart::sys::SystemPc),
            elevator: Arc::new(crate::helper::SystemElevator),
            setup,
            now: Arc::new(crate::host::now_unix),
            offset: Arc::new(crate::host::local_offset),
            hwnd: Box::new(crate::host::active_window),
            writable: Arc::new(crate::portable::writable),
            manual: false,
            hold: Cell::new(false),
            // The shell can take a moment: never on the window's thread.
            open_url: Box::new(|u| {
                let u = u.to_string();
                std::thread::spawn(move || {
                    let _ = crate::host::open_url(&u);
                });
            }),
            inspect: Arc::new(move |installed: &bool| crate::trust::inspect_from(started, &crate::trust::own_exe(), *installed)),
            fetch,
            release: Release::this(),
        }
    }
}

/// How often the window looks whether a running check has its answer.
const CHECK_POLL_MS: u64 = 50;

/// `fetch` on a thread of its own, waited for at most `deadline` (FETCH_DEADLINE, review RAB-3):
/// past it the answer is `TimedOut`, whatever the site or a proxy is doing, and the thread is
/// left to end by itself (the real fetcher's read loop stops at the same deadline, and WinHTTP's
/// own timeouts bound each step); its late answer goes nowhere.
fn fetch_within(fetch: Fetcher<str, Fetched>, path: String, deadline: Duration) -> Fetched {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let _ = tx.send(fetch(&path));
    });
    match rx.recv_timeout(deadline) {
        Ok(f) => f,
        Err(RecvTimeoutError::Timeout) => Fetched::TimedOut,
        Err(RecvTimeoutError::Disconnected) => Fetched::Failed("the fetch stopped before it answered".into()),
    }
}

/// What a portable copy writes, and what Windows records of any program it runs: said where
/// portable mode is (the chip's tip; it was About's).
const PORTABLE_TRACE: &str = "VibeBoot writes nothing to this PC but the changes you make, but Windows still records that a program ran (Prefetch, recent-programs lists).";

/// One change to the prefs, applied by the prefs thread onto the newest saved ones.
type PrefsChange = Change<Prefs>;

/// After a change, when the window looks whether the prefs thread met a garbled file.
const PREFS_TELL_MS: u64 = 500;
/// Signer workers per scan.
const SIGNERS: usize = 4;

fn prefs_writer(store: Store<Prefs>, pending: Arc<AtomicUsize>) -> Sender<PrefsChange> {
    let (tx, rx) = channel::<PrefsChange>();
    std::thread::spawn(move || {
        while let Ok(f) = rx.recv() {
            store.change(Arc::new(move |p: &mut Prefs| {
                *p = std::mem::take(p).sanitized();
                f(p);
            }));
            pending.fetch_sub(1, Ordering::SeqCst);
        }
    });
    tx
}

/// A change to make, and what the journal says about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub key: String,
    pub name: String,
    pub req: Request,
    pub undo_of: Option<String>,
    /// The entry as the list read it (`Entry::reading`): its record keeps both of its bindings
    /// for the Undo (RB4-1), and no Undo when it switches off only (RB3-5).
    pub read: crate::autostart::def::Fresh,
}

/// What a change came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Done {
    pub item: Item,
    /// The journal's last word on it (None: it was never tried).
    pub status: Option<Status>,
    /// A failed change: what is there now, read right after (a two-step write may have changed
    /// it halfway), so the list shows the real state.
    pub live: Option<Data>,
}

/// A target's lower-cased path, who signed it, and the identity of the file that answer is for.
pub type SignedTarget = (String, (SignInfo, Option<FileKey>));

/// What a worker brings back.
pub enum Msg {
    /// The state files and this PC's id, read at start (pending journal records settled).
    State { guid: String, journal: Journal, seen: Seen, told: Vec<(String, ToastKind)>, writable: Option<bool> },
    Part { epoch: u64, part: Part },
    Tasks { epoch: u64, tp: TaskPart, full: bool },
    /// Per target (its lower-cased path): who signed it, and the identity of the file that answer
    /// is for.
    Signed { epoch: u64, results: Vec<SignedTarget> },
    Changed { done: Vec<Done>, errors: Vec<String>, declined: bool, from_queue: bool },
    FullScanFailed { epoch: u64, why: String },
    Saved(Result<PathBuf, String>),
}

/// Which row is picked.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Sel {
    Entry(String),
    Fold(Group),
}

/// One scan's reads so far.
#[derive(Default)]
struct Scan {
    epoch: u64,
    entries: Vec<Entry>,
    sign: Vec<Option<SignInfo>>,
    answered: HashSet<Location>,
    failed: Vec<(Location, String)>,
    tasks_total: usize,
    finished: Option<i64>,
    full: bool,
    seen_recorded: bool,
}

#[derive(Default)]
struct State {
    prefs: Prefs,
    toast_seq: i32,
    toast_paths: HashMap<i32, PathBuf>,
    toast_time: HashMap<i32, (u64, u64)>,
    scan: Scan,
    filters: Filters,
    opened: HashSet<Group>,
    sel: Option<Sel>,
    rows: Vec<Row>,
    queue: Queue,
    busy: bool,
    busy_words: String,
    /// The entries a running batch is changing.
    busy_keys: HashSet<String>,
    /// The state files: loaded (on a worker) or not yet.
    loaded: bool,
    guid: String,
    baseline: Baseline,
    journal: Journal,
    journal_sel: Option<String>,
    sign_cache: HashMap<FileKey, SignInfo>,
    /// Tasks hidden from this account, as the last full scan counted them.
    hidden_tasks: Option<usize>,
    read_only: bool,
    /// F5 while a change was on its way: scan once it is done.
    rescan: bool,
    /// The install check: its number (an answer for another one does nothing), and while it
    /// runs, where its answer comes from.
    check_seq: u64,
    check_rx: Option<Receiver<(u64, Rows)>>,
}

thread_local! {
    static APP: RefCell<std::rc::Weak<App>> = const { RefCell::new(std::rc::Weak::new()) };
}

pub struct App {
    ui: Weak<AppWindow>,
    svc: Services,
    store: Store<Prefs>,
    journal_store: Store<Journal>,
    seen_store: Store<Seen>,
    session: String,
    st: RefCell<State>,
    prefs_tx: Sender<PrefsChange>,
    prefs_pending: Arc<AtomicUsize>,
    toasts: Rc<VecModel<ToastItem>>,
    rows: Rc<VecModel<EntryRow>>,
    pairs: Rc<VecModel<DetailPair>>,
    jrows: Rc<VecModel<JournalRow>>,
    me: RefCell<std::rc::Weak<App>>,
    inbox: Arc<Mutex<Vec<Msg>>>,
    held: RefCell<Vec<Box<dyn FnOnce() -> Msg>>>,
    scroll_seq: Cell<i32>,
    check_rows: Rc<VecModel<CheckRow>>,
    check_timer: Timer,
}

fn s(t: impl AsRef<str>) -> SharedString {
    t.as_ref().into()
}

fn lock<X>(m: &Mutex<X>) -> std::sync::MutexGuard<'_, X> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A fresh id: the time and 8 random hex digits (the journal's record ids, the session).
fn fresh_id(now: i64) -> String {
    let r = crate::helper::sys::random16().map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).unwrap_or_else(|| std::process::id() ^ (now as u32));
    format!("{now:x}-{r:08x}")
}

/// What a worker that makes changes needs.
#[derive(Clone)]
struct Ctx {
    pc: Arc<dyn Pc>,
    elevator: Arc<dyn Elevator>,
    journal: Store<Journal>,
    guid: String,
    session: String,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl Ctx {
    fn record(&self, it: &Item, status: Status) -> Record {
        let now = (self.now)();
        Record {
            id: fresh_id(now),
            time: now,
            pc: self.guid.clone(),
            session: self.session.clone(),
            location: it.req.location,
            key: it.key.clone(),
            name: it.name.clone(),
            ident: it.req.ident.clone(),
            def: Some(it.read.def),
            core: Some(it.read.core),
            def_v: crate::autostart::def::VERSION,
            off_only: it.read.off_only.clone(),
            old: it.req.old.clone(),
            new: it.req.new.clone(),
            status,
            undo_of: it.undo_of.clone(),
            settled: None,
        }
    }

    fn write(&self, r: &Record) {
        let r = r.clone();
        self.journal.change(Arc::new(move |j: &mut Journal| j.upsert(r.clone())));
    }

    /// A change whose outcome nobody told: settled against the live data (unknown stays pending).
    fn settle(&self, r: &mut Record) {
        if let Some((status, note)) = journal::settle(r, switch::read(&*self.pc, r.location, &r.ident)) {
            r.status = status;
            r.settled = Some(note.replace("at start", "after the helper ended"));
        }
    }

    /// After a change that was tried and failed: what is there now (None after anything else).
    fn live_after(&self, o: &Outcome, it: &Item) -> Option<Data> {
        matches!(o, Outcome::Failed(_)).then(|| switch::read(&*self.pc, it.req.location, &it.req.ident).ok()).flatten().filter(|(_, there)| *there).map(|(d, _)| d)
    }

    /// An Undo's refusal in an Undo's words (`switch::for_undo`: scanning again never helps it).
    fn worded(it: &Item, o: Outcome) -> Outcome {
        if it.undo_of.is_some() { switch::for_undo(o) } else { o }
    }

    /// An item whose off is bound when it is made (`switch::UNBOUND`, RB6-2: a startup file the
    /// scan could not tell apart) is bound now, to the entry as the change reads it; its record
    /// keeps why it switches off only (so no Undo). Any other item as it is. Err: refused before
    /// anything was written or journaled (there is nothing it is bound to).
    fn bound(pc: &dyn Pc, it: Item) -> Result<Item, Box<Done>> {
        if it.req.def != switch::UNBOUND {
            return Ok(it);
        }
        match switch::bind_now(pc, &it.req) {
            Ok((req, f)) => {
                let read = crate::autostart::def::Fresh { off_only: it.read.off_only.clone().or(f.off_only.clone()), ..f };
                Ok(Item { req, read, ..it })
            }
            Err(o) => Err(Box::new(Done { status: Some(Ctx::status_of(&Ctx::worded(&it, o))), item: it, live: None })),
        }
    }

    fn status_of(o: &Outcome) -> Status {
        match o {
            Outcome::Done => Status::Done,
            Outcome::Refused(w) => Status::Refused(w.clone()),
            Outcome::Failed(w) => Status::Failed(w.clone()),
        }
    }

    /// The change itself: a Journal Undo through `switch::undo` (RB7-1), any other through
    /// `switch::apply`.
    fn act(pc: &dyn Pc, it: &Item) -> Outcome {
        if it.undo_of.is_some() { switch::undo(pc, &it.req) } else { switch::apply(pc, &it.req) }
    }

    /// A batch: the direct changes one by one, then each admin job in its own helper (one
    /// prompt each). A declined prompt stops the rest (they stay as they were). The late binds
    /// of the whole batch (`Ctx::bound`) wait one step in all (RB7-2, a `sys::Step` entered for
    /// each): N startup files not read in time, on a folder that is slow by now, cost at most
    /// 25 s per kind of read before the first prompt (`sys::STEP_WAIT` and its grace), never N
    /// limits; those not bound in it are refused (`switch::LATE_BIND`), nothing written or
    /// journaled.
    fn run(&self, direct: Vec<Item>, admin: Vec<(Job, Vec<Item>)>, epoch: u64, hwnd: isize, from_queue: bool) -> Msg {
        let mut done = Vec::new();
        let mut errors = Vec::new();
        let mut declined = false;
        let late = crate::autostart::sys::Step::new(crate::autostart::sys::STEP_WAIT);
        let bound = |it: Item| late.run(|| Ctx::bound(&*self.pc, it));
        for it in direct {
            let it = match bound(it) {
                Ok(it) => it,
                Err(d) => {
                    done.push(*d);
                    continue;
                }
            };
            let mut rec = self.record(&it, Status::Pending);
            self.write(&rec);
            let out = Ctx::worded(&it, Ctx::act(&*self.pc, &it));
            rec.status = Ctx::status_of(&out);
            self.write(&rec);
            let live = self.live_after(&out, &it);
            done.push(Done { item: it, status: Some(rec.status), live });
        }
        for (job, items) in admin {
            if declined {
                done.extend(items.into_iter().map(|item| Done { item, status: None, live: None }));
                continue;
            }
            let mut ready = Vec::new();
            for it in items {
                match bound(it) {
                    Ok(it) => ready.push(it),
                    Err(d) => done.push(*d),
                }
            }
            if ready.is_empty() {
                continue;
            }
            let items = ready;
            let mut recs: Vec<Record> = items.iter().map(|it| self.record(it, Status::Pending)).collect();
            let reqs: Vec<Request> = items.iter().map(|it| it.req.clone()).collect();
            let wrote = AtomicBool::new(false);
            let connected = || {
                for r in &recs {
                    self.write(r);
                }
                wrote.store(true, Ordering::SeqCst);
            };
            let ans = self.elevator.run(job, epoch, &reqs, hwnd, &connected);
            let outs: Vec<Option<Outcome>> = match ans {
                Ok(Answer::Items(o)) if o.len() == items.len() => o,
                Ok(_) => vec![None; items.len()],
                Err(e) => {
                    if e == ElevError::Declined {
                        declined = true;
                    }
                    errors.push(e.words());
                    vec![None; items.len()]
                }
            };
            let wrote = wrote.load(Ordering::SeqCst);
            // What the helper did not answer is read and settled, in one step (RB6-3).
            crate::autostart::sys::step(|| {
                for ((it, rec), out) in items.into_iter().zip(recs.iter_mut()).zip(outs) {
                    if !wrote {
                        // The request never went out: nothing was done, nothing journaled.
                        done.push(Done { item: it, status: None, live: None });
                        continue;
                    }
                    let out = out.map(|o| Ctx::worded(&it, o));
                    let live = out.as_ref().and_then(|o| self.live_after(o, &it));
                    match out {
                        Some(o) => rec.status = Ctx::status_of(&o),
                        None => self.settle(rec),
                    }
                    self.write(rec);
                    done.push(Done { item: it, status: Some(rec.status.clone()), live });
                }
            });
        }
        Msg::Changed { done, errors, declined, from_queue }
    }
}

impl App {
    /// Wire the controller to a window made by `crate::window`, and start the first scan.
    pub fn attach(ui: &AppWindow, store: Store<Prefs>, svc: Services) -> Rc<App> {
        let prefs = store.load().sanitized();
        let prefs_pending = Arc::new(AtomicUsize::new(0));
        let prefs_tx = prefs_writer(store.clone(), prefs_pending.clone());
        let filters = Filters { recent: prefs.recent, new_only: prefs.new_only, not_ms: prefs.not_ms(), text: String::new() };
        let local = svc.setup.paths.local_data.clone();
        let session = fresh_id((svc.now)());
        let app = Rc::new(App {
            ui: ui.as_weak(),
            journal_store: Store::new(local.join("journal.json")),
            seen_store: Store::new(local.join("seen.json")),
            session,
            svc,
            store,
            st: RefCell::new(State { prefs, filters, ..State::default() }),
            prefs_tx,
            prefs_pending,
            toasts: Rc::new(VecModel::default()),
            rows: Rc::new(VecModel::default()),
            pairs: Rc::new(VecModel::default()),
            jrows: Rc::new(VecModel::default()),
            me: RefCell::new(std::rc::Weak::new()),
            inbox: Arc::new(Mutex::new(Vec::new())),
            held: RefCell::new(Vec::new()),
            scroll_seq: Cell::new(0),
            check_rows: Rc::new(VecModel::default()),
            check_timer: Timer::default(),
        });
        *app.me.borrow_mut() = Rc::downgrade(&app);
        APP.with(|a| *a.borrow_mut() = Rc::downgrade(&app));
        ui.set_toasts(ModelRc::from(app.toasts.clone()));
        ui.set_rows(ModelRc::from(app.rows.clone()));
        ui.set_detail_pairs(ModelRc::from(app.pairs.clone()));
        ui.set_journal_rows(ModelRc::from(app.jrows.clone()));
        ui.set_check_rows(ModelRc::from(app.check_rows.clone()));
        app.show_rows(&Rows::idle());
        {
            let f = app.st.borrow().filters.clone();
            ui.set_f_recent(f.recent);
            ui.set_f_new(f.new_only);
            ui.set_f_not_ms(f.not_ms);
        }
        if let Some((dir, _)) = &app.svc.setup.portable {
            ui.set_portable(s(format!("Portable: settings, the journal for Undo and the startup lists of the last {} PCs looked at are kept in {}. {PORTABLE_TRACE}", crate::autostart::seen::MAX_PCS, text::clean(&dir.to_string_lossy()))));
        }
        let bits = if cfg!(target_pointer_width = "64") { "64-bit" } else { "32-bit" };
        let how = if app.svc.setup.portable.is_some() { "portable" } else { "installed for you" };
        ui.set_about_line(s(format!("version {} · {bits} · {how}", crate::VERSION)));
        ui.set_full_tip(s("Read every scheduled task, the ones hidden from this account too (one Windows prompt for administrator rights; another account's password at the prompt does not reach VibeBoot)"));
        app.wire(ui);
        if app.store.broken() {
            app.toast("prefs.json could not be read: the settings are back to their defaults, and the old file will be kept as prefs.json.broken.", ToastKind::Error, None);
        }
        ui.set_scanning(true);
        app.rebuild();
        app.load_state();
        app
    }

    fn wire(self: &Rc<Self>, ui: &AppWindow) {
        macro_rules! on {
            ($setter:ident, |$a:ident $(, $arg:ident)*| $body:expr) => {{
                let w = Rc::downgrade(self);
                ui.$setter(move |$($arg),*| {
                    let Some($a) = w.upgrade() else { return Default::default() };
                    $body
                });
            }};
        }
        on!(on_toggle_theme, |a| a.toggle_theme());
        on!(on_copy_text, |a, t| (a.svc.copy)(&t));
        on!(on_toast_dismissed, |a, id| a.drop_toast(id));
        on!(on_toast_action, |a, id| a.toast_action(id));
        on!(on_dialogs_closed, |a| a.dialogs_closed());
        on!(on_check_install, |a| a.check_install());
        on!(on_open_site, |a| (a.svc.open_url)(crate::check::SITE));
        on!(on_scan, |a| a.scan());
        on!(on_full_scan, |a| a.full_scan());
        on!(on_open_journal, |a| a.open_journal());
        on!(on_copy_report, |a| a.copy_report());
        on!(on_save_report, |a| a.save_report());
        on!(on_filter_toggled, |a, i| a.filter_toggled(i));
        on!(on_filter_edited, |a, t| a.filter_edited(&t));
        on!(on_filter_escaped, |a| a.filter_escaped());
        on!(on_row_clicked, |a, i| a.row_clicked(i));
        on!(on_switch_clicked, |a, i| a.switch_clicked(i));
        on!(on_detail_act, |a| a.detail_act());
        on!(on_apply, |a| a.apply());
        on!(on_discard, |a| a.discard());
        on!(on_journal_picked, |a, id| a.journal_picked(&id));
        on!(on_journal_undo, |a| a.journal_undo());
        on!(on_journal_undo_all, |a| a.journal_undo_all());
        on!(on_key, |a, t, c, sh| a.key(&t, c, sh));
        on!(on_journal_key, |a, t| a.journal_key(&t));
    }

    fn ui(&self) -> Option<AppWindow> {
        self.ui.upgrade()
    }

    fn now(&self) -> i64 {
        (self.svc.now)()
    }

    fn local(&self, t: i64) -> i64 {
        t + (self.svc.offset)(t)
    }

    // ---------- prefs ----------

    pub fn prefs(&self) -> Prefs {
        self.st.borrow().prefs.clone()
    }

    pub fn save_prefs(&self, change: impl Fn(&mut Prefs) + Send + Sync + 'static) {
        let f: PrefsChange = Arc::new(change);
        f(&mut self.st.borrow_mut().prefs);
        self.prefs_pending.fetch_add(1, Ordering::SeqCst);
        if self.prefs_tx.send(f).is_err() {
            self.prefs_pending.fetch_sub(1, Ordering::SeqCst);
        }
        let w = self.me.borrow().clone();
        Timer::single_shot(Duration::from_millis(PREFS_TELL_MS), move || {
            if let Some(a) = w.upgrade() {
                a.tell_garbled();
            }
        });
    }

    fn tell_garbled(&self) {
        if self.store.take_garbled() {
            self.toast("prefs.json was damaged: it is kept as prefs.json.broken, and this window's settings are saved in its place.", ToastKind::Error, None);
        }
        for (store_garbled, name) in [(self.journal_store.take_garbled(), "journal.json"), (self.seen_store.take_garbled(), "seen.json")] {
            if store_garbled {
                self.toast(&format!("{name} was damaged: it is kept as {name}.broken, and what this window knows is saved in its place."), ToastKind::Error, None);
            }
        }
    }

    /// At exit (and in tests): let the prefs thread hand its last change to the store (at most
    /// two seconds), then write what is unwritten. The state files are written by their workers.
    ///
    /// The last write runs on a thread of its own, waited for at most two seconds: a prefs file
    /// on a share that stopped answering never holds the window's thread for good (VibePing
    /// PING-8, review X15CON-4). A prefs thread still busy after its two seconds is not waited
    /// for: at exit the process ends it, and the changes it had not written are lost, unsaid.
    pub fn finish_prefs(&self) {
        let start = Instant::now();
        let limit = Duration::from_secs(2);
        while self.prefs_pending.load(Ordering::SeqCst) > 0 && start.elapsed() < limit {
            std::thread::sleep(Duration::from_millis(2));
        }
        // A prefs thread still busy holds the prefs store: only the state files are written then.
        let prefs_busy = self.prefs_pending.load(Ordering::SeqCst) > 0;
        let (store, journal_store, seen_store) = (self.store.clone(), self.journal_store.clone(), self.seen_store.clone());
        let (tx, rx) = channel::<()>();
        // The journal (what Undo needs) and seen first: a prefs file whose read hangs (Roaming on
        // a share that stopped answering) must not keep them from being written (X15RFAMA-3).
        std::thread::spawn(move || {
            journal_store.flush();
            seen_store.flush();
            if !prefs_busy {
                store.flush();
            }
            let _ = tx.send(());
        });
        let _ = rx.recv_timeout(limit);
    }

    fn toggle_theme(&self) {
        let Some(ui) = self.ui() else { return };
        let theme = ui.global::<Theme>();
        let dark = !theme.get_dark();
        theme.set_dark(dark);
        self.save_prefs(move |p| p.theme = Some(if dark { "dark" } else { "light" }.into()));
    }

    // ---------- About's install check ----------

    /// "Check this install": one at a time, on a worker (it reads the files and may go online);
    /// the window looks for the answer every CHECK_POLL_MS meanwhile and goes on. Closing About
    /// leaves it running: the answer lands in the rows, which About shows when it opens again.
    fn check_install(&self) {
        let Some(ui) = self.ui() else { return };
        let seq = {
            let mut st = self.st.borrow_mut();
            if st.check_rx.is_some() {
                return;
            }
            st.check_seq += 1;
            st.check_seq
        };
        let (tx, rx) = channel();
        self.st.borrow_mut().check_rx = Some(rx);
        ui.set_checking(true);
        let (inspect, fetch, release) = (self.svc.inspect.clone(), self.svc.fetch.clone(), self.svc.release.clone());
        let installed = self.svc.setup.portable.is_none();
        std::thread::spawn(move || {
            let local = inspect(&installed);
            // The exe updated or replaced under this one while it ran: nothing to compare (FED3).
            let rows = if local.replaced {
                crate::check::replaced_rows(&release, &local)
            } else {
                let fetched = fetch_within(fetch, crate::check::list_path(release.app), release.wait);
                crate::check::rows(&release, &local, fetched)
            };
            let _ = tx.send((seq, rows));
        });
        let w = self.me.borrow().clone();
        self.check_timer.start(TimerMode::Repeated, Duration::from_millis(CHECK_POLL_MS), move || {
            if let Some(a) = w.upgrade() {
                a.poll_check();
            }
        });
    }

    /// The check's answer, once it is there: the rows, and the button back.
    fn poll_check(&self) {
        let got = {
            let st = self.st.borrow();
            let Some(rx) = st.check_rx.as_ref() else { return };
            match rx.try_recv() {
                Ok((seq, rows)) => Some((seq == st.check_seq).then_some(rows)),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => Some(Some(Rows::stopped())),
            }
        };
        let Some(rows) = got else { return };
        self.check_timer.stop();
        self.st.borrow_mut().check_rx = None;
        if let Some(rows) = rows {
            self.show_rows(&rows);
        }
        if let Some(ui) = self.ui() {
            ui.set_checking(false);
            ui.set_checked(true);
        }
    }

    fn show_rows(&self, rows: &Rows) {
        let dot = |d: Dot| match d {
            Dot::Idle => CheckDot::Idle,
            Dot::Ok => CheckDot::Ok,
            Dot::Warn => CheckDot::Warn,
            Dot::Danger => CheckDot::Danger,
        };
        let all: Vec<CheckRow> = rows.all().iter().map(|(name, r)| CheckRow { name: s(name), text: s(&r.text), dot: dot(r.dot) }).collect();
        self.check_rows.set_vec(all);
    }

    // ---------- workers ----------

    /// Run `work` off the UI thread; its message comes back to `handle` (tests: at once, or
    /// held until `release`).
    fn bg(&self, work: impl FnOnce() -> Msg + Send + 'static) {
        if self.svc.manual {
            if self.svc.hold.get() {
                self.held.borrow_mut().push(Box::new(work));
            } else {
                let m = work();
                self.handle(m);
            }
            return;
        }
        let inbox = self.inbox.clone();
        let _ = std::thread::Builder::new().name("worker".into()).stack_size(1024 * 1024).spawn(move || {
            let m = work();
            lock(&inbox).push(m);
            let _ = slint::invoke_from_event_loop(|| {
                APP.with(|a| {
                    if let Some(app) = a.borrow().upgrade() {
                        app.drain();
                    }
                })
            });
        });
    }

    /// Tests: the jobs held back so far.
    pub fn held(&self) -> usize {
        self.held.borrow().len()
    }

    /// Tests: let the held jobs answer, in the order they were started (the answers may start
    /// more jobs: those are held too while `hold` is on).
    pub fn release(&self) {
        let jobs = std::mem::take(&mut *self.held.borrow_mut());
        for j in jobs {
            let m = j();
            self.handle(m);
        }
    }

    fn drain(&self) {
        let msgs = std::mem::take(&mut *lock(&self.inbox));
        for m in msgs {
            self.handle(m);
        }
    }

    /// One message, as if a worker had brought it.
    pub fn handle(&self, m: Msg) {
        match m {
            Msg::State { guid, journal, seen, told, writable } => self.state_loaded(guid, journal, seen, told, writable),
            Msg::Part { epoch, part } => self.part(epoch, part),
            Msg::Tasks { epoch, tp, full } => self.tasks_read(epoch, tp, full),
            Msg::Signed { epoch, results } => self.signed(epoch, results),
            Msg::Changed { done, errors, declined, from_queue } => self.changed(done, errors, declined, from_queue),
            Msg::FullScanFailed { epoch, why } => {
                if epoch == self.st.borrow().scan.epoch {
                    self.set_busy(false, "");
                    self.toast(&why, ToastKind::Error, None);
                    self.refresh_status();
                }
            }
            Msg::Saved(Ok(p)) => {
                let name = p.file_name().map(|n| text::clean(&n.to_string_lossy())).unwrap_or_default();
                self.toast(&format!("Saved {name}"), ToastKind::Ok, Some(p));
            }
            Msg::Saved(Err(e)) => self.toast(&format!("The report could not be saved: {e}"), ToastKind::Error, None),
        }
        let rescan = {
            let mut st = self.st.borrow_mut();
            !st.busy && std::mem::take(&mut st.rescan)
        };
        if rescan {
            self.scan();
        }
    }

    // ---------- start: the state files ----------

    fn load_state(&self) {
        let pc = self.svc.pc.clone();
        let (journal, seen) = (self.journal_store.clone(), self.seen_store.clone());
        let portable = self.svc.setup.portable.clone();
        let writable = self.svc.writable.clone();
        self.bg(move || {
            let guid = pc.machine_guid().unwrap_or_else(|| "unknown-pc".into());
            let mut told = Vec::new();
            let blind = |p: &Path| matches!(std::fs::read(p), Err(e) if e.kind() != std::io::ErrorKind::NotFound);
            let j = journal.load();
            if journal.broken() {
                told.push(("journal.json could not be read: the journal starts empty here, and the old file will be kept as journal.json.broken.".to_string(), ToastKind::Error));
            } else if blind(journal.path()) {
                told.push(("journal.json cannot be read right now: this session's changes are kept and saved once it can be.".to_string(), ToastKind::Error));
            }
            let sn = seen.load();
            if seen.broken() {
                told.push(("seen.json could not be read: nothing is \"new\" this time, and the old file will be kept as seen.json.broken.".to_string(), ToastKind::Error));
            }
            // A pending change from a crash: checked against the live data and settled, all in
            // one step (RB6-3: a journal of many records on files that do not answer costs the
            // first scan at most 25 s per kind of read, `sys::STEP_WAIT` and its grace, never
            // one limit each; those not read stay pending).
            let settled = crate::autostart::sys::step(|| {
                let mut settled = 0;
                for r in j.pending(&guid) {
                    let mut r = r.clone();
                    if let Some((status, note)) = journal::settle(&r, switch::read(&*pc, r.location, &r.ident)) {
                        r.status = status;
                        r.settled = Some(note);
                        let rr = r.clone();
                        journal.change(Arc::new(move |x: &mut Journal| x.upsert(rr.clone())));
                        settled += 1;
                    }
                }
                settled
            });
            if settled > 0 {
                told.push((format!("{settled} change{} left pending when VibeBoot last stopped {} checked and settled (see the Journal).", if settled == 1 { "" } else { "s" }, if settled == 1 { "was" } else { "were" }), ToastKind::Info));
            }
            let writable = portable.map(|(dir, _)| writable(&dir));
            Msg::State { guid, journal: journal.current(), seen: sn, told, writable }
        });
    }

    fn state_loaded(&self, guid: String, j: Journal, seen: Seen, told: Vec<(String, ToastKind)>, writable: Option<bool>) {
        {
            let mut st = self.st.borrow_mut();
            st.loaded = true;
            st.baseline = seen.baseline(&guid);
            st.guid = guid;
            st.journal = j;
            st.read_only = writable == Some(false);
        }
        for (t, k) in told {
            self.toast(&t, k, None);
        }
        if writable == Some(false) {
            self.toast("Portable, read-only: settings and the journal will not be kept. Changes still work, and Undo works until VibeBoot closes.", ToastKind::Info, None);
        }
        self.record_seen();
        self.rebuild();
        // The first scan waits for the journal: it names the services this app set to Manual,
        // which the services part lists so they can be switched back on.
        if self.st.borrow().scan.epoch == 0 {
            self.scan();
        }
    }

    // ---------- the scan ----------

    /// Read every place again (the Full scan's hidden tasks are read again only by Full scan).
    pub fn scan(&self) {
        if self.st.borrow().busy {
            return;
        }
        let epoch = {
            let mut st = self.st.borrow_mut();
            let epoch = st.scan.epoch + 1;
            st.scan = Scan { epoch, ..Scan::default() };
            epoch
        };
        if let Some(ui) = self.ui() {
            ui.set_scanning(true);
        }
        self.rebuild();
        let pc = self.svc.pc.clone();
        self.bg(move || Msg::Part { epoch, part: scan::registry(&*pc) });
        let pc = self.svc.pc.clone();
        self.bg(move || Msg::Part { epoch, part: scan::startup_folders(&*pc) });
        let pc = self.svc.pc.clone();
        self.bg(move || Msg::Tasks { epoch, tp: scan::tasks(&*pc, pc.tasks()), full: false });
        let pc = self.svc.pc.clone();
        let off: std::collections::BTreeSet<String> = {
            let st = self.st.borrow();
            st.journal.switched_off_services(&st.guid)
        };
        self.bg(move || Msg::Part { epoch, part: scan::services(&*pc, &|n| off.contains(n)) });
    }

    fn part(&self, epoch: u64, mut part: Part) {
        let now = self.now();
        let added = {
            let mut st = self.st.borrow_mut();
            if st.scan.epoch != epoch {
                return;
            }
            Self::seen_evidence(&st.baseline, &mut part.entries, now);
            let from = st.scan.entries.len();
            st.scan.answered.extend(part.answered.iter().copied());
            st.scan.failed.extend(part.failed);
            st.scan.entries.extend(part.entries);
            let n = st.scan.entries.len();
            st.scan.sign.resize(n, None);
            from..n
        };
        self.after_part(epoch, added);
    }

    fn tasks_read(&self, epoch: u64, mut tp: TaskPart, full: bool) {
        let now = self.now();
        let added = {
            let mut st = self.st.borrow_mut();
            if st.scan.epoch != epoch {
                return;
            }
            if full {
                // A task this account's view did not have is one only Full scans read: the Full
                // scans' reads say when it came (R-BOOT-6), never "first seen today" for one
                // that was there all along.
                let quick: HashSet<String> = st.scan.entries.iter().filter(|e| e.location == Location::LogonTask).map(|e| e.key.clone()).collect();
                for e in tp.part.entries.iter_mut().filter(|e| !e.anonymous()) {
                    let d = if quick.contains(&e.key) { st.baseline.evidence(&e.key, e.location, now) } else { st.baseline.evidence_hidden(&e.key, now) };
                    e.dates.extend(d);
                }
            } else {
                Self::seen_evidence(&st.baseline, &mut tp.part.entries, now);
            }
            if full {
                // The full read replaces this account's view of the tasks.
                let visible = st.scan.tasks_total;
                let keep: Vec<bool> = st.scan.entries.iter().map(|e| e.location != Location::LogonTask).collect();
                let entries = std::mem::take(&mut st.scan.entries);
                let sign = std::mem::take(&mut st.scan.sign);
                for ((e, s), k) in entries.into_iter().zip(sign).zip(keep) {
                    if k {
                        st.scan.entries.push(e);
                        st.scan.sign.push(s);
                    }
                }
                st.scan.failed.retain(|(l, _)| *l != Location::LogonTask);
                st.hidden_tasks = Some(tp.total.saturating_sub(visible));
                st.scan.full = true;
                // The tasks only this read sees are recorded as seen too (BOOT-4).
                st.scan.seen_recorded = false;
            }
            st.scan.tasks_total = tp.total;
            let from = st.scan.entries.len();
            st.scan.answered.extend(tp.part.answered.iter().copied());
            st.scan.failed.extend(tp.part.failed);
            st.scan.entries.extend(tp.part.entries);
            let n = st.scan.entries.len();
            st.scan.sign.resize(n, None);
            from..n
        };
        if full {
            self.set_busy(false, "");
            let hidden = self.st.borrow().hidden_tasks.unwrap_or(0);
            self.toast(&format!("Full scan: every scheduled task read ({hidden} hidden from this account)."), ToastKind::Ok, None);
        }
        self.after_part(epoch, added);
    }

    /// What this PC's earlier looks say about when each entry came (Baseline::evidence), as one
    /// more date of the entry.
    fn seen_evidence(b: &Baseline, entries: &mut [Entry], now: i64) {
        for e in entries.iter_mut().filter(|e| !e.anonymous()) {
            if let Some(d) = b.evidence(&e.key, e.location, now) {
                e.dates.push(d);
            }
        }
    }

    /// New entries arrived: their signers (cached ones at once, the rest on workers), then the
    /// view; once every location answered, first-seen is recorded.
    fn after_part(&self, epoch: u64, added: std::ops::Range<usize>) {
        let mut todo: Vec<(String, PathBuf)> = Vec::new();
        {
            let mut st = self.st.borrow_mut();
            let mut queued: HashSet<String> = HashSet::new();
            for i in added {
                let e = &st.scan.entries[i];
                let known: Option<SignInfo> = match (&e.file, &e.target) {
                    (_, None) => Some(SignInfo { signer: Signer::Unknown("no program file to check".into()), company: None }),
                    (FileState::Missing, _) => Some(SignInfo { signer: Signer::Missing, company: None }),
                    (FileState::Unknown(w), _) => Some(SignInfo { signer: Signer::Unknown(w.clone()), company: None }),
                    (FileState::NoTarget, _) => Some(SignInfo { signer: Signer::Unknown("no program file to check".into()), company: None }),
                    (FileState::Present, Some(_)) => e.file_key.and_then(|k| st.sign_cache.get(&k).cloned()),
                };
                match known {
                    Some(k) => st.scan.sign[i] = Some(k),
                    None => {
                        let t = e.target.clone().unwrap_or_default();
                        let k = t.to_string_lossy().to_lowercase();
                        if queued.insert(k.clone()) {
                            todo.push((k, t));
                        }
                    }
                }
            }
            if st.scan.answered.len() == Location::ALL.len() && st.scan.finished.is_none() {
                st.scan.finished = Some(self.now());
            }
        }
        if !todo.is_empty() {
            self.sign(epoch, todo);
        }
        if self.st.borrow().scan.finished.is_some() {
            if let Some(ui) = self.ui() {
                ui.set_scanning(false);
            }
            self.record_seen();
        }
        self.rebuild();
    }

    /// Check the signers of `todo` (key, path): four workers, results batched (one wake-up per
    /// batch); tests: inline. The batch is one step (`sys::SIGN_STEP` of waiting in all, RB5-3):
    /// held files cost the batch that much at most, and the rest are unknown with that reason.
    fn sign(&self, epoch: u64, todo: Vec<(String, PathBuf)>) {
        let step = crate::autostart::sys::Step::new(crate::autostart::sys::SIGN_STEP);
        if self.svc.manual {
            let pc = self.svc.pc.clone();
            self.bg(move || Msg::Signed { epoch, results: step.run(|| todo.into_iter().map(|(k, p)| (k, pc.sign(&p))).collect()) });
            return;
        }
        let queue = Arc::new(Mutex::new(VecDeque::from(todo)));
        let out: Arc<Mutex<Vec<SignedTarget>>> = Arc::new(Mutex::new(Vec::new()));
        let wake = Arc::new(AtomicBool::new(false));
        for _ in 0..SIGNERS {
            let (pc, queue, out, wake, step) = (self.svc.pc.clone(), queue.clone(), out.clone(), wake.clone(), step.clone());
            let _ = std::thread::Builder::new().name("signer".into()).stack_size(1024 * 1024).spawn(move || {
                step.run(|| loop {
                    let Some((k, p)) = lock(&queue).pop_front() else { break };
                    let info = pc.sign(&p);
                    lock(&out).push((k, info));
                    if !wake.swap(true, Ordering::SeqCst) {
                        let (out, wake) = (out.clone(), wake.clone());
                        let _ = slint::invoke_from_event_loop(move || {
                            wake.store(false, Ordering::SeqCst);
                            let results = std::mem::take(&mut *lock(&out));
                            APP.with(|a| {
                                if let Some(app) = a.borrow().upgrade() {
                                    app.handle(Msg::Signed { epoch, results });
                                }
                            })
                        });
                    }
                })
            });
        }
    }

    fn signed(&self, epoch: u64, results: Vec<SignedTarget>) {
        {
            let mut st = self.st.borrow_mut();
            if st.scan.epoch != epoch {
                return;
            }
            let by: HashMap<String, (SignInfo, Option<FileKey>)> = results.into_iter().collect();
            for i in 0..st.scan.entries.len() {
                if st.scan.sign[i].is_some() {
                    continue;
                }
                let k = st.scan.entries[i].target.as_ref().map(|t| t.to_string_lossy().to_lowercase());
                if let Some((info, checked)) = k.and_then(|k| by.get(&k)) {
                    // Cached only under the identity of the file the signer opened, and only
                    // when that is the file the scan read (one replaced in between is not).
                    if info.signer.definite()
                        && let Some(fk) = st.scan.entries[i].file_key.filter(FileKey::usable)
                        && *checked == Some(fk)
                    {
                        st.sign_cache.insert(fk, info.clone());
                    }
                    st.scan.sign[i] = Some(info.clone());
                }
            }
        }
        self.rebuild();
    }

    /// First seen: once per scan, when every location answered and the state files are in.
    fn record_seen(&self) {
        let (guid, now, keys, answered, full) = {
            let mut st = self.st.borrow_mut();
            if !st.loaded || st.scan.finished.is_none() || st.scan.seen_recorded {
                return;
            }
            st.scan.seen_recorded = true;
            let failed: HashSet<Location> = st.scan.failed.iter().map(|(l, _)| *l).collect();
            let answered: Vec<Location> = st.scan.answered.iter().copied().filter(|l| !failed.contains(l)).collect();
            let full = st.scan.full && answered.contains(&Location::LogonTask);
            (st.guid.clone(), st.scan.finished.unwrap_or(0), st.scan.entries.iter().filter(|e| !e.anonymous()).map(|e| e.key.clone()).collect::<Vec<_>>(), answered, full)
        };
        let seen = self.seen_store.clone();
        let f = move || {
            seen.change(Arc::new(move |s: &mut Seen| if full { s.record_full(&guid, now, &keys, &answered) } else { s.record(&guid, now, &keys, &answered) }));
        };
        if self.svc.manual {
            f();
        } else {
            std::thread::spawn(f);
        }
    }

    fn full_scan(&self) {
        if self.st.borrow().busy || self.st.borrow().scan.finished.is_none() {
            return;
        }
        let epoch = self.st.borrow().scan.epoch;
        self.set_busy(true, "Full scan: Windows asks for administrator rights…");
        let (pc, el) = (self.svc.pc.clone(), self.svc.elevator.clone());
        let hwnd = (self.svc.hwnd)();
        self.bg(move || match el.run(Job::ScanTasks, epoch, &[], hwnd, &|| {}) {
            Ok(Answer::Tasks(list, unread)) => {
                let list: Vec<TaskRaw> = list;
                Msg::Tasks { epoch, tp: scan::tasks(&*pc, Ok((list, unread))), full: true }
            }
            Ok(Answer::Items(_)) => Msg::FullScanFailed { epoch, why: "The full scan failed: the helper answered something else.".into() },
            Err(e) => Msg::FullScanFailed { epoch, why: e.words().replace("Not done:", "Full scan not done:") },
        });
    }

    // ---------- the view ----------

    fn facts(st: &State) -> Vec<Facts> {
        st.scan.entries.iter().zip(&st.scan.sign).map(|(e, s)| Facts::of(e, s.clone(), !e.anonymous() && st.baseline.is_new(&e.key, e.location))).collect()
    }

    fn switch_state(st: &State, i: usize) -> (i32, String) {
        let e = &st.scan.entries[i];
        if st.busy_keys.contains(&e.key) {
            return (5, "Changing now".into());
        }
        if let Some(q) = st.queue.get(&e.key) {
            let on = q.on() == Some(true);
            return (if on { 3 } else { 4 }, format!("Turns {} when the administrator changes are applied", if on { "on" } else { "off" }));
        }
        // Windows' own services and tasks are left alone (the helper refuses them too): a lock,
        // not a switch.
        let f = Facts::of(e, st.scan.sign[i].clone(), false);
        if let Some(why) = changes::windows_own(e, &f) {
            return (2, why.replace("left alone", "VibeBoot leaves it alone"));
        }
        match &e.switch {
            Switch::On => (0, "On: switch it off".into()),
            Switch::Off { .. } => (1, "Off: switch it on".into()),
            Switch::Fixed(w) => (2, w.clone()),
            Switch::Unknown(w) => (6, w.clone()),
        }
    }

    /// An dded date in words: the row's column, the short form (screen reader) and the long
    /// one (tooltip, detail). Only the key's last change: "added: not known, key changed <date>".
    fn added_words(&self, d: &DateFact) -> (String, String, String) {
        let day = dates::day_text(self.local(d.at));
        if dates::weak(d) {
            let why = if d.kind == crate::autostart::DateKind::ServiceChanged { "the service key's last change: an update or a switch of its start type changes it too" } else { "the key's last change, shared by every value in it" };
            (format!("added? {day}"), format!("added: not known, key changed {day}"), format!("added: not known, key changed {day} ({why})"))
        } else {
            let w = format!("{} {day}", d.kind.words());
            (format!("added {day}"), w.clone(), w)
        }
    }

    fn entry_row(&self, st: &State, i: usize, f: &Facts, selected: bool) -> EntryRow {
        let e = &st.scan.entries[i];
        let (sw, tip) = Self::switch_state(st, i);
        let mut chips: Vec<ChipItem> = Vec::new();
        let sig = f.sign.as_ref().map(|s| &s.signer);
        if matches!(sig, Some(Signer::NotSigned)) {
            chips.push(ChipItem { text: s("unsigned"), tone: 2 });
        }
        if matches!(sig, Some(Signer::Broken(_))) {
            chips.push(ChipItem { text: s("signature broken"), tone: 3 });
        }
        if e.unread.is_some() {
            chips.push(ChipItem { text: s("could not be read"), tone: 3 });
        }
        if e.file == FileState::Missing {
            chips.push(ChipItem { text: s("file missing"), tone: 3 });
        }
        if f.new {
            chips.push(ChipItem { text: s("new"), tone: 1 });
        }
        if e.hidden {
            chips.push(ChipItem { text: s("hidden command"), tone: 2 });
        }
        let added = dates::added(&e.dates);
        let pubw = groups::publisher(f);
        let tone = match sig {
            Some(Signer::Broken(_)) | Some(Signer::Missing) => 3,
            Some(Signer::NotSigned) => 2,
            _ if f.launched().is_some() => 2,
            _ => 0,
        };
        let state = match sw {
            0 => "on",
            1 => "off",
            2 => "no switch",
            3 => "turns on when applied",
            4 => "turns off when applied",
            5 => "changing",
            _ => "switch unknown",
        };
        let chip_words: Vec<String> = chips.iter().map(|c| c.text.to_string()).collect();
        EntryRow {
            id: i as i32,
            kind: 1,
            title: s(&e.name),
            sub: s(&pubw),
            sub_tone: tone,
            switch: sw,
            switch_tip: s(tip),
            chips: ModelRc::new(VecModel::from(chips)),
            added: s(added.map(|d| self.added_words(&d).0).unwrap_or_default()),
            added_tip: s(added.map(|d| self.added_words(&d).2).unwrap_or_default()),
            selected,
            a11y: s(format!("{state}, {pubw}{}{}", if chip_words.is_empty() { String::new() } else { format!(", {}", chip_words.join(", ")) }, added.map(|d| format!(", {}", self.added_words(&d).1)).unwrap_or_default())),
        }
    }

    /// Everything the window shows from the scan: rows, summary, admin bar, detail, status.
    fn rebuild(&self) {
        let Some(ui) = self.ui() else { return };
        let (rows, models, summary, tone, empty) = {
            let mut st = self.st.borrow_mut();
            let facts = Self::facts(&st);
            let now = self.now();
            let rows = groups::rows(&st.scan.entries, &facts, &st.filters, &st.opened, &st.scan.answered, &st.scan.failed, now);
            // A selection that went away (filtered out, a new scan) falls back to nothing.
            let still = |sel: &Sel| {
                rows.iter().any(|r| match (r, sel) {
                    (Row::Entry(i), Sel::Entry(k)) => st.scan.entries[*i].key == *k,
                    (Row::Microsoft { group, .. }, Sel::Fold(g)) => group == g,
                    _ => false,
                })
            };
            if st.sel.as_ref().is_some_and(|s| !still(s)) {
                st.sel = None;
            }
            let mut models = Vec::with_capacity(rows.len());
            for (n, r) in rows.iter().enumerate() {
                models.push(match r {
                    Row::Head { group, shown, total, scanning, failed } => {
                        let (sub, tone) = if let Some(f) = failed {
                            (format!("could not be read: {}", text::clean(f)), 3)
                        } else if *scanning {
                            ("Scanning…".to_string(), 0)
                        } else if *total == 0 {
                            ("none".to_string(), 0)
                        } else if shown < total {
                            (format!("{shown} of {total} match the filters"), 0)
                        } else if *total == 1 {
                            ("1 entry".to_string(), 0)
                        } else {
                            (format!("{total} entries"), 0)
                        };
                        let a11y = format!("{}, {sub}", group.title());
                        EntryRow { id: n as i32, kind: 0, title: s(group.title()), sub: s(&sub), sub_tone: tone, a11y: s(a11y), ..EntryRow::default() }
                    }
                    Row::Microsoft { group, count, open } => {
                        let sel = st.sel == Some(Sel::Fold(*group));
                        let t = format!("{count} from Microsoft");
                        EntryRow { id: n as i32, kind: 2, title: s(&t), sub: s(if *open { "hide" } else { "show" }), selected: sel, a11y: s(format!("{t}, {}; Space to {}", if *open { "shown" } else { "folded" }, if *open { "fold them" } else { "show them" })), ..EntryRow::default() }
                    }
                    Row::Entry(i) => {
                        let sel = st.sel.as_ref() == Some(&Sel::Entry(st.scan.entries[*i].key.clone()));
                        let mut row = self.entry_row(&st, *i, &facts[*i], sel);
                        row.id = n as i32;
                        row
                    }
                });
            }
            let finished = st.scan.finished.is_some();
            let c = groups::counts(&st.scan.entries, &facts);
            let failed = !st.scan.failed.is_empty();
            let summary = if !finished {
                if st.scan.entries.is_empty() { "Scanning…".to_string() } else { format!("Scanning… {} entries so far", st.scan.entries.len()) }
            } else {
                let mut sm = groups::summary(&c);
                if failed {
                    sm.push_str(" · some places could not be read (see their groups)");
                }
                sm
            };
            let tone = if finished && (failed || c.unread > 0) { 2 } else { 0 };
            let empty = if st.scan.entries.is_empty() && finished { "Nothing starts with this PC from the places VibeBoot reads.".to_string() } else { String::new() };
            st.rows = rows.clone();
            (rows, models, summary, tone, empty)
        };
        let _ = rows;
        // Replace row by row (one notify per changed row) when the count is the same.
        if self.rows.row_count() == models.len() {
            for (i, m) in models.into_iter().enumerate() {
                if self.rows.row_data(i).as_ref() != Some(&m) {
                    self.rows.set_row_data(i, m);
                }
            }
        } else {
            self.rows.set_vec(models);
        }
        ui.set_summary(s(summary));
        ui.set_summary_tone(tone);
        ui.set_rows_empty(s(empty));
        {
            let st = self.st.borrow();
            ui.set_admin_text(s(if st.queue.is_empty() { String::new() } else { st.queue.bar_text() }));
            ui.set_admin_busy(st.busy);
            ui.set_has_report(st.scan.finished.is_some());
            let ll = match st.baseline.last_look {
                Some(t) => format!("Not there at the last look at this PC ({})", dates::day_text(self.local(t))),
                None => "The first look at this PC: nothing to compare with yet".to_string(),
            };
            ui.set_last_look(s(ll));
            // R-BOOT-3: on a first look the 30-day filter shows what changed, not what was added.
            let now = self.now();
            let n = st.scan.entries.iter().filter(|e| groups::recent(e, now)).count();
            let (label, tip, note) = groups::recent_words(st.loaded && st.baseline.last_look.is_none(), n);
            ui.set_f_recent_label(s(label));
            ui.set_f_recent_tip(s(tip));
            ui.set_list_note(s(if st.scan.finished.is_some() { note } else { String::new() }));
        }
        self.show_detail();
        self.refresh_status();
        self.refresh_journal();
    }

    fn refresh_status(&self) {
        let Some(ui) = self.ui() else { return };
        let st = self.st.borrow();
        let mut parts: Vec<String> = Vec::new();
        if self.svc.setup.portable.is_some() {
            parts.push(if st.read_only { "Portable (read-only)".into() } else { "Portable".into() });
        }
        if st.busy {
            parts.push(st.busy_words.clone());
        } else if let Some(t) = st.scan.finished {
            let lt = self.local(t);
            let sec = lt.rem_euclid(86_400);
            parts.push(format!("Scanned {:02}:{:02}:{:02}", sec / 3600, (sec / 60) % 60, sec % 60));
        } else {
            parts.push("Scanning…".into());
        }
        if st.scan.answered.contains(&Location::LogonTask) && !st.busy {
            parts.push(match (st.scan.full, st.hidden_tasks) {
                (true, Some(h)) => format!("Full scan: {} tasks read, {h} of them hidden from this account", st.scan.tasks_total),
                (false, Some(h)) if h > 0 => format!("{h} task{} hidden from this account: Full scan (admin) reads them", if h == 1 { " is" } else { "s are" }),
                (false, Some(_)) => "No tasks are hidden from this account".into(),
                _ => "Tasks as this account sees them: Full scan (admin) reads the hidden ones".into(),
            });
        }
        ui.set_status_left(s(parts.join(" · ")));
        ui.set_busy(st.busy);
    }

    fn set_busy(&self, on: bool, words: &str) {
        {
            let mut st = self.st.borrow_mut();
            st.busy = on;
            st.busy_words = words.to_string();
        }
        if let Some(ui) = self.ui() {
            ui.set_busy(on);
            ui.set_admin_busy(on);
        }
        self.refresh_status();
    }

    fn selected_index(&self) -> Option<usize> {
        let st = self.st.borrow();
        let Some(Sel::Entry(k)) = &st.sel else { return None };
        st.scan.entries.iter().position(|e| &e.key == k)
    }

    fn show_detail(&self) {
        let Some(ui) = self.ui() else { return };
        let Some(i) = self.selected_index() else {
            ui.set_detail(DetailInfo::default());
            self.pairs.set_vec(Vec::new());
            return;
        };
        let st = self.st.borrow();
        let e = &st.scan.entries[i];
        let f = Facts::of(e, st.scan.sign[i].clone(), !e.anonymous() && st.baseline.is_new(&e.key, e.location));
        let now_ft = self.svc.pc.now();
        let (action, can, note) = if let Some(q) = st.queue.get(&e.key) {
            ("Take back".to_string(), !st.busy, format!("Queued: turns {} when the administrator changes are applied.", if q.on() == Some(true) { "on" } else { "off" }))
        } else {
            let want = e.switch.on().map(|o| !o).unwrap_or(false);
            match changes::route(e, &f, want, now_ft) {
                Route::Direct(_) => (if want { "Turn on" } else { "Turn off" }.to_string(), !st.busy, if e.location == Location::LogonTask { "Your own task: changed at once, no administrator rights needed.".into() } else { "Changed at once, the way Task Manager does it.".into() }),
                Route::Admin(..) => (if want { "Turn on…" } else { "Turn off…" }.to_string(), !st.busy, "Needs administrator rights: it is queued, and Apply asks once for all of its kind.".into()),
                Route::Not(w) => (String::new(), false, w),
            }
        };
        ui.set_detail(DetailInfo { shown: true, title: s(&e.name), r#where: s(e.location.label()), action: s(action), can_act: can, action_note: s(note) });
        let mut p: Vec<DetailPair> = Vec::new();
        let mut put = |k: &str, v: String, mono: bool, tone: i32| {
            if !v.is_empty() {
                p.push(DetailPair { key: s(k), value: s(v), mono, tone });
            }
        };
        if e.name.chars().count() > 40 {
            put("Name", e.name.clone(), false, 0);
        }
        put("Command", text::clean(&e.raw), true, 0);
        if e.expanded != e.raw {
            put("Expanded", text::clean(&e.expanded), true, 0);
        }
        if let Some(t) = &e.target {
            put("Target", text::clean(&t.to_string_lossy()), true, 0);
        }
        put("File", match &e.file {
            FileState::Present => "there".into(),
            FileState::Missing => "missing: its folder answers, the file is not there".into(),
            FileState::Unknown(w) => format!("unknown: {w}"),
            FileState::NoTarget => String::new(),
        }, false, if e.file == FileState::Missing { 3 } else { 0 });
        let sig = crate::report::signer_words(&f);
        let sig_tone = match f.sign.as_ref().map(|s| &s.signer) {
            Some(Signer::NotSigned) => 2,
            Some(Signer::Broken(_)) | Some(Signer::Missing) => 3,
            _ => 0,
        };
        put("Signer", sig, false, sig_tone);
        if let Some(c) = f.sign.as_ref().and_then(|s| s.company.clone()) {
            put("Says it is from", format!("{} (the file's own words, not checked)", text::clean(&c)), false, 0);
        }
        let mut flags: Vec<String> = Vec::new();
        if e.script {
            flags.push("runs a script or command".into());
        }
        if e.hidden {
            flags.push("hidden command (an encoded command or a hidden window)".into());
        }
        if f.inline {
            flags.push("a command written into the entry: the signer above is its interpreter's, not the command's".into());
        }
        if let Some(t) = f.launched() {
            flags.push(format!("{}: Microsoft's signature on its program says nothing about that", text::clean(t)));
        }
        if f.new {
            flags.push("new since the last look".into());
        }
        if let Some(u) = &e.unread {
            flags.push(u.clone());
        }
        put("Flags", flags.join("; "), false, if e.hidden || f.launched().is_some() { 2 } else { 0 });
        put("Location", format!("{} · {}", e.location.label(), text::clean(&e.place)), true, 0);
        put("When added", dates::added(&e.dates).map(|d| self.added_words(&d).2).unwrap_or_else(|| "not known".into()), false, 0);
        for d in &e.dates {
            let k = match d.kind {
                crate::autostart::DateKind::Disabled => "Switched off",
                crate::autostart::DateKind::Added => "Added",
                crate::autostart::DateKind::Registered => "Registered",
                crate::autostart::DateKind::TaskFile => "Task file created",
                crate::autostart::DateKind::ProgramCreated | crate::autostart::DateKind::BinaryCreated => "Program created",
                crate::autostart::DateKind::RunKeyChanged => "Run key changed",
                crate::autostart::DateKind::ServiceChanged => "Settings changed",
                crate::autostart::DateKind::Appeared => "First seen by VibeBoot",
                crate::autostart::DateKind::KnownSince => "Seen by VibeBoot since",
            };
            let extra = if d.kind == crate::autostart::DateKind::RunKeyChanged { " (shared by every value in the key)" } else { "" };
            put(k, format!("{}{extra}", dates::time_text(self.local(d.at))), true, 0);
        }
        if let Switch::Off { since: None } = e.switch
            && e.location.approved().is_some() {
                put("Switched off", "date not recorded by Windows".into(), false, 0);
            }
        put("Account", e.account.clone().map(|a| text::clean(&a)).unwrap_or_default(), false, 0);
        if let Some(t) = &e.task {
            put("Runs", t.when.clone(), false, 0);
            put("State", t.state.clone(), false, 0);
            put("Last run", t.last_run.map(|r| dates::time_text(self.local(r))).unwrap_or_else(|| "never".into()), true, 0);
            put("Last result", text::clean(&t.last_result), false, 0);
            put("Author", t.author.clone().unwrap_or_default(), false, 0);
            put("Run level", t.run_level.clone().unwrap_or_default(), false, 0);
        }
        if let Some(sv) = &e.service {
            put("Service name", text::clean(&sv.name), true, 0);
            put("Start type", switch::start_words(sv.start, sv.delayed).into(), false, 0);
            put("State", sv.state.clone(), false, 0);
        }
        put("Note", e.note.clone().map(|n| text::clean(&n)).unwrap_or_default(), false, 2);
        drop(st);
        self.pairs.set_vec(p);
    }

    // ---------- input ----------

    fn row_clicked(&self, n: i32) {
        let row = self.st.borrow().rows.get(n as usize).cloned();
        match row {
            Some(Row::Entry(i)) => {
                let k = self.st.borrow().scan.entries[i].key.clone();
                self.st.borrow_mut().sel = Some(Sel::Entry(k));
                self.rebuild();
            }
            Some(Row::Microsoft { group, .. }) => {
                self.st.borrow_mut().sel = Some(Sel::Fold(group));
                self.toggle_fold(group);
            }
            _ => {}
        }
    }

    fn toggle_fold(&self, g: Group) {
        {
            let mut st = self.st.borrow_mut();
            if !st.opened.remove(&g) {
                st.opened.insert(g);
            }
        }
        self.rebuild();
    }

    fn switch_clicked(&self, n: i32) {
        let row = self.st.borrow().rows.get(n as usize).cloned();
        if let Some(Row::Entry(i)) = row {
            let k = self.st.borrow().scan.entries[i].key.clone();
            self.st.borrow_mut().sel = Some(Sel::Entry(k.clone()));
            self.flip(&k);
        }
    }

    fn detail_act(&self) {
        let k = match &self.st.borrow().sel {
            Some(Sel::Entry(k)) => k.clone(),
            _ => return,
        };
        self.flip(&k);
    }

    /// Switch an entry: at once (HKCU, the user's own tasks), or into the admin queue; switching
    /// a queued one again takes it back out.
    pub fn flip(&self, key: &str) {
        if self.st.borrow().busy {
            return;
        }
        let route = {
            let st = self.st.borrow();
            let Some(i) = st.scan.entries.iter().position(|e| e.key == key) else { return };
            let e = &st.scan.entries[i];
            if st.queue.get(key).is_some() {
                None
            } else {
                let f = Facts::of(e, st.scan.sign[i].clone(), false);
                let want = e.switch.on().map(|o| !o).unwrap_or(false);
                Some((changes::route(e, &f, want, self.svc.pc.now()), e.name.clone(), changes::reading(e), e.service.as_ref().and_then(|s| s.was_delayed)))
            }
        };
        match route {
            None => {
                self.st.borrow_mut().queue.remove(key);
                self.rebuild();
            }
            Some((Route::Not(w), name, _, _)) => self.toast(&format!("{name}: {w}"), ToastKind::Info, None),
            Some((Route::Direct(req), name, Some(read), _)) => {
                let item = Item { key: key.to_string(), name, req, undo_of: None, read };
                self.run_batch(vec![item], Vec::new(), false, "Changing…");
            }
            Some((Route::Admin(job, mut req), name, Some(read), was_delayed)) => {
                // A service this app set to Manual goes back to exactly what the journal recorded
                // (delayed start included), not just "Automatic"; without the journal's record,
                // to what the helper's note in the service's key says (FS8).
                if let (Data::ServiceStart { start: 2, .. }, Some(back)) = (&req.new, self.st.borrow().journal.recorded_before(&self.st.borrow().guid, key, &req.old)) {
                    req.new = back;
                } else if let (Data::ServiceStart { start: 2, .. }, Some(delayed)) = (&req.new, was_delayed) {
                    req.new = Data::ServiceStart { start: 2, delayed };
                }
                self.st.borrow_mut().queue.toggle(Queued { key: key.to_string(), name, job, req, read });
                self.rebuild();
            }
            // `route` binds every change to the entry's reading: none without one.
            Some((_, _, None, _)) => {}
        }
    }

    fn ctx(&self) -> Ctx {
        let st = self.st.borrow();
        Ctx { pc: self.svc.pc.clone(), elevator: self.svc.elevator.clone(), journal: self.journal_store.clone(), guid: if st.guid.is_empty() { "unknown-pc".into() } else { st.guid.clone() }, session: self.session.clone(), now: self.svc.now.clone() }
    }

    fn run_batch(&self, direct: Vec<Item>, admin: Vec<(Job, Vec<Item>)>, from_queue: bool, words: &str) {
        if direct.is_empty() && admin.is_empty() {
            return;
        }
        let words = if admin.is_empty() { words.to_string() } else { format!("{words} Windows asks for administrator rights ({} prompt{})", admin.len(), if admin.len() == 1 { "" } else { "s" }) };
        self.st.borrow_mut().busy_keys = direct.iter().chain(admin.iter().flat_map(|(_, v)| v.iter())).map(|i| i.key.clone()).collect();
        self.set_busy(true, &words);
        self.rebuild();
        let ctx = self.ctx();
        let epoch = self.st.borrow().scan.epoch;
        let hwnd = (self.svc.hwnd)();
        self.bg(move || ctx.run(direct, admin, epoch, hwnd, from_queue));
    }

    fn apply(&self) {
        let jobs = self.st.borrow().queue.jobs();
        let admin: Vec<(Job, Vec<Item>)> = jobs.into_iter().map(|(j, qs)| (j, qs.into_iter().map(|q| Item { key: q.key, name: q.name, req: q.req, undo_of: None, read: q.read }).collect())).collect();
        self.run_batch(Vec::new(), admin, true, "Applying…");
    }

    fn discard(&self) {
        if self.st.borrow().busy {
            return;
        }
        self.st.borrow_mut().queue = Queue::default();
        self.rebuild();
    }

    /// A batch came back: the entries take their new data, the queue lets go of what was tried,
    /// the journal view is read again, and anything not done is said.
    fn changed(&self, done: Vec<Done>, errors: Vec<String>, declined: bool, from_queue: bool) {
        let mut not_done: Vec<String> = Vec::new();
        {
            let mut st = self.st.borrow_mut();
            for d in &done {
                match &d.status {
                    None => {} // never tried: a queued change stays queued
                    Some(status) => {
                        st.queue.remove(&d.item.key);
                        if *status == Status::Done {
                            if let Some(i) = st.scan.entries.iter().position(|e| e.key == d.item.key) {
                                let e = &mut st.scan.entries[i];
                                // Only where the scan read what the change found: a rescan
                                // meanwhile may have read the new data already.
                                if e.data.as_ref() == Some(&d.item.req.old) || e.data.as_ref() == Some(&d.item.req.new) {
                                    let (sw, data) = switch_from(e.location, &d.item.req.new);
                                    e.switch = sw;
                                    e.data = data;
                                    if let (Some(sv), Data::ServiceStart { start, delayed }) = (e.service.as_mut(), &d.item.req.new) {
                                        sv.start = *start;
                                        sv.delayed = *delayed;
                                    }
                                    if let (Some(t), Data::TaskEnabled(on)) = (e.task.as_mut(), &d.item.req.new) {
                                        t.enabled = *on;
                                    }
                                }
                            }
                        } else if let Status::Failed(w) = status {
                            // Failed halfway: the entry shows what is there now.
                            if let Some(live) = d.live.as_ref().filter(|l| **l != d.item.req.old)
                                && let Some(e) = st.scan.entries.iter_mut().find(|e| e.key == d.item.key && e.data.as_ref() == Some(&d.item.req.old))
                            {
                                let (sw, data) = switch_from(e.location, live);
                                e.switch = sw;
                                e.data = data;
                                if let (Some(sv), Data::ServiceStart { start, delayed }) = (e.service.as_mut(), live) {
                                    sv.start = *start;
                                    sv.delayed = *delayed;
                                }
                            }
                            not_done.push(format!("{}: {w}", d.item.name));
                        } else if let Status::Refused(w) = status {
                            not_done.push(format!("{}: {w}", d.item.name));
                        } else {
                            not_done.push(format!("{}: unknown whether it was made (the journal settles it at the next start)", d.item.name));
                        }
                    }
                }
            }
            st.busy = false;
            st.busy_words.clear();
            st.busy_keys.clear();
            st.journal = self.journal_store.current();
        }
        let _ = from_queue;
        for e in &errors {
            self.toast(e, if declined { ToastKind::Info } else { ToastKind::Error }, None);
        }
        if !not_done.is_empty() {
            let tried = done.iter().filter(|d| d.status.is_some()).count();
            let head = if tried == 1 { "The change was not made".to_string() } else { format!("{} of {tried} changes were not made", not_done.len()) };
            self.toast(&format!("{head}: {}", not_done.join("; ")), ToastKind::Error, None);
        }
        if self.st.borrow().read_only || self.journal_store.unwritten() > 0 {
            // Said once at start for a read-only stick; otherwise said here.
            if !self.st.borrow().read_only {
                self.toast("The journal could not be saved: it is kept in memory, and Undo works until VibeBoot closes.", ToastKind::Error, None);
            }
        }
        self.tell_garbled();
        self.set_busy(false, "");
        self.rebuild();
    }

    // ---------- the journal ----------

    fn open_journal(&self) {
        {
            let mut st = self.st.borrow_mut();
            st.journal = self.journal_store.current();
            st.journal_sel = None;
        }
        self.refresh_journal();
        if let Some(ui) = self.ui() {
            ui.set_journal_open(true);
        }
    }

    fn refresh_journal(&self) {
        let Some(ui) = self.ui() else { return };
        let st = self.st.borrow();
        let recs = st.journal.newest_first(&st.guid);
        let mut rows = Vec::with_capacity(recs.len());
        for r in &recs {
            let undone = st.journal.undone_by(&r.id).is_some();
            let (status, tone) = match (&r.status, undone) {
                (Status::Done, true) => ("undone".to_string(), 3),
                (Status::Done, false) => (if r.undo_of.is_some() { "done (an undo)".to_string() } else { "done".to_string() }, 0),
                (Status::Pending, _) => ("pending".to_string(), 1),
                (Status::Failed(w) | Status::Refused(w), _) => (format!("not done: {}", text::clean_max(w, 60)), 2),
            };
            // A done change with no Undo for a reason its status does not say (RB-5): said in the
            // row's change line and its accessibility text.
            let can = st.journal.can_undo(&r.id);
            let no_undo = match (&r.status, undone, &can) {
                (Status::Done, false, Err(why @ (journal::NoUndo::NoDefinition | journal::NoUndo::NoCore | journal::NoUndo::OldDefinition | journal::NoUndo::OffOnly | journal::NoUndo::UndoPending))) => Some(why.words()),
                _ => None,
            };
            let status = if no_undo.is_some() { "done (no Undo)".to_string() } else { status };
            let why = no_undo.map(|w| format!(" · no Undo: {w}")).unwrap_or_default();
            let what = format!("{} · {}", text::clean(&r.name), r.location.label());
            let change = format!("{} → {}{}{why}", r.old.short(), r.new.short(), r.settled.as_ref().map(|n| format!(" · {n}")).unwrap_or_default());
            let exact = format!("{} → {}{why}", r.old.words(), r.new.words());
            let when = dates::time_text(self.local(r.time));
            rows.push(JournalRow {
                id: s(&r.id),
                when: s(&when),
                what: s(&what),
                change: s(&change),
                status: s(&status),
                tone,
                can_undo: can.is_ok(),
                selected: st.journal_sel.as_deref() == Some(r.id.as_str()),
                a11y: s(format!("{when}, {status}, {exact}")),
            });
        }
        let sel_ok = st.journal_sel.as_deref().is_some_and(|id| st.journal.can_undo(id).is_ok());
        let any_session = recs.iter().any(|r| r.session == self.session && st.journal.can_undo(&r.id).is_ok());
        let note = if recs.is_empty() {
            "Every change VibeBoot makes on this PC is written here first, with what was there before.".to_string()
        } else {
            format!("{} change{} on this PC, newest first. Undo puts back what was there, only while the entry still holds what VibeBoot wrote.", recs.len(), if recs.len() == 1 { "" } else { "s" })
        };
        drop(st);
        self.jrows.set_vec(rows);
        ui.set_journal_note(s(note));
        ui.set_journal_can_undo(sel_ok);
        ui.set_journal_can_undo_all(any_session);
    }

    fn journal_picked(&self, id: &str) {
        self.st.borrow_mut().journal_sel = Some(id.to_string());
        self.refresh_journal();
    }

    /// Up/Down/Home/End/PageUp/PageDown in the journal's list pick a change, as a click does
    /// (X15A11Y-2: Undo of one change was the mouse's alone). The row picked, for the list to
    /// bring into view; -1 for a key it does not use.
    pub fn journal_key(&self, t: &str) -> i32 {
        use slint::platform::Key;
        let k = |key: Key| t == SharedString::from(key).as_str();
        let ids: Vec<String> = {
            let st = self.st.borrow();
            st.journal.newest_first(&st.guid).iter().map(|r| r.id.clone()).collect()
        };
        if ids.is_empty() {
            return -1;
        }
        let last = ids.len() - 1;
        let at = self.st.borrow().journal_sel.as_ref().and_then(|s| ids.iter().position(|id| id == s));
        let to = if k(Key::DownArrow) {
            at.map_or(0, |a| (a + 1).min(last))
        } else if k(Key::UpArrow) {
            at.map_or(0, |a| a.saturating_sub(1))
        } else if k(Key::Home) {
            0
        } else if k(Key::End) {
            last
        } else if k(Key::PageDown) {
            at.map_or(0, |a| (a + 7).min(last))
        } else if k(Key::PageUp) {
            at.map_or(0, |a| a.saturating_sub(7))
        } else {
            return -1;
        };
        self.journal_picked(&ids[to]);
        to as i32
    }

    /// The items that undo `ids` (records this PC can undo), routed: direct or by admin job.
    fn undo_items(&self, ids: &[String]) -> (Vec<Item>, Vec<(Job, Vec<Item>)>) {
        let st = self.st.borrow();
        let mut direct = Vec::new();
        let mut admin: Vec<(Job, Vec<Item>)> = Vec::new();
        for id in ids {
            let Ok(req) = st.journal.undo_request(id) else { continue };
            let Some(r) = st.journal.get(id) else { continue };
            // An Undo's own record is never undone: it keeps the change's bindings as they were.
            let read = crate::autostart::def::Fresh { def: r.def.unwrap_or(req.def), core: r.core.unwrap_or(req.def), off_only: None };
            let item = Item { key: r.key.clone(), name: r.name.clone(), req: req.clone(), undo_of: Some(id.clone()), read };
            let own_task = st.scan.entries.iter().find(|e| e.key == r.key).and_then(|e| e.task.as_ref()).is_some_and(|t| t.own);
            match req.location {
                Location::RunUser | Location::StartupUser => direct.push(item),
                Location::LogonTask if own_task => direct.push(item),
                loc => {
                    // A task's Undo is the helper's `task-undo` (RB7-1: `switch::undo`).
                    if let Some(job) = Job::for_undo(loc) {
                        match admin.iter_mut().find(|(j, v)| *j == job && v.len() < crate::helper::MAX_ITEMS) {
                            Some((_, v)) => v.push(item),
                            None => admin.push((job, vec![item])),
                        }
                    }
                }
            }
        }
        admin.sort_by_key(|(j, _)| match j {
            Job::StartupSet => 0,
            Job::TaskSet | Job::TaskUndo => 1,
            Job::ServiceStart => 2,
            Job::ScanTasks => 3,
        });
        (direct, admin)
    }

    fn journal_undo(&self) {
        let Some(id) = self.st.borrow().journal_sel.clone() else { return };
        if self.st.borrow().busy {
            return;
        }
        let (direct, admin) = self.undo_items(&[id]);
        self.run_batch(direct, admin, false, "Undoing…");
    }

    fn journal_undo_all(&self) {
        if self.st.borrow().busy {
            return;
        }
        let ids: Vec<String> = {
            let st = self.st.borrow();
            st.journal.newest_first(&st.guid).into_iter().filter(|r| r.session == self.session && st.journal.can_undo(&r.id).is_ok()).map(|r| r.id.clone()).collect()
        };
        let (direct, admin) = self.undo_items(&ids);
        self.run_batch(direct, admin, false, "Undoing this session's changes…");
    }

    // ---------- filters ----------

    fn filter_toggled(&self, i: i32) {
        let f = {
            let mut st = self.st.borrow_mut();
            match i {
                0 => st.filters.recent = !st.filters.recent,
                1 => st.filters.new_only = !st.filters.new_only,
                2 => {
                    st.filters.not_ms = !st.filters.not_ms;
                    st.opened.clear();
                }
                _ => return,
            }
            st.filters.clone()
        };
        if let Some(ui) = self.ui() {
            ui.set_f_recent(f.recent);
            ui.set_f_new(f.new_only);
            ui.set_f_not_ms(f.not_ms);
        }
        self.save_prefs(move |p| {
            p.recent = f.recent;
            p.new_only = f.new_only;
            p.not_ms = Some(f.not_ms);
        });
        self.rebuild();
    }

    fn filter_edited(&self, t: &str) {
        self.st.borrow_mut().filters.text = t.to_string();
        self.rebuild();
    }

    /// Escape in the filter: clears it (and goes no further); empty, it passes on.
    fn filter_escaped(&self) -> bool {
        if self.st.borrow().filters.text.is_empty() {
            return false;
        }
        self.st.borrow_mut().filters.text.clear();
        if let Some(ui) = self.ui() {
            ui.set_f_text(s(""));
        }
        self.rebuild();
        true
    }

    // ---------- keys ----------

    /// Up/Down/Home/End move the pick among entries and folds, Space or Enter switch the picked
    /// entry (or open its fold), F5 scans, Ctrl+F goes to the filter.
    pub fn key(&self, t: &str, ctrl: bool, _shift: bool) -> bool {
        use slint::platform::Key;
        let k = |key: Key| t == SharedString::from(key).as_str();
        if k(Key::F5) {
            if self.st.borrow().busy {
                // Not in silence: the scan follows as soon as the change on its way is done.
                self.st.borrow_mut().rescan = true;
                self.toast("Scanning… as soon as the change on its way is done.", ToastKind::Info, None);
            } else {
                self.scan();
            }
            return true;
        }
        if ctrl && (t == "f" || t == "F") {
            if let Some(ui) = self.ui() {
                ui.invoke_focus_filter();
            }
            return true;
        }
        let pickable: Vec<usize> = self.st.borrow().rows.iter().enumerate().filter(|(_, r)| !matches!(r, Row::Head { .. })).map(|(n, _)| n).collect();
        if pickable.is_empty() {
            return false;
        }
        let cur = {
            let st = self.st.borrow();
            st.rows.iter().position(|r| match (r, &st.sel) {
                (Row::Entry(i), Some(Sel::Entry(key))) => st.scan.entries[*i].key == *key,
                (Row::Microsoft { group, .. }, Some(Sel::Fold(g))) => group == g,
                _ => false,
            })
        };
        let at = cur.and_then(|c| pickable.iter().position(|&p| p == c));
        let target = if k(Key::DownArrow) {
            Some(at.map_or(0, |a| (a + 1).min(pickable.len() - 1)))
        } else if k(Key::UpArrow) {
            Some(at.map_or(0, |a| a.saturating_sub(1)))
        } else if k(Key::Home) {
            Some(0)
        } else if k(Key::End) {
            Some(pickable.len() - 1)
        } else if k(Key::PageDown) {
            Some(at.map_or(0, |a| (a + 10).min(pickable.len() - 1)))
        } else if k(Key::PageUp) {
            Some(at.map_or(0, |a| a.saturating_sub(10)))
        } else {
            None
        };
        if let Some(tgt) = target {
            let n = pickable[tgt];
            let row = self.st.borrow().rows[n].clone();
            let sel = match row {
                Row::Entry(i) => Sel::Entry(self.st.borrow().scan.entries[i].key.clone()),
                Row::Microsoft { group, .. } => Sel::Fold(group),
                Row::Head { .. } => return true,
            };
            self.st.borrow_mut().sel = Some(sel);
            self.rebuild();
            self.scroll_to(n);
            return true;
        }
        if t == " " || k(Key::Return) {
            let sel = self.st.borrow().sel.clone();
            match sel {
                Some(Sel::Entry(key)) => self.flip(&key),
                Some(Sel::Fold(g)) => self.toggle_fold(g),
                None => return false,
            }
            return true;
        }
        false
    }

    fn scroll_to(&self, n: usize) {
        let Some(ui) = self.ui() else { return };
        ui.set_scroll_to(n as i32);
        self.scroll_seq.set(self.scroll_seq.get() + 1);
        ui.set_scroll_seq(self.scroll_seq.get());
    }

    // ---------- the report ----------

    pub fn report(&self) -> String {
        let st = self.st.borrow();
        let facts = Self::facts(&st);
        let scanned = st.scan.finished.map(|t| dates::time_text(self.local(t))).unwrap_or_else(|| "(not finished)".into());
        let summary = groups::summary(&groups::counts(&st.scan.entries, &facts));
        let failed: Vec<String> = st.scan.failed.iter().map(|(l, w)| format!("{}: {w}", l.label())).collect();
        let mut notes = Vec::new();
        notes.push(match (st.scan.full, st.hidden_tasks) {
            (true, Some(h)) => format!("Scheduled tasks: every task read with administrator rights ({h} hidden from this account)."),
            (false, Some(h)) if h > 0 => format!("Scheduled tasks: {h} hidden from this account were not read (Full scan reads them)."),
            _ => "Scheduled tasks: as this account sees them.".into(),
        });
        if let Some(t) = st.baseline.last_look {
            notes.push(format!("New means not there at the last look at this PC ({}).", dates::day_text(self.local(t))));
        }
        let head = crate::report::Head { scanned: &scanned, summary: &summary, failed, notes };
        let offset = self.svc.offset.clone();
        crate::report::build(&head, &st.scan.entries, &facts, &move |t| offset(t))
    }

    fn copy_report(&self) -> bool {
        if self.st.borrow().scan.finished.is_none() {
            return false;
        }
        let r = self.report();
        let ok = (self.svc.copy)(&r);
        if !ok {
            self.toast("The report could not be copied (the clipboard is busy).", ToastKind::Error, None);
        }
        ok
    }

    fn save_report(&self) {
        if self.st.borrow().scan.finished.is_none() {
            return;
        }
        let day = dates::day_text(self.local(self.now())).split('.').rev().collect::<Vec<_>>().join("-");
        let Some(path) = (self.svc.save_dialog)(&format!("VibeBoot report {day}.txt")) else { return };
        let body = crate::host::clipboard_text(&self.report());
        self.bg(move || Msg::Saved(crate::prefs::write_atomic(&path, body.as_bytes()).map(|_| path).map_err(|e| text::clean(&e.to_string()))));
    }

    // ---------- toasts ----------

    /// A toast, bottom right: errors stay 10 s, the rest 5 s. With `reveal` it offers "Show".
    pub fn toast(&self, text: &str, kind: ToastKind, reveal: Option<PathBuf>) {
        let id = {
            let mut st = self.st.borrow_mut();
            st.toast_seq += 1;
            let id = st.toast_seq;
            if let Some(p) = reveal.clone() {
                st.toast_paths.insert(id, p);
            }
            id
        };
        while self.toasts.row_count() >= 3 {
            let old = self.toasts.row_data(0).map(|t| t.id).unwrap_or(0);
            self.drop_toast(old);
        }
        self.toasts.push(ToastItem { id, text: s(crate::autostart::text::clean_max(text, 600)), kind, action: if reveal.is_some() { s("Show") } else { s("") } });
        self.arm_toast(id, if kind == ToastKind::Error { 10_000 } else { 5_000 });
    }

    fn dialog_open(&self) -> bool {
        self.ui().is_some_and(|ui| ui.get_about_open() || ui.get_journal_open())
    }

    fn arm_toast(&self, id: i32, ms: u64) {
        let generation = {
            let mut st = self.st.borrow_mut();
            let t = st.toast_time.entry(id).or_insert((0, ms));
            t.0 += 1;
            t.0
        };
        let w = self.me.borrow().clone();
        Timer::single_shot(Duration::from_millis(ms), move || {
            let Some(a) = w.upgrade() else { return };
            let current = a.st.borrow().toast_time.get(&id).is_some_and(|t| t.0 == generation);
            if current && !a.dialog_open() {
                a.drop_toast(id);
            }
        });
    }

    fn dialogs_closed(&self) {
        let all: Vec<(i32, u64)> = self.st.borrow().toast_time.iter().map(|(id, t)| (*id, t.1)).collect();
        for (id, ms) in all {
            self.arm_toast(id, ms);
        }
    }

    fn drop_toast(&self, id: i32) {
        if let Some(i) = self.toasts.iter().position(|t| t.id == id) {
            self.toasts.remove(i);
        }
        self.st.borrow_mut().toast_time.remove(&id);
        self.st.borrow_mut().toast_paths.remove(&id);
    }

    fn toast_action(&self, id: i32) {
        let p = self.st.borrow().toast_paths.get(&id).cloned();
        if let Some(p) = p {
            (self.svc.reveal)(&p);
        }
        self.drop_toast(id);
    }

    // ---------- for tests ----------

    /// The entries as the window has them now.
    pub fn entries(&self) -> Vec<Entry> {
        self.st.borrow().scan.entries.clone()
    }

    /// The admin queue's keys.
    pub fn queued(&self) -> Vec<String> {
        self.st.borrow().queue.items.iter().map(|q| q.key.clone()).collect()
    }

    pub fn journal(&self) -> Journal {
        self.journal_store.current()
    }

    pub fn session(&self) -> String {
        self.session.clone()
    }

    /// Pick an entry by its key (as a click on its row does).
    pub fn pick(&self, key: &str) {
        self.st.borrow_mut().sel = Some(Sel::Entry(key.to_string()));
        self.rebuild();
    }
}

/// An entry's switch from its data after a change.
fn switch_from(loc: Location, d: &Data) -> (Switch, Option<Data>) {
    match d {
        Data::Approved(v) => run::switch_of(loc, v.as_ref().map(|b| (approved::REG_BINARY, b.clone())).as_ref()),
        Data::TaskEnabled(on) => (if *on { Switch::On } else { Switch::Off { since: None } }, Some(d.clone())),
        Data::ServiceStart { start, .. } => (if *start == 2 { Switch::On } else { Switch::Off { since: None } }, Some(d.clone())),
    }
}
