//! Services and drivers: the service manager's list (`EnumServicesStatusExW`, Win32 services and
//! drivers, every state), each one's configuration (`QueryServiceConfigW`: start type, binary
//! path, account; `QueryServiceConfig2W`: delayed automatic start), and which file each runs:
//! a svchost-hosted service's `Parameters\ServiceDll` (or the service key's own `ServiceDll`);
//! a driver's `\SystemRoot\...`, `System32\drivers\...` and `\??\C:\...` paths resolved.

use super::cmdline::{self, Command};
use super::pc::{Pc, Service};
use super::{Hive, text};
use std::path::PathBuf;

pub const SERVICES_KEY: &str = r"SYSTEM\CurrentControlSet\Services";

/// What a service runs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Target {
    pub expanded: String,
    pub cmd: Command,
    /// The file it is about: the service's exe, its ServiceDll, the driver's .sys.
    pub target: Option<PathBuf>,
    pub note: Option<String>,
    /// What its program is handed from outside Windows' own folders (`cmdline::through`).
    pub through: Option<String>,
}

impl Target {
    /// Its program's signature says nothing about what it runs (`Entry::borrowed`).
    pub fn borrowed(&self) -> bool {
        self.through.is_some() || cmdline::inline(self.cmd.script, self.target.as_deref())
    }
}

/// The Windows folder (`%SystemRoot%`).
fn windir(pc: &dyn Pc) -> String {
    pc.env("SystemRoot").unwrap_or_else(|| r"C:\Windows".into())
}

/// A driver's image path as a file: `\SystemRoot\x` and `%SystemRoot%\x` under the Windows
/// folder, `\??\C:\x` and `\\?\C:\x` as `C:\x`, a relative `System32\drivers\x.sys` under the
/// Windows folder, and an empty path as `System32\drivers\<name>.sys` (Windows' default).
pub fn driver_path(pc: &dyn Pc, name: &str, image: &str) -> PathBuf {
    let image = cmdline::expand(image.trim(), &|v| pc.env(v));
    let image = image.trim().trim_matches('"');
    let win = windir(pc);
    let lower = image.to_ascii_lowercase();
    if image.is_empty() {
        return PathBuf::from(format!(r"{win}\System32\drivers\{name}.sys"));
    }
    if lower.starts_with(r"\systemroot\") {
        return PathBuf::from(format!(r"{win}\{}", &image[r"\systemroot\".len()..]));
    }
    if let Some(rest) = image.strip_prefix(r"\??\").or_else(|| image.strip_prefix(r"\\?\")) {
        return PathBuf::from(rest);
    }
    let b = image.as_bytes();
    let absolute = (b.len() >= 3 && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')) || image.starts_with(r"\\");
    if absolute {
        PathBuf::from(image)
    } else {
        PathBuf::from(format!(r"{win}\{}", image.trim_start_matches('\\')))
    }
}

/// What a service or driver runs (None only for a service whose path cannot be told at all).
pub fn target(pc: &dyn Pc, s: &Service) -> Option<Target> {
    if s.driver() {
        let p = driver_path(pc, &s.name, &s.binary);
        return Some(Target { expanded: p.to_string_lossy().into_owned(), cmd: Command { program: Some(p.clone()), target: Some(p.clone()), ..Command::default() }, target: Some(p), note: None, through: None });
    }
    let raw = s.binary.trim();
    if raw.is_empty() {
        return Some(Target { note: Some("no program path in its settings".into()), ..Target::default() });
    }
    // Services may start with \SystemRoot\ or \??\ too (drivers' forms).
    let mut expanded = cmdline::expand(raw, &|v| pc.env(v));
    let lower = expanded.to_ascii_lowercase();
    if lower.starts_with(r"\systemroot\") {
        expanded = format!(r"{}\{}", windir(pc), &expanded[r"\systemroot\".len()..]);
    } else if let Some(rest) = expanded.strip_prefix(r"\??\") {
        expanded = rest.to_string();
    }
    let sys = pc.sys_dirs();
    let cmd = cmdline::resolve(&expanded, &sys, &|p| pc.exists(p));
    let through = super::run::through_of(pc, &cmd);
    let mut t = Target { expanded, target: cmd.target.clone(), note: cmd.note.map(str::to_string), through, cmd };
    if hosted(&t) {
        match service_dll(pc, &s.name) {
            Some(dll) => t.target = Some(dll),
            None => t.note = Some("hosted by svchost, but its settings name no ServiceDll".into()),
        }
    }
    Some(t)
}

/// Its program is svchost: what runs is its `ServiceDll`.
pub fn hosted(t: &Target) -> bool {
    t.cmd.program.as_ref().and_then(|p| p.file_name()).is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("svchost.exe") || n.to_string_lossy().eq_ignore_ascii_case("svchost"))
}

/// A svchost service's DLL: `Parameters\ServiceDll`, else the service key's `ServiceDll`.
pub fn service_dll(pc: &dyn Pc, name: &str) -> Option<PathBuf> {
    let dll: Vec<u16> = "ServiceDll".encode_utf16().collect();
    for key in [format!(r"{SERVICES_KEY}\{name}\Parameters"), format!(r"{SERVICES_KEY}\{name}")] {
        if let Ok(Some((kind, data))) = pc.reg_value(Hive::Machine, &key, &dll)
            && let Some(s) = super::pc::reg_text(kind, &data) {
                let s = cmdline::expand(s.trim(), &|v| pc.env(v));
                let s = s.trim().trim_matches('"');
                if !s.is_empty() {
                    return Some(PathBuf::from(s));
                }
            }
    }
    None
}

/// FS8: the note VibeBoot's helper keeps in a service's own key when it switches it to Manual:
/// what it was (Automatic, delayed or not). It lives with the service, machine-wide, written
/// where only administrators can write and read by anyone who can read the service: the list
/// shows the service, switchable back on, whatever became of the journal (a read-only stick, a
/// garbled or capped journal, another account, another copy of the app). Written before the
/// switch (no note, no switch), cleared once it is switched back on.
pub const OFF_NOTE: &str = "VibeBootSwitchedOff";

/// The note's bytes: `VB`, version 1, the start type it had (2, Automatic), its delayed flag.
pub fn off_note(start: u32, delayed: bool) -> [u8; 5] {
    [b'V', b'B', 1, start.min(255) as u8, u8::from(delayed)]
}

fn note_name() -> Vec<u16> {
    OFF_NOTE.encode_utf16().collect()
}

/// The service's note, if VibeBoot switched it to Manual from Automatic: its delayed flag then.
/// Anything else (no note, a cleared one, another shape) is None.
pub fn switched_off_note(pc: &dyn Pc, name: &str) -> Option<bool> {
    match pc.reg_value(Hive::Machine, &format!(r"{SERVICES_KEY}\{name}"), &note_name()) {
        Ok(Some((super::approved::REG_BINARY, b))) if b.len() == 5 && b[..3] == [b'V', b'B', 1] && b[3] == 2 && b[4] <= 1 => Some(b[4] == 1),
        _ => None,
    }
}

/// Keep the note before a switch to Manual (`old`: what it is now). Err: not kept, in words.
pub fn keep_off_note(pc: &dyn Pc, name: &str, start: u32, delayed: bool) -> Result<(), String> {
    pc.reg_set_binary(Hive::Machine, &format!(r"{SERVICES_KEY}\{name}"), &note_name(), &off_note(start, delayed))
}

/// Clear the note once the service is switched back on (empty: no note); only where there is one.
pub fn clear_off_note(pc: &dyn Pc, name: &str) {
    let path = format!(r"{SERVICES_KEY}\{name}");
    if matches!(pc.reg_value(Hive::Machine, &path, &note_name()), Ok(Some((_, b))) if !b.is_empty()) {
        let _ = pc.reg_set_binary(Hive::Machine, &path, &note_name(), &[]);
    }
}

/// Windows' own services, by key name (Windows 10 and 11, every edition's usual set; per-user
/// services by their template name). A service on this list is Windows' even when its program
/// file is gone, so VibeBoot never switches it: a missing file there is a damaged Windows, not
/// a leftover. Read from a Windows 11 26200 PC's service list (the services Windows itself
/// hosts) plus the ones that live outside the Windows folder (Defender) or come with optional
/// features.
pub const WINDOWS_SERVICES: &[&str] = &[
    "AarSvc", "ADPSvc", "AJRouter", "ALG", "AppIDSvc", "Appinfo", "AppMgmt", "AppReadiness", "AppVClient", "AppXSvc", "ApxSvc", "AssignedAccessManagerSvc", "AudioEndpointBuilder", "Audiosrv", "autotimesvc", "AxInstSV",
    "BcastDVRUserService", "BDESVC", "BFE", "BITS", "BluetoothUserService", "BrokerInfrastructure", "BTAGService", "BthAvctpSvc", "BthHFSrv", "bthserv",
    "camsvc", "CaptureService", "cbdhsvc", "CDPSvc", "CDPUserSvc", "CertPropSvc", "ClipSVC", "CloudBackupRestoreSvc", "cloudidsvc", "CmService", "COMSysApp", "ConsentUxUserSvc", "CoreMessagingRegistrar", "CredentialEnrollmentManagerUserSvc", "CryptSvc", "CscService",
    "DcomLaunch", "dcsvc", "defragsvc", "DeviceAssociationBrokerSvc", "DeviceAssociationService", "DeviceInstall", "DevicePickerUserSvc", "DevicesFlowUserSvc", "DevQueryBroker", "Dhcp", "diagnosticshub.standardcollector.service", "diagsvc", "DiagTrack", "DialogBlockingService", "DispBrokerDesktopSvc", "DisplayEnhancementService", "DmEnrollmentSvc", "dmwappushservice", "Dnscache", "DoSvc", "dot3svc", "DPS", "DsmSvc", "DsSvc", "DusmSvc",
    "EapHost", "EFS", "embeddedmode", "EntAppSvc", "EventLog", "EventSystem",
    "Fax", "fdPHost", "FDResPub", "fhsvc", "FontCache", "FontCache3.0.0.0", "FrameServer", "FrameServerMonitor",
    "GameInputSvc", "gcs", "GraphicsPerfSvc", "gpsvc",
    "hidserv", "hns", "hpatchmon", "HvHost",
    "icssvc", "IKEEXT", "InstallService", "InventorySvc", "iphlpsvc", "IpxlatCfgSvc", "IsoEnvBroker",
    "KeyIso", "KtmRm",
    "LanmanServer", "LanmanWorkstation", "lfsvc", "LicenseManager", "lltdsvc", "lmhosts", "LocalKdc", "LSM", "LxpSvc", "LxssManager",
    "MapsBroker", "McmSvc", "McpManagementService", "MDCoreSvc", "MessagingService", "midisrv", "MixedRealityOpenXRSvc", "mpssvc", "MSDTC", "MSiSCSI", "msiserver", "MsKeyboardFilter",
    "NaturalAuthentication", "NcaSvc", "NcbService", "NcdAutoSetup", "Netlogon", "Netman", "netprofm", "NetSetupSvc", "NetTcpPortSharing", "NgcCtnrSvc", "NgcSvc", "NlaSvc", "NPSMSvc", "nsi", "nvagent",
    "OneSyncSvc",
    "P9RdrService", "p2pimsvc", "p2psvc", "PcaSvc", "PeerDistSvc", "PenService", "perceptionsimulation", "PerfHost", "PhoneSvc", "PimIndexMaintenanceSvc", "pla", "PlugPlay", "PNRPAutoReg", "PNRPsvc", "PolicyAgent", "Power", "PrintDeviceConfigurationService", "PrintNotify", "PrintScanBrokerService", "PrintWorkflowUserSvc", "ProfSvc", "PushToInstall",
    "QWAVE",
    "RasAuto", "RasMan", "refsdedupsvc", "RemoteAccess", "RemoteRegistry", "RetailDemo", "RmSvc", "RpcEptMapper", "RpcLocator", "RpcSs",
    "SamSs", "SCardSvr", "ScDeviceEnum", "Schedule", "SCPolicySvc", "SDRSVC", "seclogon", "SecurityHealthService", "SEMgrSvc", "SENS", "Sense", "SensorDataService", "SensorService", "SensrSvc", "SessionEnv", "SgrmBroker", "SharedAccess", "SharedRealitySvc", "ShellHWDetection", "shpamsvc", "smphost", "SmsRouter", "SNMPTrap", "spectrum", "Spooler", "sppsvc", "SSDPSRV", "ssh-agent", "sshd", "SstpSvc", "StateRepository", "StiSvc", "StorSvc", "svsvc", "swprv", "SysMain", "SystemEventsBroker",
    "TabletInputService", "TapiSrv", "TermService", "TextInputManagementService", "Themes", "TieringEngineService", "TimeBroker", "TimeBrokerSvc", "TokenBroker", "TrkWks", "TroubleshootingSvc", "TrustedInstaller", "tzautoupdate",
    "UdkUserSvc", "UevAgentService", "uhssvc", "UmRdpService", "UnistoreSvc", "upnphost", "UserDataSvc", "UserManager", "UsoSvc",
    "VacSvc", "VaultSvc", "vds", "vmcompute", "vmicguestinterface", "vmicheartbeat", "vmickvpexchange", "vmicrdv", "vmicshutdown", "vmictimesync", "vmicvmsession", "vmicvss", "vmms", "VSS",
    "W32Time", "WaaSMedicSvc", "WalletService", "WarpJITSvc", "wbengine", "WbioSrvc", "Wcmsvc", "wcncsvc", "WdiServiceHost", "WdiSystemHost", "WdNisSvc", "WebClient", "webthreatdefsvc", "webthreatdefusersvc", "Wecsvc", "WEPHOSTSVC", "wercplsupport", "WerSvc", "WFDSConMgrSvc", "whesvc", "WiaRpc", "WinDefend", "WinHttpAutoProxySvc", "Winmgmt", "WinRM", "wisvc", "WlanSvc", "wlidsvc", "wlpasvc", "WManSvc", "wmiApSrv", "WMIRegistrationService", "WMPNetworkSvc", "workfolderssvc", "WpcMonSvc", "WPDBusEnum", "WpnService", "WpnUserService", "WSAIFabricSvc", "wscsvc", "WSearch", "WSService", "wuauserv", "wudfsvc", "wuqisvc", "WwanSvc",
    "XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc",
    "ZTHELPER",
];

/// Whether a service is one of Windows' own (`WINDOWS_SERVICES`), by its key name; a per-user
/// service's instance (`CDPUserSvc_880ea`) by its template's name.
pub fn windows_own(name: &str) -> bool {
    let base = match name.rsplit_once('_') {
        Some((b, suffix)) if !b.is_empty() && !suffix.is_empty() && suffix.bytes().all(|c| c.is_ascii_hexdigit()) => b,
        _ => name,
    };
    WINDOWS_SERVICES.iter().any(|w| w.eq_ignore_ascii_case(name) || w.eq_ignore_ascii_case(base))
}

/// A service's state in words.
pub fn state_words(state: u32) -> &'static str {
    match state {
        1 => "stopped",
        2 => "starting",
        3 => "stopping",
        4 => "running",
        5 => "resuming",
        6 => "pausing",
        7 => "paused",
        _ => "unknown",
    }
}

/// The service's shown name: its display name, else its key name (cleaned).
pub fn shown_name(s: &Service) -> String {
    let d = text::clean(&s.display);
    if d.is_empty() { text::clean(&s.name) } else { d }
}

// ---------- the real service manager ----------

#[cfg(windows)]
pub mod sys {
    use super::super::pc::Service;
    use super::super::text;
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_SERVICE_DOES_NOT_EXIST, GetLastError};
    use windows_sys::Win32::System::Services::*;

    /// A service manager or service handle, closed once.
    struct H(SC_HANDLE);
    impl Drop for H {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: opened by OpenSCManagerW / OpenServiceW, closed once.
                unsafe { CloseServiceHandle(self.0) };
            }
        }
    }

    fn last() -> String {
        // SAFETY: reads the calling thread's last error.
        text::os_words(unsafe { GetLastError() })
    }

    fn manager(access: u32) -> Result<H, String> {
        // SAFETY: the local machine's active database.
        let h = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), access) };
        if h.is_null() { Err(format!("the service manager could not be opened ({})", last())) } else { Ok(H(h)) }
    }

    unsafe fn wstr(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        // SAFETY: a NUL-terminated string inside a buffer the service manager filled.
        unsafe {
            let n = (0..).take_while(|&i| *p.add(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
        }
    }

    /// One service's configuration, by an open handle.
    fn config(h: &H, name: &str, display: &str, state: u32) -> Result<Service, String> {
        let mut need = 0u32;
        // SAFETY: a size query first.
        unsafe { QueryServiceConfigW(h.0, std::ptr::null_mut(), 0, &mut need) };
        // SAFETY: reads the last error right after the call.
        if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || need == 0 || need > 64 * 1024 {
            return Err(last());
        }
        let mut buf = vec![0u64; (need as usize).div_ceil(8)];
        // SAFETY: a buffer of `need` bytes, aligned for the struct.
        if unsafe { QueryServiceConfigW(h.0, buf.as_mut_ptr().cast(), need, &mut need) } == 0 {
            return Err(last());
        }
        // SAFETY: the buffer holds a QUERY_SERVICE_CONFIGW written by the call above.
        let c = unsafe { &*(buf.as_ptr() as *const QUERY_SERVICE_CONFIGW) };
        let mut delayed = SERVICE_DELAYED_AUTO_START_INFO { fDelayedAutostart: 0 };
        let mut n = 0u32;
        // SAFETY: a fixed-size struct of its own size.
        let ok = unsafe { QueryServiceConfig2W(h.0, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, (&mut delayed as *mut SERVICE_DELAYED_AUTO_START_INFO).cast(), size_of::<SERVICE_DELAYED_AUTO_START_INFO>() as u32, &mut n) } != 0;
        Ok(Service {
            name: name.to_string(),
            display: if display.is_empty() { unsafe { wstr(c.lpDisplayName) } } else { display.to_string() },
            kind: c.dwServiceType,
            start: c.dwStartType,
            delayed: ok && delayed.fDelayedAutostart != 0,
            // SAFETY: strings inside the buffer above.
            binary: unsafe { wstr(c.lpBinaryPathName) },
            account: unsafe { wstr(c.lpServiceStartName) },
            state,
        })
    }

    /// Every Win32 service and driver, in every state. Services whose configuration could not be
    /// read are named in the second list (never silently left out).
    pub fn all() -> Result<super::super::pc::ServiceList, String> {
        let scm = manager(SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE)?;
        let mut out = Vec::new();
        let mut failed = Vec::new();
        let mut resume = 0u32;
        // At most 256 KB per call: a bigger buffer is refused (RPC_X_BAD_STUB_DATA, measured on
        // 26200); the resume handle carries on.
        let mut buf = vec![0u64; 32 * 1024];
        loop {
            let mut need = 0u32;
            let mut count = 0u32;
            // SAFETY: a buffer and its size in bytes; the resume handle carries on a long list.
            let ok = unsafe { EnumServicesStatusExW(scm.0, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut need, &mut count, &mut resume, std::ptr::null()) } != 0;
            // SAFETY: the last error of the call above.
            let err = unsafe { GetLastError() };
            if !ok && err != ERROR_MORE_DATA {
                return Err(format!("the service list could not be read ({})", text::os_words(err)));
            }
            // SAFETY: the call wrote `count` records at the start of the buffer.
            let recs = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW, count as usize) };
            for r in recs {
                // SAFETY: strings inside the buffer.
                let (name, display) = unsafe { (wstr(r.lpServiceName), wstr(r.lpDisplayName)) };
                let state = r.ServiceStatusProcess.dwCurrentState;
                let w = text::wide(&name);
                // SAFETY: a NUL-terminated name; query access only.
                let h = H(unsafe { OpenServiceW(scm.0, w.as_ptr(), SERVICE_QUERY_CONFIG) });
                if h.0.is_null() {
                    failed.push((name, last()));
                    continue;
                }
                match config(&h, &name, &display, state) {
                    Ok(s) => out.push(s),
                    Err(e) => failed.push((name, e)),
                }
            }
            if ok {
                break;
            }
            if count == 0 && need as usize > buf.len() * 8 {
                return Err("the service list could not be read (one entry larger than 256 KB)".into());
            }
        }
        Ok((out, failed))
    }

    /// One service by its key name; None when it does not exist.
    pub fn one(name: &str) -> Result<Option<Service>, String> {
        let scm = manager(SC_MANAGER_CONNECT)?;
        let w = text::wide(name);
        // SAFETY: a NUL-terminated name; query access only.
        let h = H(unsafe { OpenServiceW(scm.0, w.as_ptr(), SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS) });
        if h.0.is_null() {
            // SAFETY: the last error of OpenServiceW.
            let e = unsafe { GetLastError() };
            return if e == ERROR_SERVICE_DOES_NOT_EXIST { Ok(None) } else { Err(text::os_words(e)) };
        }
        let mut st: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        // SAFETY: a status struct for an open handle.
        let state = if unsafe { QueryServiceStatus(h.0, &mut st) } != 0 { st.dwCurrentState } else { 0 };
        config(&h, name, "", state).map(Some)
    }

    /// Set a service's start type and delayed flag (needs admin: the helper).
    pub fn set_start(name: &str, start: u32, delayed: bool) -> Result<(), String> {
        let scm = manager(SC_MANAGER_CONNECT)?;
        let w = text::wide(name);
        // SAFETY: a NUL-terminated name.
        let h = H(unsafe { OpenServiceW(scm.0, w.as_ptr(), SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG) });
        if h.0.is_null() {
            return Err(last());
        }
        // SAFETY: only the start type changes; every other setting is SERVICE_NO_CHANGE / null.
        let ok = unsafe { ChangeServiceConfigW(h.0, SERVICE_NO_CHANGE, start, SERVICE_NO_CHANGE, std::ptr::null(), std::ptr::null(), std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(), std::ptr::null()) } != 0;
        if !ok {
            return Err(last());
        }
        let mut info = SERVICE_DELAYED_AUTO_START_INFO { fDelayedAutostart: i32::from(delayed) };
        // SAFETY: the delayed-start struct for an open handle.
        if unsafe { ChangeServiceConfig2W(h.0, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, (&mut info as *mut SERVICE_DELAYED_AUTO_START_INFO).cast()) } == 0 {
            return Err(last());
        }
        Ok(())
    }
}
