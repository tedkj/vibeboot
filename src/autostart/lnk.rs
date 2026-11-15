//! A startup-folder shortcut, read through `IShellLinkW`: `IPersistFile::Load` read-only,
//! `GetPath` with `SLGP_RAWPATH` (variables left for `cmdline::expand`), `GetArguments`. Never
//! `Resolve` (it searches the disk, may wait on a share and can change the shortcut).

use super::pc::Lnk;
use std::path::Path;

#[cfg(windows)]
pub fn read(path: &Path) -> Result<Lnk, String> {
    use std::ffi::c_void;
    use windows_sys::Win32::System::Com::{CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoCreateInstance, CoInitializeEx, CoUninitialize, STGM_READ};
    use windows_sys::Win32::UI::Shell::SLGP_RAWPATH;
    use windows_sys::core::{GUID, HRESULT};

    const CLSID_SHELL_LINK: GUID = GUID::from_u128(0x00021401_0000_0000_c000_000000000046);
    const IID_ISHELL_LINK_W: GUID = GUID::from_u128(0x000214f9_0000_0000_c000_000000000046);
    const IID_IPERSIST_FILE: GUID = GUID::from_u128(0x0000010b_0000_0000_c000_000000000046);
    // IUnknown 0..2; IShellLinkW: GetPath 3, GetArguments 10; IPersistFile: Load 5.
    const QUERY_INTERFACE: usize = 0;
    const RELEASE: usize = 2;
    const GET_PATH: usize = 3;
    const GET_ARGUMENTS: usize = 10;
    const LOAD: usize = 5;

    struct Obj(*mut c_void);
    impl Obj {
        unsafe fn f(&self, n: usize) -> *const c_void {
            // SAFETY: a live COM object starts with its vtable pointer.
            unsafe { *(*(self.0 as *const *const *const c_void)).add(n) }
        }
    }
    impl Drop for Obj {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: IUnknown::Release.
                unsafe {
                    let f: extern "system" fn(*mut c_void) -> u32 = std::mem::transmute(self.f(RELEASE));
                    f(self.0);
                }
            }
        }
    }
    struct Com(bool);
    impl Drop for Com {
        fn drop(&mut self) {
            if self.0 {
                // SAFETY: balanced with this thread's successful CoInitializeEx.
                unsafe { CoUninitialize() };
            }
        }
    }
    let err = |what: &str, hr: HRESULT| format!("{what} ({})", super::text::os_words(hr as u32));

    // SAFETY: COM for this thread while `_com` lives.
    let _com = Com(unsafe { CoInitializeEx(std::ptr::null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32) } >= 0);
    let mut p: *mut c_void = std::ptr::null_mut();
    // SAFETY: an out pointer for the interface asked for.
    let hr = unsafe { CoCreateInstance(&CLSID_SHELL_LINK, std::ptr::null_mut(), CLSCTX_INPROC_SERVER, &IID_ISHELL_LINK_W, &mut p) };
    if hr < 0 {
        return Err(err("the shortcut reader is not available", hr));
    }
    let link = Obj(p);
    let mut pf: *mut c_void = std::ptr::null_mut();
    // SAFETY: IUnknown::QueryInterface for IPersistFile.
    let hr = unsafe {
        let f: extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT = std::mem::transmute(link.f(QUERY_INTERFACE));
        f(link.0, &IID_IPERSIST_FILE, &mut pf)
    };
    if hr < 0 {
        return Err(err("the shortcut reader is not available", hr));
    }
    let file = Obj(pf);
    let w = super::text::nul(&{
        use std::os::windows::ffi::OsStrExt;
        path.as_os_str().encode_wide().collect::<Vec<u16>>()
    });
    // SAFETY: IPersistFile::Load(LPCOLESTR, DWORD), read only.
    let hr = unsafe {
        let f: extern "system" fn(*mut c_void, *const u16, u32) -> HRESULT = std::mem::transmute(file.f(LOAD));
        f(file.0, w.as_ptr(), STGM_READ)
    };
    if hr < 0 {
        return Err(err("not a shortcut Windows can read", hr));
    }
    let mut buf = vec![0u16; 32_768];
    // SAFETY: IShellLinkW::GetPath(LPWSTR, int, WIN32_FIND_DATAW*, DWORD) with no find data.
    let hr = unsafe {
        let f: extern "system" fn(*mut c_void, *mut u16, i32, *mut c_void, u32) -> HRESULT = std::mem::transmute(link.f(GET_PATH));
        f(link.0, buf.as_mut_ptr(), buf.len() as i32, std::ptr::null_mut(), SLGP_RAWPATH as u32)
    };
    let path_text = if hr >= 0 {
        let n = buf.iter().position(|&u| u == 0).unwrap_or(0);
        String::from_utf16_lossy(&buf[..n])
    } else {
        String::new()
    };
    let mut abuf = vec![0u16; 32_768];
    // SAFETY: IShellLinkW::GetArguments(LPWSTR, int).
    let hr = unsafe {
        let f: extern "system" fn(*mut c_void, *mut u16, i32) -> HRESULT = std::mem::transmute(link.f(GET_ARGUMENTS));
        f(link.0, abuf.as_mut_ptr(), abuf.len() as i32)
    };
    let args = if hr >= 0 {
        let n = abuf.iter().position(|&u| u == 0).unwrap_or(0);
        String::from_utf16_lossy(&abuf[..n])
    } else {
        String::new()
    };
    Ok(Lnk { path: path_text, args })
}
