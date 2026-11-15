//! Who signed a target file (VibeVerify's `authenticode.rs`, cut down to what the scanner says):
//! `WinVerifyTrust` with the generic Authenticode policy, no UI, revocation from the cache only
//! (no network), and Windows' own files through the system catalogs. The signer's name and its
//! chain's root sort it: **Microsoft** ("Microsoft Windows", "Microsoft Windows Publisher",
//! "Microsoft Corporation", on a chain that ends at one of Microsoft's own roots; "Microsoft
//! Windows Hardware Compatibility Publisher" signs other makers' drivers and is not Microsoft),
//! **signed by <name>**, **not signed**, **signature broken**, **file missing** (NotFound with
//! the nearest folder above it answering, the scan's own rule), **unknown** (anything else). The
//! version resource's CompanyName comes along ("says it is from", unverified).
//!
//! The answer is for the file the handle opened: its identity, size and last write come from the
//! same handle (the cache's key), so a file replaced between check and key is never cached under
//! the new one's key. Blocking (a catalog lookup hashes the file): call it from a worker.

use super::{FileKey, SignInfo, Signer};

/// The signer names that are Microsoft's own.
pub const MICROSOFT: [&str; 3] = ["Microsoft Windows", "Microsoft Windows Publisher", "Microsoft Corporation"];

/// Microsoft's own roots that sign code (SHA-1 thumbprints, as this PC's Root store lists them,
/// 2026-10-22): Root Certificate Authority 2010 (Windows), 2011 (Microsoft Corporation), the
/// 2001 Root Certificate Authority and the 1997 Root Authority (old catalogs), ECC Product Root
/// 2018, RSA Root 2017 and Identity Verification Root 2020. The time-stamping roots and the old
/// Authenticode root (other makers' code) are not among them.
pub const MICROSOFT_ROOTS: [&str; 7] = [
    "3B1EFD3A66EA28B16697394703A72CA340A05BD5",
    "8F43288AD272F3103B6FB1428485EA3014C0BCFE",
    "CDD4EEAE6000AC7F40C3802C171E30148030C072",
    "A43489159A520F0D93D032CCAF37E7FE20A8B419",
    "06F1AA330B927B753A40E68CDF22E34BCBEF3352",
    "73A5E64A3BFF8316FF0EDCCC618A906E4EAE4D74",
    "F40042E2E5F7E8EF8189FED15519AECE42C3BFA2",
];

/// Whether a root certificate (its SHA-1 thumbprint) is one of Microsoft's own.
pub fn microsoft_root(thumbprint: &[u8]) -> bool {
    let hex: String = thumbprint.iter().map(|b| format!("{b:02X}")).collect();
    MICROSOFT_ROOTS.contains(&hex.as_str())
}

/// A trusted signer's name as a kind: Microsoft only when the name is Microsoft's and the chain
/// ends at a Microsoft root (a certificate named "Microsoft Corporation" from a company CA or a
/// test root an installer left is someone else's).
pub fn kind_of(name: &str, ms_root: bool) -> Signer {
    let n = name.trim();
    if MICROSOFT.iter().any(|m| m.eq_ignore_ascii_case(n)) {
        if ms_root { Signer::Microsoft } else { Signer::SignedBy(format!("{n} (not under a Microsoft root)")) }
    } else {
        Signer::SignedBy(n.to_string())
    }
}

// WinVerifyTrust's answers (HRESULTs as u32).
const TRUST_E_NOSIGNATURE: u32 = 0x800B_0100;
const TRUST_E_SUBJECT_FORM_UNKNOWN: u32 = 0x800B_0003;
const TRUST_E_PROVIDER_UNKNOWN: u32 = 0x800B_0001;
const TRUST_E_BAD_DIGEST: u32 = 0x8009_6010;
const TRUST_E_EXPLICIT_DISTRUST: u32 = 0x800B_0111;
const CERT_E_EXPIRED: u32 = 0x800B_0101;
const CERT_E_UNTRUSTEDROOT: u32 = 0x800B_0109;
const CERT_E_CHAINING: u32 = 0x800B_010A;
const CERT_E_REVOKED: u32 = 0x800B_010C;
const CERT_E_UNTRUSTEDTESTROOT: u32 = 0x800B_010D;
const CRYPT_E_FILE_ERROR: u32 = 0x8009_2003;
const CRYPT_E_NO_REVOCATION_CHECK: u32 = 0x8009_2012;
const CRYPT_E_REVOCATION_OFFLINE: u32 = 0x8009_2013;
const CRYPT_E_REVOKED: u32 = 0x8009_2010;

/// A WinVerifyTrust answer as a kind (`ms_root`: the chain ends at a Microsoft root). Pure, so
/// every code is tested.
pub fn classify(code: u32, signer: Option<String>, ms_root: bool) -> Signer {
    let name = || signer.clone().unwrap_or_else(|| "an unnamed publisher".into());
    match code {
        0 | CRYPT_E_NO_REVOCATION_CHECK | CRYPT_E_REVOCATION_OFFLINE => kind_of(&name(), ms_root),
        TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN => Signer::NotSigned,
        TRUST_E_BAD_DIGEST => Signer::Broken("the file was changed after it was signed".into()),
        TRUST_E_EXPLICIT_DISTRUST => Signer::Broken("the certificate is blocked on this PC".into()),
        CERT_E_REVOKED | CRYPT_E_REVOKED => Signer::Broken("the certificate was revoked".into()),
        CERT_E_EXPIRED => Signer::Broken("the certificate expired and the signature has no timestamp".into()),
        CERT_E_UNTRUSTEDROOT | CERT_E_UNTRUSTEDTESTROOT | CERT_E_CHAINING => Signer::Broken(format!("Windows does not trust the certificate{}", signer.as_ref().map(|s| format!(" ({s})")).unwrap_or_default())),
        CRYPT_E_FILE_ERROR => Signer::Unknown("Windows could not read the file to check it".into()),
        other => Signer::Broken(format!("Windows refused it (0x{other:08X})")),
    }
}

/// The signer of `path`, and the identity of the file that answer is for.
#[cfg(windows)]
pub fn check(path: &std::path::Path) -> (SignInfo, Option<FileKey>) {
    use std::os::windows::fs::OpenOptionsExt;
    let company = sys::company(path);
    let file = match std::fs::OpenOptions::new().read(true).share_mode(7).open(path) {
        Ok(f) => f,
        // The scan's own rule: missing when the nearest folder above it that exists answers (an
        // uninstalled program's whole folder gone is still "missing").
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let s = match super::sys::absent(path) {
                super::FileState::Missing => Signer::Missing,
                super::FileState::Unknown(w) => Signer::Unknown(w),
                _ => Signer::Unknown("its folder could not be read".into()),
            };
            return (SignInfo { signer: s, company }, None);
        }
        Err(e) => return (SignInfo { signer: Signer::Unknown(super::text::clean(&e.to_string())), company }, None),
    };
    if file.metadata().map(|m| m.is_dir()).unwrap_or(false) {
        return (SignInfo { signer: Signer::Unknown("a folder, not a file".into()), company }, None);
    }
    let signer = sys::verify(path, &file);
    let key = super::sys::file_key(&file);
    (SignInfo { signer, company }, key)
}

/// How many bytes of a value `VerQueryValueW` points at (`at`, `len` bytes) lie inside the
/// version buffer it was asked of (`buf` bytes from `start`): never a read past it, whatever
/// the resource says (IN-VibeBoot-5). 0 when it points outside.
pub fn within(start: usize, buf: usize, at: usize, len: usize) -> usize {
    match at.checked_sub(start) {
        Some(off) if off < buf => len.min(buf - off),
        _ => 0,
    }
}

/// The UTF-16 units `VerQueryValueW` points at (`p`, `n` bytes), read only as far as they lie
/// inside the version buffer `buf` it was asked of (IN-VibeBoot-5). Read out of `buf`'s bytes,
/// never as a `&[u16]` carved from it: a `Vec<u8>` promises no 2-byte alignment, so such a
/// slice would be undefined behaviour at an odd address (FA10).
pub fn units(buf: &[u8], p: *const u8, n: usize) -> Vec<u16> {
    let bytes = within(buf.as_ptr() as usize, buf.len(), p as usize, n);
    if bytes == 0 {
        return Vec::new();
    }
    // `within` gave bytes > 0, so `p` lies in `buf` and the `bytes` from it too.
    let off = p as usize - buf.as_ptr() as usize;
    buf[off..off + bytes].as_chunks::<2>().0.iter().map(|&b| u16::from_le_bytes(b)).collect()
}

/// The Translation list `VerQueryValueW` points at (`p`, `n` bytes) as (language, code page)
/// pairs, read only as far as it lies inside the version buffer `buf` it was asked of
/// (IN-VibeBoot-5; `sys::company`'s own call, tested on its own since RIN1-14).
pub fn translations(buf: &[u8], p: *const u8, n: usize) -> Vec<(u16, u16)> {
    units(buf, p, n).as_chunks::<2>().0.iter().map(|c| (c[0], c[1])).collect()
}

#[cfg(windows)]
mod sys {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    /// The signer's display name from a verified trust state, and whether its chain ends at one
    /// of Microsoft's roots.
    unsafe fn signer_name(state: windows_sys::Win32::Foundation::HANDLE) -> (Option<String>, bool) {
        use windows_sys::Win32::Security::Cryptography::{CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_SHA1_HASH_PROP_ID, CertGetCertificateContextProperty, CertGetNameStringW};
        use windows_sys::Win32::Security::WinTrust::{WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData};
        // SAFETY: pointers from WinVerifyTrust's own state, checked for null at each step.
        unsafe {
            if state.is_null() {
                return (None, false);
            }
            let prov = WTHelperProvDataFromStateData(state);
            if prov.is_null() {
                return (None, false);
            }
            let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
            if sgnr.is_null() || (*sgnr).csCertChain == 0 || (*sgnr).pasCertChain.is_null() {
                return (None, false);
            }
            // The root: the chain's last certificate, by its SHA-1 thumbprint.
            let root = WTHelperGetProvCertFromChain(sgnr, (*sgnr).csCertChain - 1);
            let ms_root = !root.is_null() && !(*root).pCert.is_null() && {
                let mut thumb = [0u8; 20];
                let mut len = thumb.len() as u32;
                CertGetCertificateContextProperty((*root).pCert, CERT_SHA1_HASH_PROP_ID, thumb.as_mut_ptr().cast(), &mut len) != 0 && len == 20 && super::microsoft_root(&thumb)
            };
            let cert = (*(*sgnr).pasCertChain).pCert;
            if cert.is_null() {
                return (None, ms_root);
            }
            let mut buf = [0u16; 512];
            let n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, std::ptr::null(), buf.as_mut_ptr(), buf.len() as u32);
            if n <= 1 {
                return (None, ms_root);
            }
            let s = super::super::text::clean_max(&String::from_utf16_lossy(&buf[..n as usize - 1]), 120);
            ((!s.is_empty()).then_some(s), ms_root)
        }
    }

    /// One WinVerifyTrust call (verify, read the signer and its root, close).
    unsafe fn trust(mut data: windows_sys::Win32::Security::WinTrust::WINTRUST_DATA) -> (u32, Option<String>, bool) {
        use windows_sys::Win32::Security::WinTrust::*;
        // SAFETY: a filled WINTRUST_DATA whose union points at live structs; closed after.
        unsafe {
            data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
            data.dwUIChoice = WTD_UI_NONE;
            data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
            data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
            data.dwStateAction = WTD_STATEACTION_VERIFY;
            let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            let code = WinVerifyTrust(std::ptr::null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast()) as u32;
            let (signer, ms_root) = signer_name(data.hWVTStateData);
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(std::ptr::null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast());
            (code, signer, ms_root)
        }
    }

    fn is_pe(file: &std::fs::File) -> bool {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = file;
        let mut b = [0u8; 2];
        let ok = f.seek(SeekFrom::Start(0)).is_ok() && f.read_exact(&mut b).is_ok() && &b == b"MZ";
        let _ = f.seek(SeekFrom::Start(0));
        ok
    }

    /// The catalog check for a file that carries no signature of its own.
    unsafe fn catalog(path: &Path, file: &std::fs::File) -> Option<(u32, Option<String>, bool)> {
        use windows_sys::Win32::Security::Cryptography::Catalog::*;
        use windows_sys::Win32::Security::WinTrust::*;
        let handle = file.as_raw_handle();
        for alg in [windows_sys::core::w!("SHA256"), windows_sys::core::w!("SHA1")] {
            // SAFETY: catalog admin calls with buffers of the sizes they report; every context
            // acquired here is released here.
            unsafe {
                let mut admin: isize = 0;
                if CryptCATAdminAcquireContext2(&mut admin, std::ptr::null(), alg, std::ptr::null(), 0) == 0 {
                    continue;
                }
                let mut len = 0u32;
                CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut len, std::ptr::null_mut(), 0);
                let mut hash = vec![0u8; len as usize];
                if len == 0 || len > 1024 || CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut len, hash.as_mut_ptr(), 0) == 0 {
                    CryptCATAdminReleaseContext(admin, 0);
                    continue;
                }
                let info = CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), len, 0, std::ptr::null_mut());
                if info == 0 {
                    CryptCATAdminReleaseContext(admin, 0);
                    continue;
                }
                let mut ci = CATALOG_INFO { cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32, wszCatalogFile: [0; 260] };
                let result = if CryptCATCatalogInfoFromContext(info, &mut ci, 0) != 0 {
                    let tag: Vec<u16> = hash.iter().map(|b| format!("{b:02X}")).collect::<String>().encode_utf16().chain(std::iter::once(0)).collect();
                    let member: Vec<u16> = {
                        use std::os::windows::ffi::OsStrExt;
                        path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
                    };
                    let mut cat = WINTRUST_CATALOG_INFO {
                        cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                        pcwszCatalogFilePath: ci.wszCatalogFile.as_ptr(),
                        pcwszMemberTag: tag.as_ptr(),
                        pcwszMemberFilePath: member.as_ptr(),
                        hMemberFile: handle,
                        pbCalculatedFileHash: hash.as_mut_ptr(),
                        cbCalculatedFileHash: len,
                        hCatAdmin: admin,
                        ..Default::default()
                    };
                    let mut data = WINTRUST_DATA { dwUnionChoice: WTD_CHOICE_CATALOG, ..Default::default() };
                    data.Anonymous.pCatalog = &mut cat;
                    Some(trust(data))
                } else {
                    None
                };
                CryptCATAdminReleaseCatalogContext(admin, info, 0);
                CryptCATAdminReleaseContext(admin, 0);
                if result.is_some() {
                    return result;
                }
            }
        }
        None
    }

    pub fn verify(path: &Path, file: &std::fs::File) -> Signer {
        use windows_sys::Win32::Security::WinTrust::*;
        let wide: Vec<u16> = {
            use std::os::windows::ffi::OsStrExt;
            path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
        };
        let mut info = WINTRUST_FILE_INFO { cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32, pcwszFilePath: wide.as_ptr(), hFile: file.as_raw_handle(), pgKnownSubject: std::ptr::null_mut() };
        let mut data = WINTRUST_DATA { dwUnionChoice: WTD_CHOICE_FILE, ..Default::default() };
        data.Anonymous.pFile = &mut info;
        // SAFETY: `info` and `wide` outlive the call.
        let (code, signer, ms_root) = unsafe { trust(data) };
        if code == TRUST_E_NOSIGNATURE && is_pe(file) {
            // SAFETY: the open file's handle and path.
            if let Some((c, s, r)) = unsafe { catalog(path, file) } {
                return classify(c, s, r);
            }
        }
        classify(code, signer, ms_root)
    }

    /// The version resource's CompanyName (first language listed), cleaned; None without one.
    pub fn company(path: &Path) -> Option<String> {
        use windows_sys::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
        let wide: Vec<u16> = {
            use std::os::windows::ffi::OsStrExt;
            path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
        };
        let mut h = 0u32;
        // SAFETY: a NUL-terminated path.
        let size = unsafe { GetFileVersionInfoSizeW(wide.as_ptr(), &mut h) } as usize;
        if size == 0 || size > 4 * 1024 * 1024 {
            return None;
        }
        let mut buf = vec![0u8; size];
        // SAFETY: a buffer of the size asked for.
        if unsafe { GetFileVersionInfoW(wide.as_ptr(), 0, size as u32, buf.as_mut_ptr().cast()) } == 0 {
            return None;
        }
        let mut p: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut n = 0u32;
        let tr = super::super::text::wide(r"\VarFileInfo\Translation");
        // SAFETY: a version block of `size` bytes and a NUL-terminated query; what comes back is
        // read out of `buf`'s bytes only (`units`).
        let langs: Vec<(u16, u16)> = unsafe {
            if VerQueryValueW(buf.as_ptr().cast(), tr.as_ptr(), &mut p, &mut n) != 0 && !p.is_null() && n >= 4 {
                // Clamped to `buf`, as CompanyName is below.
                translations(&buf, p as *const u8, n as usize)
            } else {
                Vec::new()
            }
        };
        for (lang, cp) in langs.iter().copied().chain([(0x0409, 0x04B0), (0x0409, 0x04E4), (0, 0x04B0)]) {
            let q = super::super::text::wide(&format!(r"\StringFileInfo\{lang:04x}{cp:04x}\CompanyName"));
            // SAFETY: as above.
            unsafe {
                if VerQueryValueW(buf.as_ptr().cast(), q.as_ptr(), &mut p, &mut n) != 0 && !p.is_null() && n > 0 {
                    let s = units(&buf, p as *const u8, (n as usize).saturating_mul(2));
                    let end = s.iter().position(|&u| u == 0).unwrap_or(s.len());
                    let t = super::super::text::clean_max(&String::from_utf16_lossy(&s[..end]), 120);
                    if !t.is_empty() {
                        return Some(t);
                    }
                }
            }
        }
        None
    }
}
