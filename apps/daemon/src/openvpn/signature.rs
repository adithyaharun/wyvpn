use std::path::Path;

use sha2::{Digest, Sha256};

use super::binary::Check;

#[cfg(target_os = "macos")]
fn team_id() -> Option<&'static str> {
    option_env!("WYVPN_TEAM_ID").filter(|team| !team.is_empty())
}

#[cfg(target_os = "macos")]
pub fn signed_build() -> bool {
    team_id().is_some()
}

#[cfg(not(target_os = "macos"))]
pub fn signed_build() -> bool {
    false
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn pin_decision(pin: &str, actual_hex: &str) -> Check {
    if pin.len() != 64 || !pin.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Check::Fail("the compiled-in OpenVPN checksum is malformed".to_owned());
    }
    if pin.eq_ignore_ascii_case(actual_hex) {
        Check::Pass
    } else {
        Check::Fail("checksum does not match the pinned OpenVPN build".to_owned())
    }
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn verify_pin(path: &Path, pin: &str) -> Check {
    match std::fs::read(path) {
        Ok(bytes) => pin_decision(pin, &trust::hex(&Sha256::digest(bytes))),
        Err(err) => Check::Fail(format!("cannot read the binary to checksum it: {err}")),
    }
}

#[cfg(target_os = "macos")]
pub fn verify(path: &Path) -> Check {
    match (
        team_id(),
        option_env!("WYVPN_OPENVPN_SHA256").filter(|pin| !pin.is_empty()),
    ) {
        (Some(team), _) => macos::verify(path, team, macos::OPENVPN_IDENTIFIER),
        (None, Some(pin)) => verify_pin(path, pin),
        (None, None) => Check::Skip("no signing team id or checksum compiled in".to_owned()),
    }
}

#[cfg(target_os = "macos")]
pub fn verify_hook(path: &Path) -> Check {
    match team_id() {
        Some(team) => macos::verify(path, team, macos::DAEMON_IDENTIFIER),
        None => Check::Skip("no signing team id compiled in".to_owned()),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn verify_hook(_path: &Path) -> Check {
    Check::Skip("the hook is not signature-checked on this platform".to_owned())
}

#[cfg(windows)]
pub fn verify(path: &Path) -> Check {
    windows::verify(
        path,
        option_env!("WYVPN_PUBLISHER").filter(|name| !name.is_empty()),
    )
}

#[cfg(windows)]
pub use windows::{LoadError, WintunModule, load_wintun};

#[cfg(not(any(target_os = "macos", windows)))]
pub fn verify(_path: &Path) -> Check {
    Check::Skip("bundled binaries are not used on this platform".to_owned())
}

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
mod trust {
    pub const CERT_E_REVOCATION_FAILURE: i32 = 0x800B_010E_u32 as i32;
    pub const CRYPT_E_REVOCATION_OFFLINE: i32 = 0x8009_2013_u32 as i32;
    pub const CRYPT_E_NO_REVOCATION_CHECK: i32 = 0x8009_2012_u32 as i32;
    pub const CRYPT_E_NO_REVOCATION_DLL: i32 = 0x8009_2011_u32 as i32;

    #[derive(Debug, PartialEq, Eq)]
    pub enum Verdict {
        Trusted,
        RevocationUnknown,
        Rejected,
    }

    pub fn classify(status: i32) -> Verdict {
        match status {
            0 => Verdict::Trusted,
            CERT_E_REVOCATION_FAILURE
            | CRYPT_E_REVOCATION_OFFLINE
            | CRYPT_E_NO_REVOCATION_CHECK
            | CRYPT_E_NO_REVOCATION_DLL => Verdict::RevocationUnknown,
            _ => Verdict::Rejected,
        }
    }

    const CERT_TRUST_REVOCATION_STATUS_UNKNOWN: u32 = 0x40;
    const CERT_TRUST_IS_OFFLINE_REVOCATION: u32 = 0x0100_0000;

    pub fn revocation_gap_only(status: i32, chain_errors: u32, signer_error: u32) -> bool {
        chain_errors & !(CERT_TRUST_REVOCATION_STATUS_UNKNOWN | CERT_TRUST_IS_OFFLINE_REVOCATION)
            == 0
            && (signer_error == 0 || signer_error as i32 == status)
    }

    pub struct SignerPin {
        pub publisher: &'static str,
        pub issuer: &'static str,
        pub issuer_sha256: &'static [&'static str],
    }

    pub const WINTUN: SignerPin = SignerPin {
        publisher: "WireGuard LLC",
        issuer: "DigiCert EV Code Signing CA (SHA2)",
        issuer_sha256: &["c7460b0edda1b44c8e2164b234ebecc3962a6a37a936b74a6e7d46682938f084"],
    };

    pub fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn check_signer(
        pin: &SignerPin,
        subject: &str,
        issuer: Option<&str>,
        issuer_sha256: Option<&str>,
    ) -> Result<(), String> {
        if subject != pin.publisher {
            return Err(format!("untrusted publisher \"{subject}\""));
        }
        let issuer = issuer.ok_or("cannot read the issuing certificate")?;
        if issuer != pin.issuer {
            return Err(format!("untrusted issuer \"{issuer}\""));
        }
        let thumbprint = issuer_sha256.ok_or("cannot hash the issuing certificate")?;
        if !pin
            .issuer_sha256
            .iter()
            .any(|pinned| pinned.eq_ignore_ascii_case(thumbprint))
        {
            return Err("the issuing certificate is not pinned".to_owned());
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const CA: &str = "C7460B0EDDA1B44C8E2164B234EBECC3962A6A37A936B74A6E7D46682938F084";

        #[test]
        fn classify_separates_revocation_outcomes() {
            assert_eq!(classify(0), Verdict::Trusted);
            for status in [
                CERT_E_REVOCATION_FAILURE,
                CRYPT_E_REVOCATION_OFFLINE,
                CRYPT_E_NO_REVOCATION_CHECK,
                CRYPT_E_NO_REVOCATION_DLL,
            ] {
                assert_eq!(classify(status), Verdict::RevocationUnknown);
            }
            for status in [
                0x800B_010C_u32 as i32,
                0x8009_2010_u32 as i32,
                0x800B_0109_u32 as i32,
                0x8009_6010_u32 as i32,
                0x800B_0100_u32 as i32,
                1,
            ] {
                assert_eq!(classify(status), Verdict::Rejected);
            }
        }

        #[test]
        fn revocation_gap_tolerates_only_revocation_bits() {
            let status = CRYPT_E_REVOCATION_OFFLINE;
            assert!(revocation_gap_only(status, 0, 0));
            assert!(revocation_gap_only(status, 0x40 | 0x0100_0000, 0));
            assert!(revocation_gap_only(status, 0x40, status as u32));
            assert!(!revocation_gap_only(status, 0x40 | 0x1, 0));
            assert!(!revocation_gap_only(status, 0x20, 0));
            assert!(!revocation_gap_only(status, 0x40, 0x800B_0109));
        }

        #[test]
        fn pinned_thumbprints_are_well_formed() {
            for pin in WINTUN.issuer_sha256 {
                assert_eq!(pin.len(), 64);
                assert!(pin.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
            }
        }

        #[test]
        fn signer_must_match_publisher_issuer_and_thumbprint() {
            let ok = check_signer(
                &WINTUN,
                "WireGuard LLC",
                Some("DigiCert EV Code Signing CA (SHA2)"),
                Some(CA),
            );
            assert_eq!(ok, Ok(()));
            let wrong_publisher =
                check_signer(&WINTUN, "OpenVPN Inc.", Some(WINTUN.issuer), Some(CA));
            assert!(wrong_publisher.unwrap_err().contains("publisher"));
            let wrong_issuer = check_signer(&WINTUN, WINTUN.publisher, Some("Other CA"), Some(CA));
            assert!(wrong_issuer.unwrap_err().contains("issuer"));
            let wrong_hash = check_signer(
                &WINTUN,
                WINTUN.publisher,
                Some(WINTUN.issuer),
                Some(&"0".repeat(64)),
            );
            assert!(wrong_hash.unwrap_err().contains("not pinned"));
        }

        #[test]
        fn missing_chain_data_is_rejected() {
            assert!(check_signer(&WINTUN, WINTUN.publisher, None, None).is_err());
            assert!(check_signer(&WINTUN, WINTUN.publisher, Some(WINTUN.issuer), None).is_err());
        }

        #[test]
        fn hex_is_lowercase_and_padded() {
            assert_eq!(hex(&[0x00, 0xab, 0x0f]), "00ab0f");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";

    #[test]
    fn pin_decision_matches_case_insensitively() {
        assert_eq!(pin_decision(PIN, PIN), Check::Pass);
        assert_eq!(pin_decision(&PIN.to_uppercase(), PIN), Check::Pass);
        assert!(
            matches!(pin_decision(PIN, &"0".repeat(64)), Check::Fail(r) if r.contains("checksum"))
        );
    }

    #[test]
    fn pin_decision_rejects_malformed_pins() {
        for bad in ["", "abc", &"g".repeat(64), &PIN[..63], &format!("{PIN}0")] {
            assert!(matches!(pin_decision(bad, bad), Check::Fail(r) if r.contains("malformed")));
        }
    }

    #[test]
    fn verify_pin_hashes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("bin");
        std::fs::write(&file, b"hello").unwrap();
        let sum = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert_eq!(verify_pin(&file, sum), Check::Pass);
        assert!(matches!(verify_pin(&file, PIN), Check::Fail(_)));
        assert!(matches!(
            verify_pin(&dir.path().join("nope"), sum),
            Check::Fail(_)
        ));
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{CString, c_void};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;

    use core_foundation_sys::base::{CFRelease, CFTypeRef, kCFAllocatorDefault};
    use core_foundation_sys::string::{CFStringCreateWithCString, kCFStringEncodingUTF8};
    use core_foundation_sys::url::CFURLCreateFromFileSystemRepresentation;
    use security_framework_sys::code_signing::{
        SecRequirementCreateWithString, SecRequirementRef, SecStaticCodeCheckValidity,
        SecStaticCodeCreateWithPath, SecStaticCodeRef, kSecCSCheckAllArchitectures,
        kSecCSStrictValidate,
    };

    use super::Check;

    struct Owned(*mut c_void);

    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CFRelease(self.0 as CFTypeRef) };
            }
        }
    }

    pub const OPENVPN_IDENTIFIER: &str = "com.aprdth.wyvpn.openvpn";
    pub const DAEMON_IDENTIFIER: &str = "com.aprdth.wyvpn.daemon";

    pub fn requirement_text(team: &str, identifier: &str) -> Option<String> {
        if team.is_empty() || !team.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return None;
        }
        Some(format!(
            "identifier \"{identifier}\" and anchor apple generic and certificate leaf[subject.OU] = \"{team}\""
        ))
    }

    pub fn verify(path: &Path, team: &str, identifier: &str) -> Check {
        let Some(text) = requirement_text(team, identifier) else {
            return Check::Fail("invalid team id".to_owned());
        };
        let text = CString::new(text).expect("requirement has no NUL");
        let bytes = path.as_os_str().as_bytes();

        let url = Owned(
            unsafe {
                CFURLCreateFromFileSystemRepresentation(
                    kCFAllocatorDefault,
                    bytes.as_ptr(),
                    bytes.len() as isize,
                    0,
                )
            }
            .cast_mut()
            .cast(),
        );
        if url.0.is_null() {
            return Check::Fail("cannot build a URL for the binary".to_owned());
        }
        let requirement_string = Owned(
            unsafe {
                CFStringCreateWithCString(kCFAllocatorDefault, text.as_ptr(), kCFStringEncodingUTF8)
            }
            .cast_mut()
            .cast(),
        );
        if requirement_string.0.is_null() {
            return Check::Fail("cannot build the signing requirement".to_owned());
        }

        let mut code: SecStaticCodeRef = ptr::null_mut();
        let status = unsafe { SecStaticCodeCreateWithPath(url.0.cast(), 0, &mut code) };
        let code = Owned(code.cast());
        if status != 0 {
            return Check::Fail(format!(
                "cannot read the code signature (OSStatus {status})"
            ));
        }
        let mut requirement: SecRequirementRef = ptr::null_mut();
        let status = unsafe {
            SecRequirementCreateWithString(requirement_string.0.cast(), 0, &mut requirement)
        };
        let requirement = Owned(requirement.cast());
        if status != 0 {
            return Check::Fail(format!("invalid signing requirement (OSStatus {status})"));
        }
        let status = unsafe {
            SecStaticCodeCheckValidity(
                code.0.cast(),
                kSecCSCheckAllArchitectures | kSecCSStrictValidate,
                requirement.0.cast(),
            )
        };
        if status == 0 {
            Check::Pass
        } else {
            Check::Fail(format!(
                "code signature does not match the expected team (OSStatus {status})"
            ))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn requirement_rejects_injection() {
            let text = requirement_text("AB12CD34EF", OPENVPN_IDENTIFIER).unwrap();
            assert!(text.contains("AB12CD34EF"));
            assert!(text.starts_with("identifier \"com.aprdth.wyvpn.openvpn\" and "));
            let text = requirement_text("AB12CD34EF", DAEMON_IDENTIFIER).unwrap();
            assert!(text.starts_with("identifier \"com.aprdth.wyvpn.daemon\" and "));
            assert!(requirement_text("", OPENVPN_IDENTIFIER).is_none());
            assert!(requirement_text("A\" or anchor apple", OPENVPN_IDENTIFIER).is_none());
        }

        #[test]
        #[ignore = "needs a signed binary"]
        fn unsigned_binary_fails() {
            let check = verify(Path::new("/bin/ls"), "ABCDE12345", OPENVPN_IDENTIFIER);
            assert!(matches!(check, Check::Fail(_)));
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::ptr;

    use sha2::{Digest, Sha256};
    use windows_sys::Win32::Foundation::{
        CloseHandle, FreeLibrary, GENERIC_READ, HANDLE, HMODULE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Cryptography::{
        CERT_CONTEXT, CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW,
    };
    use windows_sys::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
        WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_CHAIN, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE,
        WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::LibraryLoader::{
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
    };

    use super::Check;
    use super::trust::{self, Verdict};

    const COMMUNITY_PUBLISHER: &str = "OpenVPN Inc.";

    struct Signer {
        chain_errors: Option<u32>,
        signer_error: u32,
        subject: String,
        issuer: Option<String>,
        issuer_sha256: Option<String>,
    }

    struct FileGuard(HANDLE);

    impl Drop for FileGuard {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful CreateFileW and is closed once.
            unsafe { CloseHandle(self.0) };
        }
    }

    pub enum LoadError {
        Io(String),
        Untrusted(String),
    }

    pub struct WintunModule {
        path: PathBuf,
        module: HMODULE,
        file: Option<FileGuard>,
    }

    // SAFETY: the module handle is only freed on drop; the file handle is only closed on drop.
    unsafe impl Send for WintunModule {}

    impl WintunModule {
        pub fn path(&self) -> &Path {
            &self.path
        }

        pub fn release_file(&mut self) {
            self.file = None;
        }
    }

    impl Drop for WintunModule {
        fn drop(&mut self) {
            // SAFETY: the module came from a successful LoadLibraryExW and is freed once.
            unsafe { FreeLibrary(self.module) };
        }
    }

    pub fn publisher_allowed(subject: &str, ours: Option<&str>) -> bool {
        subject == COMMUNITY_PUBLISHER || ours.is_some_and(|name| subject == name)
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    pub fn verify(path: &Path, ours: Option<&str>) -> Check {
        let wide = wide(path);
        verify_file(&wide, ptr::null_mut(), false, |signer| {
            if publisher_allowed(&signer.subject, ours) {
                Ok(())
            } else {
                Err(format!("untrusted publisher \"{}\"", signer.subject))
            }
        })
    }

    pub fn load_wintun(path: &Path) -> Result<WintunModule, LoadError> {
        let wide = wide(path);
        // SAFETY: wide is NUL-terminated; the null arguments are documented as optional.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(LoadError::Io(format!(
                "cannot open wintun.dll: {}",
                std::io::Error::last_os_error()
            )));
        }
        let file = FileGuard(handle);
        match verify_file(&wide, file.0, true, |signer| {
            trust::check_signer(
                &trust::WINTUN,
                &signer.subject,
                signer.issuer.as_deref(),
                signer.issuer_sha256.as_deref(),
            )
        }) {
            Check::Pass => {}
            Check::Skip(reason) | Check::Fail(reason) => return Err(LoadError::Untrusted(reason)),
        }
        // SAFETY: wide is NUL-terminated and absolute; the file stays open and unwritable meanwhile.
        let module = unsafe {
            LoadLibraryExW(
                wide.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(LoadError::Io(format!(
                "cannot load wintun.dll: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(WintunModule {
            path: path.to_owned(),
            module,
            file: Some(file),
        })
    }

    fn verify_file(
        wide: &[u16],
        file_handle: HANDLE,
        revocation: bool,
        accept: impl Fn(&Signer) -> Result<(), String>,
    ) -> Check {
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: wide.as_ptr(),
            hFile: file_handle,
            pgKnownSubject: ptr::null_mut(),
        };
        let (checks, flags) = if revocation {
            (WTD_REVOKE_WHOLECHAIN, WTD_REVOCATION_CHECK_CHAIN)
        } else {
            (WTD_REVOKE_NONE, WTD_REVOCATION_CHECK_NONE)
        };
        let mut data = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            pPolicyCallbackData: ptr::null_mut(),
            pSIPClientData: ptr::null_mut(),
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: checks,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
            dwStateAction: WTD_STATEACTION_VERIFY,
            hWVTStateData: ptr::null_mut(),
            pwszURLReference: ptr::null_mut(),
            dwProvFlags: flags,
            dwUIContext: 0,
            pSignatureSettings: ptr::null_mut(),
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: data and action are fully initialised and outlive the call.
        let status = unsafe {
            WinVerifyTrust(
                ptr::null_mut(),
                &mut action,
                ptr::from_mut(&mut data).cast::<c_void>(),
            )
        };
        let verdict = trust::classify(status);
        let result = if verdict == Verdict::Rejected {
            Check::Fail(format!("Authenticode check failed (0x{status:08X})"))
        } else {
            if verdict == Verdict::RevocationUnknown {
                tracing::warn!(
                    status = format!("0x{status:08X}"),
                    "certificate revocation could not be checked; relying on the pinned signer"
                );
            }
            match signer(data.hWVTStateData) {
                Some(signer)
                    if verdict == Verdict::RevocationUnknown
                        && !signer.chain_errors.is_some_and(|errors| {
                            trust::revocation_gap_only(status, errors, signer.signer_error)
                        }) =>
                {
                    Check::Fail(format!(
                        "the signer chain has errors besides revocation (0x{status:08X})"
                    ))
                }
                Some(signer) => match accept(&signer) {
                    Ok(()) => Check::Pass,
                    Err(reason) => Check::Fail(reason),
                },
                None => Check::Fail("cannot read the signer certificate".to_owned()),
            }
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: closes the state opened above with the same data.
        unsafe {
            WinVerifyTrust(
                ptr::null_mut(),
                &mut action,
                ptr::from_mut(&mut data).cast::<c_void>(),
            );
        }
        result
    }

    fn signer(state: *mut c_void) -> Option<Signer> {
        // SAFETY: state comes from a completed WinVerifyTrust; every returned pointer is null-checked.
        unsafe {
            let provider = WTHelperProvDataFromStateData(state);
            if provider.is_null() {
                return None;
            }
            let signer = WTHelperGetProvSignerFromChain(provider, 0, 0, 0);
            if signer.is_null() || (*signer).csCertChain == 0 || (*signer).pasCertChain.is_null() {
                return None;
            }
            let chain = (*signer).pasCertChain;
            let subject = cert_name((*chain).pCert)?;
            let issuer_cert = if (*signer).csCertChain >= 2 {
                (*chain.add(1)).pCert
            } else {
                ptr::null()
            };
            let issuer = cert_name(issuer_cert);
            let issuer_sha256 = cert_sha256(issuer_cert);
            let context = (*signer).pChainContext;
            let chain_errors = if context.is_null() {
                None
            } else {
                Some((*context).TrustStatus.dwErrorStatus)
            };
            Some(Signer {
                chain_errors,
                signer_error: (*signer).dwError,
                subject,
                issuer,
                issuer_sha256,
            })
        }
    }

    unsafe fn cert_sha256(cert: *const CERT_CONTEXT) -> Option<String> {
        // SAFETY: cert is null or a live context whose encoded bytes span cbCertEncoded.
        unsafe {
            if cert.is_null() || (*cert).pbCertEncoded.is_null() {
                return None;
            }
            let der =
                std::slice::from_raw_parts((*cert).pbCertEncoded, (*cert).cbCertEncoded as usize);
            Some(trust::hex(&Sha256::digest(der)))
        }
    }

    unsafe fn cert_name(cert: *const CERT_CONTEXT) -> Option<String> {
        if cert.is_null() {
            return None;
        }
        // SAFETY: cert is non-null and live; the buffer length comes from the sizing call.
        unsafe {
            let len = CertGetNameStringW(
                cert,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                ptr::null(),
                ptr::null_mut(),
                0,
            );
            if len <= 1 {
                return None;
            }
            let mut buf = vec![0u16; len as usize];
            CertGetNameStringW(
                cert,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                ptr::null(),
                buf.as_mut_ptr(),
                len,
            );
            buf.truncate(len as usize - 1);
            Some(String::from_utf16_lossy(&buf))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn publisher_allowlist() {
            assert!(publisher_allowed("OpenVPN Inc.", None));
            assert!(publisher_allowed("Example Ltd", Some("Example Ltd")));
            assert!(!publisher_allowed("Example Ltd", None));
            assert!(!publisher_allowed("Other", Some("Example Ltd")));
        }
    }
}
