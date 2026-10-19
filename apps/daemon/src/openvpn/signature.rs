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
        Ok(bytes) => {
            let hex: String = Sha256::digest(bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            pin_decision(pin, &hex)
        }
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
pub fn verify_wintun(path: &Path) -> Check {
    windows::verify_with(path, windows::wintun_publisher_allowed)
}

#[cfg(not(any(target_os = "macos", windows)))]
pub fn verify(_path: &Path) -> Check {
    Check::Skip("bundled binaries are not used on this platform".to_owned())
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
    use std::path::Path;
    use std::ptr;

    use windows_sys::Win32::Security::Cryptography::{
        CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW,
    };
    use windows_sys::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
        WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvSignerFromChain,
        WTHelperProvDataFromStateData, WinVerifyTrust,
    };

    use super::Check;

    const COMMUNITY_PUBLISHER: &str = "OpenVPN Inc.";
    const WINTUN_PUBLISHER: &str = "WireGuard LLC";

    pub fn publisher_allowed(subject: &str, ours: Option<&str>) -> bool {
        subject == COMMUNITY_PUBLISHER || ours.is_some_and(|name| subject == name)
    }

    pub fn wintun_publisher_allowed(subject: &str) -> bool {
        subject == WINTUN_PUBLISHER
    }

    pub fn verify(path: &Path, ours: Option<&str>) -> Check {
        verify_with(path, |subject| publisher_allowed(subject, ours))
    }

    pub fn verify_with(path: &Path, allowed: impl Fn(&str) -> bool) -> Check {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: wide.as_ptr(),
            hFile: ptr::null_mut(),
            pgKnownSubject: ptr::null_mut(),
        };
        let mut data = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            pPolicyCallbackData: ptr::null_mut(),
            pSIPClientData: ptr::null_mut(),
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
            dwStateAction: WTD_STATEACTION_VERIFY,
            hWVTStateData: ptr::null_mut(),
            pwszURLReference: ptr::null_mut(),
            dwProvFlags: WTD_REVOCATION_CHECK_NONE,
            dwUIContext: 0,
            pSignatureSettings: ptr::null_mut(),
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = unsafe {
            WinVerifyTrust(
                ptr::null_mut(),
                &mut action,
                ptr::from_mut(&mut data).cast::<c_void>(),
            )
        };
        let result = if status == 0 {
            match signer_name(data.hWVTStateData) {
                Some(subject) if allowed(&subject) => Check::Pass,
                Some(subject) => Check::Fail(format!("untrusted publisher \"{subject}\"")),
                None => Check::Fail("cannot read the signer certificate".to_owned()),
            }
        } else {
            Check::Fail(format!("Authenticode check failed (0x{status:08X})"))
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        unsafe {
            WinVerifyTrust(
                ptr::null_mut(),
                &mut action,
                ptr::from_mut(&mut data).cast::<c_void>(),
            );
        }
        result
    }

    fn signer_name(state: *mut c_void) -> Option<String> {
        unsafe {
            let provider = WTHelperProvDataFromStateData(state);
            if provider.is_null() {
                return None;
            }
            let signer = WTHelperGetProvSignerFromChain(provider, 0, 0, 0);
            if signer.is_null() || (*signer).csCertChain == 0 {
                return None;
            }
            let cert = (*(*signer).pasCertChain).pCert;
            if cert.is_null() {
                return None;
            }
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

        #[test]
        fn wintun_publisher_allowlist() {
            assert!(wintun_publisher_allowed("WireGuard LLC"));
            assert!(!wintun_publisher_allowed("OpenVPN Inc."));
        }
    }
}
