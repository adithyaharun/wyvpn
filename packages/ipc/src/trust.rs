use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTrust {
    Trusted,
    Untrusted,
}

#[cfg(unix)]
pub fn socket_server(stream: &tokio::net::UnixStream) -> io::Result<PeerTrust> {
    Ok(uid_trust(stream.peer_cred()?.uid()))
}

#[cfg(unix)]
pub fn uid_trust(uid: u32) -> PeerTrust {
    if uid == 0 {
        PeerTrust::Trusted
    } else {
        PeerTrust::Untrusted
    }
}

#[cfg(windows)]
pub fn pipe_server(
    pipe: &tokio::net::windows::named_pipe::NamedPipeClient,
) -> io::Result<PeerTrust> {
    use std::os::windows::io::AsRawHandle;
    pipe_server_handle(pipe.as_raw_handle())
}

#[cfg(windows)]
pub fn pipe_server_handle(pipe: std::os::windows::io::RawHandle) -> io::Result<PeerTrust> {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

    let mut pid = 0u32;
    if unsafe { GetNamedPipeServerProcessId(pipe as HANDLE, &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(match service_process_id()? {
        Some(service) if service == pid => PeerTrust::Trusted,
        _ => PeerTrust::Untrusted,
    })
}

#[cfg(windows)]
fn service_process_id() -> io::Result<Option<u32>> {
    use std::ptr;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
        SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS_PROCESS,
    };

    const SERVICE_NAME: &str = "wyvpnd";
    const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

    struct Handle(*mut core::ffi::c_void);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe { CloseServiceHandle(self.0) };
        }
    }

    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(io::Error::last_os_error());
    }
    let manager = Handle(manager);
    let name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
    let service = unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_QUERY_STATUS) };
    if service.is_null() {
        let err = io::Error::last_os_error();
        return if err.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST) {
            Ok(None)
        } else {
            Err(err)
        };
    }
    let service = Handle(service);
    let mut status: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let mut needed = 0u32;
    let queried = unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            ptr::from_mut(&mut status).cast(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    };
    if queried == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(
        (status.dwCurrentState == SERVICE_RUNNING && status.dwProcessId != 0)
            .then_some(status.dwProcessId),
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn only_root_is_trusted() {
        assert_eq!(uid_trust(0), PeerTrust::Trusted);
        for uid in [1, 501, 1000, u32::MAX] {
            assert_eq!(uid_trust(uid), PeerTrust::Untrusted);
        }
    }
}
