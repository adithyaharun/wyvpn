use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;

use crate::admin::Peer;
use crate::server::handle_connection;
use crate::state::State;

#[cfg(unix)]
pub use unix::{Listener, bind, default_socket_group};
#[cfg(windows)]
pub use windows::{Listener, bind, default_socket_group};

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::io;
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    use nix::unistd::Group;
    use tokio::net::UnixListener;

    pub struct Listener(pub UnixListener);

    pub fn default_socket_group() -> &'static str {
        if cfg!(target_os = "macos") {
            "admin"
        } else {
            "wyvpn"
        }
    }

    pub fn bind(path: &str, group: &str) -> io::Result<Listener> {
        let path = Path::new(path);
        if let Ok(meta) = fs::symlink_metadata(path) {
            if meta.file_type().is_socket() {
                fs::remove_file(path)?;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a socket", path.display()),
                ));
            }
        }

        let staging = Staging::create(path)?;
        let listener = UnixListener::bind(&staging.socket)?;
        let mode = if chown_group(&staging.socket, group) {
            0o660
        } else {
            0o600
        };
        fs::set_permissions(&staging.socket, fs::Permissions::from_mode(mode))?;
        fs::rename(&staging.socket, path)?;
        tracing::info!(path = %path.display(), mode = format_args!("{mode:o}"), "socket ready");
        Ok(Listener(listener))
    }

    struct Staging {
        dir: PathBuf,
        socket: PathBuf,
    }

    impl Staging {
        // the socket is only reachable through a 0700 directory until its final mode is set
        fn create(target: &Path) -> io::Result<Self> {
            let parent = match target.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => parent,
                _ => Path::new("."),
            };
            let dir = parent.join(format!(".wy{}", wyvpn_core::rng::alphanumeric(8)));
            fs::DirBuilder::new().mode(0o700).create(&dir)?;
            let socket = dir.join("s");
            Ok(Self { dir, socket })
        }
    }

    impl Drop for Staging {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn chown_group(path: &Path, group: &str) -> bool {
        match Group::from_name(group) {
            Ok(Some(found)) => match std::os::unix::fs::chown(path, None, Some(found.gid.as_raw()))
            {
                Ok(()) => true,
                Err(err) => {
                    tracing::warn!(group, %err, "cannot assign socket group, restricting to owner");
                    false
                }
            },
            _ => {
                tracing::warn!(group, "socket group not found, restricting to owner");
                false
            }
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::ffi::c_void;
    use std::io;
    use std::ptr;

    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

    const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0012019b;;;AU)";
    const MAX_PIPE_INSTANCES: usize = if super::DEFAULT_MAX_CONNECTIONS < 253 {
        super::DEFAULT_MAX_CONNECTIONS + 1
    } else {
        254
    };

    pub struct PipeSecurity {
        descriptor: PSECURITY_DESCRIPTOR,
        attributes: Box<SECURITY_ATTRIBUTES>,
    }

    unsafe impl Send for PipeSecurity {}
    unsafe impl Sync for PipeSecurity {}

    impl PipeSecurity {
        pub fn new() -> io::Result<Self> {
            let sddl: Vec<u16> = PIPE_SDDL.encode_utf16().chain(Some(0)).collect();
            let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
            let converted = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            };
            if converted == 0 {
                return Err(io::Error::last_os_error());
            }
            let attributes = Box::new(SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            });
            Ok(Self {
                descriptor,
                attributes,
            })
        }

        pub fn create(&self, name: &str, first: bool) -> io::Result<NamedPipeServer> {
            let mut options = ServerOptions::new();
            options
                .first_pipe_instance(first)
                .max_instances(MAX_PIPE_INSTANCES)
                .reject_remote_clients(true);
            let attributes = ptr::from_ref::<SECURITY_ATTRIBUTES>(&self.attributes)
                .cast_mut()
                .cast::<c_void>();
            unsafe { options.create_with_security_attributes_raw(name, attributes) }
        }
    }

    impl Drop for PipeSecurity {
        fn drop(&mut self) {
            unsafe { LocalFree(self.descriptor) };
        }
    }

    pub struct Listener {
        pub name: String,
        pub next: NamedPipeServer,
        pub security: PipeSecurity,
    }

    pub fn default_socket_group() -> &'static str {
        ""
    }

    pub fn bind(name: &str, _group: &str) -> io::Result<Listener> {
        let security = PipeSecurity::new()?;
        let next = security.create(name, true)?;
        Ok(Listener {
            name: name.to_owned(),
            next,
            security,
        })
    }
}

const DEFAULT_MAX_CONNECTIONS: usize = 32;
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_connections: usize,
    pub idle: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            idle: Duration::from_secs(60),
        }
    }
}

async fn accept_failed(err: &io::Error) {
    tracing::warn!(%err, "accept failed");
    tokio::time::sleep(ACCEPT_BACKOFF).await;
}

#[cfg(unix)]
pub async fn serve(
    listener: Listener,
    state: Arc<State>,
    limits: Limits,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    tokio::pin!(shutdown);
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    loop {
        let permit = tokio::select! {
            () = &mut shutdown => return Ok(()),
            permit = slots.clone().acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => return Ok(()),
            },
        };
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            accepted = listener.0.accept() => match accepted {
                Ok((stream, _)) => {
                    let peer = Peer::of(&stream);
                    tokio::spawn(handle_connection(stream, state.clone(), peer, limits.idle, permit));
                }
                Err(err) => accept_failed(&err).await,
            }
        }
    }
}

#[cfg(windows)]
pub async fn serve(
    listener: Listener,
    state: Arc<State>,
    limits: Limits,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    tokio::pin!(shutdown);
    let Listener {
        name,
        mut next,
        security,
    } = listener;
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    loop {
        let permit = tokio::select! {
            () = &mut shutdown => return Ok(()),
            permit = slots.clone().acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => return Ok(()),
            },
        };
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            connected = next.connect() => {
                if let Err(err) = connected {
                    accept_failed(&err).await;
                    continue;
                }
                match security.create(&name, false) {
                    Ok(fresh) => {
                        let stream = std::mem::replace(&mut next, fresh);
                        tokio::spawn(handle_connection(stream, state.clone(), Peer::Unknown, limits.idle, permit));
                    }
                    Err(err) => accept_failed(&err).await,
                }
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[tokio::test]
    async fn socket_is_not_world_accessible() {
        let dir = crate::testdata::private_tempdir();
        let path = dir.path().join("wyvpn.sock");
        let _listener = bind(path.to_str().unwrap(), "wyvpn-no-such-group").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[tokio::test]
    async fn stale_socket_is_replaced() {
        let dir = crate::testdata::private_tempdir();
        let path = dir.path().join("wyvpn.sock");
        drop(bind(path.to_str().unwrap(), "").unwrap());
        assert!(path.exists());
        bind(path.to_str().unwrap(), "").unwrap();
    }

    #[tokio::test]
    async fn refuses_to_replace_regular_file() {
        let dir = crate::testdata::private_tempdir();
        let path = dir.path().join("file");
        std::fs::write(&path, b"x").unwrap();
        assert!(bind(path.to_str().unwrap(), "").is_err());
    }
}
