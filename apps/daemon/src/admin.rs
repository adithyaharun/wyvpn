use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use wyvpn_ipc::{ErrorBody, ErrorCode};

const LINK_NAME: &str = "wyvpn-cli";

#[derive(Debug, Clone, Copy)]
pub enum Peer {
    Unknown,
    #[cfg(unix)]
    Cred {
        uid: u32,
        gid: u32,
    },
    #[cfg(test)]
    Fixed {
        admin: bool,
    },
}

impl Peer {
    #[cfg(unix)]
    pub fn of(stream: &tokio::net::UnixStream) -> Self {
        match stream.peer_cred() {
            Ok(cred) => Self::Cred {
                uid: cred.uid(),
                gid: cred.gid(),
            },
            Err(err) => {
                tracing::warn!(%err, "cannot read peer credentials");
                Self::Unknown
            }
        }
    }

    #[cfg_attr(not(unix), allow(unused_variables))]
    pub fn is_admin(&self, group: &str) -> bool {
        match *self {
            Self::Unknown => false,
            #[cfg(unix)]
            Self::Cred { uid, gid } => uid == 0 || in_group(uid, gid, group),
            #[cfg(test)]
            Self::Fixed { admin } => admin,
        }
    }
}

#[cfg(unix)]
pub fn membership(uid: u32, primary_gid: u32, groups: &[u32], admin_gid: Option<u32>) -> bool {
    uid == 0 || admin_gid.is_some_and(|admin| primary_gid == admin || groups.contains(&admin))
}

#[cfg(unix)]
fn in_group(uid: u32, primary_gid: u32, group: &str) -> bool {
    use nix::unistd::{Group, Uid, User};

    let admin_gid = match Group::from_name(group) {
        Ok(Some(found)) => Some(found.gid.as_raw()),
        _ => None,
    };
    let groups = match User::from_uid(Uid::from_raw(uid)) {
        Ok(Some(user)) => group_list(&user.name, primary_gid),
        _ => Vec::new(),
    };
    membership(uid, primary_gid, &groups, admin_gid)
}

#[cfg(target_os = "macos")]
fn group_list(user: &str, primary_gid: u32) -> Vec<u32> {
    use std::ffi::{CString, c_char, c_int};

    unsafe extern "C" {
        fn getgrouplist(
            name: *const c_char,
            basegid: c_int,
            groups: *mut c_int,
            ngroups: *mut c_int,
        ) -> c_int;
    }

    let Ok(name) = CString::new(user) else {
        return Vec::new();
    };
    let mut capacity: c_int = 64;
    for _ in 0..4 {
        let mut groups = vec![0 as c_int; capacity as usize];
        let mut count = capacity;
        let status = unsafe {
            getgrouplist(
                name.as_ptr(),
                primary_gid as c_int,
                groups.as_mut_ptr(),
                &mut count,
            )
        };
        if status >= 0 {
            groups.truncate(count.max(0) as usize);
            return groups.into_iter().map(|gid| gid as u32).collect();
        }
        capacity = count.max(capacity.saturating_mul(2));
    }
    Vec::new()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn group_list(user: &str, primary_gid: u32) -> Vec<u32> {
    use std::ffi::CString;

    use nix::unistd::{Gid, getgrouplist};

    CString::new(user)
        .ok()
        .and_then(|name| getgrouplist(&name, Gid::from_raw(primary_gid)).ok())
        .map(|groups| groups.iter().map(|gid| gid.as_raw()).collect())
        .unwrap_or_default()
}

#[derive(Debug, Clone)]
pub struct AdminConfig {
    pub enabled: bool,
    pub group: String,
    pub bin_dir: PathBuf,
    pub bundled_cli: PathBuf,
    pub data_dir: PathBuf,
}

impl AdminConfig {
    pub fn system(data_dir: PathBuf) -> Self {
        let bundled_cli = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join(LINK_NAME)))
            .unwrap_or_else(|| PathBuf::from(LINK_NAME));
        Self {
            enabled: cfg!(target_os = "macos"),
            group: "admin".to_owned(),
            bin_dir: PathBuf::from("/usr/local/bin"),
            bundled_cli,
            data_dir,
        }
    }

    pub fn link_path(&self) -> PathBuf {
        self.bin_dir.join(LINK_NAME)
    }
}

fn internal(context: &str, err: &io::Error) -> ErrorBody {
    tracing::error!(%err, context, "admin operation failed");
    ErrorBody::new(ErrorCode::Internal, format!("{context}: {err}"))
}

fn points_to(link: &Path, target: &Path) -> bool {
    fs::read_link(link).is_ok_and(|current| current == target)
}

#[cfg(unix)]
pub fn install_cli(config: &AdminConfig) -> Result<(), ErrorBody> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};

    if !config.bundled_cli.is_file() {
        return Err(ErrorBody::new(
            ErrorCode::NotFound,
            format!("bundled CLI not found at {}", config.bundled_cli.display()),
        ));
    }
    let link = config.link_path();
    match fs::symlink_metadata(&link) {
        Ok(meta) if meta.file_type().is_symlink() && points_to(&link, &config.bundled_cli) => {
            return Ok(());
        }
        Ok(_) => {
            return Err(ErrorBody::new(
                ErrorCode::AlreadyExists,
                format!("{} already exists", link.display()),
            ));
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(internal("cannot inspect the CLI link", &err)),
    }

    if !config.bin_dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(&config.bin_dir)
            .map_err(|err| internal("cannot create the CLI directory", &err))?;
        fs::set_permissions(&config.bin_dir, fs::Permissions::from_mode(0o755))
            .map_err(|err| internal("cannot set CLI directory permissions", &err))?;
        if nix::unistd::geteuid().is_root() {
            std::os::unix::fs::chown(&config.bin_dir, Some(0), Some(0))
                .map_err(|err| internal("cannot set CLI directory owner", &err))?;
        }
    }

    let staged = config
        .bin_dir
        .join(format!(".{LINK_NAME}.{}", wyvpn_core::rng::alphanumeric(8)));
    symlink(&config.bundled_cli, &staged)
        .map_err(|err| internal("cannot create the CLI link", &err))?;
    fs::rename(&staged, &link).map_err(|err| {
        let _ = fs::remove_file(&staged);
        internal("cannot create the CLI link", &err)
    })
}

#[cfg(not(unix))]
pub fn install_cli(_config: &AdminConfig) -> Result<(), ErrorBody> {
    Err(ErrorBody::new(
        ErrorCode::NotImplemented,
        "not supported on this platform",
    ))
}

pub fn remove_cli_link(config: &AdminConfig) -> Result<(), ErrorBody> {
    let link = config.link_path();
    let ours = fs::symlink_metadata(&link)
        .is_ok_and(|meta| meta.file_type().is_symlink() && points_to(&link, &config.bundled_cli));
    if ours {
        fs::remove_file(&link).map_err(|err| internal("cannot remove the CLI link", &err))?;
    }
    Ok(())
}

pub fn wipe_data(dir: &Path) -> Result<(), ErrorBody> {
    if dir.parent().is_none() || dir.components().count() < 2 {
        return Err(ErrorBody::new(
            ErrorCode::Internal,
            "refusing to wipe an unsafe data directory",
        ));
    }
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            return Err(ErrorBody::new(
                ErrorCode::Internal,
                "data directory is not a plain directory",
            ));
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(internal("cannot inspect the data directory", &err)),
    }
    let entries =
        fs::read_dir(dir).map_err(|err| internal("cannot read the data directory", &err))?;
    let mut failure = None;
    for entry in entries {
        let removed = entry.and_then(|entry| {
            if entry.file_type()?.is_dir() {
                fs::remove_dir_all(entry.path())
            } else {
                fs::remove_file(entry.path())
            }
        });
        if let Err(err) = removed {
            failure.get_or_insert(err);
        }
    }
    failure.map_or(Ok(()), |err| {
        Err(internal("cannot remove stored data", &err))
    })
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    struct Fixture {
        _dir: tempfile::TempDir,
        config: AdminConfig,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let cli = dir.path().join("app").join("wyvpn-cli");
        fs::create_dir(cli.parent().unwrap()).unwrap();
        fs::write(&cli, b"#!/bin/sh\n").unwrap();
        let data = dir.path().join("data");
        fs::create_dir(&data).unwrap();
        let config = AdminConfig {
            enabled: true,
            group: "admin".to_owned(),
            bin_dir: dir.path().join("usr").join("local").join("bin"),
            bundled_cli: cli,
            data_dir: data,
        };
        Fixture { _dir: dir, config }
    }

    #[test]
    fn membership_decision() {
        assert!(membership(0, 20, &[], None));
        assert!(membership(501, 20, &[], Some(20)));
        assert!(membership(501, 20, &[12, 80], Some(80)));
        assert!(!membership(501, 20, &[12, 61], Some(80)));
        assert!(!membership(501, 20, &[80], None));
    }

    #[test]
    fn unknown_peer_is_never_admin() {
        assert!(!Peer::Unknown.is_admin("admin"));
        assert!(Peer::Cred { uid: 0, gid: 0 }.is_admin("no-such-group-wyvpn"));
        assert!(
            !Peer::Cred {
                uid: 4_000_000,
                gid: 4_000_000
            }
            .is_admin("no-such-group-wyvpn")
        );
    }

    #[test]
    fn install_creates_link_and_directory() {
        let fx = fixture();
        install_cli(&fx.config).unwrap();
        let link = fx.config.link_path();
        assert_eq!(fs::read_link(&link).unwrap(), fx.config.bundled_cli);
        let leftovers = fs::read_dir(&fx.config.bin_dir).unwrap().count();
        assert_eq!(leftovers, 1);
    }

    #[test]
    fn install_is_idempotent() {
        let fx = fixture();
        install_cli(&fx.config).unwrap();
        install_cli(&fx.config).unwrap();
    }

    #[test]
    fn install_refuses_foreign_entries() {
        let fx = fixture();
        fs::create_dir_all(&fx.config.bin_dir).unwrap();
        let link = fx.config.link_path();
        fs::write(&link, b"mine").unwrap();
        let err = install_cli(&fx.config).unwrap_err();
        assert_eq!(err.code, ErrorCode::AlreadyExists);
        assert_eq!(fs::read(&link).unwrap(), b"mine");

        fs::remove_file(&link).unwrap();
        symlink("/somewhere/else", &link).unwrap();
        let err = install_cli(&fx.config).unwrap_err();
        assert_eq!(err.code, ErrorCode::AlreadyExists);
        assert_eq!(fs::read_link(&link).unwrap(), Path::new("/somewhere/else"));
    }

    #[test]
    fn install_needs_the_bundled_cli() {
        let fx = fixture();
        fs::remove_file(&fx.config.bundled_cli).unwrap();
        assert_eq!(
            install_cli(&fx.config).unwrap_err().code,
            ErrorCode::NotFound
        );
    }

    #[test]
    fn remove_only_takes_our_link() {
        let fx = fixture();
        install_cli(&fx.config).unwrap();
        remove_cli_link(&fx.config).unwrap();
        assert!(fs::symlink_metadata(fx.config.link_path()).is_err());

        let link = fx.config.link_path();
        symlink("/somewhere/else", &link).unwrap();
        remove_cli_link(&fx.config).unwrap();
        assert!(fs::symlink_metadata(&link).is_ok());
        remove_cli_link(&AdminConfig {
            bin_dir: fx.config.bin_dir.join("missing"),
            ..fx.config.clone()
        })
        .unwrap();
    }

    #[test]
    fn wipe_clears_contents_without_following_links() {
        let fx = fixture();
        let outside = fx._dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"x").unwrap();
        let data = &fx.config.data_dir;
        fs::write(data.join("a.json"), b"x").unwrap();
        fs::create_dir(data.join("run")).unwrap();
        fs::write(data.join("run").join("b"), b"x").unwrap();
        symlink(&outside, data.join("escape")).unwrap();

        wipe_data(data).unwrap();
        assert_eq!(fs::read_dir(data).unwrap().count(), 0);
        assert!(outside.join("keep").exists());
    }

    #[test]
    fn wipe_refuses_symlinked_or_shallow_dirs() {
        let fx = fixture();
        let link = fx._dir.path().join("link");
        symlink(&fx.config.data_dir, &link).unwrap();
        fs::write(fx.config.data_dir.join("a.json"), b"x").unwrap();
        assert!(wipe_data(&link).is_err());
        assert!(wipe_data(Path::new("/")).is_err());
        assert!(fx.config.data_dir.join("a.json").exists());
    }
}
