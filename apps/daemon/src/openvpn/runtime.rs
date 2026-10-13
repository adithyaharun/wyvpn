use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use wyvpn_core::Secret;

pub const RUN_DIR: &str = "run";
pub const CONFIG_FILE: &str = "openvpn.conf";
#[cfg_attr(windows, allow(dead_code))]
pub const MGMT_SOCKET: &str = "mgmt.sock";

const ID_LEN: usize = 16;

#[derive(Debug)]
pub struct RuntimeDir {
    path: PathBuf,
}

impl RuntimeDir {
    pub fn create(data_dir: &Path, config: &Secret) -> io::Result<Self> {
        let run = std::path::absolute(data_dir)?.join(RUN_DIR);
        create_private_dir(&run, true)?;
        let id = wyvpn_core::rng::alphanumeric(ID_LEN).to_ascii_lowercase();
        let path = run.join(&id);
        create_private_dir(&path, false)?;
        let dir = Self { path };
        dir.write_config(config)?;
        Ok(dir)
    }

    fn write_config(&self, config: &Secret) -> io::Result<()> {
        let mut file = crate::storage::create_private(&self.config_path())?;
        file.write_all(config.expose().as_bytes())?;
        file.sync_all()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn config_path(&self) -> PathBuf {
        self.path.join(CONFIG_FILE)
    }

    #[cfg_attr(windows, allow(dead_code))]
    pub fn management_socket(&self) -> PathBuf {
        self.path.join(MGMT_SOCKET)
    }

    pub fn remove(&self) {
        match fs::remove_dir_all(&self.path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                tracing::warn!(dir = %self.path.display(), %err, "cannot remove runtime directory");
            }
        }
    }
}

impl Drop for RuntimeDir {
    fn drop(&mut self) {
        self.remove();
    }
}

pub fn sweep(data_dir: &Path) -> usize {
    let run = data_dir.join(RUN_DIR);
    let Ok(entries) = fs::read_dir(&run) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let result = match entry.file_type() {
            Ok(kind) if kind.is_dir() => fs::remove_dir_all(&path),
            _ => fs::remove_file(&path),
        };
        match result {
            Ok(()) => removed += 1,
            Err(err) => {
                tracing::warn!(path = %path.display(), %err, "cannot sweep stale runtime entry");
            }
        }
    }
    removed
}

#[cfg(unix)]
fn create_private_dir(path: &Path, recursive: bool) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    fs::DirBuilder::new()
        .recursive(recursive)
        .mode(0o700)
        .create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
fn create_private_dir(path: &Path, recursive: bool) -> io::Result<()> {
    if recursive {
        fs::create_dir_all(path)
    } else {
        fs::create_dir(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn layout_and_modes() {
        use std::os::unix::fs::PermissionsExt;

        let data = crate::testdata::private_tempdir();
        let config = Secret::new("client\nremote x 1194\n");
        let dir = RuntimeDir::create(data.path(), &config).unwrap();

        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(dir.path()), 0o700);
        assert_eq!(mode(&dir.config_path()), 0o600);
        assert_eq!(
            fs::read_to_string(dir.config_path()).unwrap(),
            config.expose()
        );
        assert_eq!(dir.path().parent().unwrap(), data.path().join(RUN_DIR));
        assert_eq!(dir.management_socket().file_name().unwrap(), MGMT_SOCKET);
        let id = dir.path().file_name().unwrap().to_str().unwrap();
        assert!(!id.is_empty());
        assert!(id.bytes().all(|b| b.is_ascii_alphanumeric()));
    }

    #[test]
    fn ids_are_unique_and_remove_is_idempotent() {
        let data = crate::testdata::private_tempdir();
        let first = RuntimeDir::create(data.path(), &Secret::new("a")).unwrap();
        let second = RuntimeDir::create(data.path(), &Secret::new("b")).unwrap();
        assert_ne!(first.path(), second.path());
        let path = first.path().to_path_buf();
        first.remove();
        first.remove();
        assert!(!path.exists());
        drop(second);
    }

    #[test]
    fn drop_removes_the_directory() {
        let data = crate::testdata::private_tempdir();
        let dir = RuntimeDir::create(data.path(), &Secret::new("a")).unwrap();
        let path = dir.path().to_path_buf();
        drop(dir);
        assert!(!path.exists());
    }

    #[test]
    fn sweep_removes_stale_directories_and_strays() {
        let data = crate::testdata::private_tempdir();
        assert_eq!(sweep(data.path()), 0);

        let run = data.path().join(RUN_DIR);
        let stale = RuntimeDir::create(data.path(), &Secret::new("a")).unwrap();
        std::mem::forget(stale);
        create_private_dir(&run.join("other"), false).unwrap();
        create_private_dir(&run.join("other").join("nested"), false).unwrap();
        fs::write(run.join("stray"), b"x").unwrap();
        fs::write(data.path().join("keep.json"), b"{}").unwrap();

        assert_eq!(sweep(data.path()), 3);
        assert_eq!(fs::read_dir(&run).unwrap().count(), 0);
        assert!(data.path().join("keep.json").exists());
    }
}
