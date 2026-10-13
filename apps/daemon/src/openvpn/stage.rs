use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

pub const BIN_DIR: &str = "bin";

pub fn bin_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(BIN_DIR)
}

pub fn stage(source: &Path, dir: &Path, name: &str) -> io::Result<PathBuf> {
    if fs::symlink_metadata(dir).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Err(io::Error::other(format!("{} is a symlink", dir.display())));
    }
    crate::storage::prepare_dir(dir)?;
    let bytes = fs::read(source)?;
    let digest = Sha256::digest(&bytes);
    let dest = dir.join(name);

    let current = fs::symlink_metadata(&dest)
        .is_ok_and(|meta| meta.is_file())
        .then(|| fs::read(&dest).ok())
        .flatten()
        .is_some_and(|existing| Sha256::digest(&existing) == digest);
    if !current {
        write_atomic(dir, &dest, &bytes)?;
    }
    Ok(dest)
}

fn write_atomic(dir: &Path, dest: &Path, bytes: &[u8]) -> io::Result<()> {
    let staged = dir.join(format!(".stage.{}", wyvpn_core::rng::alphanumeric(8)));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o700);
    let written = options.open(&staged).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    match written.and_then(|()| fs::rename(&staged, dest)) {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = fs::remove_file(&staged);
            Err(err)
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn copies_reuses_and_refreshes() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("src");
        let dir = tmp.path().join("bin");
        fs::write(&source, b"one").unwrap();

        let dest = stage(&source, &dir, "tool").unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"one");
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dest), 0o700);

        let inode = |path: &Path| std::os::unix::fs::MetadataExt::ino(&fs::metadata(path).unwrap());
        let before = inode(&dest);
        stage(&source, &dir, "tool").unwrap();
        assert_eq!(inode(&dest), before);

        fs::write(&source, b"two").unwrap();
        stage(&source, &dir, "tool").unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"two");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
    }

    #[test]
    fn refuses_a_symlinked_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("src");
        fs::write(&source, b"x").unwrap();
        let real = tmp.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = tmp.path().join("bin");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(stage(&source, &link, "tool").is_err());
    }
}
