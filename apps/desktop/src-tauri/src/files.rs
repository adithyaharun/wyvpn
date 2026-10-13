use std::fs::File;
use std::io::Read;
use std::path::Path;

use zeroize::Zeroizing;

use crate::error::CmdError;

pub struct ImportFile {
    pub name: String,
    pub bytes: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for ImportFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportFile")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

pub fn check_size(len: u64, limit: usize) -> Result<(), CmdError> {
    if usize::try_from(len).is_ok_and(|len| len <= limit) {
        Ok(())
    } else {
        Err(CmdError::too_large(limit))
    }
}

pub fn read_import_file(path: &Path, limit: usize) -> Result<ImportFile, CmdError> {
    let unreadable =
        |error: std::io::Error| CmdError::io(&format!("cannot read the file: {}", error.kind()));
    if !std::fs::metadata(path).map_err(unreadable)?.is_file() {
        return Err(CmdError::io("the selected item is not a regular file"));
    }
    let file = File::open(path).map_err(unreadable)?;
    let metadata = file.metadata().map_err(unreadable)?;
    if !metadata.is_file() {
        return Err(CmdError::io("the selected item is not a regular file"));
    }
    check_size(metadata.len(), limit)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    check_size(bytes.len() as u64, limit)?;
    let name = path.file_name().map_or_else(
        || "profile".to_owned(),
        |n| n.to_string_lossy().into_owned(),
    );
    Ok(ImportFile { name, bytes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn size_check_boundaries() {
        assert!(check_size(10, 10).is_ok());
        assert_eq!(check_size(11, 10).unwrap_err().code, "too_large");
    }

    #[test]
    fn reads_small_file_with_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("office.ovpn");
        std::fs::write(&path, b"hello").unwrap();
        let file = read_import_file(&path, 16).unwrap();
        assert_eq!(file.name, "office.ovpn");
        assert_eq!(file.bytes.as_slice(), b"hello");
    }

    #[test]
    fn rejects_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.tar");
        let mut out = File::create(&path).unwrap();
        out.write_all(&[0u8; 17]).unwrap();
        assert_eq!(read_import_file(&path, 16).unwrap_err().code, "too_large");
    }

    #[test]
    fn rejects_directories_and_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_import_file(dir.path(), 16).unwrap_err().code, "io");
        let missing = dir.path().join("none");
        let error = read_import_file(&missing, 16).unwrap_err();
        assert_eq!(error.code, "io");
        assert!(!error.message.contains("none"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_fifos_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pipe.ovpn");
        let made = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap();
        assert!(made.success());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(read_import_file(&path, 16));
        });
        let result = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("read_import_file hung on a fifo");
        assert_eq!(result.unwrap_err().code, "io");
    }
}
