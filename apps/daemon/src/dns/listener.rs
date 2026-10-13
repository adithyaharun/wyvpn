use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::timeout;

use super::report::{HookReport, sanitize};

pub const SOCKET_NAME: &str = "hook.sock";
const MAX_LINE: u64 = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(2);

pub struct HookListener {
    inner: UnixListener,
    path: PathBuf,
}

impl HookListener {
    pub fn bind(runtime_dir: &Path) -> io::Result<Self> {
        let path = runtime_dir.join(SOCKET_NAME);
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if !meta.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a socket", path.display()),
                ));
            }
            fs::remove_file(&path)?;
        }
        let inner = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(Self { inner, path })
    }

    pub async fn next(&mut self) -> Option<HookReport> {
        loop {
            let (stream, _) = self.inner.accept().await.ok()?;
            if let Some(report) = read_report(stream).await {
                return Some(report);
            }
        }
    }
}

impl Drop for HookListener {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

async fn read_report(stream: UnixStream) -> Option<HookReport> {
    let (reader, mut writer) = stream.into_split();
    let mut line = String::new();
    let mut reader = BufReader::new(reader.take(MAX_LINE));
    let read = timeout(IO_TIMEOUT, reader.read_line(&mut line)).await;
    if !matches!(read, Ok(Ok(n)) if n > 0) || !line.ends_with('\n') {
        return None;
    }
    let report = sanitize(serde_json::from_str(&line).ok()?);
    let _ = timeout(IO_TIMEOUT, writer.write_all(b"ok\n")).await;
    Some(report)
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    use super::*;
    use crate::dns::report::{DnsSettings, HookPhase};

    fn send(dir: &Path, payload: &[u8]) -> std::thread::JoinHandle<String> {
        let path = dir.join(SOCKET_NAME);
        let payload = payload.to_vec();
        std::thread::spawn(move || {
            let mut stream = UnixStream::connect(path).unwrap();
            stream.write_all(&payload).unwrap();
            let mut ack = String::new();
            let _ = BufReader::new(stream).read_line(&mut ack);
            ack
        })
    }

    #[tokio::test]
    async fn delivers_report_and_acks() {
        let dir = tempfile::tempdir().unwrap();
        let mut listener = HookListener::bind(dir.path()).unwrap();
        let mode = fs::metadata(dir.path().join(SOCKET_NAME))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        let report = HookReport {
            phase: HookPhase::Up,
            dev: "utun3".into(),
            dns: DnsSettings {
                servers: vec!["10.0.0.1".parse().unwrap()],
                domains: vec!["corp.example".into()],
                search: vec![],
            },
        };
        let mut payload = serde_json::to_vec(&report).unwrap();
        payload.push(b'\n');
        let client = send(dir.path(), &payload);
        assert_eq!(listener.next().await, Some(report));
        assert_eq!(client.join().unwrap(), "ok\n");
    }

    #[tokio::test]
    async fn skips_garbage_and_revalidates() {
        let dir = tempfile::tempdir().unwrap();
        let mut listener = HookListener::bind(dir.path()).unwrap();
        let junk = send(dir.path(), b"not json\n");
        let hostile = send(
            dir.path(),
            br#"{"phase":"up","dev":"x y","dns":{"servers":["1.1.1.1"],"domains":["a b"],"search":[]}}
"#,
        );
        let report = listener.next().await.unwrap();
        drop(listener);
        assert_eq!(report.dev, "");
        assert!(report.dns.domains.is_empty());
        assert_eq!(report.dns.servers.len(), 1);
        assert_eq!(junk.join().unwrap(), "");
        assert_eq!(hostile.join().unwrap(), "ok\n");
    }

    #[tokio::test]
    async fn rebinds_over_stale_socket_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        drop(std::os::unix::net::UnixListener::bind(dir.path().join(SOCKET_NAME)).unwrap());
        let second = HookListener::bind(dir.path()).unwrap();
        drop(second);
        assert!(!dir.path().join(SOCKET_NAME).exists());
    }

    #[test]
    fn refuses_to_replace_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(SOCKET_NAME), b"x").unwrap();
        assert!(HookListener::bind(dir.path()).is_err());
    }
}
