use serde::Serialize;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use wyvpn_ipc::{
    Outcome, ProtocolMismatch, Request, RequestEnvelope, Response, ServerMessage, check_hello,
    decode_line, encode_line, trust::PeerTrust,
};
use zeroize::Zeroizing;

use crate::error::CmdError;

#[cfg(unix)]
type Stream = tokio::net::UnixStream;
#[cfg(windows)]
type Stream = tokio::net::windows::named_pipe::NamedPipeClient;

const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;
const UNTRUSTED_MESSAGE: &str = "the service socket is not owned by the system";
const PERMISSION_MESSAGE: &str = "your account is not allowed to use the WyVPN service";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Mismatch {
    pub client_version: String,
    pub client_protocol: u32,
    pub daemon_version: Option<String>,
    pub daemon_protocol: Option<u32>,
}

impl Mismatch {
    fn older_daemon() -> Self {
        Self {
            client_version: wyvpn_ipc::VERSION.to_owned(),
            client_protocol: wyvpn_ipc::PROTOCOL_VERSION,
            daemon_version: None,
            daemon_protocol: None,
        }
    }

    pub fn outdated(daemon_version: &str) -> Self {
        Self {
            client_version: wyvpn_ipc::VERSION.to_owned(),
            client_protocol: wyvpn_ipc::PROTOCOL_VERSION,
            daemon_version: Some(daemon_version.to_owned()),
            daemon_protocol: Some(wyvpn_ipc::PROTOCOL_VERSION),
        }
    }
}

impl From<ProtocolMismatch> for Mismatch {
    fn from(value: ProtocolMismatch) -> Self {
        Self {
            client_version: value.client_version,
            client_protocol: value.client_protocol,
            daemon_version: Some(value.daemon_version),
            daemon_protocol: Some(value.daemon_protocol),
        }
    }
}

impl std::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.daemon_version, self.daemon_protocol) {
            (Some(version), Some(protocol)) => write!(
                f,
                "WyVPN {} (protocol {}) cannot talk to service {version} (protocol {protocol}); update WyVPN or restart the service",
                self.client_version, self.client_protocol
            ),
            _ => write!(
                f,
                "WyVPN {} (protocol {}) cannot talk to an older service; update WyVPN or restart the service",
                self.client_version, self.client_protocol
            ),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("cannot reach the WyVPN service: {0}")]
    Io(#[from] std::io::Error),
    #[error("the WyVPN service closed the connection")]
    Closed,
    #[error("the WyVPN service sent an oversized message")]
    LineTooLong,
    #[error("the service socket is not owned by the system")]
    UntrustedPeer,
    #[error("unexpected reply from the WyVPN service: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("{PERMISSION_MESSAGE}")]
    PermissionDenied,
    #[error("{0}")]
    Incompatible(Box<Mismatch>),
}

impl ClientError {
    fn connect(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            Self::PermissionDenied
        } else {
            Self::Io(error)
        }
    }
}

impl From<ClientError> for CmdError {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::UntrustedPeer => CmdError::unavailable(UNTRUSTED_MESSAGE),
            ClientError::Io(_) | ClientError::Closed | ClientError::LineTooLong => {
                CmdError::unavailable(&error.to_string())
            }
            ClientError::Decode(_) => CmdError::internal(&error.to_string()),
            ClientError::PermissionDenied => CmdError::new("permission_denied", PERMISSION_MESSAGE),
            ClientError::Incompatible(_) => CmdError::unavailable(&error.to_string()),
        }
    }
}

pub struct Client {
    reader: BufReader<ReadHalf<Stream>>,
    pending: Vec<u8>,
    writer: WriteHalf<Stream>,
    next_id: u64,
    daemon_version: String,
}

impl Client {
    pub async fn connect(path: &str, require_trusted_peer: bool) -> Result<Self, ClientError> {
        #[cfg(unix)]
        let stream = Stream::connect(path).await.map_err(ClientError::connect)?;
        #[cfg(windows)]
        let stream = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(path)
            .map_err(ClientError::connect)?;
        if require_trusted_peer {
            verify_peer(&stream)?;
        }
        let (reader, writer) = tokio::io::split(stream);
        let mut client = Self {
            reader: BufReader::new(reader),
            pending: Vec::new(),
            writer,
            next_id: 1,
            daemon_version: String::new(),
        };
        client.handshake().await?;
        Ok(client)
    }

    pub fn daemon_version(&self) -> &str {
        &self.daemon_version
    }

    async fn handshake(&mut self) -> Result<(), ClientError> {
        match self.call(Request::hello()).await? {
            Ok(Response::Hello {
                daemon_version,
                protocol,
            }) => {
                check_hello(&daemon_version, protocol)
                    .map_err(|mismatch| ClientError::Incompatible(Box::new(mismatch.into())))?;
                self.daemon_version = daemon_version;
                Ok(())
            }
            _ => Err(ClientError::Incompatible(
                Box::new(Mismatch::older_daemon()),
            )),
        }
    }

    pub async fn send(&mut self, request: Request) -> Result<u64, ClientError> {
        let id = self.next_id;
        self.next_id += 1;
        let line = Zeroizing::new(encode_line(&RequestEnvelope { id, request })?);
        self.writer.write_all(&line).await?;
        Ok(id)
    }

    pub async fn read(&mut self) -> Result<ServerMessage, ClientError> {
        read_line(&mut self.reader, &mut self.pending, MAX_LINE_BYTES).await?;
        let line = std::mem::take(&mut self.pending);
        Ok(decode_line(&line)?)
    }

    pub async fn call(
        &mut self,
        request: Request,
    ) -> Result<Result<Response, CmdError>, ClientError> {
        let id = self.send(request).await?;
        loop {
            if let ServerMessage::Response(response) = self.read().await?
                && response.id == id
            {
                return Ok(match response.outcome {
                    Outcome::Result(result) => Ok(result),
                    Outcome::Error(error) => Err(error.into()),
                });
            }
        }
    }
}

// Cancel-safe: partial input stays in `line` until a newline completes it.
async fn read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut Vec<u8>,
    cap: usize,
) -> Result<(), ClientError> {
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            return Err(ClientError::Closed);
        }
        let newline = chunk.iter().position(|byte| *byte == b'\n');
        let take = newline.unwrap_or(chunk.len());
        if line.len() + take > cap {
            return Err(ClientError::LineTooLong);
        }
        line.extend_from_slice(&chunk[..take]);
        reader.consume(take + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(());
        }
    }
}

fn verify_peer(stream: &Stream) -> Result<(), ClientError> {
    #[cfg(unix)]
    let trust = wyvpn_ipc::trust::socket_server(stream);
    #[cfg(windows)]
    let trust = wyvpn_ipc::trust::pipe_server(stream);
    check_trust(trust?)
}

fn check_trust(trust: PeerTrust) -> Result<(), ClientError> {
    match trust {
        PeerTrust::Trusted => Ok(()),
        PeerTrust::Untrusted => Err(ClientError::UntrustedPeer),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn only_root_owned_sockets_are_trusted() {
        assert!(check_trust(wyvpn_ipc::trust::uid_trust(0)).is_ok());
        for uid in [1, 501, 1000, u32::MAX] {
            let error = check_trust(wyvpn_ipc::trust::uid_trust(uid)).unwrap_err();
            assert!(matches!(error, ClientError::UntrustedPeer));
            let cmd = CmdError::from(error);
            assert_eq!(cmd.code, "daemon_unavailable");
            assert_eq!(cmd.message, UNTRUSTED_MESSAGE);
        }
    }

    #[tokio::test]
    async fn reads_lines_up_to_the_cap() {
        let (mut tx, rx) = tokio::io::duplex(64);
        tx.write_all(b"abcd\nef\n").await.unwrap();
        let mut reader = BufReader::new(rx);
        let mut line = Vec::new();
        read_line(&mut reader, &mut line, 4).await.unwrap();
        assert_eq!(line, b"abcd");
        line.clear();
        read_line(&mut reader, &mut line, 4).await.unwrap();
        assert_eq!(line, b"ef");
    }

    #[tokio::test]
    async fn a_full_session_log_fits_under_the_line_cap() {
        let (mut tx, rx) = tokio::io::duplex(4096);
        let line = vec![b'x'; 700 * 1024];
        let writer = tokio::spawn(async move {
            tx.write_all(&line).await.unwrap();
            tx.write_all(b"\n").await.unwrap();
        });
        let mut reader = BufReader::new(rx);
        let mut out = Vec::new();
        read_line(&mut reader, &mut out, MAX_LINE_BYTES)
            .await
            .unwrap();
        assert_eq!(out.len(), 700 * 1024);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_line_is_an_error() {
        let (mut tx, rx) = tokio::io::duplex(64);
        tx.write_all(b"abcde\n").await.unwrap();
        let mut reader = BufReader::new(rx);
        let mut line = Vec::new();
        let error = read_line(&mut reader, &mut line, 4).await.unwrap_err();
        assert!(matches!(error, ClientError::LineTooLong));
    }

    #[tokio::test]
    async fn unterminated_flood_stops_at_the_cap() {
        let (mut tx, rx) = tokio::io::duplex(16);
        let writer = tokio::spawn(async move {
            let chunk = [b'x'; 16];
            while tx.write_all(&chunk).await.is_ok() {}
        });
        let mut reader = BufReader::new(rx);
        let mut line = Vec::new();
        let error = read_line(&mut reader, &mut line, 100).await.unwrap_err();
        assert!(matches!(error, ClientError::LineTooLong));
        assert!(line.len() <= 100);
        drop(reader);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn end_of_stream_is_closed() {
        let (mut tx, rx) = tokio::io::duplex(64);
        tx.write_all(b"partial").await.unwrap();
        drop(tx);
        let mut reader = BufReader::new(rx);
        let mut line = Vec::new();
        let error = read_line(&mut reader, &mut line, 100).await.unwrap_err();
        assert!(matches!(error, ClientError::Closed));
    }

    #[tokio::test]
    async fn interrupted_read_keeps_partial_input() {
        let (mut tx, rx) = tokio::io::duplex(64);
        let mut reader = BufReader::new(rx);
        let mut line = Vec::new();
        tx.write_all(b"hel").await.unwrap();
        let waited = tokio::time::timeout(
            std::time::Duration::from_millis(30),
            read_line(&mut reader, &mut line, 100),
        )
        .await;
        assert!(waited.is_err());
        tx.write_all(b"lo\n").await.unwrap();
        read_line(&mut reader, &mut line, 100).await.unwrap();
        assert_eq!(line, b"hello");
    }
}
