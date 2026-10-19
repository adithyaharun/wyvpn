use std::io;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use wyvpn_core::auth::OpenVpnCredentials;
use zeroize::Zeroizing;

pub const MAX_LINE: usize = 4096;
const MAX_FIELD: usize = 64;
const MAX_MESSAGE: usize = 200;
const AUTH_REALM: &str = "Auth";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelEvent {
    State {
        name: String,
        tunnel_ip: Option<String>,
        remote: Option<String>,
    },
    Connected {
        tunnel_ip: Option<String>,
        remote: Option<String>,
    },
    Bytes {
        rx: u64,
        tx: u64,
    },
    Handshake(u64),
    AuthFailed,
    Fatal(String),
    Log(String),
    Exited(Option<i32>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Terminate,
}

#[derive(Default)]
pub struct Setup {
    pub credentials: Option<OpenVpnCredentials>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    State {
        name: String,
        tunnel_ip: Option<String>,
        remote: Option<String>,
    },
    ByteCount {
        rx: u64,
        tx: u64,
    },
    NeedPassword {
        realm: String,
        wants_username: bool,
    },
    VerificationFailed,
    Fatal(String),
    Hold,
    Info,
    Unknown,
}

pub fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' | '"' => {
                out.push('\\');
                out.push(ch);
            }
            '\n' | '\r' | '\0' => {}
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn clean_field(value: &str) -> Option<String> {
    let safe = |ch: char| {
        ch.is_ascii_alphanumeric() || matches!(ch, '.' | ':' | '[' | ']' | '-' | '_' | '%')
    };
    (!value.is_empty() && value.len() <= MAX_FIELD && value.chars().all(safe))
        .then(|| value.to_owned())
}

fn clean_state_name(value: &str) -> Option<String> {
    (!value.is_empty()
        && value.len() <= 32
        && value.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'))
    .then(|| value.to_owned())
}

fn clean_text(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_MESSAGE)
        .collect()
}

pub fn parse_line(line: &str) -> Message {
    let line = line.trim_end_matches(['\r', '\n']);
    if let Some(rest) = line.strip_prefix(">STATE:") {
        return parse_state(rest);
    }
    if let Some(rest) = line.strip_prefix(">BYTECOUNT:") {
        let mut parts = rest.split(',');
        return match (
            parts.next().and_then(|v| v.trim().parse().ok()),
            parts.next().and_then(|v| v.trim().parse().ok()),
        ) {
            (Some(rx), Some(tx)) => Message::ByteCount { rx, tx },
            _ => Message::Unknown,
        };
    }
    if let Some(rest) = line.strip_prefix(">PASSWORD:") {
        return parse_password(rest);
    }
    if let Some(rest) = line.strip_prefix(">FATAL:") {
        return Message::Fatal(clean_text(rest));
    }
    if line.starts_with(">HOLD:") {
        return Message::Hold;
    }
    if line.starts_with(">INFO:") {
        return Message::Info;
    }
    Message::Unknown
}

fn parse_state(rest: &str) -> Message {
    let fields: Vec<&str> = rest.split(',').collect();
    let Some(name) = fields.get(1).and_then(|name| clean_state_name(name)) else {
        return Message::Unknown;
    };
    let field = |index: usize| fields.get(index).and_then(|value| clean_field(value));
    let tunnel_ip = field(3);
    let remote = match (field(4), field(5)) {
        (Some(ip), Some(port)) if ip.contains(':') => Some(format!("[{ip}]:{port}")),
        (Some(ip), Some(port)) => Some(format!("{ip}:{port}")),
        (Some(ip), None) => Some(ip),
        _ => None,
    };
    Message::State {
        name,
        tunnel_ip,
        remote,
    }
}

fn parse_password(rest: &str) -> Message {
    if rest.starts_with("Verification Failed") {
        return Message::VerificationFailed;
    }
    let Some(after) = rest.strip_prefix("Need '") else {
        return Message::Unknown;
    };
    let Some((realm, tail)) = after.split_once('\'') else {
        return Message::Unknown;
    };
    Message::NeedPassword {
        realm: realm.to_owned(),
        wants_username: tail.contains("username/password"),
    }
}

pub struct LineReader<R> {
    reader: BufReader<R>,
    line: Vec<u8>,
    overflowed: bool,
}

impl<R: AsyncRead + Unpin> LineReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
            line: Vec::new(),
            overflowed: false,
        }
    }

    pub async fn next_line(&mut self) -> io::Result<Option<String>> {
        loop {
            let chunk = self.reader.fill_buf().await?;
            if chunk.is_empty() {
                if self.line.is_empty() && !self.overflowed {
                    return Ok(None);
                }
                return Ok(Some(self.take()));
            }
            let newline = chunk.iter().position(|&b| b == b'\n');
            let end = newline.unwrap_or(chunk.len());
            let room = MAX_LINE.saturating_sub(self.line.len());
            if end > room {
                self.overflowed = true;
            }
            self.line.extend_from_slice(&chunk[..end.min(room)]);
            let consumed = newline.map_or(end, |at| at + 1);
            self.reader.consume(consumed);
            if newline.is_some() {
                return Ok(Some(self.take()));
            }
        }
    }

    fn take(&mut self) -> String {
        self.overflowed = false;
        let text = String::from_utf8_lossy(&self.line).into_owned();
        self.line.clear();
        text
    }
}

async fn send<W: AsyncWrite + Unpin>(writer: &mut W, line: &str) -> io::Result<()> {
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

async fn emit(events: &mpsc::Sender<TunnelEvent>, event: TunnelEvent) {
    let _ = events.send(event).await;
}

pub async fn drive<S>(
    stream: S,
    mut setup: Setup,
    events: &mpsc::Sender<TunnelEvent>,
    commands: &mut mpsc::Receiver<Command>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (read, mut write) = tokio::io::split(stream);
    let mut lines = LineReader::new(read);

    send(&mut write, "state on").await?;
    send(&mut write, "bytecount 5").await?;

    let mut commands_open = true;
    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line? else {
                    return Ok(());
                };
                handle(parse_line(&line), &mut write, &mut setup, events).await?;
            }
            command = commands.recv(), if commands_open => match command {
                Some(Command::Terminate) => send(&mut write, "signal SIGTERM").await?,
                None => commands_open = false,
            },
        }
    }
}

async fn handle<W: AsyncWrite + Unpin>(
    message: Message,
    write: &mut W,
    setup: &mut Setup,
    events: &mpsc::Sender<TunnelEvent>,
) -> io::Result<()> {
    match message {
        Message::State {
            name,
            tunnel_ip,
            remote,
        } => {
            let connected = name == "CONNECTED";
            emit(
                events,
                TunnelEvent::State {
                    name,
                    tunnel_ip: tunnel_ip.clone(),
                    remote: remote.clone(),
                },
            )
            .await;
            if connected {
                emit(events, TunnelEvent::Connected { tunnel_ip, remote }).await;
            }
        }
        Message::ByteCount { rx, tx } => emit(events, TunnelEvent::Bytes { rx, tx }).await,
        Message::Hold => send(write, "hold release").await?,
        Message::NeedPassword {
            realm,
            wants_username,
        } => {
            let credentials = setup.credentials.take();
            match credentials {
                Some(credentials) if realm == AUTH_REALM && wants_username => {
                    let username = Zeroizing::new(format!(
                        "username {} {}",
                        quote(AUTH_REALM),
                        quote(&credentials.username)
                    ));
                    send(write, &username).await?;
                    let password = Zeroizing::new(format!(
                        "password {} {}",
                        quote(AUTH_REALM),
                        quote(credentials.password.expose())
                    ));
                    send(write, &password).await?;
                }
                _ => {
                    emit(
                        events,
                        TunnelEvent::Fatal("unsupported or repeated credential request".into()),
                    )
                    .await;
                }
            }
        }
        Message::VerificationFailed => emit(events, TunnelEvent::AuthFailed).await,
        Message::Fatal(text) => emit(events, TunnelEvent::Fatal(text)).await,
        Message::Info | Message::Unknown => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{DuplexStream, ReadHalf, WriteHalf};
    use wyvpn_core::Secret;

    struct Peer {
        lines: LineReader<ReadHalf<DuplexStream>>,
        write: WriteHalf<DuplexStream>,
    }

    impl Peer {
        async fn say(&mut self, text: &str) {
            self.write.write_all(text.as_bytes()).await.unwrap();
            self.write.write_all(b"\n").await.unwrap();
        }

        async fn expect(&mut self, want: &str) {
            let got = tokio::time::timeout(Duration::from_secs(2), self.lines.next_line())
                .await
                .expect("timed out waiting for client line")
                .unwrap()
                .expect("client closed");
            assert_eq!(got, want);
        }
    }

    struct Harness {
        peer: Peer,
        events: mpsc::Receiver<TunnelEvent>,
        commands: mpsc::Sender<Command>,
        task: tokio::task::JoinHandle<io::Result<()>>,
    }

    fn harness(setup: Setup) -> Harness {
        let (client, server) = tokio::io::duplex(8192);
        let (read, write) = tokio::io::split(server);
        let (events_tx, events) = mpsc::channel(32);
        let (commands, mut commands_rx) = mpsc::channel(4);
        let task =
            tokio::spawn(async move { drive(client, setup, &events_tx, &mut commands_rx).await });
        Harness {
            peer: Peer {
                lines: LineReader::new(read),
                write,
            },
            events,
            commands,
            task,
        }
    }

    fn credentials() -> OpenVpnCredentials {
        OpenVpnCredentials {
            username: "user".into(),
            password: Secret::new("pa\"ss\\word"),
        }
    }

    async fn next(events: &mut mpsc::Receiver<TunnelEvent>) -> TunnelEvent {
        tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .expect("timed out waiting for event")
            .expect("event channel closed")
    }

    #[tokio::test]
    async fn connect_flow_reports_state_and_bytes() {
        let mut h = harness(Setup {
            credentials: Some(credentials()),
        });
        h.peer.expect("state on").await;
        h.peer.expect("bytecount 5").await;
        h.peer
            .say(">INFO:OpenVPN Management Interface Version 5")
            .await;
        h.peer.say(">HOLD:Waiting for hold release:0").await;
        h.peer.expect("hold release").await;
        h.peer.say(">PASSWORD:Need 'Auth' username/password").await;
        h.peer.expect(r#"username "Auth" "user""#).await;
        h.peer.expect(r#"password "Auth" "pa\"ss\\word""#).await;
        h.peer.say(">STATE:1700000000,AUTH,,,,,,").await;
        h.peer
            .say(">STATE:1700000001,CONNECTED,SUCCESS,10.8.0.2,203.0.113.5,1194,,")
            .await;
        h.peer.say(">BYTECOUNT:1024,2048").await;

        assert_eq!(
            next(&mut h.events).await,
            TunnelEvent::State {
                name: "AUTH".into(),
                tunnel_ip: None,
                remote: None
            }
        );
        assert_eq!(
            next(&mut h.events).await,
            TunnelEvent::State {
                name: "CONNECTED".into(),
                tunnel_ip: Some("10.8.0.2".into()),
                remote: Some("203.0.113.5:1194".into())
            }
        );
        assert_eq!(
            next(&mut h.events).await,
            TunnelEvent::Connected {
                tunnel_ip: Some("10.8.0.2".into()),
                remote: Some("203.0.113.5:1194".into())
            }
        );
        assert_eq!(
            next(&mut h.events).await,
            TunnelEvent::Bytes { rx: 1024, tx: 2048 }
        );
        drop(h.peer);
        h.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn credentials_are_answered_once() {
        let mut h = harness(Setup {
            credentials: Some(credentials()),
        });
        h.peer.expect("state on").await;
        h.peer.expect("bytecount 5").await;
        h.peer.say(">PASSWORD:Need 'Auth' username/password").await;
        h.peer.expect(r#"username "Auth" "user""#).await;
        h.peer.expect(r#"password "Auth" "pa\"ss\\word""#).await;
        h.peer.say(">PASSWORD:Need 'Auth' username/password").await;
        assert!(matches!(next(&mut h.events).await, TunnelEvent::Fatal(_)));
        h.peer.say(">HOLD:x").await;
        h.peer.expect("hold release").await;
    }

    #[tokio::test]
    async fn auth_failure_and_fatal() {
        let mut h = harness(Setup::default());
        h.peer.say(">PASSWORD:Verification Failed: 'Auth'").await;
        assert_eq!(next(&mut h.events).await, TunnelEvent::AuthFailed);
        h.peer.say(">FATAL:Cannot open TUN/TAP\u{7} dev").await;
        assert_eq!(
            next(&mut h.events).await,
            TunnelEvent::Fatal("Cannot open TUN/TAP dev".into())
        );
    }

    #[tokio::test]
    async fn terminate_sends_signal() {
        let mut h = harness(Setup::default());
        h.peer.expect("state on").await;
        h.peer.expect("bytecount 5").await;
        h.commands.send(Command::Terminate).await.unwrap();
        h.peer.expect("signal SIGTERM").await;
    }

    #[test]
    fn quoting_escapes_backslash_and_quote() {
        assert_eq!(quote("plain"), r#""plain""#);
        assert_eq!(quote(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(quote("a\nb\r\0c"), r#""abc""#);
    }

    #[test]
    fn parser_handles_ipv6_missing_fields_and_garbage() {
        assert_eq!(
            parse_line(">STATE:1,CONNECTED,SUCCESS,10.8.0.2,2001:db8::1,443,,"),
            Message::State {
                name: "CONNECTED".into(),
                tunnel_ip: Some("10.8.0.2".into()),
                remote: Some("[2001:db8::1]:443".into())
            }
        );
        assert_eq!(
            parse_line(">STATE:1,WAIT,,"),
            Message::State {
                name: "WAIT".into(),
                tunnel_ip: None,
                remote: None
            }
        );
        for garbage in [
            "",
            ">",
            ">STATE:",
            ">STATE:1",
            ">STATE:1,lower,x",
            ">STATE:1,CONNECTED,x,<script>,;rm,99",
            ">BYTECOUNT:abc",
            ">BYTECOUNT:1",
            ">PASSWORD:Need '",
            ">PASSWORD:",
            "\u{0}\u{1}\u{ff}",
        ] {
            let _ = parse_line(garbage);
        }
        assert_eq!(parse_line(">BYTECOUNT:abc"), Message::Unknown);
        assert_eq!(
            parse_line(">STATE:1,CONNECTED,x,<script>,;rm,99"),
            Message::State {
                name: "CONNECTED".into(),
                tunnel_ip: None,
                remote: None
            }
        );
        assert_eq!(
            parse_line(">PASSWORD:Need 'Private Key' password"),
            Message::NeedPassword {
                realm: "Private Key".into(),
                wants_username: false
            }
        );
    }

    #[tokio::test]
    async fn overlong_lines_are_truncated_not_fatal() {
        let (mut tx, rx) = tokio::io::duplex(64 * 1024);
        let mut reader = LineReader::new(rx);
        let mut payload = vec![b'a'; MAX_LINE * 3];
        payload.extend_from_slice(b"\nnext\n");
        tx.write_all(&payload).await.unwrap();
        drop(tx);
        assert_eq!(reader.next_line().await.unwrap().unwrap().len(), MAX_LINE);
        assert_eq!(reader.next_line().await.unwrap().unwrap(), "next");
        assert!(reader.next_line().await.unwrap().is_none());
    }
}
