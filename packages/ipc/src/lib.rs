use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub mod trust;

pub const MAX_IMPORT_BYTES: usize = 256 * 1024;

// Bump on any change that older clients or daemons cannot decode.
pub const PROTOCOL_VERSION: u32 = 1;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Default, PartialEq, Eq, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sensitive(String);

impl Sensitive {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn decode_base64(&self) -> Option<Zeroizing<Vec<u8>>> {
        STANDARD.decode(&self.0).ok().map(Zeroizing::new)
    }
}

impl fmt::Debug for Sensitive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImportSource {
    File { name: String, data: Sensitive },
    Uri { uri: Sensitive },
}

impl ImportSource {
    pub fn file(name: impl Into<String>, bytes: &[u8]) -> Self {
        Self::File {
            name: name.into(),
            data: Sensitive::new(STANDARD.encode(bytes)),
        }
    }

    pub fn uri(uri: impl Into<String>) -> Self {
        Self::Uri {
            uri: Sensitive::new(uri),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    None,
    Pin,
    Otp,
    PinOtp,
    Sso,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    WireGuard,
    OpenVpn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    ListProfiles,
    Connect {
        profile_id: String,
        transport: Option<Transport>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auto_reconnect: Option<bool>,
    },
    Disconnect {
        profile_id: String,
    },
    SubmitCredentials {
        profile_id: String,
        pin: Option<Sensitive>,
        otp: Option<Sensitive>,
    },
    Status,
    Subscribe,
    ImportProfile {
        source: ImportSource,
        #[serde(default)]
        replace: bool,
    },
    RemoveProfile {
        profile_id: String,
    },
    RenameProfile {
        profile_id: String,
        name: String,
    },
    SessionLog,
    Hello {
        client_version: String,
        protocol: u32,
    },
    InstallCli,
    Uninstall {
        remove_data: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    CredentialsRequired {
        profile_id: String,
        mode: AuthMode,
    },
    StateChanged {
        profile_id: String,
        state: ConnectionState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<ErrorBody>,
    },
    Stats {
        profile_id: String,
        rx_bytes: u64,
        tx_bytes: u64,
    },
    ProfilesChanged,
    Log {
        profile_id: String,
        lines: Vec<LogLine>,
    },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSummary {
    pub id: String,
    pub name: String,
    pub server_name: String,
    pub server_host: String,
    pub user: String,
    pub auth_mode: AuthMode,
    pub transports: Vec<Transport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionStatus {
    pub profile_id: String,
    pub profile_name: String,
    pub state: ConnectionState,
    pub transport: Option<Transport>,
    pub tunnel_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_ip: Option<String>,
    pub server_endpoint: Option<String>,
    pub connected_since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_handshake: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub awaiting: Option<AuthMode>,
}

impl ConnectionStatus {
    pub fn disconnected(profile_id: impl Into<String>) -> Self {
        Self {
            profile_id: profile_id.into(),
            profile_name: String::new(),
            state: ConnectionState::Disconnected,
            transport: None,
            tunnel_ip: None,
            local_ip: None,
            server_endpoint: None,
            connected_since: None,
            last_handshake: None,
            rx_bytes: 0,
            tx_bytes: 0,
            error: None,
            awaiting: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogSource {
    Tunnel,
    Daemon,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogLine {
    pub seq: u64,
    pub at_ms: u64,
    pub source: LogSource,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Profiles {
        profiles: Vec<ProfileSummary>,
    },
    Status {
        statuses: Vec<ConnectionStatus>,
    },
    Subscribed,
    Imported {
        profiles: Vec<ProfileSummary>,
    },
    Ok,
    Profile {
        profile: ProfileSummary,
    },
    Log {
        profile_id: Option<String>,
        lines: Vec<LogLine>,
    },
    Hello {
        daemon_version: String,
        protocol: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    NotImplemented,
    NotFound,
    InvalidRequest,
    InvalidState,
    AlreadyExists,
    UnsupportedAuth,
    AuthFailed,
    Timeout,
    Server,
    Internal,
    PermissionDenied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
}

impl ErrorBody {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ErrorBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ErrorBody {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub id: u64,
    pub request: Request,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Result(Response),
    Error(ErrorBody),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub id: u64,
    #[serde(flatten)]
    pub outcome: Outcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event: Event,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerMessage {
    Response(ResponseEnvelope),
    Event(EventEnvelope),
}

impl Request {
    pub fn hello() -> Self {
        Self::Hello {
            client_version: VERSION.to_owned(),
            protocol: PROTOCOL_VERSION,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolMismatch {
    pub client_version: String,
    pub client_protocol: u32,
    pub daemon_version: String,
    pub daemon_protocol: u32,
}

impl fmt::Display for ProtocolMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WyVPN {} (protocol {}) cannot talk to service {} (protocol {}); update WyVPN or restart the service",
            self.client_version, self.client_protocol, self.daemon_version, self.daemon_protocol
        )
    }
}

impl std::error::Error for ProtocolMismatch {}

pub fn check_hello(daemon_version: &str, daemon_protocol: u32) -> Result<(), ProtocolMismatch> {
    if daemon_protocol == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ProtocolMismatch {
            client_version: VERSION.to_owned(),
            client_protocol: PROTOCOL_VERSION,
            daemon_version: daemon_version.to_owned(),
            daemon_protocol,
        })
    }
}

pub fn encode_line<T: Serialize>(message: &T) -> serde_json::Result<Vec<u8>> {
    let mut line = serde_json::to_vec(message)?;
    line.push(b'\n');
    Ok(line)
}

pub fn decode_line<T: serde::de::DeserializeOwned>(line: &[u8]) -> serde_json::Result<T> {
    serde_json::from_slice(line.trim_ascii())
}

pub const SOCKET_ENV: &str = "WYVPN_SOCKET";

pub fn socket_path() -> String {
    std::env::var(SOCKET_ENV)
        .ok()
        .filter(|path| !path.is_empty())
        .unwrap_or_else(|| SOCKET_PATH.to_owned())
}

pub const BUNDLE_ID_PREFIX: &str = "com.aprdth.wyvpn";

#[cfg(unix)]
pub const SOCKET_PATH: &str = "/var/run/wyvpn.sock";

#[cfg(windows)]
pub const SOCKET_PATH: &str = r"\\.\pipe\wyvpn";

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_MARKERS: [&str; 7] = [
        "secret", "pin", "otp", "password", "private", "key", "token",
    ];

    fn assert_no_secret_keys(value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, inner) in map {
                    let lower = key.to_ascii_lowercase();
                    assert!(
                        !SECRET_MARKERS.iter().any(|m| lower.contains(m)),
                        "secret-looking field: {key}"
                    );
                    assert_no_secret_keys(inner);
                }
            }
            serde_json::Value::Array(items) => items.iter().for_each(assert_no_secret_keys),
            _ => {}
        }
    }

    fn sample_profile() -> ProfileSummary {
        ProfileSummary {
            id: "p1".into(),
            name: "Office".into(),
            server_name: "gw".into(),
            server_host: "vpn.example.com".into(),
            user: "alice".into(),
            auth_mode: AuthMode::PinOtp,
            transports: vec![Transport::WireGuard, Transport::OpenVpn],
            imported_name: None,
        }
    }

    #[test]
    fn summaries_have_no_secret_fields() {
        let status = ConnectionStatus {
            transport: Some(Transport::WireGuard),
            tunnel_ip: Some("10.0.0.2".into()),
            server_endpoint: Some("vpn.example.com:51820".into()),
            connected_since: Some(1),
            last_handshake: Some(2),
            ..ConnectionStatus::disconnected("p1")
        };
        assert_no_secret_keys(&serde_json::to_value(sample_profile()).unwrap());
        assert_no_secret_keys(&serde_json::to_value(status).unwrap());
    }

    #[test]
    fn response_envelope_round_trips() {
        let ok = ResponseEnvelope {
            id: 7,
            outcome: Outcome::Result(Response::Profiles {
                profiles: vec![sample_profile()],
            }),
        };
        let line = encode_line(&ok).unwrap();
        assert_eq!(line.last(), Some(&b'\n'));
        match decode_line::<ServerMessage>(&line).unwrap() {
            ServerMessage::Response(back) => assert_eq!(back, ok),
            ServerMessage::Event(_) => panic!("expected response"),
        }

        let err = ResponseEnvelope {
            id: 8,
            outcome: Outcome::Error(ErrorBody::new(ErrorCode::NotImplemented, "nope")),
        };
        let text = String::from_utf8(encode_line(&err).unwrap()).unwrap();
        assert!(text.contains(r#""error":{"code":"not_implemented""#));
    }

    #[test]
    fn request_debug_hides_credentials_and_import_data() {
        let requests = [
            Request::SubmitCredentials {
                profile_id: "p1".into(),
                pin: Some(Sensitive::new("4321")),
                otp: Some(Sensitive::new("987654")),
            },
            Request::ImportProfile {
                source: ImportSource::uri("https://vpn.example.com/ku/bearer"),
                replace: false,
            },
            Request::ImportProfile {
                source: ImportSource::file("a.ovpn", b"PRIVATE-KEY-BYTES"),
                replace: true,
            },
        ];
        for request in requests {
            let text = format!("{request:?}");
            for needle in ["4321", "987654", "bearer", "UFJJVkFURS1LRVk", "PRIVATE"] {
                assert!(!text.contains(needle), "{text}");
            }
        }
    }

    #[test]
    fn import_source_round_trips() {
        let source = ImportSource::file("a.ovpn", b"hello");
        let json = serde_json::to_string(&source).unwrap();
        let back: ImportSource = serde_json::from_str(&json).unwrap();
        let ImportSource::File { name, data } = back else {
            panic!();
        };
        assert_eq!(name, "a.ovpn");
        assert_eq!(data.decode_base64().unwrap().as_slice(), b"hello");
    }

    #[test]
    fn unknown_event_type_decodes_as_unknown() {
        let line = br#"{"event":{"type":"from_the_future","x":1}}"#;
        match decode_line::<ServerMessage>(line).unwrap() {
            ServerMessage::Event(envelope) => assert!(matches!(envelope.event, Event::Unknown)),
            ServerMessage::Response(_) => panic!("expected event"),
        }
    }

    #[test]
    fn awaiting_is_optional_on_the_wire() {
        let idle = serde_json::to_value(ConnectionStatus::disconnected("p1")).unwrap();
        assert!(idle.get("awaiting").is_none());
        let waiting = ConnectionStatus {
            awaiting: Some(AuthMode::Pin),
            ..ConnectionStatus::disconnected("p1")
        };
        let json = serde_json::to_value(&waiting).unwrap();
        assert_eq!(json["awaiting"], "pin");
        let back: ConnectionStatus = serde_json::from_value(json).unwrap();
        assert_eq!(back, waiting);
        let mut legacy = serde_json::to_value(ConnectionStatus::disconnected("p1")).unwrap();
        legacy.as_object_mut().unwrap().remove("awaiting");
        assert!(
            serde_json::from_value::<ConnectionStatus>(legacy)
                .unwrap()
                .awaiting
                .is_none()
        );
    }

    #[test]
    fn already_exists_serializes_snake_case() {
        let json = serde_json::to_string(&ErrorCode::AlreadyExists).unwrap();
        assert_eq!(json, "\"already_exists\"");
    }

    #[test]
    fn event_decodes_as_event() {
        let line = br#"{"event":{"type":"state_changed","profile_id":"p1","state":"connected"}}"#;
        assert!(matches!(
            decode_line::<ServerMessage>(line).unwrap(),
            ServerMessage::Event(_)
        ));
    }

    fn sample_line(seq: u64) -> LogLine {
        LogLine {
            seq,
            at_ms: 1_700_000_000_000 + seq,
            source: LogSource::Tunnel,
            text: format!("line {seq}"),
        }
    }

    fn request_round_trip(request: Request) -> serde_json::Value {
        let line = encode_line(&RequestEnvelope { id: 1, request }).unwrap();
        let back: RequestEnvelope = decode_line(&line).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(serde_json::to_value(&back).unwrap(), json);
        json["request"].clone()
    }

    fn event_round_trip(event: Event) -> Event {
        let line = encode_line(&EventEnvelope { event }).unwrap();
        match decode_line::<ServerMessage>(&line).unwrap() {
            ServerMessage::Event(envelope) => envelope.event,
            ServerMessage::Response(_) => panic!("expected event"),
        }
    }

    #[test]
    fn new_requests_round_trip() {
        let rename = request_round_trip(Request::RenameProfile {
            profile_id: "p1".into(),
            name: "Office".into(),
        });
        assert_eq!(
            rename,
            serde_json::json!({"type": "rename_profile", "profile_id": "p1", "name": "Office"})
        );
        let log = request_round_trip(Request::SessionLog);
        assert_eq!(log, serde_json::json!({"type": "session_log"}));
        let connect = request_round_trip(Request::Connect {
            profile_id: "p1".into(),
            transport: None,
            auto_reconnect: Some(false),
        });
        assert_eq!(connect["auto_reconnect"], false);
    }

    #[test]
    fn new_responses_round_trip() {
        let renamed = ProfileSummary {
            name: "Home".into(),
            imported_name: Some("Office".into()),
            ..sample_profile()
        };
        for response in [
            Response::Profile { profile: renamed },
            Response::Log {
                profile_id: Some("p1".into()),
                lines: vec![sample_line(1), sample_line(2)],
            },
            Response::Log {
                profile_id: None,
                lines: vec![],
            },
        ] {
            let envelope = ResponseEnvelope {
                id: 3,
                outcome: Outcome::Result(response),
            };
            match decode_line::<ServerMessage>(&encode_line(&envelope).unwrap()).unwrap() {
                ServerMessage::Response(back) => assert_eq!(back, envelope),
                ServerMessage::Event(_) => panic!("expected response"),
            }
        }
    }

    #[test]
    fn hello_round_trips_and_mismatch_names_both_versions() {
        let value = request_round_trip(Request::hello());
        assert_eq!(value["type"], "hello");
        assert_eq!(value["protocol"], PROTOCOL_VERSION);
        assert_eq!(value["client_version"], VERSION);
        assert_eq!(
            request_round_trip(Request::Uninstall { remove_data: true })["remove_data"],
            true
        );
        assert_eq!(
            request_round_trip(Request::InstallCli)["type"],
            "install_cli"
        );

        assert!(check_hello("9.9.9", PROTOCOL_VERSION).is_ok());
        let message = check_hello("0.0.1", PROTOCOL_VERSION + 1)
            .unwrap_err()
            .to_string();
        assert!(message.contains(VERSION));
        assert!(message.contains("0.0.1"));
        assert!(message.contains(&format!("protocol {}", PROTOCOL_VERSION + 1)));
    }

    #[test]
    fn new_events_round_trip() {
        assert!(matches!(
            event_round_trip(Event::ProfilesChanged),
            Event::ProfilesChanged
        ));
        let Event::Log { profile_id, lines } = event_round_trip(Event::Log {
            profile_id: "p1".into(),
            lines: vec![sample_line(4)],
        }) else {
            panic!("expected log");
        };
        assert_eq!(profile_id, "p1");
        assert_eq!(lines, vec![sample_line(4)]);
        let json = serde_json::to_value(sample_line(4)).unwrap();
        assert_eq!(json["source"], "tunnel");
    }

    #[test]
    fn payloads_without_new_fields_decode() {
        let connect: Request =
            serde_json::from_str(r#"{"type":"connect","profile_id":"p1","transport":null}"#)
                .unwrap();
        assert!(matches!(
            connect,
            Request::Connect {
                auto_reconnect: None,
                ..
            }
        ));

        let mut status = serde_json::to_value(ConnectionStatus::disconnected("p1")).unwrap();
        assert!(status.get("local_ip").is_none());
        assert!(status.get("last_handshake").is_none());
        status.as_object_mut().unwrap().remove("local_ip");
        assert!(
            serde_json::from_value::<ConnectionStatus>(status)
                .unwrap()
                .local_ip
                .is_none()
        );

        let profile = serde_json::to_value(sample_profile()).unwrap();
        assert!(profile.get("imported_name").is_none());
        assert_eq!(
            serde_json::from_value::<ProfileSummary>(profile).unwrap(),
            sample_profile()
        );
    }
}
