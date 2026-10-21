use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::mpsc::UnboundedSender;
use tokio::time::{Instant, MissedTickBehavior, interval, sleep, sleep_until, timeout};
use wyvpn_ipc::{
    ConnectionStatus, Event, EventEnvelope, LogLine, Outcome, ProfileSummary, Request, Response,
    ServerMessage,
};

use crate::client::{Client, ClientError, Mismatch};
use crate::error::CmdError;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SessionLogReply {
    pub profile_id: Option<String>,
    pub lines: Vec<LogLine>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonAvailability {
    Available,
    Outdated(Mismatch),
    Unreachable,
    Incompatible(Mismatch),
    NotPermitted,
}

impl DaemonAvailability {
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available | Self::Outdated(_))
    }
}

fn ready_availability(daemon_version: &str, self_restarts: bool) -> DaemonAvailability {
    if self_restarts && daemon_version != wyvpn_ipc::VERSION {
        DaemonAvailability::Outdated(Mismatch::outdated(daemon_version))
    } else {
        DaemonAvailability::Available
    }
}

pub fn classify(error: &ClientError, linux: bool) -> DaemonAvailability {
    match error {
        ClientError::Incompatible(mismatch) => {
            DaemonAvailability::Incompatible((**mismatch).clone())
        }
        ClientError::PermissionDenied if linux => DaemonAvailability::NotPermitted,
        _ => DaemonAvailability::Unreachable,
    }
}

#[derive(Debug, Clone)]
pub enum BridgeMsg {
    Subscribed,
    Availability(DaemonAvailability),
    Event(Event),
    Statuses(Vec<ConnectionStatus>),
    Profiles(Vec<ProfileSummary>),
}

#[derive(Debug, Clone)]
pub struct EventConfig {
    pub backoff: Vec<Duration>,
    pub heartbeat: Duration,
    pub read_timeout: Duration,
    pub healthy_after: Duration,
}

impl Default for EventConfig {
    fn default() -> Self {
        Self {
            backoff: [500, 1000, 2000, 5000].map(Duration::from_millis).to_vec(),
            heartbeat: Duration::from_secs(10),
            read_timeout: Duration::from_secs(30),
            healthy_after: Duration::from_secs(30),
        }
    }
}

pub struct Bridge {
    socket: String,
    availability: Mutex<DaemonAvailability>,
    request_timeout: Duration,
    require_trusted_peer: bool,
}

impl Bridge {
    pub fn new(socket: String) -> Self {
        Self {
            socket,
            availability: Mutex::new(DaemonAvailability::Unreachable),
            request_timeout: Duration::from_secs(60),
            require_trusted_peer: !cfg!(debug_assertions),
        }
    }

    #[cfg(all(test, unix))]
    fn trusting_any_peer(mut self) -> Self {
        self.require_trusted_peer = false;
        self
    }

    pub fn socket(&self) -> &str {
        &self.socket
    }

    pub fn is_available(&self) -> bool {
        self.availability().is_available()
    }

    pub fn availability(&self) -> DaemonAvailability {
        self.availability
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn set_availability(&self, value: DaemonAvailability) -> bool {
        let mut current = self
            .availability
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let changed = *current != value;
        *current = value;
        changed
    }

    pub fn set_available(&self, value: bool) -> bool {
        self.set_availability(if value {
            DaemonAvailability::Available
        } else {
            DaemonAvailability::Unreachable
        })
    }

    fn transition(&self, tx: &UnboundedSender<BridgeMsg>, next: DaemonAvailability) -> bool {
        if self.set_availability(next.clone()) {
            return tx.send(BridgeMsg::Availability(next)).is_ok();
        }
        true
    }

    pub async fn request(&self, request: Request) -> Result<Response, CmdError> {
        let attempt = async {
            let mut client = Client::connect(&self.socket, self.require_trusted_peer).await?;
            client.call(request).await
        };
        match timeout(self.request_timeout, attempt).await {
            Ok(result) => result.map_err(CmdError::from)?,
            Err(_) => Err(CmdError::new("timeout", "the WyVPN service did not answer")),
        }
    }

    pub async fn list_profiles(&self) -> Result<Vec<ProfileSummary>, CmdError> {
        match self.request(Request::ListProfiles).await? {
            Response::Profiles { profiles } => Ok(profiles),
            _ => Err(unexpected()),
        }
    }

    pub async fn statuses(&self) -> Result<Vec<ConnectionStatus>, CmdError> {
        match self.request(Request::Status).await? {
            Response::Status { statuses } => Ok(statuses),
            _ => Err(unexpected()),
        }
    }

    pub async fn import(
        &self,
        source: wyvpn_ipc::ImportSource,
        replace: bool,
    ) -> Result<Vec<ProfileSummary>, CmdError> {
        match self
            .request(Request::ImportProfile { source, replace })
            .await?
        {
            Response::Imported { profiles } => Ok(profiles),
            _ => Err(unexpected()),
        }
    }

    pub async fn rename_profile(
        &self,
        profile_id: String,
        name: String,
    ) -> Result<ProfileSummary, CmdError> {
        match self
            .request(Request::RenameProfile { profile_id, name })
            .await?
        {
            Response::Profile { profile } => Ok(profile),
            _ => Err(unexpected()),
        }
    }

    pub async fn session_log(&self) -> Result<SessionLogReply, CmdError> {
        match self.request(Request::SessionLog).await? {
            Response::Log { profile_id, lines } => Ok(SessionLogReply { profile_id, lines }),
            _ => Err(unexpected()),
        }
    }

    pub async fn ok(&self, request: Request) -> Result<(), CmdError> {
        match self.request(request).await? {
            Response::Ok => Ok(()),
            _ => Err(unexpected()),
        }
    }

    pub async fn run_events(&self, tx: UnboundedSender<BridgeMsg>, config: EventConfig) {
        let mut failures = 0usize;
        loop {
            let next = match subscribe(&self.socket, self.require_trusted_peer).await {
                Ok(client) => {
                    let ready =
                        ready_availability(client.daemon_version(), cfg!(target_os = "macos"));
                    if tx.send(BridgeMsg::Subscribed).is_err() || !self.transition(&tx, ready) {
                        return;
                    }
                    let connected_at = Instant::now();
                    let _ = pump(client, &tx, &config).await;
                    if tx.is_closed() {
                        return;
                    }
                    if connected_at.elapsed() >= config.healthy_after {
                        failures = 0;
                    } else {
                        failures += 1;
                    }
                    DaemonAvailability::Unreachable
                }
                Err(error) => {
                    failures += 1;
                    classify(&error, cfg!(target_os = "linux"))
                }
            };
            if !self.transition(&tx, next) {
                return;
            }
            let step = failures.saturating_sub(1).min(config.backoff.len() - 1);
            sleep(config.backoff[step]).await;
        }
    }
}

fn unexpected() -> CmdError {
    CmdError::internal("unexpected reply from the WyVPN service")
}

async fn subscribe(socket: &str, require_trusted_peer: bool) -> Result<Client, ClientError> {
    let attempt = async {
        let mut client = Client::connect(socket, require_trusted_peer).await?;
        match client.call(Request::Subscribe).await? {
            Ok(Response::Subscribed) => Ok(client),
            _ => Err(ClientError::Closed),
        }
    };
    timeout(Duration::from_secs(5), attempt)
        .await
        .map_err(|_| ClientError::Closed)?
}

async fn pump(
    mut client: Client,
    tx: &UnboundedSender<BridgeMsg>,
    config: &EventConfig,
) -> Result<(), ClientError> {
    let mut beat = interval(config.heartbeat);
    beat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut deadline = Instant::now() + config.read_timeout;
    let mut status_id = None;
    let mut profiles_id = None;
    loop {
        tokio::select! {
            _ = beat.tick() => {
                let sent = timeout(config.read_timeout, async {
                    let status = client.send(Request::Status).await?;
                    let profiles = client.send(Request::ListProfiles).await?;
                    Ok::<_, ClientError>((status, profiles))
                })
                .await
                .map_err(|_| ClientError::Closed)??;
                status_id = Some(sent.0);
                profiles_id = Some(sent.1);
            }
            _ = sleep_until(deadline) => return Err(ClientError::Closed),
            message = client.read() => {
                deadline = Instant::now() + config.read_timeout;
                let message = match message {
                    Ok(message) => message,
                    Err(ClientError::Decode(error)) => {
                        tracing::debug!("skipping undecodable service message: {error}");
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                let sent = match message {
                    ServerMessage::Event(EventEnvelope { event: Event::Unknown }) => Ok(()),
                    ServerMessage::Event(envelope) => tx.send(BridgeMsg::Event(envelope.event)),
                    ServerMessage::Response(response) if Some(response.id) == status_id => {
                        match response.outcome {
                            Outcome::Result(Response::Status { statuses }) => {
                                tx.send(BridgeMsg::Statuses(statuses))
                            }
                            _ => Ok(()),
                        }
                    }
                    ServerMessage::Response(response) if Some(response.id) == profiles_id => {
                        match response.outcome {
                            Outcome::Result(Response::Profiles { profiles }) => {
                                tx.send(BridgeMsg::Profiles(profiles))
                            }
                            _ => Ok(()),
                        }
                    }
                    ServerMessage::Response(_) => Ok(()),
                };
                if sent.is_err() {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod ready_tests {
    use super::*;

    #[test]
    fn outdated_when_daemon_restarts_itself_and_versions_differ() {
        match ready_availability("9.9.9", true) {
            DaemonAvailability::Outdated(mismatch) => {
                assert_eq!(mismatch.daemon_version.as_deref(), Some("9.9.9"));
                assert_eq!(mismatch.daemon_protocol, Some(wyvpn_ipc::PROTOCOL_VERSION));
                assert_eq!(mismatch.client_version, wyvpn_ipc::VERSION);
                assert_eq!(mismatch.client_protocol, wyvpn_ipc::PROTOCOL_VERSION);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn available_when_daemon_does_not_restart_itself_or_versions_match() {
        assert_eq!(
            ready_availability("9.9.9", false),
            DaemonAvailability::Available
        );
        assert_eq!(
            ready_availability(wyvpn_ipc::VERSION, true),
            DaemonAvailability::Available
        );
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;
    use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};
    use tokio::task::{JoinHandle, JoinSet};
    use wyvpn_ipc::{
        AuthMode, ConnectionState, ErrorBody, ErrorCode, EventEnvelope, ImportSource,
        RequestEnvelope, ResponseEnvelope, Sensitive, Transport, decode_line, encode_line,
    };

    type Log = Arc<Mutex<Vec<Request>>>;

    fn profile() -> ProfileSummary {
        ProfileSummary {
            id: "p1".into(),
            name: "Office".into(),
            server_name: "gw".into(),
            server_host: "vpn.example.com".into(),
            user: "alice".into(),
            auth_mode: AuthMode::Pin,
            transports: vec![Transport::OpenVpn],
            imported_name: None,
        }
    }

    fn reply(request: &Request) -> Outcome {
        match request {
            Request::ListProfiles => Outcome::Result(Response::Profiles {
                profiles: vec![profile()],
            }),
            Request::Status => Outcome::Result(Response::Status {
                statuses: vec![ConnectionStatus::disconnected("p1")],
            }),
            Request::Subscribe => Outcome::Result(Response::Subscribed),
            Request::Hello { .. } => Outcome::Result(Response::Hello {
                daemon_version: wyvpn_ipc::VERSION.into(),
                protocol: wyvpn_ipc::PROTOCOL_VERSION,
            }),
            Request::ImportProfile { .. } => Outcome::Result(Response::Imported {
                profiles: vec![profile()],
            }),
            Request::Connect { .. } => {
                Outcome::Error(ErrorBody::new(ErrorCode::InvalidState, "busy\u{1b}[31m"))
            }
            Request::RenameProfile { profile_id, .. } if profile_id == "old" => {
                Outcome::Error(ErrorBody::new(ErrorCode::InvalidRequest, "unknown request"))
            }
            Request::RenameProfile { name, .. } => Outcome::Result(Response::Profile {
                profile: ProfileSummary {
                    name: name.clone(),
                    imported_name: Some("Office".into()),
                    ..profile()
                },
            }),
            Request::SessionLog => Outcome::Result(Response::Log {
                profile_id: Some("p1".into()),
                lines: vec![wyvpn_ipc::LogLine {
                    seq: 1,
                    at_ms: 5,
                    source: wyvpn_ipc::LogSource::Daemon,
                    text: "connecting".into(),
                }],
            }),
            _ => Outcome::Result(Response::Ok),
        }
    }

    async fn serve(
        stream: tokio::net::UnixStream,
        log: Log,
        silent: bool,
        noisy: bool,
        log_hello: bool,
    ) {
        let (reader, mut writer) = tokio::io::split(stream);
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let Ok(envelope) = decode_line::<RequestEnvelope>(line.as_bytes()) else {
                return;
            };
            if log_hello || !matches!(envelope.request, Request::Hello { .. }) {
                log.lock().unwrap().push(envelope.request.clone());
            }
            let subscribed = matches!(envelope.request, Request::Subscribe);
            if silent && !subscribed && !matches!(envelope.request, Request::Hello { .. }) {
                continue;
            }
            let response = ResponseEnvelope {
                id: envelope.id,
                outcome: reply(&envelope.request),
            };
            writer
                .write_all(&encode_line(&response).unwrap())
                .await
                .unwrap();
            if subscribed {
                if noisy {
                    writer
                        .write_all(
                            b"this is not json\n{\"event\":{\"type\":\"from_the_future\"}}\n",
                        )
                        .await
                        .unwrap();
                }
                let event = EventEnvelope {
                    event: Event::StateChanged {
                        profile_id: "p1".into(),
                        state: ConnectionState::Connecting,
                        error: None,
                    },
                };
                writer
                    .write_all(&encode_line(&event).unwrap())
                    .await
                    .unwrap();
            }
        }
    }

    fn fake(path: &Path, silent: bool) -> (JoinHandle<()>, Log) {
        fake_with(path, silent, false)
    }

    fn fake_with(path: &Path, silent: bool, noisy: bool) -> (JoinHandle<()>, Log) {
        spawn_fake(path, silent, noisy, false)
    }

    fn fake_logging_hello(path: &Path) -> (JoinHandle<()>, Log) {
        spawn_fake(path, false, false, true)
    }

    fn spawn_fake(
        path: &Path,
        silent: bool,
        noisy: bool,
        log_hello: bool,
    ) -> (JoinHandle<()>, Log) {
        let listener = UnixListener::bind(path).unwrap();
        let log = Log::default();
        let shared = log.clone();
        let handle = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                connections.spawn(serve(stream, shared.clone(), silent, noisy, log_hello));
            }
        });
        (handle, log)
    }

    fn socket() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("d.sock");
        (dir, path)
    }

    fn quick() -> EventConfig {
        EventConfig {
            backoff: vec![Duration::from_millis(20)],
            heartbeat: Duration::from_millis(50),
            read_timeout: Duration::from_millis(300),
            healthy_after: Duration::from_millis(100),
        }
    }

    async fn next(rx: &mut UnboundedReceiver<BridgeMsg>) -> BridgeMsg {
        timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("bridge message")
            .expect("channel open")
    }

    async fn expect_availability(rx: &mut UnboundedReceiver<BridgeMsg>, want: bool) {
        loop {
            if let BridgeMsg::Availability(got) = next(rx).await {
                assert_eq!(got.is_available(), want);
                return;
            }
        }
    }

    #[tokio::test]
    async fn requests_map_to_ipc_and_back() {
        let (_dir, path) = socket();
        let (_server, log) = fake(&path, false);
        let bridge = Bridge::new(path.to_string_lossy().into_owned()).trusting_any_peer();

        assert_eq!(bridge.list_profiles().await.unwrap(), vec![profile()]);
        assert_eq!(bridge.statuses().await.unwrap().len(), 1);
        bridge
            .import(ImportSource::file("a.ovpn", b"data"), true)
            .await
            .unwrap();
        bridge
            .ok(Request::SubmitCredentials {
                profile_id: "p1".into(),
                pin: Some(Sensitive::new("1234")),
                otp: None,
            })
            .await
            .unwrap();
        bridge
            .ok(Request::Disconnect {
                profile_id: "p1".into(),
            })
            .await
            .unwrap();

        let log = log.lock().unwrap();
        assert!(matches!(log[0], Request::ListProfiles));
        assert!(matches!(log[1], Request::Status));
        match &log[2] {
            Request::ImportProfile {
                source: ImportSource::File { name, data },
                replace: true,
            } => {
                assert_eq!(name, "a.ovpn");
                assert_eq!(data.decode_base64().unwrap().as_slice(), b"data");
            }
            other => panic!("{other:?}"),
        }
        match &log[3] {
            Request::SubmitCredentials {
                pin: Some(pin),
                otp: None,
                ..
            } => {
                assert_eq!(pin.expose(), "1234");
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(log[4], Request::Disconnect { .. }));
    }

    #[tokio::test]
    async fn daemon_errors_and_unavailability_map_to_codes() {
        let (_dir, path) = socket();
        let bridge = Bridge::new(path.to_string_lossy().into_owned()).trusting_any_peer();
        let error = bridge.list_profiles().await.unwrap_err();
        assert_eq!(error.code, "daemon_unavailable");

        let (_server, _log) = fake(&path, false);
        let error = bridge
            .ok(Request::Connect {
                profile_id: "p1".into(),
                transport: None,
                auto_reconnect: None,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, "invalid_state");
        assert_eq!(error.message, "busy[31m");
    }

    #[tokio::test]
    async fn rename_maps_to_ipc_and_back() {
        let (_dir, path) = socket();
        let (_server, log) = fake(&path, false);
        let bridge = Bridge::new(path.to_string_lossy().into_owned()).trusting_any_peer();

        let renamed = bridge
            .rename_profile("p1".into(), "Home".into())
            .await
            .unwrap();
        assert_eq!(renamed.name, "Home");
        assert_eq!(renamed.imported_name.as_deref(), Some("Office"));
        match &log.lock().unwrap()[0] {
            Request::RenameProfile { profile_id, name } => {
                assert_eq!((profile_id.as_str(), name.as_str()), ("p1", "Home"));
            }
            other => panic!("{other:?}"),
        }

        let error = bridge
            .rename_profile("old".into(), "x".into())
            .await
            .unwrap_err();
        assert_eq!(error.code, "invalid_request");
    }

    #[tokio::test]
    async fn session_log_maps_to_the_command_shape() {
        let (_dir, path) = socket();
        let (_server, log) = fake(&path, false);
        let bridge = Bridge::new(path.to_string_lossy().into_owned()).trusting_any_peer();

        let reply = bridge.session_log().await.unwrap();
        assert!(matches!(log.lock().unwrap()[0], Request::SessionLog));
        assert_eq!(reply.profile_id.as_deref(), Some("p1"));
        assert_eq!(reply.lines[0].text, "connecting");
        assert_eq!(
            serde_json::to_value(&reply).unwrap(),
            serde_json::json!({
                "profile_id": "p1",
                "lines": [{"seq": 1, "at_ms": 5, "source": "daemon", "text": "connecting"}],
            })
        );
    }

    #[tokio::test]
    async fn connect_requests_carry_the_reconnect_setting() {
        let (_dir, path) = socket();
        let (_server, log) = fake(&path, false);
        let bridge = Bridge::new(path.to_string_lossy().into_owned()).trusting_any_peer();
        let settings = crate::settings::Settings {
            auto_reconnect: false,
            ..Default::default()
        };

        let _ = bridge.ok(settings.connect_request("p1".into(), None)).await;
        assert!(matches!(
            log.lock().unwrap()[0],
            Request::Connect {
                auto_reconnect: Some(false),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn connect_requests_pass_the_chosen_transport_through() {
        let (_dir, path) = socket();
        let (_server, log) = fake(&path, false);
        let bridge = Bridge::new(path.to_string_lossy().into_owned()).trusting_any_peer();
        let settings = crate::settings::Settings::default();

        for transport in [Some(Transport::WireGuard), Some(Transport::OpenVpn), None] {
            let _ = bridge
                .ok(settings.connect_request("p1".into(), transport))
                .await;
        }
        let sent: Vec<_> = log
            .lock()
            .unwrap()
            .iter()
            .map(|request| match request {
                Request::Connect { transport, .. } => *transport,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            sent,
            [Some(Transport::WireGuard), Some(Transport::OpenVpn), None]
        );
    }

    #[tokio::test]
    async fn profile_and_log_events_reach_the_model_channel() {
        let (_dir, path) = socket();
        let listener = UnixListener::bind(&path).unwrap();
        let _server = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (reader, mut writer) = tokio::io::split(stream);
                    let mut lines = BufReader::new(reader).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let envelope = decode_line::<RequestEnvelope>(line.as_bytes()).unwrap();
                        let response = ResponseEnvelope {
                            id: envelope.id,
                            outcome: reply(&envelope.request),
                        };
                        writer
                            .write_all(&encode_line(&response).unwrap())
                            .await
                            .unwrap();
                        if matches!(envelope.request, Request::Subscribe) {
                            for event in [
                                Event::ProfilesChanged,
                                Event::Log {
                                    profile_id: "p1".into(),
                                    lines: vec![],
                                },
                            ] {
                                writer
                                    .write_all(&encode_line(&EventEnvelope { event }).unwrap())
                                    .await
                                    .unwrap();
                            }
                        }
                    }
                });
            }
        });
        let bridge = Arc::new(Bridge::new(path.to_string_lossy().into_owned()).trusting_any_peer());
        let (tx, mut rx) = unbounded_channel();
        let task = tokio::spawn({
            let bridge = bridge.clone();
            async move { bridge.run_events(tx, quick()).await }
        });

        let (mut changed, mut logged) = (false, false);
        while !(changed && logged) {
            match next(&mut rx).await {
                BridgeMsg::Event(Event::ProfilesChanged) => {
                    assert!(crate::shell::refreshes_profiles(&BridgeMsg::Event(
                        Event::ProfilesChanged
                    )));
                    changed = true;
                }
                BridgeMsg::Event(Event::Log { profile_id, .. }) => {
                    assert_eq!(profile_id, "p1");
                    logged = true;
                }
                _ => {}
            }
        }
        task.abort();
    }

    #[tokio::test]
    async fn forwards_events_and_heartbeat_statuses() {
        let (_dir, path) = socket();
        let (_server, _log) = fake(&path, false);
        let bridge = Arc::new(Bridge::new(path.to_string_lossy().into_owned()).trusting_any_peer());
        let (tx, mut rx) = unbounded_channel();
        let task = tokio::spawn({
            let bridge = bridge.clone();
            async move { bridge.run_events(tx, quick()).await }
        });

        expect_availability(&mut rx, true).await;
        assert!(bridge.is_available());
        let (mut saw_event, mut saw_status, mut saw_profiles) = (false, false, false);
        while !(saw_event && saw_status && saw_profiles) {
            match next(&mut rx).await {
                BridgeMsg::Event(Event::StateChanged { state, .. }) => {
                    assert_eq!(state, ConnectionState::Connecting);
                    saw_event = true;
                }
                BridgeMsg::Statuses(statuses) => {
                    assert_eq!(statuses[0].profile_id, "p1");
                    saw_status = true;
                }
                BridgeMsg::Profiles(profiles) => {
                    assert_eq!(profiles, vec![profile()]);
                    saw_profiles = true;
                }
                BridgeMsg::Subscribed => {}
                other => panic!("{other:?}"),
            }
        }
        task.abort();
    }

    #[tokio::test]
    async fn undecodable_and_unknown_messages_keep_the_connection() {
        let (_dir, path) = socket();
        let (_server, log) = fake_with(&path, false, true);
        let bridge = Arc::new(Bridge::new(path.to_string_lossy().into_owned()).trusting_any_peer());
        let (tx, mut rx) = unbounded_channel();
        let task = tokio::spawn({
            let bridge = bridge.clone();
            async move { bridge.run_events(tx, quick()).await }
        });

        expect_availability(&mut rx, true).await;
        let (mut saw_event, mut beats) = (false, 0);
        while !saw_event || beats < 3 {
            match next(&mut rx).await {
                BridgeMsg::Event(Event::StateChanged { .. }) => saw_event = true,
                BridgeMsg::Statuses(_) => beats += 1,
                BridgeMsg::Profiles(_) | BridgeMsg::Subscribed => {}
                other => panic!("{other:?}"),
            }
        }
        let subscribes = log
            .lock()
            .unwrap()
            .iter()
            .filter(|request| matches!(request, Request::Subscribe))
            .count();
        assert_eq!(subscribes, 1);
        assert!(bridge.is_available());
        task.abort();
    }

    async fn flapping_server(path: &Path) -> (JoinHandle<()>, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = UnixListener::bind(path).unwrap();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = accepted.clone();
        let handle = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                let (reader, mut writer) = tokio::io::split(stream);
                let mut lines = BufReader::new(reader).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let envelope = decode_line::<RequestEnvelope>(line.as_bytes()).unwrap();
                    let subscribed = matches!(envelope.request, Request::Subscribe);
                    let response = ResponseEnvelope {
                        id: envelope.id,
                        outcome: reply(&envelope.request),
                    };
                    writer
                        .write_all(&encode_line(&response).unwrap())
                        .await
                        .unwrap();
                    if subscribed {
                        break;
                    }
                }
            }
        });
        (handle, accepted)
    }

    #[tokio::test]
    async fn short_lived_connections_keep_backing_off() {
        let (_dir, path) = socket();
        let (_server, accepted) = flapping_server(&path).await;
        let bridge = Arc::new(Bridge::new(path.to_string_lossy().into_owned()).trusting_any_peer());
        let (tx, _rx) = unbounded_channel();
        let config = EventConfig {
            backoff: vec![Duration::from_millis(10), Duration::from_secs(3600)],
            healthy_after: Duration::from_secs(3600),
            ..quick()
        };
        let task = tokio::spawn({
            let bridge = bridge.clone();
            async move { bridge.run_events(tx, config).await }
        });
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
        task.abort();
    }

    #[tokio::test]
    async fn reconnects_after_daemon_restart() {
        let (_dir, path) = socket();
        let (server, _log) = fake(&path, false);
        let bridge = Arc::new(Bridge::new(path.to_string_lossy().into_owned()).trusting_any_peer());
        let (tx, mut rx) = unbounded_channel();
        let task = tokio::spawn({
            let bridge = bridge.clone();
            async move { bridge.run_events(tx, quick()).await }
        });
        expect_availability(&mut rx, true).await;

        server.abort();
        let _ = server.await;
        std::fs::remove_file(&path).unwrap();
        expect_availability(&mut rx, false).await;
        assert!(!bridge.is_available());

        let (_server, _log) = fake(&path, false);
        expect_availability(&mut rx, true).await;
        assert!(bridge.is_available());
        task.abort();
    }

    #[tokio::test]
    async fn silent_daemon_is_detected_by_read_timeout() {
        let (_dir, path) = socket();
        let (_server, _log) = fake(&path, true);
        let bridge = Arc::new(Bridge::new(path.to_string_lossy().into_owned()).trusting_any_peer());
        let (tx, mut rx) = unbounded_channel();
        let task = tokio::spawn({
            let bridge = bridge.clone();
            async move { bridge.run_events(tx, quick()).await }
        });
        expect_availability(&mut rx, true).await;
        expect_availability(&mut rx, false).await;
        task.abort();
    }

    fn serve_fixed(path: &Path, outcome: Outcome) -> JoinHandle<()> {
        let listener = UnixListener::bind(path).unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let outcome = outcome.clone();
                tokio::spawn(async move {
                    let (reader, mut writer) = tokio::io::split(stream);
                    let mut lines = BufReader::new(reader).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let envelope = decode_line::<RequestEnvelope>(line.as_bytes()).unwrap();
                        let response = ResponseEnvelope {
                            id: envelope.id,
                            outcome: if matches!(envelope.request, Request::Subscribe) {
                                Outcome::Result(Response::Subscribed)
                            } else {
                                outcome.clone()
                            },
                        };
                        writer
                            .write_all(&encode_line(&response).unwrap())
                            .await
                            .unwrap();
                    }
                });
            }
        })
    }

    async fn first_availability(bridge: &Arc<Bridge>) -> DaemonAvailability {
        let (tx, mut rx) = unbounded_channel();
        let task = tokio::spawn({
            let bridge = bridge.clone();
            async move { bridge.run_events(tx, quick()).await }
        });
        loop {
            if let BridgeMsg::Availability(got) = next(&mut rx).await {
                task.abort();
                return got;
            }
        }
    }

    #[tokio::test]
    async fn every_connection_starts_with_hello() {
        let (_dir, path) = socket();
        let (_server, log) = fake_logging_hello(&path);
        let bridge = Bridge::new(path.to_string_lossy().into_owned()).trusting_any_peer();
        bridge.list_profiles().await.unwrap();
        bridge.statuses().await.unwrap();
        let log = log.lock().unwrap();
        assert!(matches!(log[0], Request::Hello { .. }));
        assert!(matches!(log[1], Request::ListProfiles));
        assert!(matches!(log[2], Request::Hello { .. }));
        assert!(matches!(log[3], Request::Status));
    }

    #[tokio::test]
    async fn subscription_says_hello_first() {
        let (_dir, path) = socket();
        let (_server, log) = fake_logging_hello(&path);
        let bridge = Arc::new(Bridge::new(path.to_string_lossy().into_owned()).trusting_any_peer());
        assert_eq!(
            first_availability(&bridge).await,
            DaemonAvailability::Available
        );
        let log = log.lock().unwrap();
        assert!(matches!(log[0], Request::Hello { .. }));
        assert!(matches!(log[1], Request::Subscribe));
    }

    #[tokio::test]
    async fn protocol_mismatch_is_incompatible() {
        let (_dir, path) = socket();
        let _server = serve_fixed(
            &path,
            Outcome::Result(Response::Hello {
                daemon_version: "9.9.9".into(),
                protocol: wyvpn_ipc::PROTOCOL_VERSION + 1,
            }),
        );
        let bridge = Arc::new(Bridge::new(path.to_string_lossy().into_owned()).trusting_any_peer());
        match first_availability(&bridge).await {
            DaemonAvailability::Incompatible(mismatch) => {
                assert_eq!(mismatch.daemon_version.as_deref(), Some("9.9.9"));
                assert_eq!(
                    mismatch.daemon_protocol,
                    Some(wyvpn_ipc::PROTOCOL_VERSION + 1)
                );
                assert_eq!(mismatch.client_version, wyvpn_ipc::VERSION);
            }
            other => panic!("{other:?}"),
        }
        assert!(!bridge.is_available());
        let error = bridge.list_profiles().await.unwrap_err();
        assert_eq!(error.code, "daemon_unavailable");
        assert!(error.message.contains("9.9.9"));
    }

    #[tokio::test]
    async fn same_protocol_other_version_is_outdated() {
        let (_dir, path) = socket();
        let _server = serve_fixed(
            &path,
            Outcome::Result(Response::Hello {
                daemon_version: "9.9.9".into(),
                protocol: wyvpn_ipc::PROTOCOL_VERSION,
            }),
        );
        let bridge = Arc::new(Bridge::new(path.to_string_lossy().into_owned()).trusting_any_peer());
        assert_eq!(
            first_availability(&bridge).await,
            ready_availability("9.9.9", cfg!(target_os = "macos"))
        );
        assert!(bridge.is_available());
    }

    #[tokio::test]
    async fn same_protocol_same_version_is_available() {
        let (_dir, path) = socket();
        let _server = serve_fixed(
            &path,
            Outcome::Result(Response::Hello {
                daemon_version: wyvpn_ipc::VERSION.into(),
                protocol: wyvpn_ipc::PROTOCOL_VERSION,
            }),
        );
        let bridge = Arc::new(Bridge::new(path.to_string_lossy().into_owned()).trusting_any_peer());
        assert_eq!(
            first_availability(&bridge).await,
            DaemonAvailability::Available
        );
    }

    #[tokio::test]
    async fn older_daemon_rejecting_hello_is_incompatible() {
        let (_dir, path) = socket();
        let _server = serve_fixed(
            &path,
            Outcome::Error(ErrorBody::new(
                ErrorCode::InvalidRequest,
                "unknown variant `hello`",
            )),
        );
        let bridge = Arc::new(Bridge::new(path.to_string_lossy().into_owned()).trusting_any_peer());
        match first_availability(&bridge).await {
            DaemonAvailability::Incompatible(mismatch) => {
                assert_eq!(mismatch.daemon_version, None);
                assert_eq!(mismatch.daemon_protocol, None);
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_socket_is_unreachable() {
        let (_dir, path) = socket();
        let bridge = Arc::new(Bridge::new(path.to_string_lossy().into_owned()).trusting_any_peer());
        let (tx, mut rx) = unbounded_channel();
        let task = tokio::spawn({
            let bridge = bridge.clone();
            async move { bridge.run_events(tx, quick()).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(rx.try_recv().is_err());
        assert_eq!(bridge.availability(), DaemonAvailability::Unreachable);
        task.abort();
    }

    #[test]
    fn permission_denied_maps_to_not_permitted_on_linux_only() {
        assert_eq!(
            classify(&ClientError::PermissionDenied, true),
            DaemonAvailability::NotPermitted
        );
        assert_eq!(
            classify(&ClientError::PermissionDenied, false),
            DaemonAvailability::Unreachable
        );
        let refused = ClientError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        assert_eq!(classify(&refused, true), DaemonAvailability::Unreachable);
        assert_eq!(
            classify(&ClientError::UntrustedPeer, true),
            DaemonAvailability::Unreachable
        );
    }

    #[tokio::test]
    async fn unreadable_socket_is_permission_denied() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path) = socket();
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let denied = std::os::unix::net::UnixStream::connect(&path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied);
        if denied {
            let error = Client::connect(&path.to_string_lossy(), false).await.err();
            assert!(matches!(error, Some(ClientError::PermissionDenied)));
            let cmd = CmdError::from(ClientError::PermissionDenied);
            assert_eq!(cmd.code, "permission_denied");
        }
    }
}
