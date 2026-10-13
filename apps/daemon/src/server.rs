use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::OwnedSemaphorePermit;
use tokio::sync::broadcast::{self, error::RecvError};
use wyvpn_ipc::{
    ErrorBody, ErrorCode, Event, EventEnvelope, Outcome, Request, RequestEnvelope,
    ResponseEnvelope, decode_line, encode_line,
};
use zeroize::{Zeroize, Zeroizing};

use crate::admin::Peer;
use crate::control::dispatch;
use crate::state::State;

pub const MAX_LINE_BYTES: usize = 512 * 1024;

async fn next_event(events: &mut Option<broadcast::Receiver<Event>>) -> Option<Event> {
    let Some(rx) = events else {
        return std::future::pending().await;
    };
    loop {
        match rx.recv().await {
            Ok(event) => return Some(event),
            Err(RecvError::Lagged(_)) => {}
            Err(RecvError::Closed) => return None,
        }
    }
}

fn request_id(line: &[u8]) -> u64 {
    serde_json::from_slice::<serde_json::Value>(line)
        .ok()
        .and_then(|value| value["id"].as_u64())
        .unwrap_or(0)
}

enum Line {
    Complete,
    Eof,
}

async fn read_line<R>(reader: &mut R, line: &mut Vec<u8>, max: usize) -> io::Result<Line>
where
    R: AsyncBufRead + Unpin,
{
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(if line.is_empty() {
                Line::Eof
            } else {
                Line::Complete
            });
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.unwrap_or(available.len());
        if line.len() + take > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request line too long",
            ));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Line::Complete);
        }
    }
}

pub async fn handle_connection<S>(
    stream: S,
    state: Arc<State>,
    peer: Peer,
    idle: Duration,
    _permit: OwnedSemaphorePermit,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    if let Err(err) = run(stream, &state, &peer, idle).await {
        tracing::debug!(%err, "connection closed with error");
    }
}

async fn idle_timeout(subscribed: bool, idle: Duration) {
    if subscribed {
        std::future::pending::<()>().await;
    } else {
        tokio::time::sleep(idle).await;
    }
}

async fn run<S>(stream: S, state: &Arc<State>, peer: &Peer, idle: Duration) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line = Zeroizing::new(Vec::new());
    let mut events = None;

    loop {
        tokio::select! {
            () = idle_timeout(events.is_some(), idle) => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "idle connection closed"));
            }
            read = read_line(&mut reader, &mut line, MAX_LINE_BYTES) => {
                match read {
                    Ok(Line::Eof) => return Ok(()),
                    Ok(Line::Complete) => {}
                    Err(err) => {
                        let reply = ResponseEnvelope {
                            id: 0,
                            outcome: Outcome::Error(ErrorBody::new(ErrorCode::InvalidRequest, "request line too long")),
                        };
                        if err.kind() == io::ErrorKind::InvalidData {
                            let _ = writer.write_all(&encode_line(&reply)?).await;
                        }
                        return Err(err);
                    }
                }
                if line.trim_ascii().is_empty() {
                    line.zeroize();
                    continue;
                }
                let reply = match decode_line::<RequestEnvelope>(&line) {
                    Ok(envelope) => {
                        line.zeroize();
                        if matches!(envelope.request, Request::Subscribe) && events.is_none() {
                            events = Some(state.events.subscribe());
                        }
                        ResponseEnvelope { id: envelope.id, outcome: dispatch(state, peer, envelope.request).await }
                    }
                    Err(err) => {
                        let id = request_id(&line);
                        line.zeroize();
                        ResponseEnvelope {
                            id,
                            outcome: Outcome::Error(ErrorBody::new(ErrorCode::InvalidRequest, err.to_string())),
                        }
                    }
                };
                writer.write_all(&encode_line(&reply)?).await?;
            }
            event = next_event(&mut events) => {
                match event {
                    Some(event) => writer.write_all(&encode_line(&EventEnvelope { event })?).await?,
                    None => events = None,
                }
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::path::{Path, PathBuf};

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    use wyvpn_ipc::{
        AuthMode, ConnectionState, ConnectionStatus, ImportSource, MAX_IMPORT_BYTES,
        ProfileSummary, Response, Sensitive, ServerMessage, Transport,
    };

    use super::*;
    use crate::launcher::{Launcher, fake};
    use crate::listener::{Limits, bind, serve};
    use crate::openvpn::management::TunnelEvent;
    use crate::state::MemoryProfiles;
    use crate::storage::FileProfiles;
    use crate::testdata;

    struct Client {
        lines: tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
        writer: tokio::net::unix::OwnedWriteHalf,
        next_id: u64,
    }

    impl Client {
        async fn connect(path: &Path) -> Self {
            let (reader, writer) = UnixStream::connect(path).await.unwrap().into_split();
            Self {
                lines: BufReader::new(reader).lines(),
                writer,
                next_id: 1,
            }
        }

        async fn call(&mut self, request: Request) -> ResponseEnvelope {
            let id = self.next_id;
            self.next_id += 1;
            let line = encode_line(&RequestEnvelope { id, request }).unwrap();
            self.writer.write_all(&line).await.unwrap();
            match self.read().await {
                ServerMessage::Response(response) => {
                    assert_eq!(response.id, id);
                    response
                }
                ServerMessage::Event(_) => panic!("unexpected event"),
            }
        }

        async fn read(&mut self) -> ServerMessage {
            let line = self.lines.next_line().await.unwrap().unwrap();
            decode_line(line.as_bytes()).unwrap()
        }

        async fn event(&mut self) -> Event {
            match self.read().await {
                ServerMessage::Event(envelope) => envelope.event,
                ServerMessage::Response(_) => panic!("expected event"),
            }
        }
    }

    struct Harness {
        dir: tempfile::TempDir,
        socket: PathBuf,
        state: Arc<State>,
        _stop: tokio::sync::oneshot::Sender<()>,
    }

    impl Harness {
        async fn new() -> Self {
            Self::limited(Limits::default()).await
        }

        async fn limited(limits: Limits) -> Self {
            let dir = testdata::private_tempdir();
            let store = FileProfiles::open(dir.path().join("data")).unwrap();
            Self::start(dir, Arc::new(State::new(store)), limits).await
        }

        async fn launching(launcher: Arc<dyn Launcher>) -> Self {
            let dir = testdata::private_tempdir();
            let store = FileProfiles::open(dir.path().join("data")).unwrap();
            let state = Arc::new(State::with_launcher(store, launcher));
            Self::start(dir, state, Limits::default()).await
        }

        async fn with_state(dir: tempfile::TempDir, state: Arc<State>) -> Self {
            Self::start(dir, state, Limits::default()).await
        }

        async fn start(dir: tempfile::TempDir, state: Arc<State>, limits: Limits) -> Self {
            let socket = dir.path().join("wyvpn.sock");
            let listener = bind(socket.to_str().unwrap(), "").unwrap();
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let served = state.clone();
            tokio::spawn(async move {
                let _ = serve(listener, served, limits, async {
                    let _ = stopped.await;
                })
                .await;
            });
            Self {
                dir,
                socket,
                state,
                _stop: stop,
            }
        }

        async fn client(&self) -> Client {
            Client::connect(&self.socket).await
        }

        async fn import_as(&self, client: &mut Client, contents: &str, replace: bool) -> Outcome {
            let source = ImportSource::file("/anywhere/office.ovpn", contents.as_bytes());
            client
                .call(Request::ImportProfile { source, replace })
                .await
                .outcome
        }

        async fn import(&self, client: &mut Client, contents: &str) -> ProfileSummary {
            let Outcome::Result(Response::Imported { mut profiles }) =
                self.import_as(client, contents, false).await
            else {
                panic!("import failed");
            };
            assert_eq!(profiles.len(), 1);
            profiles.remove(0)
        }
    }

    fn error_of(response: ResponseEnvelope) -> ErrorBody {
        match response.outcome {
            Outcome::Error(error) => error,
            Outcome::Result(other) => panic!("expected error, got {other:?}"),
        }
    }

    fn connect_request(profile_id: &str, transport: Option<Transport>) -> Request {
        Request::Connect {
            profile_id: profile_id.to_owned(),
            transport,
            auto_reconnect: None,
        }
    }

    fn submit_request(profile_id: &str, pin: Option<&str>) -> Request {
        Request::SubmitCredentials {
            profile_id: profile_id.to_owned(),
            pin: pin.map(Sensitive::new),
            otp: None,
        }
    }

    #[tokio::test]
    async fn list_and_status_round_trip() {
        let state = Arc::new(State::new(MemoryProfiles::default()));
        let profile = wyvpn_core::Profile::parse(testdata::PIN_PROFILE).unwrap();
        let stored = crate::state::StoredProfile {
            id: "p1".into(),
            name: "Office".into(),
            display_name: None,
            profile,
            tls_pins: Default::default(),
        };
        state.source.save(&stored).unwrap();
        let connected = ConnectionStatus {
            profile_name: "Office".into(),
            state: ConnectionState::Connected,
            tunnel_ip: Some("10.0.0.2".into()),
            ..ConnectionStatus::disconnected("p1")
        };
        state.set_status(connected.clone());
        let harness = Harness::with_state(testdata::private_tempdir(), state).await;
        let mut client = harness.client().await;

        let listed = client.call(Request::ListProfiles).await;
        assert_eq!(
            listed.outcome,
            Outcome::Result(Response::Profiles {
                profiles: vec![stored.summary()]
            })
        );
        assert_eq!(stored.summary().auth_mode, AuthMode::Pin);

        let status = client.call(Request::Status).await;
        assert_eq!(
            status.outcome,
            Outcome::Result(Response::Status {
                statuses: vec![connected]
            })
        );
    }

    #[tokio::test]
    async fn malformed_request_gets_error_and_connection_survives() {
        let harness = Harness::new().await;
        let mut client = harness.client().await;

        client
            .writer
            .write_all(b"{\"id\":5,\"request\":1}\n")
            .await
            .unwrap();
        let ServerMessage::Response(response) = client.read().await else {
            panic!("expected response");
        };
        assert_eq!(response.id, 5);
        assert!(
            matches!(response.outcome, Outcome::Error(ref e) if e.code == ErrorCode::InvalidRequest)
        );

        assert!(matches!(
            client.call(Request::Status).await.outcome,
            Outcome::Result(Response::Status { .. })
        ));
    }

    #[tokio::test]
    async fn subscribers_receive_events() {
        let harness = Harness::new().await;
        let mut client = harness.client().await;

        assert_eq!(
            client.call(Request::Subscribe).await.outcome,
            Outcome::Result(Response::Subscribed)
        );
        harness.state.publish(Event::StateChanged {
            profile_id: "p1".into(),
            state: ConnectionState::Connecting,
            error: None,
        });
        assert!(matches!(client.read().await, ServerMessage::Event(_)));
    }

    #[tokio::test]
    async fn import_with_the_same_profile_twice_is_invalid() {
        let harness = Harness::new().await;
        let mut client = harness.client().await;
        let mut builder = tar::Builder::new(Vec::new());
        for name in ["one.ovpn", "two.ovpn"] {
            let data = testdata::PIN_PROFILE.as_bytes();
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            builder.append_data(&mut header, name, data).unwrap();
        }
        let bytes = builder.into_inner().unwrap();
        let source = ImportSource::file("bundle.tar", &bytes);
        for replace in [false, true] {
            let outcome = client
                .call(Request::ImportProfile {
                    source: source.clone(),
                    replace,
                })
                .await
                .outcome;
            let Outcome::Error(error) = outcome else {
                panic!("expected an error");
            };
            assert_eq!(error.code, ErrorCode::InvalidRequest);
            assert_eq!(error.message, "the import contains the same profile twice");
        }
        let Outcome::Result(Response::Profiles { profiles }) =
            client.call(Request::ListProfiles).await.outcome
        else {
            panic!();
        };
        assert!(profiles.is_empty());
    }

    #[tokio::test]
    async fn import_list_and_remove() {
        let harness = Harness::new().await;
        let mut client = harness.client().await;
        let summary = harness.import(&mut client, testdata::PIN_PROFILE).await;
        assert_eq!(summary.name, "office");
        assert_eq!(summary.user, "alice");
        assert_eq!(summary.auth_mode, AuthMode::Pin);
        assert_eq!(
            summary.transports,
            vec![Transport::OpenVpn, Transport::WireGuard]
        );

        assert_eq!(summary.id.len(), 32);
        let refused = harness
            .import_as(&mut client, testdata::PIN_PROFILE, false)
            .await;
        assert!(matches!(refused, Outcome::Error(ref e) if e.code == ErrorCode::AlreadyExists));
        let Outcome::Result(Response::Imported { profiles: again }) = harness
            .import_as(&mut client, testdata::PIN_PROFILE, true)
            .await
        else {
            panic!("replace failed");
        };
        assert_eq!(again[0].id, summary.id);

        let Outcome::Result(Response::Profiles { profiles }) =
            client.call(Request::ListProfiles).await.outcome
        else {
            panic!();
        };
        assert_eq!(profiles, vec![summary.clone()]);

        let missing = error_of(
            client
                .call(Request::RemoveProfile {
                    profile_id: "nope".into(),
                })
                .await,
        );
        assert_eq!(missing.code, ErrorCode::NotFound);
        let traversal = error_of(
            client
                .call(Request::RemoveProfile {
                    profile_id: "../data".into(),
                })
                .await,
        );
        assert_eq!(traversal.code, ErrorCode::NotFound);

        assert_eq!(
            client
                .call(Request::RemoveProfile {
                    profile_id: summary.id
                })
                .await
                .outcome,
            Outcome::Result(Response::Ok)
        );
        let Outcome::Result(Response::Profiles { profiles }) =
            client.call(Request::ListProfiles).await.outcome
        else {
            panic!();
        };
        assert!(profiles.is_empty());
    }

    #[tokio::test]
    async fn import_rejects_bad_sources() {
        let harness = Harness::new().await;
        let mut client = harness.client().await;
        let sources = [
            ImportSource::file("big.ovpn", &vec![b'x'; MAX_IMPORT_BYTES + 1]),
            ImportSource::file("junk.ovpn", b"client\ndev tun\n"),
            ImportSource::File {
                name: "bad.ovpn".into(),
                data: Sensitive::new("not base64!"),
            },
            ImportSource::uri("not a link"),
        ];
        for source in sources {
            let request = Request::ImportProfile {
                source,
                replace: false,
            };
            let error = error_of(client.call(request).await);
            assert_eq!(error.code, ErrorCode::InvalidRequest, "{}", error.message);
        }
        let Outcome::Result(Response::Profiles { profiles }) =
            client.call(Request::ListProfiles).await.outcome
        else {
            panic!();
        };
        assert!(profiles.is_empty());
    }

    #[tokio::test]
    async fn legacy_path_sources_are_not_accepted() {
        let harness = Harness::new().await;
        let mut client = harness.client().await;
        let path = harness.dir.path().join("secret.ovpn");
        std::fs::write(&path, testdata::PIN_PROFILE).unwrap();
        let line = format!(
            "{{\"id\":3,\"request\":{{\"type\":\"import_profile\",\"source\":\"{}\"}}}}\n",
            path.display()
        );
        client.writer.write_all(line.as_bytes()).await.unwrap();
        let ServerMessage::Response(response) = client.read().await else {
            panic!();
        };
        assert!(matches!(response.outcome, Outcome::Error(_)));
        let Outcome::Result(Response::Profiles { profiles }) =
            client.call(Request::ListProfiles).await.outcome
        else {
            panic!();
        };
        assert!(profiles.is_empty());
    }

    #[tokio::test]
    async fn connection_cap_queues_extra_clients_until_a_slot_frees() {
        let harness = Harness::limited(Limits {
            max_connections: 2,
            idle: Duration::from_secs(30),
        })
        .await;
        let mut first = harness.client().await;
        let mut second = harness.client().await;
        first.call(Request::Status).await;
        second.call(Request::Status).await;

        let mut third = harness.client().await;
        let line = encode_line(&RequestEnvelope {
            id: 1,
            request: Request::Status,
        })
        .unwrap();
        third.writer.write_all(&line).await.unwrap();
        let waiting = tokio::time::timeout(Duration::from_millis(300), third.lines.next_line());
        assert!(waiting.await.is_err());

        drop(first);
        let ServerMessage::Response(response) = third.read().await else {
            panic!();
        };
        assert_eq!(response.id, 1);
    }

    #[tokio::test]
    async fn idle_connections_are_closed_but_subscribers_are_kept() {
        let harness = Harness::limited(Limits {
            max_connections: 4,
            idle: Duration::from_millis(150),
        })
        .await;
        let mut idle = harness.client().await;
        let mut subscriber = harness.client().await;
        subscriber.call(Request::Subscribe).await;

        assert!(idle.lines.next_line().await.unwrap().is_none());

        harness.state.publish(Event::StateChanged {
            profile_id: "p1".into(),
            state: ConnectionState::Connecting,
            error: None,
        });
        assert!(matches!(subscriber.read().await, ServerMessage::Event(_)));
    }

    async fn prompted(
        harness: &Harness,
        client: &mut Client,
        transport: Option<Transport>,
    ) -> String {
        let summary = harness.import(client, testdata::PIN_PROFILE).await;
        client.call(Request::Subscribe).await;
        assert_eq!(
            client
                .call(connect_request(&summary.id, transport))
                .await
                .outcome,
            Outcome::Result(Response::Ok)
        );
        assert!(matches!(
            client.event().await,
            Event::StateChanged {
                state: ConnectionState::Connecting,
                ..
            }
        ));
        assert!(matches!(
            client.event().await,
            Event::CredentialsRequired { mode: AuthMode::Pin, ref profile_id } if *profile_id == summary.id
        ));
        let Outcome::Result(Response::Status { statuses }) =
            client.call(Request::Status).await.outcome
        else {
            panic!();
        };
        assert_eq!(statuses[0].state, ConnectionState::Connecting);
        assert_eq!(
            statuses[0].transport,
            Some(transport.unwrap_or(Transport::WireGuard))
        );

        let missing = error_of(client.call(submit_request(&summary.id, None)).await);
        assert_eq!(missing.code, ErrorCode::InvalidRequest);
        let empty = error_of(client.call(submit_request(&summary.id, Some(""))).await);
        assert_eq!(empty.code, ErrorCode::InvalidRequest);
        assert_eq!(
            harness.state.connection_state(&summary.id),
            ConnectionState::Connecting
        );
        summary.id
    }

    #[tokio::test]
    async fn wireguard_connect_prompts_for_pin_then_is_not_implemented() {
        let harness = Harness::new().await;
        let mut client = harness.client().await;
        let id = prompted(&harness, &mut client, None).await;

        let done = error_of(client.call(submit_request(&id, Some("0000"))).await);
        assert_eq!(done.code, ErrorCode::NotImplemented);
        assert_eq!(done.message, "tunnel bring-up not implemented");
        assert!(!format!("{done:?}").contains("0000"));
        assert!(matches!(
            client.event().await,
            Event::StateChanged {
                state: ConnectionState::Disconnected,
                ..
            }
        ));
        assert_eq!(
            harness.state.connection_state(&id),
            ConnectionState::Disconnected
        );

        let again = error_of(client.call(submit_request(&id, Some("0000"))).await);
        assert_eq!(again.code, ErrorCode::InvalidState);
    }

    #[tokio::test]
    async fn openvpn_connect_runs_a_session_to_connected_and_disconnect() {
        let (launcher, mut launches) = fake::pair();
        let harness = Harness::launching(launcher).await;
        let mut client = harness.client().await;
        let id = prompted(&harness, &mut client, Some(Transport::OpenVpn)).await;

        assert_eq!(
            client.call(submit_request(&id, Some("0000"))).await.outcome,
            Outcome::Result(Response::Ok)
        );
        let process = launches.recv().await.unwrap();
        assert!(process.credentials.is_some());
        process
            .send(TunnelEvent::Connected {
                tunnel_ip: Some("10.8.0.2".into()),
                remote: Some("203.0.113.5:1194".into()),
            })
            .await;
        assert!(matches!(
            client.event().await,
            Event::StateChanged {
                state: ConnectionState::Connected,
                error: None,
                ..
            }
        ));
        let Outcome::Result(Response::Status { statuses }) =
            client.call(Request::Status).await.outcome
        else {
            panic!();
        };
        assert_eq!(statuses[0].tunnel_ip.as_deref(), Some("10.8.0.2"));
        assert_eq!(statuses[0].transport, Some(Transport::OpenVpn));

        let again = error_of(client.call(submit_request(&id, Some("0000"))).await);
        assert_eq!(again.code, ErrorCode::InvalidState);

        let request = Request::Disconnect {
            profile_id: id.clone(),
        };
        assert_eq!(
            client.call(request).await.outcome,
            Outcome::Result(Response::Ok)
        );
        for expected in [
            ConnectionState::Disconnecting,
            ConnectionState::Disconnected,
        ] {
            assert!(matches!(
                client.event().await,
                Event::StateChanged { state, .. } if state == expected
            ));
        }
        assert!(process.stopped());
    }

    #[tokio::test]
    async fn wireguard_override_needs_support_and_disconnect_resets() {
        let harness = Harness::new().await;
        let mut client = harness.client().await;
        let summary = harness
            .import(
                &mut client,
                &testdata::ovpn(&[("\"wg\": true", "\"wg\": false")]),
            )
            .await;
        assert_eq!(summary.transports, vec![Transport::OpenVpn]);

        let refused = error_of(
            client
                .call(connect_request(&summary.id, Some(Transport::WireGuard)))
                .await,
        );
        assert_eq!(refused.code, ErrorCode::InvalidRequest);

        client.call(connect_request(&summary.id, None)).await;
        let Outcome::Result(Response::Status { statuses }) =
            client.call(Request::Status).await.outcome
        else {
            panic!();
        };
        assert_eq!(statuses[0].transport, Some(Transport::OpenVpn));
        assert_eq!(statuses[0].state, ConnectionState::Connecting);

        client
            .call(Request::Disconnect {
                profile_id: summary.id.clone(),
            })
            .await;
        assert_eq!(
            harness.state.connection_state(&summary.id),
            ConnectionState::Disconnected
        );
        let unknown = error_of(
            client
                .call(Request::Disconnect {
                    profile_id: "nope".into(),
                })
                .await,
        );
        assert_eq!(unknown.code, ErrorCode::NotFound);
        let unknown = error_of(client.call(connect_request("nope", None)).await);
        assert_eq!(unknown.code, ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn unsupported_modes_fail_without_partial_login() {
        let variants = [
            ("\"password_mode\": \"pin\"", "\"password_mode\": \"otp\""),
            (
                "\"password_mode\": \"pin\"",
                "\"password_mode\": \"otp_pin\"",
            ),
            ("\"wg\": true", "\"wg\": true, \"sso_auth\": true"),
            ("\"wg\": true", "\"wg\": true, \"device_auth\": true"),
            ("\"wg\": true", "\"wg\": false, \"dynamic_firewall\": true"),
        ];
        for (from, to) in variants {
            let harness = Harness::new().await;
            let mut client = harness.client().await;
            let summary = harness
                .import(&mut client, &testdata::ovpn(&[(from, to)]))
                .await;
            client.call(Request::Subscribe).await;

            let error = error_of(client.call(connect_request(&summary.id, None)).await);
            assert_eq!(error.code, ErrorCode::UnsupportedAuth, "{to}");
            assert_eq!(
                harness.state.connection_state(&summary.id),
                ConnectionState::Disconnected
            );
            let submit = error_of(client.call(submit_request(&summary.id, Some("0000"))).await);
            assert_eq!(submit.code, ErrorCode::InvalidState);
            harness.state.publish(Event::StateChanged {
                profile_id: "marker".into(),
                state: ConnectionState::Error,
                error: None,
            });
            assert!(matches!(
                client.event().await,
                Event::StateChanged { ref profile_id, .. } if profile_id == "marker"
            ));
        }
    }

    #[tokio::test]
    async fn overlong_line_closes_the_connection() {
        let harness = Harness::new().await;
        let mut client = harness.client().await;

        let _ = client
            .writer
            .write_all(&vec![b'a'; MAX_LINE_BYTES + 1024])
            .await;
        let mut closed = false;
        while let Ok(Some(line)) = client.lines.next_line().await {
            if let Ok(ServerMessage::Response(response)) = decode_line(line.as_bytes()) {
                assert!(
                    matches!(response.outcome, Outcome::Error(ref e) if e.code == ErrorCode::InvalidRequest)
                );
            }
        }
        closed |= client.lines.next_line().await.map_or(true, |l| l.is_none());
        assert!(closed);

        let mut fresh = harness.client().await;
        assert!(matches!(
            fresh.call(Request::Status).await.outcome,
            Outcome::Result(Response::Status { .. })
        ));
    }

    #[tokio::test]
    async fn line_at_the_limit_is_accepted() {
        let harness = Harness::new().await;
        let mut client = harness.client().await;
        let pad = " ".repeat(MAX_LINE_BYTES - 40);
        let line = format!("{{\"id\":9,\"request\":{{\"type\":\"status\"}}{pad}}}\n");
        assert!(line.len() <= MAX_LINE_BYTES + 1);
        client.writer.write_all(line.as_bytes()).await.unwrap();
        let ServerMessage::Response(response) = client.read().await else {
            panic!();
        };
        assert_eq!(response.id, 9);
        assert!(matches!(
            response.outcome,
            Outcome::Result(Response::Status { .. })
        ));
    }

    async fn rename(client: &mut Client, id: &str, name: &str) -> Outcome {
        client
            .call(Request::RenameProfile {
                profile_id: id.into(),
                name: name.into(),
            })
            .await
            .outcome
    }

    async fn listed(client: &mut Client) -> Vec<ProfileSummary> {
        let Outcome::Result(Response::Profiles { profiles }) =
            client.call(Request::ListProfiles).await.outcome
        else {
            panic!();
        };
        profiles
    }

    #[tokio::test]
    async fn rename_sets_the_name_and_keeps_the_imported_name() {
        let harness = Harness::new().await;
        let mut client = harness.client().await;
        let summary = harness.import(&mut client, testdata::PIN_PROFILE).await;
        assert_eq!(summary.imported_name, None);

        let Outcome::Result(Response::Profile { profile }) =
            rename(&mut client, &summary.id, "  Home office  ").await
        else {
            panic!("rename failed");
        };
        assert_eq!(profile.name, "Home office");
        assert_eq!(profile.imported_name.as_deref(), Some("office"));
        assert_eq!(listed(&mut client).await, vec![profile]);
    }

    #[tokio::test]
    async fn empty_name_resets_to_the_imported_name() {
        let harness = Harness::new().await;
        let mut client = harness.client().await;
        let summary = harness.import(&mut client, testdata::PIN_PROFILE).await;
        rename(&mut client, &summary.id, "Home").await;
        let Outcome::Result(Response::Profile { profile }) =
            rename(&mut client, &summary.id, "   ").await
        else {
            panic!("reset failed");
        };
        assert_eq!(profile, summary);
        assert_eq!(listed(&mut client).await, vec![summary]);
    }

    #[tokio::test]
    async fn renaming_to_the_imported_name_stores_no_override() {
        let harness = Harness::new().await;
        let mut client = harness.client().await;
        let summary = harness.import(&mut client, testdata::PIN_PROFILE).await;
        let Outcome::Result(Response::Profile { profile }) =
            rename(&mut client, &summary.id, " office ").await
        else {
            panic!("rename failed");
        };
        assert_eq!(profile.imported_name, None);
        assert_eq!(profile, summary);
    }

    #[tokio::test]
    async fn replace_import_keeps_the_display_name() {
        let harness = Harness::new().await;
        let mut client = harness.client().await;
        let summary = harness.import(&mut client, testdata::PIN_PROFILE).await;
        rename(&mut client, &summary.id, "Home").await;
        let Outcome::Result(Response::Imported { profiles }) = harness
            .import_as(&mut client, testdata::PIN_PROFILE, true)
            .await
        else {
            panic!("replace failed");
        };
        assert_eq!(profiles[0].name, "Home");
        assert_eq!(profiles[0].imported_name.as_deref(), Some("office"));
        assert_eq!(listed(&mut client).await, profiles);
    }

    #[tokio::test]
    async fn invalid_names_fail_and_store_nothing() {
        let harness = Harness::new().await;
        let mut client = harness.client().await;
        let summary = harness.import(&mut client, testdata::PIN_PROFILE).await;
        rename(&mut client, &summary.id, "Home").await;
        let before = listed(&mut client).await;
        for name in ["a\nb", "a\u{7}b", &"x".repeat(65)] {
            let Outcome::Error(error) = rename(&mut client, &summary.id, name).await else {
                panic!("expected an error for {name:?}");
            };
            assert_eq!(error.code, ErrorCode::InvalidRequest);
            assert_eq!(listed(&mut client).await, before);
        }
        let longest = "x".repeat(64);
        assert!(matches!(
            rename(&mut client, &summary.id, &longest).await,
            Outcome::Result(Response::Profile { .. })
        ));
    }

    #[tokio::test]
    async fn renaming_an_unknown_profile_is_not_found() {
        let harness = Harness::new().await;
        let mut client = harness.client().await;
        for id in ["nope", "../data"] {
            let Outcome::Error(error) = rename(&mut client, id, "Home").await else {
                panic!("expected an error");
            };
            assert_eq!(error.code, ErrorCode::NotFound);
        }
    }

    #[tokio::test]
    async fn subscribers_receive_profiles_changed() {
        let harness = Harness::new().await;
        let mut client = harness.client().await;
        let mut watcher = harness.client().await;
        assert_eq!(
            watcher.call(Request::Subscribe).await.outcome,
            Outcome::Result(Response::Subscribed)
        );
        let summary = harness.import(&mut client, testdata::PIN_PROFILE).await;
        assert!(matches!(watcher.event().await, Event::ProfilesChanged));
        rename(&mut client, &summary.id, "Home").await;
        assert!(matches!(watcher.event().await, Event::ProfilesChanged));
        client
            .call(Request::RemoveProfile {
                profile_id: summary.id,
            })
            .await;
        assert!(matches!(watcher.event().await, Event::ProfilesChanged));
    }
}
