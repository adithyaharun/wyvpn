#![cfg(unix)]

use std::process::Output;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::process::Command;
use wyvpn_ipc::{
    AuthMode, ConnectionState, ConnectionStatus, ErrorBody, ErrorCode, Event, EventEnvelope,
    ImportSource, Outcome, ProfileSummary, Request, RequestEnvelope, Response, ResponseEnvelope,
    Transport, decode_line, encode_line,
};

fn spawn_daemon(path: &std::path::Path) {
    let listener = UnixListener::bind(path).unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (reader, mut writer) = stream.into_split();
                let mut lines = BufReader::new(reader).lines();
                while let Some(line) = lines.next_line().await.unwrap() {
                    let envelope: RequestEnvelope = decode_line(line.as_bytes()).unwrap();
                    let outcome = Outcome::Result(match envelope.request {
                        Request::Hello { .. } => Response::Hello {
                            daemon_version: wyvpn_ipc::VERSION.into(),
                            protocol: wyvpn_ipc::PROTOCOL_VERSION,
                        },
                        Request::ListProfiles => Response::Profiles {
                            profiles: vec![ProfileSummary {
                                id: "p1".into(),
                                name: "Office".into(),
                                server_name: "gw".into(),
                                server_host: "vpn.example.com".into(),
                                user: "alice".into(),
                                auth_mode: AuthMode::Pin,
                                transports: vec![Transport::OpenVpn, Transport::WireGuard],
                                imported_name: None,
                            }],
                        },
                        Request::Status => Response::Status {
                            statuses: vec![ConnectionStatus {
                                profile_name: "Office".into(),
                                state: ConnectionState::Connected,
                                tunnel_ip: Some("10.0.0.2".into()),
                                local_ip: Some("192.168.1.5".into()),
                                transport: Some(Transport::WireGuard),
                                connected_since: Some(1),
                                ..ConnectionStatus::disconnected("p1")
                            }],
                        },
                        _ => Response::Ok,
                    });
                    let reply = ResponseEnvelope {
                        id: envelope.id,
                        outcome,
                    };
                    writer
                        .write_all(&encode_line(&reply).unwrap())
                        .await
                        .unwrap();
                }
            });
        }
    });
}

async fn run(socket: &std::path::Path, args: &[&str]) -> Output {
    run_with_stdin(socket, args, "").await
}

async fn run_with_stdin(socket: &std::path::Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wyvpn-cli"))
        .args(args)
        .env("WYVPN_SOCKET", socket)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    input.write_all(stdin.as_bytes()).await.unwrap();
    drop(input);
    child.wait_with_output().await.unwrap()
}

type Seen = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

fn summary() -> ProfileSummary {
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

fn crowded_profiles() -> Vec<ProfileSummary> {
    let renamed = ProfileSummary {
        name: "HQ".into(),
        imported_name: Some("Office".into()),
        ..summary()
    };
    let dup = |id: &str| ProfileSummary {
        id: id.into(),
        name: "Dup".into(),
        ..summary()
    };
    vec![renamed, dup("p2"), dup("p3")]
}

#[derive(Clone, Copy)]
enum Scenario {
    Legacy,
    Connects,
    ConnectsDual,
    AuthFails,
    Connected,
    Idle,
    Crowded,
    StaleProtocol,
    OldDaemon,
}

fn spawn_recording_daemon(path: &std::path::Path) -> Seen {
    spawn_scripted_daemon(path, Scenario::Legacy)
}

fn state_event(state: ConnectionState, error: Option<ErrorBody>) -> Event {
    Event::StateChanged {
        profile_id: "p1".into(),
        state,
        error,
    }
}

fn spawn_scripted_daemon(path: &std::path::Path, scenario: Scenario) -> Seen {
    let seen = Seen::default();
    let recorded = seen.clone();
    let listener = UnixListener::bind(path).unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let recorded = recorded.clone();
            tokio::spawn(async move {
                let (reader, mut writer) = stream.into_split();
                let mut lines = BufReader::new(reader).lines();
                while let Some(line) = lines.next_line().await.unwrap() {
                    let envelope: RequestEnvelope = decode_line(line.as_bytes()).unwrap();
                    let mut events = Vec::new();
                    let outcome = match envelope.request {
                        Request::Hello { .. } => match scenario {
                            Scenario::StaleProtocol => Outcome::Result(Response::Hello {
                                daemon_version: "0.0.1".into(),
                                protocol: wyvpn_ipc::PROTOCOL_VERSION + 1,
                            }),
                            Scenario::OldDaemon => Outcome::Error(ErrorBody::new(
                                ErrorCode::InvalidRequest,
                                "unknown variant `hello`",
                            )),
                            _ => Outcome::Result(Response::Hello {
                                daemon_version: wyvpn_ipc::VERSION.into(),
                                protocol: wyvpn_ipc::PROTOCOL_VERSION,
                            }),
                        },
                        Request::InstallCli | Request::Uninstall { .. } => {
                            Outcome::Error(ErrorBody::new(ErrorCode::InvalidRequest, "unsupported"))
                        }
                        Request::ListProfiles => Outcome::Result(Response::Profiles {
                            profiles: if matches!(scenario, Scenario::Crowded) {
                                crowded_profiles()
                            } else {
                                vec![ProfileSummary {
                                    transports: if matches!(scenario, Scenario::ConnectsDual) {
                                        vec![Transport::OpenVpn, Transport::WireGuard]
                                    } else {
                                        summary().transports
                                    },
                                    ..summary()
                                }]
                            },
                        }),
                        Request::ImportProfile { source, replace } => {
                            let described = match &source {
                                ImportSource::File { name, data } => format!(
                                    "file {name} {}",
                                    String::from_utf8(data.decode_base64().unwrap().to_vec())
                                        .unwrap()
                                ),
                                ImportSource::Uri { uri } => format!("uri {}", uri.expose()),
                            };
                            recorded.lock().unwrap().push(format!(
                                "import{} {described}",
                                if replace { " replace" } else { "" }
                            ));
                            Outcome::Result(Response::Imported {
                                profiles: vec![summary()],
                            })
                        }
                        Request::RemoveProfile { profile_id } => {
                            recorded
                                .lock()
                                .unwrap()
                                .push(format!("remove {profile_id}"));
                            Outcome::Result(Response::Ok)
                        }
                        Request::Connect {
                            profile_id,
                            transport,
                            ..
                        } => {
                            recorded
                                .lock()
                                .unwrap()
                                .push(format!("connect {profile_id} {transport:?}"));
                            events.push(Event::CredentialsRequired {
                                profile_id,
                                mode: AuthMode::Pin,
                            });
                            Outcome::Result(Response::Ok)
                        }
                        Request::SubmitCredentials { pin, .. } => {
                            recorded.lock().unwrap().push(format!(
                                "pin {}",
                                pin.map(|p| p.expose().to_owned()).unwrap_or_default()
                            ));
                            match scenario {
                                Scenario::Connects | Scenario::ConnectsDual => {
                                    events.push(state_event(ConnectionState::Connecting, None));
                                    events.push(state_event(ConnectionState::Connected, None));
                                    Outcome::Result(Response::Ok)
                                }
                                Scenario::AuthFails => {
                                    events.push(state_event(ConnectionState::Connecting, None));
                                    events.push(state_event(
                                        ConnectionState::Error,
                                        Some(ErrorBody::new(ErrorCode::AuthFailed, "bad creds")),
                                    ));
                                    Outcome::Result(Response::Ok)
                                }
                                _ => Outcome::Error(ErrorBody::new(
                                    ErrorCode::NotImplemented,
                                    "tunnel bring-up not implemented",
                                )),
                            }
                        }
                        Request::Subscribe => Outcome::Result(Response::Subscribed),
                        Request::RenameProfile { profile_id, name } => {
                            recorded
                                .lock()
                                .unwrap()
                                .push(format!("rename {profile_id} [{name}]"));
                            if profile_id != "p1" {
                                Outcome::Error(ErrorBody::new(
                                    ErrorCode::NotFound,
                                    "profile not found",
                                ))
                            } else if name.chars().count() > 64 {
                                Outcome::Error(ErrorBody::new(
                                    ErrorCode::InvalidRequest,
                                    "name is too long",
                                ))
                            } else if name.trim().is_empty() {
                                Outcome::Result(Response::Profile { profile: summary() })
                            } else {
                                Outcome::Result(Response::Profile {
                                    profile: ProfileSummary {
                                        name,
                                        imported_name: Some("Office".into()),
                                        ..summary()
                                    },
                                })
                            }
                        }
                        Request::SessionLog => {
                            Outcome::Error(ErrorBody::new(ErrorCode::InvalidRequest, "unsupported"))
                        }
                        Request::Status => {
                            let status = match scenario {
                                Scenario::Connects
                                | Scenario::ConnectsDual
                                | Scenario::Connected => ConnectionStatus {
                                    profile_name: "Office".into(),
                                    state: ConnectionState::Connected,
                                    transport: Some(Transport::OpenVpn),
                                    tunnel_ip: Some("10.8.0.6".into()),
                                    server_endpoint: Some("203.0.113.5:1194".into()),
                                    connected_since: Some(1),
                                    rx_bytes: 2048,
                                    tx_bytes: 512,
                                    ..ConnectionStatus::disconnected("p1")
                                },
                                _ => ConnectionStatus::disconnected("p1"),
                            };
                            Outcome::Result(Response::Status {
                                statuses: vec![status],
                            })
                        }
                        Request::Disconnect { profile_id } => {
                            recorded
                                .lock()
                                .unwrap()
                                .push(format!("disconnect {profile_id}"));
                            events.push(state_event(ConnectionState::Disconnecting, None));
                            events.push(state_event(ConnectionState::Disconnected, None));
                            Outcome::Result(Response::Ok)
                        }
                    };
                    let reply = ResponseEnvelope {
                        id: envelope.id,
                        outcome,
                    };
                    writer
                        .write_all(&encode_line(&reply).unwrap())
                        .await
                        .unwrap();
                    for event in events {
                        writer
                            .write_all(&encode_line(&EventEnvelope { event }).unwrap())
                            .await
                            .unwrap();
                    }
                }
            });
        }
    });
    seen
}

fn collect_keys(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, inner) in map {
                out.push(key.to_ascii_lowercase());
                collect_keys(inner, out);
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|i| collect_keys(i, out)),
        _ => {}
    }
}

#[tokio::test]
async fn json_output_is_valid_and_has_no_secret_fields() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    spawn_daemon(&socket);

    for args in [["list", "--json"], ["status", "--json"]] {
        let output = run(&socket, &args).await;
        assert!(output.status.success(), "{args:?}");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let mut keys = Vec::new();
        collect_keys(&value, &mut keys);
        assert!(!keys.is_empty());
        for key in keys {
            for marker in [
                "secret", "pin", "otp", "password", "private", "key", "token",
            ] {
                assert!(!key.contains(marker), "secret-looking field: {key}");
            }
        }
    }
}

#[tokio::test]
async fn human_output_is_a_table() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    spawn_daemon(&socket);

    let list = String::from_utf8(run(&socket, &["list"]).await.stdout).unwrap();
    assert!(list.starts_with("NAME"));
    assert!(list.contains("Office"));

    let status = String::from_utf8(run(&socket, &["status"]).await.stdout).unwrap();
    assert!(status.contains("connected"));
    assert!(status.contains("10.0.0.2"));
    assert!(status.contains("192.168.1.5"));
}

#[tokio::test]
async fn unreachable_daemon_names_the_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("missing.sock");

    let output = run(&socket, &["status"]).await;
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(socket.to_str().unwrap()), "{stderr}");
}

#[tokio::test]
async fn connect_reads_the_pin_from_stdin_and_never_prints_it() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    let seen = spawn_recording_daemon(&socket);

    let output = run_with_stdin(&socket, &["connect", "Office", "--pin-stdin"], "4821\n").await;
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("tunnel bring-up not implemented"),
        "{stderr}"
    );
    assert!(!stderr.contains("4821"));
    assert!(!String::from_utf8(output.stdout).unwrap().contains("4821"));
    assert_eq!(
        *seen.lock().unwrap(),
        ["connect p1 None", "pin 4821", "disconnect p1"]
    );
}

#[tokio::test]
async fn connect_rejects_an_empty_pin() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    let seen = spawn_recording_daemon(&socket);

    let output = run_with_stdin(&socket, &["connect", "p1", "--pin-stdin"], "\n").await;
    assert!(!output.status.success());
    assert_eq!(*seen.lock().unwrap(), ["connect p1 None", "disconnect p1"]);
}

#[tokio::test]
async fn connect_disconnects_when_the_pin_read_fails() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    let seen = spawn_recording_daemon(&socket);

    let output = run_with_stdin(&socket, &["connect", "p1", "--pin-stdin"], "").await;
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("PIN is empty"), "{stderr}");
    assert_eq!(*seen.lock().unwrap(), ["connect p1 None", "disconnect p1"]);
}

#[tokio::test]
async fn import_sends_file_contents_and_remove_resolves_names() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    let seen = spawn_recording_daemon(&socket);
    let file = dir.path().join("office.ovpn");
    std::fs::write(&file, "x").unwrap();

    let output = run(&socket, &["import", file.to_str().unwrap()]).await;
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout).unwrap().contains("Office"));

    let output = run(&socket, &["import", "--replace", file.to_str().unwrap()]).await;
    assert!(output.status.success());

    let output = run(&socket, &["import", "vpn.example.com/ku/abc"]).await;
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("warning"), "{stderr}");

    let output = run_with_stdin(&socket, &["import", "-"], "vpn.example.com/ku/def\n").await;
    assert!(output.status.success());
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("warning")
    );

    let output = run(&socket, &["remove", "Office"]).await;
    assert!(output.status.success());

    let seen = seen.lock().unwrap();
    assert_eq!(seen[0], "import file office.ovpn x");
    assert_eq!(seen[1], "import replace file office.ovpn x");
    assert_eq!(seen[2], "import uri vpn.example.com/ku/abc");
    assert_eq!(seen[3], "import uri vpn.example.com/ku/def");
    assert_eq!(seen[4], "remove p1");
}

#[tokio::test]
async fn import_refuses_oversized_files_without_contacting_the_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    let seen = spawn_recording_daemon(&socket);
    let file = dir.path().join("big.ovpn");
    std::fs::write(&file, vec![b'x'; wyvpn_ipc::MAX_IMPORT_BYTES + 1]).unwrap();

    let output = run(&socket, &["import", file.to_str().unwrap()]).await;
    assert!(!output.status.success());
    assert!(
        !seen
            .lock()
            .unwrap()
            .iter()
            .any(|call| call.starts_with("disconnect"))
    );
}

#[tokio::test]
async fn connect_prints_the_tunnel_ip_and_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    let seen = spawn_scripted_daemon(&socket, Scenario::Connects);

    let output = run_with_stdin(&socket, &["connect", "Office", "--pin-stdin"], "4821\n").await;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout.trim(),
        "connected (openvpn): 10.8.0.6 via 203.0.113.5:1194"
    );
    assert!(!stdout.contains("4821"));
    assert_eq!(*seen.lock().unwrap(), ["connect p1 None", "pin 4821"]);

    let output = run_with_stdin(&socket, &["connect", "p1", "--pin-stdin", "--json"], "1\n").await;
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["tunnel_ip"], "10.8.0.6");
    assert_eq!(value["state"], "connected");
    assert_eq!(value["profile_name"], "Office");
}

#[tokio::test]
async fn connect_reports_a_rejected_pin_and_fails() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    let seen = spawn_scripted_daemon(&socket, Scenario::AuthFails);

    let output = run_with_stdin(&socket, &["connect", "Office", "--pin-stdin"], "0000\n").await;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("PIN was rejected"), "{stderr}");
    assert!(!stderr.contains("0000"));
    assert!(
        !seen
            .lock()
            .unwrap()
            .iter()
            .any(|call| call.starts_with("disconnect"))
    );
}

#[tokio::test]
async fn disconnect_waits_for_the_disconnected_event() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    let seen = spawn_scripted_daemon(&socket, Scenario::Connected);

    let output = run(&socket, &["disconnect", "Office"]).await;
    assert!(output.status.success());
    assert_eq!(*seen.lock().unwrap(), ["disconnect p1"]);
}

#[tokio::test]
async fn disconnect_returns_immediately_when_already_disconnected() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    let seen = spawn_scripted_daemon(&socket, Scenario::Idle);

    let output = run(&socket, &["disconnect", "Office"]).await;
    assert!(output.status.success());
    assert!(
        !seen
            .lock()
            .unwrap()
            .iter()
            .any(|call| call.starts_with("disconnect"))
    );
}

#[tokio::test]
async fn rename_sets_and_resets_the_name() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    let seen = spawn_recording_daemon(&socket);

    let output = run(&socket, &["rename", "Office", "HQ"]).await;
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "renamed: HQ"
    );

    let output = run(&socket, &["rename", "p1", "--reset"]).await;
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "reset to imported name: Office"
    );

    let output = run(&socket, &["rename", "p1", "HQ", "--json"]).await;
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["name"], "HQ");
    assert_eq!(value["imported_name"], "Office");

    assert_eq!(
        *seen.lock().unwrap(),
        ["rename p1 [HQ]", "rename p1 []", "rename p1 [HQ]"]
    );
}

#[tokio::test]
async fn rename_reports_unknown_profiles_and_invalid_names() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    spawn_recording_daemon(&socket);

    let output = run(&socket, &["rename", "ghost", "HQ"]).await;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("profile not found"), "{stderr}");

    let output = run(&socket, &["rename", "Office", &"x".repeat(65)]).await;
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("name is too long"), "{stderr}");
}

#[tokio::test]
async fn rename_requires_exactly_one_of_name_or_reset() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    let seen = spawn_recording_daemon(&socket);

    for args in [
        vec!["rename", "Office"],
        vec!["rename", "Office", "HQ", "--reset"],
    ] {
        let output = run(&socket, &args).await;
        assert!(!output.status.success(), "{args:?}");
    }
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn rename_whitespace_name_reports_a_reset() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    spawn_recording_daemon(&socket);

    let output = run(&socket, &["rename", "p1", "  "]).await;
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "reset to imported name: Office"
    );
}

#[tokio::test]
async fn profiles_resolve_by_imported_name_and_reject_ambiguous_names() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    let seen = spawn_scripted_daemon(&socket, Scenario::Crowded);

    let output = run(&socket, &["rename", "Office", "--reset"]).await;
    assert!(output.status.success());
    assert_eq!(*seen.lock().unwrap(), ["rename p1 []"]);

    let output = run(&socket, &["remove", "Dup"]).await;
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("ambiguous"), "{stderr}");
    assert!(stderr.contains("p2, p3"), "{stderr}");
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn handshake_succeeds_before_other_requests() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    spawn_scripted_daemon(&socket, Scenario::Idle);

    let output = run(&socket, &["list"]).await;
    assert!(output.status.success());
}

#[tokio::test]
async fn protocol_mismatch_fails_naming_both_versions() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    let seen = spawn_scripted_daemon(&socket, Scenario::StaleProtocol);

    let output = run(&socket, &["remove", "p1"]).await;
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(wyvpn_ipc::VERSION), "{stderr}");
    assert!(stderr.contains("0.0.1"), "{stderr}");
    assert!(
        stderr.contains("update WyVPN or restart the service"),
        "{stderr}"
    );
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn daemon_without_hello_support_asks_for_update() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    spawn_scripted_daemon(&socket, Scenario::OldDaemon);

    let output = run(&socket, &["status"]).await;
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("older than this CLI"), "{stderr}");
    assert!(
        stderr.contains("update WyVPN or restart the service"),
        "{stderr}"
    );
}

#[tokio::test]
async fn connect_rejects_a_transport_the_profile_lacks_before_sending() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    let seen = spawn_scripted_daemon(&socket, Scenario::Connects);

    let output = run(&socket, &["connect", "Office", "--transport", "wireguard"]).await;
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("supported transports: openvpn"), "{stderr}");
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn connect_accepts_a_supported_transport() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wyvpn.sock");
    let seen = spawn_scripted_daemon(&socket, Scenario::ConnectsDual);

    let output = run_with_stdin(
        &socket,
        &[
            "connect",
            "Office",
            "--transport",
            "wireguard",
            "--pin-stdin",
        ],
        "4821\n",
    )
    .await;
    assert!(output.status.success());
    assert_eq!(seen.lock().unwrap()[0], "connect p1 Some(WireGuard)");
}
