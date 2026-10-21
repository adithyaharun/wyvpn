use rmcp::{
    ErrorData, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerConfig},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::client::Client;
use crate::{connect, view};

const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const CONTROL_TOOLS: [&str; 2] = ["connect", "disconnect"];

#[derive(Debug, Deserialize, JsonSchema)]
struct ProfileParam {
    /// Profile id as returned by list_profiles
    profile_id: String,
}

#[derive(Clone)]
pub struct WyvpnMcp {
    socket: String,
    tool_router: ToolRouter<Self>,
}

fn tool_error(err: impl std::fmt::Display) -> ErrorData {
    ErrorData::internal_error(err.to_string(), None)
}

fn json<T: serde::Serialize>(value: &T) -> Result<String, ErrorData> {
    serde_json::to_string_pretty(value).map_err(tool_error)
}

impl WyvpnMcp {
    pub fn new(socket: String, allow_control: bool) -> Self {
        let mut tool_router = Self::tool_router();
        if !allow_control {
            for name in CONTROL_TOOLS {
                tool_router.remove_route(name);
            }
        }
        Self {
            socket,
            tool_router,
        }
    }

    async fn client(&self) -> Result<Client, ErrorData> {
        Client::connect(&self.socket).await.map_err(tool_error)
    }
}

#[tool_router]
impl WyvpnMcp {
    #[tool(
        description = "List configured VPN profiles",
        annotations(read_only_hint = true)
    )]
    async fn list_profiles(&self) -> Result<String, ErrorData> {
        let profiles = view::fetch_profiles(&mut self.client().await?)
            .await
            .map_err(tool_error)?;
        json(&profiles)
    }

    #[tool(
        description = "Connection status of every profile: name, state, transport, server endpoint, tunnel IP, local IP, connected-since, uptime, byte counters and last error",
        annotations(read_only_hint = true)
    )]
    async fn connection_status(&self) -> Result<String, ErrorData> {
        let views = view::fetch_status(&mut self.client().await?)
            .await
            .map_err(tool_error)?;
        json(&views)
    }

    #[tool(
        description = "Connect a VPN profile and wait for the outcome; profiles that need a PIN cannot be connected here"
    )]
    async fn connect(
        &self,
        Parameters(ProfileParam { profile_id }): Parameters<ProfileParam>,
    ) -> Result<String, ErrorData> {
        let mut client = self.client().await?;
        let view = tokio::time::timeout(
            CONNECT_TIMEOUT,
            connect::run(&mut client, profile_id, None, connect::Pin::Unavailable),
        )
        .await
        .map_err(|_| tool_error("timed out waiting for the connection"))?
        .map_err(tool_error)?;
        json(&view)
    }

    #[tool(description = "Disconnect a VPN profile and wait until it is disconnected")]
    async fn disconnect(
        &self,
        Parameters(ProfileParam { profile_id }): Parameters<ProfileParam>,
    ) -> Result<String, ErrorData> {
        connect::disconnect(&mut self.client().await?, &profile_id)
            .await
            .map_err(tool_error)?;
        Ok("disconnected".into())
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for WyvpnMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
}

pub async fn run(socket: String, allow_control: bool) -> anyhow::Result<()> {
    let service = WyvpnMcp::new(socket, allow_control)
        .serve(rmcp::transport::stdio())
        .await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use rmcp::{
        ClientHandler, ServiceExt,
        model::{CallToolRequestParams, ClientConfig},
    };
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;
    use wyvpn_ipc::{
        AuthMode, ConnectionState, ConnectionStatus, ErrorBody, ErrorCode, Outcome, ProfileSummary,
        Request, RequestEnvelope, Response, ResponseEnvelope, Transport, decode_line, encode_line,
    };

    use super::*;

    struct Dummy;

    impl ClientHandler for Dummy {
        fn get_info(&self) -> ClientConfig {
            ClientConfig::default()
        }
    }

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
                                    transports: vec![Transport::WireGuard],
                                    imported_name: None,
                                }],
                            },
                            Request::Status => Response::Status {
                                statuses: vec![ConnectionStatus {
                                    profile_id: "p1".into(),
                                    profile_name: "Office".into(),
                                    state: ConnectionState::Connected,
                                    transport: Some(Transport::WireGuard),
                                    tunnel_ip: Some("10.0.0.2".into()),
                                    local_ip: None,
                                    server_endpoint: Some("vpn.example.com:51820\x1b[2J".into()),
                                    connected_since: Some(1),
                                    last_handshake: None,
                                    rx_bytes: 10,
                                    tx_bytes: 20,
                                    error: Some(ErrorBody::new(ErrorCode::Server, "late\x1b[2J")),
                                    awaiting: None,
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

    async fn start(
        allow_control: bool,
    ) -> (
        tempfile::TempDir,
        rmcp::service::RunningService<rmcp::RoleClient, Dummy>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wyvpn.sock");
        spawn_daemon(&path);

        let (client_io, server_io) = tokio::io::duplex(65536);
        let socket = path.to_str().unwrap().to_owned();
        tokio::spawn(async move {
            let server = WyvpnMcp::new(socket, allow_control)
                .serve(server_io)
                .await
                .unwrap();
            let _ = server.waiting().await;
        });
        (dir, Dummy.serve(client_io).await.unwrap())
    }

    async fn tool_text(
        client: &rmcp::service::RunningService<rmcp::RoleClient, Dummy>,
        name: &'static str,
    ) -> String {
        let result = client
            .call_tool(CallToolRequestParams::new(name))
            .await
            .unwrap();
        result.content[0].as_text().unwrap().text.clone()
    }

    fn keys(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, inner) in map {
                    out.push(key.to_ascii_lowercase());
                    keys(inner, out);
                }
            }
            serde_json::Value::Array(items) => items.iter().for_each(|i| keys(i, out)),
            _ => {}
        }
    }

    #[tokio::test]
    async fn read_only_by_default() {
        let (_dir, client) = start(false).await;
        let mut names: Vec<String> = client
            .list_all_tools()
            .await
            .unwrap()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        names.sort();
        assert_eq!(names, ["connection_status", "list_profiles"]);
    }

    #[tokio::test]
    async fn control_tools_need_allow_control() {
        let (_dir, client) = start(true).await;
        let names: Vec<String> = client
            .list_all_tools()
            .await
            .unwrap()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        assert!(names.contains(&"connect".to_owned()));
        assert!(names.contains(&"disconnect".to_owned()));
        assert!(
            names
                .iter()
                .all(|name| !name.contains("import") && !name.contains("remove")),
            "{names:?}"
        );
    }

    #[tokio::test]
    async fn tool_results_have_expected_fields_and_no_secrets() {
        let (_dir, client) = start(false).await;

        let status: serde_json::Value =
            serde_json::from_str(&tool_text(&client, "connection_status").await).unwrap();
        let entry = &status[0];
        assert_eq!(entry["profile_name"], "Office");
        assert_eq!(entry["state"], "connected");
        assert_eq!(entry["tunnel_ip"], "10.0.0.2");
        assert_eq!(entry["transport"], "wire_guard");
        assert_eq!(entry["server_endpoint"], "vpn.example.com:51820[2J");
        assert_eq!(entry["connected_since"], 1);
        assert_eq!(entry["rx_bytes"], 10);
        assert_eq!(entry["tx_bytes"], 20);
        assert_eq!(entry["error"]["code"], "server");
        assert_eq!(entry["error"]["message"], "late[2J");
        assert!(entry["uptime_secs"].as_u64().unwrap() > 0);

        let profiles: serde_json::Value =
            serde_json::from_str(&tool_text(&client, "list_profiles").await).unwrap();
        for value in [&status, &profiles] {
            let mut all = Vec::new();
            keys(value, &mut all);
            for key in all {
                for marker in [
                    "secret", "pin", "otp", "password", "private", "key", "token",
                ] {
                    assert!(!key.contains(marker), "secret-looking field: {key}");
                }
            }
        }
    }
}
