use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use crypto_box::aead::{Aead, OsRng};
use crypto_box::{Nonce, PublicKey, SalsaBox, SecretKey};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};
use wyvpn_core::Secret;
use wyvpn_core::Unsupported;
use wyvpn_core::http::{ApiClient, HttpRequest, Method};
use wyvpn_core::sign::hmac_base64;
use wyvpn_core::tls::{Pins, TlsPolicy};
use wyvpn_core::wireguard::Platform;

use super::*;
use crate::testdata;

const SYNC_SECRET: &str = "Xy9Pq2Lm7Nr4St6Uv8Wz0Ab3Cd5Ef1Gh";
const PIN: &str = "1234";

#[derive(Clone)]
enum Reply {
    Accept { web_no_ssl: bool },
    Deny(&'static str),
    Status(u16),
    WrongKey,
}

struct Peer {
    secret: SecretKey,
    reply: Reply,
    keys: Arc<Mutex<Vec<String>>>,
    passwords: Arc<Mutex<Vec<String>>>,
}

fn config(web_no_ssl: bool) -> serde_json::Value {
    serde_json::json!({
        "address": "10.200.0.5/24",
        "hostname": "203.0.113.9",
        "gateway": "10.200.0.1",
        "port": 51820,
        "ping_interval": 30,
        "web_port": 443,
        "web_no_ssl": web_no_ssl,
        "public_key": STANDARD.encode([7u8; 32]),
        "routes": [{"network": "10.0.0.0/8"}],
        "dns_servers": ["10.200.0.1"],
    })
}

fn envelope(
    client: &PublicKey,
    key: &SecretKey,
    plaintext: &serde_json::Value,
) -> serde_json::Value {
    let nonce = [9u8; 24];
    let cipher = SalsaBox::new(client, key)
        .encrypt(
            Nonce::from_slice(&nonce),
            serde_json::to_vec(plaintext).unwrap().as_slice(),
        )
        .unwrap();
    let (data, nonce) = (STANDARD.encode(cipher), STANDARD.encode(nonce));
    let signature = hmac_base64(
        &Secret::new(SYNC_SECRET),
        format!("{data}&{nonce}").as_bytes(),
    );
    serde_json::json!({"data": data, "nonce": nonce, "signature": signature})
}

impl Respond for Peer {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let field = |name: &str| STANDARD.decode(body[name].as_str().unwrap()).unwrap();
        let client = PublicKey::from_slice(&field("public_key")).unwrap();
        let inner = SalsaBox::new(&client, &self.secret)
            .decrypt(Nonce::from_slice(&field("nonce")), field("data").as_slice())
            .unwrap();
        let inner: serde_json::Value = serde_json::from_slice(&inner).unwrap();
        self.passwords
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(inner["password"].as_str().unwrap().to_owned());
        self.keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(inner["wg_public_key"].as_str().unwrap().to_owned());
        let reply = match &self.reply {
            Reply::Accept { web_no_ssl } => envelope(
                &client,
                &self.secret,
                &serde_json::json!({"allow": true, "configuration": config(*web_no_ssl), "reason": null}),
            ),
            Reply::Deny(reason) => envelope(
                &client,
                &self.secret,
                &serde_json::json!({"allow": false, "configuration": null, "reason": reason}),
            ),
            Reply::WrongKey => envelope(
                &client,
                &SecretKey::generate(&mut OsRng),
                &serde_json::json!({"allow": true}),
            ),
            Reply::Status(code) => return ResponseTemplate::new(*code),
        };
        ResponseTemplate::new(200).set_body_json(reply)
    }
}

struct Rig {
    server: MockServer,
    secret: SecretKey,
    keys: Arc<Mutex<Vec<String>>>,
    passwords: Arc<Mutex<Vec<String>>>,
}

impl Rig {
    async fn start(reply: Reply) -> Self {
        Self::start_with(reply, SecretKey::generate(&mut OsRng)).await
    }

    async fn start_with(reply: Reply, secret: SecretKey) -> Self {
        let keys = Arc::new(Mutex::new(Vec::new()));
        let passwords = Arc::new(Mutex::new(Vec::new()));
        let server = MockServer::start().await;
        Mock::given(wiremock::matchers::path_regex("^/key/wg/"))
            .respond_with(Peer {
                secret: SecretKey::from_bytes(secret.to_bytes()),
                reply,
                keys: keys.clone(),
                passwords: passwords.clone(),
            })
            .mount(&server)
            .await;
        Self {
            server,
            secret,
            keys,
            passwords,
        }
    }

    fn profile(&self, hosts: &[String], extra: &[(&str, &str)]) -> Profile {
        let hosts = format!(
            "[{}]",
            hosts
                .iter()
                .map(|h| format!("\"{h}\""))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let key = format!(
            "\"server_box_public_key\": \"{}\"",
            STANDARD.encode(self.secret.public_key().as_bytes())
        );
        let mut replacements = vec![
            ("[\"https://vpn.example.com\"]", hosts.as_str()),
            (
                "\"server_box_public_key\": \"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\"",
                key.as_str(),
            ),
            ("remote vpn.example.com 1194 udp\n", ""),
        ];
        replacements.extend_from_slice(extra);
        Profile::parse(&testdata::ovpn(&replacements)).unwrap()
    }

    fn seen_keys(&self) -> Vec<String> {
        self.keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn seen_passwords(&self) -> Vec<String> {
        self.passwords
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    async fn requests(&self) -> usize {
        self.server.received_requests().await.unwrap().len()
    }
}

fn client() -> ApiClient {
    ApiClient::new(TlsPolicy::Verify)
        .unwrap()
        .allow_plain_http()
}

fn device() -> DeviceInfo {
    DeviceInfo {
        hostname: "laptop".into(),
        platform: Platform::Mac,
        client_version: "0.1.0".into(),
        mac_addr: "aa:bb:cc:dd:ee:ff".into(),
        mac_addrs: vec!["aa:bb:cc:dd:ee:ff".into()],
        public_address: String::new(),
        public_address6: String::new(),
    }
}

async fn run(profile: &Profile) -> Result<WireGuardSession, RegisterError> {
    let hosts = profile.header.sync_hosts.clone();
    register_hosts(
        &client(),
        &hosts,
        profile,
        &device(),
        Some(PIN),
        Timeouts::default(),
    )
    .await
}

#[tokio::test]
async fn falls_back_to_the_next_host_with_a_fresh_key() {
    let live = Rig::start(Reply::Accept { web_no_ssl: false }).await;
    let dead = Rig::start_with(
        Reply::Status(500),
        SecretKey::from_bytes(live.secret.to_bytes()),
    )
    .await;
    let profile = live.profile(&[dead.server.uri(), live.server.uri()], &[]);
    let session = run(&profile).await.unwrap();
    assert_eq!(dead.requests().await, 1);
    assert_eq!(live.requests().await, 1);
    let (dead_key, live_key) = (dead.seen_keys(), live.seen_keys());
    assert_eq!(live_key, [session.keys.public_key_base64()]);
    assert_eq!(dead_key.len(), 1);
    assert_ne!(dead_key[0], live_key[0]);
    assert_eq!(live.seen_passwords(), [PIN]);
}

#[tokio::test]
async fn fails_only_after_every_host_fails() {
    let a = Rig::start(Reply::Status(500)).await;
    let b = Rig::start_with(
        Reply::Status(429),
        SecretKey::from_bytes(a.secret.to_bytes()),
    )
    .await;
    let profile = a.profile(&[a.server.uri(), b.server.uri()], &[]);
    let err = run(&profile).await.unwrap_err();
    assert_eq!(a.requests().await, 1);
    assert_eq!(b.requests().await, 1);
    assert!(matches!(err, RegisterError::ServerOffline));
}

#[tokio::test]
async fn denial_carries_a_sanitized_reason_and_auth_failed() {
    let rig = Rig::start(Reply::Deny("Too many\u{1b}[2J devices\n")).await;
    let err = run(&rig.profile(&[rig.server.uri()], &[]))
        .await
        .unwrap_err();
    match &err {
        RegisterError::Denied { reason } => {
            assert_eq!(reason.as_deref(), Some("Too many[2J devices"));
        }
        other => panic!("unexpected {other:?}"),
    }
    let body = err.to_body();
    assert_eq!(body.code, ErrorCode::AuthFailed);
    assert!(body.message.contains("Too many[2J devices"));
    assert_eq!(rig.requests().await, 1);
}

#[tokio::test]
async fn status_413_and_429_are_distinct() {
    let rig = Rig::start(Reply::Status(413)).await;
    let err = run(&rig.profile(&[rig.server.uri()], &[]))
        .await
        .unwrap_err();
    assert!(matches!(err, RegisterError::KeyReused));
    assert_eq!(err.to_body().code, ErrorCode::Server);

    let rig = Rig::start(Reply::Status(429)).await;
    let err = run(&rig.profile(&[rig.server.uri()], &[]))
        .await
        .unwrap_err();
    assert!(matches!(err, RegisterError::ServerOffline));
    assert_eq!(err.to_body().message, "server instance is offline");
}

#[tokio::test]
async fn timeouts_map_to_the_timeout_code() {
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&server)
        .await;
    let request = HttpRequest {
        method: Method::GET,
        url: url::Url::parse(&server.uri()).unwrap(),
        headers: Vec::new(),
        body: None,
        timeout: Duration::from_millis(100),
    };
    let err = client().execute(request).await.unwrap_err();
    let err = RegisterError::from(err);
    assert!(matches!(err, RegisterError::Timeout));
    assert_eq!(err.to_body().code, ErrorCode::Timeout);
}

#[tokio::test]
async fn web_no_ssl_is_refused_after_registration() {
    let rig = Rig::start(Reply::Accept { web_no_ssl: true }).await;
    let err = run(&rig.profile(&[rig.server.uri()], &[]))
        .await
        .unwrap_err();
    assert!(matches!(err, RegisterError::InsecureKeepalive));
    assert_eq!(err.to_body().code, ErrorCode::Server);

    let rig = Rig::start(Reply::Accept { web_no_ssl: false }).await;
    let session = run(&rig.profile(&[rig.server.uri()], &[])).await.unwrap();
    assert!(!session.config.web_no_ssl);
}

#[tokio::test]
async fn decryption_failure_drops_the_key_without_trying_other_hosts() {
    let bad = Rig::start(Reply::WrongKey).await;
    let spare = Rig::start(Reply::Accept { web_no_ssl: false }).await;
    let profile = bad.profile(&[bad.server.uri(), spare.server.uri()], &[]);
    let err = run(&profile).await.unwrap_err();
    assert!(matches!(err, RegisterError::Core(CoreError::Decrypt)));
    assert_eq!(err.to_body().code, ErrorCode::Server);
    assert_eq!(spare.requests().await, 0);
}

#[tokio::test]
async fn pre_auth_profiles_are_rejected_before_any_request() {
    let rig = Rig::start(Reply::Accept { web_no_ssl: false }).await;
    let uri = rig.server.uri();
    for (marker, expected) in [
        ("\"sso_auth\": true", Unsupported::Sso),
        ("\"device_auth\": true", Unsupported::DeviceAuth),
        ("\"dynamic_firewall\": true", Unsupported::DynamicFirewall),
    ] {
        let extra = format!("\"wg\": true,\n# {marker}");
        let profile = rig.profile(
            std::slice::from_ref(&uri),
            &[("\"wg\": true", extra.as_str())],
        );
        let err = run(&profile).await.unwrap_err();
        match &err {
            RegisterError::Core(CoreError::Unsupported(found)) => assert_eq!(*found, expected),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(err.to_body().code, ErrorCode::UnsupportedAuth);
    }
    assert_eq!(rig.requests().await, 0);
}

#[tokio::test]
async fn production_client_refuses_plain_http() {
    let rig = Rig::start(Reply::Accept { web_no_ssl: false }).await;
    let profile = rig.profile(&[rig.server.uri()], &[]);
    let client = https_client(&Pins::new()).unwrap();
    let hosts = profile.header.sync_hosts.clone();
    let timeouts = Timeouts::default();
    let err = register_hosts(&client, &hosts, &profile, &device(), Some(PIN), timeouts)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        RegisterError::Core(CoreError::InsecureScheme)
    ));
    assert_eq!(rig.requests().await, 0);
}

#[tokio::test]
async fn slow_servers_hit_the_request_timeout() {
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&server)
        .await;
    let rig = Rig::start(Reply::Status(500)).await;
    let profile = rig.profile(&[server.uri()], &[]);
    let timeouts = Timeouts {
        request: Duration::from_millis(100),
        total: Duration::from_secs(30),
    };
    let hosts = profile.header.sync_hosts.clone();
    let err = register_hosts(&client(), &hosts, &profile, &device(), Some(PIN), timeouts)
        .await
        .unwrap_err();
    assert!(matches!(err, RegisterError::Timeout));
    assert_eq!(err.to_body().code, ErrorCode::Timeout);
}

#[tokio::test]
async fn the_total_deadline_bounds_the_whole_host_walk() {
    let slow = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(500).set_delay(Duration::from_millis(300)))
        .mount(&slow)
        .await;
    let rig = Rig::start(Reply::Status(500)).await;
    let hosts = vec![slow.uri(), slow.uri(), slow.uri()];
    let profile = rig.profile(&hosts, &[]);
    let timeouts = Timeouts {
        request: Duration::from_secs(5),
        total: Duration::from_millis(500),
    };
    let started = std::time::Instant::now();
    let err = register_hosts(&client(), &hosts, &profile, &device(), Some(PIN), timeouts)
        .await
        .unwrap_err();
    assert!(matches!(err, RegisterError::Timeout));
    assert_eq!(err.to_body().code, ErrorCode::Timeout);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn server_text_is_sanitized_in_error_bodies() {
    let err = RegisterError::from(CoreError::InvalidResponse(
        "bad\u{1b}[2J\u{202e}text".into(),
    ));
    assert_eq!(err.to_body().message, "invalid server response: bad[2Jtext");
    let long = RegisterError::from(CoreError::Rejected {
        reason: Some("x".repeat(1000)),
    });
    assert!(long.to_body().message.chars().count() < 260);
}
