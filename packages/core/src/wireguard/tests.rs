use super::*;
use crate::sign::{hmac_base64, string_to_sign};
use crate::testdata::{self, SYNC_SECRET, SYNC_TOKEN};
use crate::tls::TlsPolicy;
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use std::mem::ManuallyDrop;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Accept,
    BadHmac,
    WrongKey,
    Deny,
    DeviceNotApproved,
    Sso,
    Keepalive,
}

struct FakeServer {
    secret: SecretKey,
    mode: Mode,
}

fn config_json(server_wg_key: &str) -> serde_json::Value {
    serde_json::json!({
        "address": "10.200.0.5/24",
        "address6": "fd00::5/64",
        "hostname": "203.0.113.9",
        "hostname6": "2001:db8::9",
        "gateway": "10.200.0.1",
        "gateway6": "fd00::1",
        "port": 51820,
        "mtu": 1420,
        "ping_interval": 30,
        "ping_timeout": 120,
        "web_port": 9443,
        "web_no_ssl": true,
        "public_key": server_wg_key,
        "routes": [{"network": "0.0.0.0/0", "next_hop": "10.200.0.1", "metric": 10, "net_gateway": false}],
        "routes6": [{"network": "::/0"}],
        "dns_servers": ["10.200.0.1"],
        "search_domains": ["corp.example"],
        "network_links": []
    })
}

fn wg_public_key_b64() -> String {
    STANDARD.encode([7u8; 32])
}

impl FakeServer {
    fn check(
        &self,
        request: &Request,
    ) -> std::result::Result<(Vec<u8>, PublicKey, serde_json::Value), String> {
        let header = |name: &str| {
            request
                .headers
                .get(name)
                .map(|v| v.to_str().unwrap().to_owned())
                .ok_or(format!("missing {name}"))
        };
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).map_err(|e| e.to_string())?;
        let field = |name: &str| {
            body[name]
                .as_str()
                .map(str::to_owned)
                .ok_or(format!("missing {name}"))
        };
        let (data, nonce, public, signature) = (
            field("data")?,
            field("nonce")?,
            field("public_key")?,
            field("signature")?,
        );
        if body["device_signature"] != "" {
            return Err("device signature".into());
        }

        let auth_nonce = header("auth-nonce")?;
        if auth_nonce.len() > 32 {
            return Err("nonce too long".into());
        }
        let to_sign = string_to_sign(
            &header("auth-token")?,
            &header("auth-timestamp")?,
            &auth_nonce,
            request.method.as_str(),
            request.url.path(),
            &[&data, &nonce, &public, &signature],
        );
        if header("auth-signature")? != hmac_base64(&Secret::new(SYNC_SECRET), to_sign.as_bytes())
            || header("auth-token")? != SYNC_TOKEN
        {
            return Err("bad hmac".into());
        }

        let user_key = RsaPrivateKey::from_pkcs8_pem(testdata::KEY_PKCS8)
            .unwrap()
            .to_public_key();
        let digest = Sha512::digest(format!("{data}&{nonce}&{public}"));
        let salt = (user_key.n().bits() - 1).div_ceil(8) - 66;
        user_key
            .verify(
                Pss::new_with_salt::<Sha512>(salt),
                &digest,
                &STANDARD.decode(&signature).unwrap(),
            )
            .map_err(|_| "bad rsa".to_owned())?;

        let client_pub = PublicKey::from_slice(&STANDARD.decode(&public).unwrap()).unwrap();
        let plain = SalsaBox::new(&client_pub, &self.secret)
            .decrypt(
                Nonce::from_slice(&STANDARD.decode(&nonce).unwrap()),
                STANDARD.decode(&data).unwrap().as_slice(),
            )
            .map_err(|_| "undecryptable".to_owned())?;
        let inner: serde_json::Value = serde_json::from_slice(&plain).map_err(|e| e.to_string())?;
        Ok((plain, client_pub, inner))
    }

    fn envelope(
        &self,
        client_pub: &PublicKey,
        plaintext: &serde_json::Value,
        key: &SecretKey,
    ) -> serde_json::Value {
        let nonce = rng::random_bytes::<24>();
        let cipher = SalsaBox::new(client_pub, key)
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
}

impl Respond for FakeServer {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let (_, client_pub, inner) = match self.check(request) {
            Ok(ok) => ok,
            Err(msg) => return ResponseTemplate::new(400).set_body_string(msg),
        };
        let expected_method = if self.mode == Mode::Keepalive {
            "PUT"
        } else {
            "POST"
        };
        if request.method.as_str() != expected_method
            || inner["wg_public_key"].as_str().map(str::len) != Some(44)
        {
            return ResponseTemplate::new(400).set_body_string("bad inner");
        }
        for key in [
            "device_id",
            "device_name",
            "platform",
            "mac_addr",
            "token",
            "nonce",
            "password",
            "timestamp",
            "public_address",
            "public_address6",
        ] {
            if inner.get(key).is_none() {
                return ResponseTemplate::new(400).set_body_string(format!("inner lacks {key}"));
            }
        }
        let expected_password = if self.mode == Mode::Keepalive {
            ""
        } else {
            "1234"
        };
        if inner["password"] != expected_password
            || inner["token"].as_str().unwrap().len() != 16
            || inner["nonce"].as_str().unwrap().len() != 16
        {
            return ResponseTemplate::new(400).set_body_string("bad credentials");
        }

        let body = match self.mode {
            Mode::Accept | Mode::BadHmac => self.envelope(
                &client_pub,
                &serde_json::json!({"allow": true, "configuration": config_json(&wg_public_key_b64()), "reason": null}),
                &self.secret,
            ),
            Mode::WrongKey => self.envelope(
                &client_pub,
                &serde_json::json!({"allow": true}),
                &SecretKey::generate(&mut OsRng),
            ),
            Mode::Deny => self.envelope(
                &client_pub,
                &serde_json::json!({"allow": false, "configuration": null, "reason": "Too many devices"}),
                &self.secret,
            ),
            Mode::DeviceNotApproved => self.envelope(
                &client_pub,
                &serde_json::json!({"allow": false, "token": null, "reason": null, "reg_key": "ABCD"}),
                &self.secret,
            ),
            Mode::Sso => serde_json::json!({"sso_token": "t", "sso_url": "https://sso.example/key/request?state=x"}),
            Mode::Keepalive => self.envelope(
                &client_pub,
                &serde_json::json!({"status": true, "timestamp": 1_760_000_000}),
                &self.secret,
            ),
        };
        let mut body = body;
        if self.mode == Mode::BadHmac {
            body["data"] = STANDARD.encode(b"tampered").into();
        }
        ResponseTemplate::new(200).set_body_json(body)
    }
}

fn profile_for(server: &SecretKey, extra: &[&str]) -> Profile {
    let key = format!(
        "\"server_box_public_key\": \"{}\"",
        STANDARD.encode(server.public_key().as_bytes())
    );
    let mut fields = vec!["\"wg\": true", "\"password_mode\": \"pin\"", key.as_str()];
    fields.extend_from_slice(extra);
    Profile::parse(&testdata::ovpn(&fields, "")).unwrap()
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

fn input(device: &DeviceInfo) -> RegistrationInput<'_> {
    RegistrationInput {
        device,
        pin: Some("1234"),
        auth_token: None,
    }
}

fn client() -> ApiClient {
    ApiClient::new(TlsPolicy::Verify)
        .unwrap()
        .allow_plain_http()
}

async fn serve(mode: Mode) -> (MockServer, SecretKey) {
    let secret = SecretKey::generate(&mut OsRng);
    let responder = FakeServer {
        secret: SecretKey::from_bytes(secret.to_bytes()),
        mode,
    };
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::path_regex("^/key/wg/"))
        .respond_with(responder)
        .mount(&server)
        .await;
    (server, secret)
}

#[test]
fn keys_are_clamped_unique_and_consistent() {
    let a = WireGuardKeys::generate();
    let b = WireGuardKeys::generate();
    assert_ne!(a.public_key_base64(), b.public_key_base64());
    assert_eq!(a.private[0] & 7, 0);
    assert_eq!(a.private[31] & 0xC0, 0x40);
    assert_eq!(
        a.public,
        *SecretKey::from_bytes(*a.private).public_key().as_bytes()
    );
    assert_eq!(a.public_key_base64().len(), 44);
    assert_eq!(a.private_key_base64().len(), 44);
    let rendered = format!("{a:?}");
    assert!(!rendered.contains(&*a.private_key_base64()));
}

#[test]
#[allow(unsafe_code)]
fn private_key_is_zeroed_on_drop() {
    let mut keys = ManuallyDrop::new(WireGuardKeys::generate());
    let ptr = keys.private.as_ptr();
    assert!(keys.private.iter().any(|b| *b != 0));
    // SAFETY: the storage lives on this stack frame; only the destructor has run.
    let after = unsafe {
        ManuallyDrop::drop(&mut keys);
        std::slice::from_raw_parts(ptr, 32)
    };
    assert!(after.iter().all(|b| *b == 0));
}

#[test]
fn config_parses_documented_fields() {
    let config = WireGuardConfig::from_json(config_json(&wg_public_key_b64())).unwrap();
    assert_eq!(config.address.to_string(), "10.200.0.5/24");
    assert_eq!(config.address6.unwrap().to_string(), "fd00::5/64");
    assert_eq!(config.endpoint().to_string(), "203.0.113.9:51820");
    assert_eq!(config.gateway, Ipv4Addr::new(10, 200, 0, 1));
    assert_eq!(config.mtu, Some(1420));
    assert_eq!(config.routes[0].network.to_string(), "0.0.0.0/0");
    assert_eq!(config.routes[0].metric, Some(10));
    assert_eq!(config.routes6[0].network.to_string(), "::/0");
    assert_eq!(config.dns_servers, vec![IpAddr::from([10, 200, 0, 1])]);
    assert_eq!(config.search_domains, vec!["corp.example"]);
    assert_eq!(config.keepalive_base_url(), "http://10.200.0.1:9443");
    assert_eq!(config.keepalive_interval(), Duration::from_secs(30));
}

#[test]
fn config_validation_rejects_bad_input() {
    let key = wg_public_key_b64();
    let mutate = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut value = config_json(&key);
        f(&mut value);
        WireGuardConfig::from_json(value)
    };
    assert!(
        mutate(&|v| {
            v.as_object_mut().unwrap().remove("address");
        })
        .is_err()
    );
    assert!(mutate(&|v| v["address"] = "fd00::1/64".into()).is_err());
    assert!(mutate(&|v| v["address6"] = "10.0.0.1/24".into()).is_err());
    assert!(mutate(&|v| v["port"] = 0.into()).is_err());
    assert!(mutate(&|v| v["public_key"] = "AAAA".into()).is_err());
    assert!(mutate(&|v| v["public_key"] = "not base64!".into()).is_err());
    for bad in [
        "",
        "a b",
        "-x.example",
        "x..example",
        "host/name",
        "1.2.3.999",
        "a\u{202e}b",
    ] {
        assert!(mutate(&|v| v["hostname"] = bad.into()).is_err(), "{bad:?}");
    }
    assert!(mutate(&|v| v["hostname6"] = "vpn.example".into()).is_err());
    assert!(mutate(&|v| v["routes"] = serde_json::json!([{"network": "::/0"}])).is_err());
    assert!(mutate(&|v| v["routes"] = serde_json::json!([{"network": "10.0.0.0/33"}])).is_err());
    let minimal = mutate(&|v| {
        let map = v.as_object_mut().unwrap();
        for k in [
            "mtu",
            "routes",
            "routes6",
            "dns_servers",
            "address6",
            "ping_interval",
        ] {
            map.remove(k);
        }
    })
    .unwrap();
    assert_eq!(minimal.mtu, None);
    assert!(minimal.routes.is_empty());
    assert_eq!(minimal.keepalive_interval(), Duration::from_secs(15));
    assert_eq!(mutate(&|v| v["mtu"] = 0.into()).unwrap().mtu, None);
    assert_eq!(Cidr::from_str("10.1.2.3").unwrap().prefix, 32);
}

#[test]
fn pss_salt_is_the_maximum_length() {
    let key = RsaPrivateKey::from_pkcs8_pem(testdata::KEY_PKCS8).unwrap();
    assert_eq!(pss_salt_len(&key), 256 - 64 - 2);
    let digest = Sha512::digest(b"payload");
    let signature = sign_digest(&key, &digest).unwrap();
    let public = key.to_public_key();
    assert!(
        public
            .verify(Pss::new_with_salt::<Sha512>(190), &digest, &signature)
            .is_ok()
    );
    assert!(
        public
            .verify(Pss::new_with_salt::<Sha512>(64), &digest, &signature)
            .is_err()
    );
}

#[test]
fn pkcs1_private_keys_are_accepted() {
    let key = load_private_key(&Secret::new(testdata::KEY_PKCS1)).unwrap();
    let public = RsaPublicKey::from_pkcs1_pem(testdata::PUB_PKCS1).unwrap();
    assert_eq!(key.to_public_key(), public);
}

#[test]
fn every_request_uses_fresh_key_and_nonces() {
    let server = SecretKey::generate(&mut OsRng);
    let profile = profile_for(&server, &[]);
    let device = device();
    let a = PendingRegistration::start(&profile, &input(&device)).unwrap();
    let b = PendingRegistration::start(&profile, &input(&device)).unwrap();
    assert_ne!(a.keys.public_key_base64(), b.keys.public_key_base64());
    assert_ne!(a.request().body, b.request().body);
    assert_ne!(
        a.request().header("auth-nonce"),
        b.request().header("auth-nonce")
    );
    assert!(!format!("{a:?}").contains("1234"));
    assert_eq!(
        a.request().header("user-agent"),
        Some(VENDOR_USER_AGENT_CLIENT)
    );
}

#[test]
fn unsupported_modes_never_build_a_request() {
    let server = SecretKey::generate(&mut OsRng);
    let device = device();
    for (extra, expected) in [
        (&["\"password_mode\": \"otp_pin\""][..], Unsupported::PinOtp),
        (&["\"password_mode\": \"otp\""], Unsupported::Otp),
        (&["\"sso_auth\": true"], Unsupported::Sso),
        (&["\"device_auth\": true"], Unsupported::DeviceAuth),
    ] {
        let mut fields = vec!["\"wg\": true"];
        let key = format!(
            "\"server_box_public_key\": \"{}\"",
            STANDARD.encode(server.public_key().as_bytes())
        );
        fields.push(&key);
        fields.extend_from_slice(extra);
        let profile = Profile::parse(&testdata::ovpn(&fields, "")).unwrap();
        match PendingRegistration::start(&profile, &input(&device)) {
            Err(Error::Unsupported(found)) => assert_eq!(found, expected),
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn registration_round_trip() {
    let (mock, secret) = serve(Mode::Accept).await;
    let profile = profile_for(&secret, &[]);
    let device = device();
    let session = register_at(&client(), &mock.uri(), &profile, &input(&device))
        .await
        .unwrap();
    assert_eq!(session.config.address.to_string(), "10.200.0.5/24");
    assert_eq!(session.config.public_key.to_string(), wg_public_key_b64());
    assert_eq!(session.keys.public_key_base64().len(), 44);
}

#[tokio::test]
async fn registration_walks_hosts_and_keeps_going_past_http_errors() {
    let (mock, secret) = serve(Mode::Accept).await;
    let dead = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(429))
        .mount(&dead)
        .await;
    let hosts = vec![dead.uri(), mock.uri()];
    let profile = profile_for(&secret, &[]);
    let device = device();
    assert!(
        register_with_hosts(
            &client(),
            &hosts,
            &profile,
            &input(&device),
            REGISTER_TIMEOUT
        )
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn tampered_response_signature_discards_the_key() {
    let (mock, secret) = serve(Mode::BadHmac).await;
    let profile = profile_for(&secret, &[]);
    let device = device();
    let err = register_at(&client(), &mock.uri(), &profile, &input(&device))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::ResponseSignature));
}

#[tokio::test]
async fn undecryptable_response_discards_the_key() {
    let (mock, secret) = serve(Mode::WrongKey).await;
    let profile = profile_for(&secret, &[]);
    let device = device();
    let pending = PendingRegistration::start(&profile, &input(&device)).unwrap();
    let http = pending.request().clone().into_http(&mock.uri()).unwrap();
    let response = client().execute(http).await.unwrap();
    let err = pending.finish(&response).unwrap_err();
    assert!(matches!(err, Error::Decrypt));
}

#[tokio::test]
async fn denial_device_approval_and_sso_are_distinct_errors() {
    let device = device();
    let (mock, secret) = serve(Mode::Deny).await;
    let err = register_at(
        &client(),
        &mock.uri(),
        &profile_for(&secret, &[]),
        &input(&device),
    )
    .await
    .unwrap_err();
    assert!(matches!(&err, Error::Rejected { reason: Some(r) } if r == "Too many devices"));

    let (mock, secret) = serve(Mode::DeviceNotApproved).await;
    let err = register_at(
        &client(),
        &mock.uri(),
        &profile_for(&secret, &[]),
        &input(&device),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::Unsupported(Unsupported::DeviceAuth)));

    let (mock, secret) = serve(Mode::Sso).await;
    let err = register_at(
        &client(),
        &mock.uri(),
        &profile_for(&secret, &[]),
        &input(&device),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::Unsupported(Unsupported::Sso)));
}

#[tokio::test]
async fn keepalive_round_trip_uses_put() {
    let (mock, secret) = serve(Mode::Keepalive).await;
    let profile = profile_for(&secret, &[]);
    let device = device();
    let session = WireGuardSession {
        keys: WireGuardKeys::generate(),
        config: WireGuardConfig::from_json(config_json(&wg_public_key_b64())).unwrap(),
    };
    let keepalive = KeepaliveInput {
        device: &device,
        auth_token: None,
    };
    let pending = PendingKeepalive::start(&profile, &session, &keepalive).unwrap();
    assert_eq!(pending.request().method, Method::PUT);
    assert_eq!(
        pending
            .http_request()
            .unwrap()
            .url
            .as_str()
            .split("/key")
            .next(),
        Some("http://10.200.0.1:9443")
    );
    let http = pending.request().clone().into_http(&mock.uri()).unwrap();
    let response = client().execute(http).await.unwrap();
    let alive = pending.finish(&response).unwrap();
    assert!(alive.status);
    assert_eq!(alive.timestamp, 1_760_000_000);
}

#[test]
fn hosts_list_sync_hosts_before_remotes_and_apply_port_rules() {
    let server = SecretKey::generate(&mut OsRng);
    let hosts = "\"sync_hosts\": [\"https://sync-a.example:9443\", \"https://vpn.example.com\"]";
    let body = "remote 2001:db8::7 1194 udp\n";
    let key = format!(
        "\"server_box_public_key\": \"{}\"",
        STANDARD.encode(server.public_key().as_bytes())
    );
    let text = testdata::ovpn(&["\"wg\": true", hosts, &key], body);
    let profile = Profile::parse(&text).unwrap();
    assert_eq!(
        registration_hosts(&profile),
        [
            "https://sync-a.example:9443",
            "https://vpn.example.com",
            "https://192.0.2.7",
            "https://[2001:db8::7]",
        ]
    );
}

#[test]
fn hosts_without_sync_hosts_fall_back_to_remotes() {
    let profile = profile_for(&SecretKey::generate(&mut OsRng), &[]);
    assert_eq!(
        registration_hosts(&profile),
        ["https://vpn.example.com", "https://192.0.2.7"]
    );
}

#[test]
fn endpoints_format_hosts_with_brackets_for_ipv6() {
    let mut config = config_json(&wg_public_key_b64());
    let parse = |host: &str, config: &mut serde_json::Value| {
        config["hostname"] = host.into();
        WireGuardConfig::from_json(config.clone())
            .unwrap()
            .endpoint()
    };
    assert_eq!(
        parse("203.0.113.9", &mut config).to_string(),
        "203.0.113.9:51820"
    );
    assert_eq!(
        parse("2001:db8::9", &mut config).to_string(),
        "[2001:db8::9]:51820"
    );
    assert_eq!(
        parse("VPN.Example.com", &mut config).to_string(),
        "vpn.example.com:51820"
    );
}

#[tokio::test]
async fn most_specific_error_wins_across_hosts() {
    let secret = SecretKey::generate(&mut OsRng);
    let profile = profile_for(&secret, &[]);
    let device = device();
    for order in [[429, 500], [500, 429]] {
        let mut hosts = Vec::new();
        let mut servers = Vec::new();
        for code in order {
            let server = MockServer::start().await;
            Mock::given(wiremock::matchers::any())
                .respond_with(ResponseTemplate::new(code))
                .mount(&server)
                .await;
            hosts.push(server.uri());
            servers.push(server);
        }
        let err = register_with_hosts(
            &client(),
            &hosts,
            &profile,
            &input(&device),
            REGISTER_TIMEOUT,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::Status(429)), "{order:?}: {err:?}");
    }
    let err = register_with_hosts(&client(), &[], &profile, &input(&device), REGISTER_TIMEOUT)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NoSyncHosts));
}

#[test]
fn unusable_hosts_are_dropped_and_duplicates_collapsed() {
    let server = SecretKey::generate(&mut OsRng);
    let hosts = [
        "http://plain.example",
        "https://user:pw@creds.example",
        "https://query.example/?x=1",
        "https://frag.example/#f",
        "https://path.example/api",
        "https://127.0.0.1",
        "https://169.254.1.1",
        "https://0.0.0.0",
        "https://224.0.0.1",
        "https://[::1]",
        "https://[fe80::1]",
        "not a url",
        "https://Good.Example:443/",
        "https://good.example",
        "https://good.example:9443",
        "https://203.0.113.4/",
    ];
    let hosts = format!("\"sync_hosts\": {}", serde_json::to_string(&hosts).unwrap());
    let profile = profile_for(&server, &[&hosts]);
    assert_eq!(
        registration_hosts(&profile),
        [
            "https://good.example",
            "https://good.example:9443",
            "https://203.0.113.4",
            "https://vpn.example.com",
            "https://192.0.2.7",
        ]
    );
}

#[test]
fn bracketed_ipv6_remotes_are_not_double_bracketed_and_hosts_are_capped() {
    let server = SecretKey::generate(&mut OsRng);
    let many: Vec<String> = (1..=12).map(|n| format!("https://h{n}.example")).collect();
    let hosts = format!("\"sync_hosts\": {}", serde_json::to_string(&many).unwrap());
    let key = format!(
        "\"server_box_public_key\": \"{}\"",
        STANDARD.encode(server.public_key().as_bytes())
    );
    let capped = Profile::parse(&testdata::ovpn(&["\"wg\": true", &hosts, &key], "")).unwrap();
    let listed = registration_hosts(&capped);
    assert_eq!(listed.len(), 8);
    assert_eq!(listed[7], "https://h8.example");

    let text = testdata::ovpn(&["\"wg\": true", &key], "remote [2001:db8::7] 1194 udp\n");
    let profile = Profile::parse(&text).unwrap();
    assert!(registration_hosts(&profile).contains(&"https://[2001:db8::7]".to_owned()));
}

#[test]
fn inputs_redact_secrets_in_debug() {
    let device = device();
    let rendered = format!(
        "{:?} {:?}",
        RegistrationInput {
            device: &device,
            pin: Some("98765"),
            auth_token: Some("abcdefghijklmnop"),
        },
        KeepaliveInput {
            device: &device,
            auth_token: Some("abcdefghijklmnop"),
        }
    );
    assert!(!rendered.contains("98765") && !rendered.contains("abcdefghijklmnop"));
    assert!(rendered.contains("<redacted>"));
}

#[test]
fn dynamic_firewall_profiles_never_build_a_registration() {
    let server = SecretKey::generate(&mut OsRng);
    let profile = profile_for(&server, &["\"dynamic_firewall\": true"]);
    let device = device();
    match PendingRegistration::start(&profile, &input(&device)) {
        Err(Error::Unsupported(Unsupported::DynamicFirewall)) => {}
        other => panic!("unexpected {other:?}"),
    }
}
