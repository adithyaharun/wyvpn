#![cfg(feature = "live")]

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use wyvpn_core::auth::openvpn_credentials;
use wyvpn_core::http::ApiClient;
use wyvpn_core::import::import_uri;
use wyvpn_core::sign::{generate_nonce, unix_now};
use wyvpn_core::sync::{SyncOutcome, build_sync_request, parse_sync_response};
use wyvpn_core::tls::TlsPolicy;
use wyvpn_core::wireguard::{
    DeviceInfo, KeepaliveInput, Platform, RegistrationInput, WireGuardSession, register_at,
    send_keepalive_at,
};
use wyvpn_core::{AuthMode, Error, NamedProfile, Profile, read_profiles};

const PIN_ENV: &str = "WYVPN_TEST_PIN";

struct Loaded {
    profiles: Vec<NamedProfile>,
    via: &'static str,
    tls_verified_by_roots: Option<bool>,
}

fn secrets_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.secrets")
}

fn variant(debug: &str) -> &str {
    debug
        .split(|c: char| !c.is_alphanumeric())
        .next()
        .unwrap_or("unknown")
}

fn describe(err: &Error) -> String {
    match err {
        Error::Status(code) => format!("Status({code})"),
        Error::Unsupported(inner) => format!("Unsupported({})", variant(&format!("{inner:?}"))),
        other => variant(&format!("{other:?}")).to_owned(),
    }
}

fn expect<T>(result: wyvpn_core::Result<T>, step: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{step} failed: {}", describe(&err)),
    }
}

async fn load(kind: &str) -> Option<Loaded> {
    let dir = secrets_dir();
    let link = dir.join(format!("{kind}.link"));
    if let Ok(text) = std::fs::read_to_string(&link) {
        let imported = expect(import_uri(text.trim()).await, "import");
        return Some(Loaded {
            profiles: imported.profiles,
            via: "link",
            tls_verified_by_roots: imported.tls.map(|t| t.verified_by_roots),
        });
    }
    for extension in ["tar", "ovpn"] {
        let name = format!("{kind}.{extension}");
        if let Ok(bytes) = std::fs::read(dir.join(&name)) {
            return Some(Loaded {
                profiles: expect(read_profiles(&name, &bytes), "profile read"),
                via: if extension == "tar" {
                    "tar"
                } else {
                    "ovpn file"
                },
                tls_verified_by_roots: None,
            });
        }
    }
    println!("[{kind}] skipped: no {kind}.link, {kind}.tar or {kind}.ovpn in .secrets/");
    None
}

fn cached(kind: &'static str) -> Option<Arc<Loaded>> {
    static WG: OnceLock<Option<Arc<Loaded>>> = OnceLock::new();
    static OVPN: OnceLock<Option<Arc<Loaded>>> = OnceLock::new();
    let cell = if kind == "wg" { &WG } else { &OVPN };
    cell.get_or_init(|| {
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(load(kind))
                .map(Arc::new)
        })
        .join()
        .expect("loader thread")
    })
    .clone()
}

fn pick(loaded: &Loaded, want_wireguard: bool) -> Option<&Profile> {
    loaded
        .profiles
        .iter()
        .map(|named| &named.profile)
        .find(|profile| !want_wireguard || profile.wireguard_available())
}

fn pin_for(profile: &Profile, kind: &str) -> Result<Option<String>, ()> {
    match profile.auth_mode() {
        AuthMode::None => Ok(None),
        AuthMode::Pin => match std::env::var(PIN_ENV).ok().filter(|p| !p.is_empty()) {
            Some(pin) => Ok(Some(pin)),
            None => {
                println!("[{kind}] skipped: set {PIN_ENV}");
                Err(())
            }
        },
        other => {
            println!("[{kind}] skipped: auth mode {other:?} is not supported");
            Err(())
        }
    }
}

fn client() -> ApiClient {
    expect(ApiClient::new(TlsPolicy::first_use()), "http client")
}

fn device() -> DeviceInfo {
    DeviceInfo {
        hostname: "wyvpn-live-test".into(),
        platform: Platform::current(),
        client_version: env!("CARGO_PKG_VERSION").into(),
        mac_addr: String::new(),
        mac_addrs: Vec::new(),
        public_address: String::new(),
        public_address6: String::new(),
    }
}

fn hosts(profile: &Profile) -> Vec<String> {
    let mut hosts = profile.header.sync_hosts.clone();
    for remote in profile.remotes() {
        let url = if remote.host.contains(':') {
            format!("https://[{}]", remote.host)
        } else {
            format!("https://{}", remote.host)
        };
        if !hosts.contains(&url) {
            hosts.push(url);
        }
    }
    hosts
}

fn session_token() -> String {
    wyvpn_core::rng::alphanumeric(16)
}

#[tokio::test]
#[ignore = "needs a real server and .secrets/"]
async fn live_import() {
    let mut any = false;
    for kind in ["wg", "ovpn"] {
        let Some(loaded) = cached(kind) else { continue };
        any = true;
        let profile = &loaded.profiles[0].profile;
        println!(
            "[{kind}] loaded via {}: {} profile(s), auth {:?}, transports {:?}, tls verified by roots: {:?}",
            loaded.via,
            loaded.profiles.len(),
            profile.auth_mode(),
            profile.transports(),
            loaded.tls_verified_by_roots,
        );
    }
    if !any {
        println!("nothing to test");
    }
}

#[tokio::test]
#[ignore = "needs a real server and .secrets/"]
async fn live_sync() {
    let client = client();
    for kind in ["wg", "ovpn"] {
        let Some(loaded) = cached(kind) else { continue };
        let profile = &loaded.profiles[0].profile;
        let mut synced = false;
        for host in &profile.header.sync_hosts {
            let request = expect(
                build_sync_request(profile, host, unix_now(), &generate_nonce()),
                "sync request",
            );
            let response = match client.execute(request).await {
                Ok(response) => response,
                Err(err) => {
                    println!("[{kind}] sync host unreachable: {}", describe(&err));
                    continue;
                }
            };
            println!("[{kind}] sync HTTP status: {}", response.status);
            match expect(parse_sync_response(profile, &response), "sync response") {
                SyncOutcome::Unchanged => println!("[{kind}] sync: unchanged, signature n/a"),
                SyncOutcome::Updated(_) => println!("[{kind}] sync: updated, signature verified"),
            }
            synced = true;
            break;
        }
        assert!(synced, "[{kind}] no sync host answered");
    }
}

#[tokio::test]
#[ignore = "needs a real server and .secrets/"]
async fn live_openvpn_credentials() {
    let Some(loaded) = cached("ovpn") else { return };
    let profile = &loaded.profiles[0].profile;
    let Ok(pin) = pin_for(profile, "ovpn") else {
        return;
    };
    let built = expect(
        openvpn_credentials(profile, pin.as_deref(), None),
        "credential build",
    );
    let envelope = if profile.header.server_box_public_key.is_some() {
        "box"
    } else if profile.header.server_public_key_pem().is_some() {
        "rsa"
    } else {
        "plain"
    };
    println!(
        "[ovpn] credentials built: {}, envelope: {envelope}",
        built.is_some()
    );
}

#[tokio::test]
#[ignore = "needs a real server and .secrets/"]
async fn live_wireguard_registration() {
    let Some(loaded) = cached("wg") else { return };
    let Some(profile) = pick(&loaded, true) else {
        println!("[wg] skipped: no profile with WireGuard enabled");
        return;
    };
    let Ok(pin) = pin_for(profile, "wg") else {
        return;
    };
    let client = client();
    let device = device();
    let token = session_token();
    let input = RegistrationInput {
        device: &device,
        pin: pin.as_deref(),
        auth_token: Some(&token),
    };

    let mut registered: Option<(String, WireGuardSession)> = None;
    for host in hosts(profile) {
        match register_at(&client, &host, profile, &input).await {
            Ok(session) => {
                println!("[wg] register accepted");
                registered = Some((host, session));
                break;
            }
            Err(err) => println!("[wg] register failed: {}", describe(&err)),
        }
    }
    let (host, session) = registered.expect("[wg] registration did not succeed");

    let config = &session.config;
    println!("[wg] configuration decrypted");
    println!("[wg] tunnel address: {}", config.address);
    println!("[wg] ipv6 address assigned: {}", config.address6.is_some());
    println!(
        "[wg] routes: {} v4, {} v6; dns servers: {}",
        config.routes.len(),
        config.routes6.len(),
        config.dns_servers.len()
    );
    println!(
        "[wg] keepalive interval: {}s",
        config.keepalive_interval().as_secs()
    );
    println!("[wg] server version: not exposed by the API");

    let keepalive = KeepaliveInput {
        device: &device,
        auth_token: Some(&token),
    };
    match send_keepalive_at(&client, &host, profile, &session, &keepalive).await {
        Ok(alive) => println!("[wg] keepalive accepted: {}", alive.status),
        Err(err) => println!("[wg] keepalive failed: {}", describe(&err)),
    }
}
