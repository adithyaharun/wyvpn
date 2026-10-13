use crate::auth::{decode_box_public_key, password_for, resolve_auth_token};
use crate::error::{Error, Result, Unsupported};
use crate::http::{ApiClient, HttpRequest, HttpResponse, Method};
use crate::profile::Profile;
use crate::rng;
use crate::secret::Secret;
use crate::sign::{generate_nonce, sign_request, unix_now, verify_hmac_base64};
use crate::vendor::VENDOR_USER_AGENT_CLIENT;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use crypto_box::aead::{Aead, OsRng};
use crypto_box::{Nonce, PublicKey, SalsaBox, SecretKey};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{Pss, RsaPrivateKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;
use url::Url;
use wyvpn_ipc::Transport;
use zeroize::Zeroizing;

const REGISTER_TIMEOUT: Duration = Duration::from_secs(40);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(15);
const BOX_NONCE_LEN: usize = 24;
const INNER_NONCE_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Windows,
    Mac,
    Unknown,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::Mac
        } else {
            Self::Unknown
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Windows => "win",
            Self::Mac => "mac",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub hostname: String,
    pub platform: Platform,
    pub client_version: String,
    pub mac_addr: String,
    pub mac_addrs: Vec<String>,
    pub public_address: String,
    pub public_address6: String,
}

#[derive(Debug, Clone, Copy)]
pub struct RegistrationInput<'a> {
    pub device: &'a DeviceInfo,
    pub pin: Option<&'a str>,
    pub auth_token: Option<&'a str>,
}

#[derive(Debug, Clone, Copy)]
pub struct KeepaliveInput<'a> {
    pub device: &'a DeviceInfo,
    pub auth_token: Option<&'a str>,
}

pub struct WireGuardKeys {
    private: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl WireGuardKeys {
    pub fn generate() -> Self {
        let mut private = Zeroizing::new(rng::random_bytes::<32>());
        private[0] &= 248;
        private[31] &= 127;
        private[31] |= 64;
        let public = *SecretKey::from_bytes(*private).public_key().as_bytes();
        Self { private, public }
    }

    pub fn public_key_base64(&self) -> String {
        STANDARD.encode(self.public)
    }

    pub fn private_key_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(STANDARD.encode(*self.private))
    }
}

impl fmt::Debug for WireGuardKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireGuardKeys")
            .field("public", &self.public_key_base64())
            .field("private", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl FromStr for Cidr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let bad = || Error::InvalidResponse(format!("invalid network {s:?}"));
        let (addr, prefix) = match s.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (s, None),
        };
        let addr: IpAddr = addr.parse().map_err(|_| bad())?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p.parse::<u8>().map_err(|_| bad())?,
            None => max,
        };
        if prefix > max {
            return Err(bad());
        }
        Ok(Self { addr, prefix })
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Route {
    pub network: Cidr,
    #[serde(default)]
    pub next_hop: Option<IpAddr>,
    #[serde(default)]
    pub metric: Option<u32>,
    #[serde(default)]
    pub net_gateway: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardConfig {
    pub address: Cidr,
    pub address6: Option<Cidr>,
    pub hostname: String,
    pub hostname6: Option<String>,
    pub gateway: Ipv4Addr,
    pub gateway6: Option<Ipv6Addr>,
    pub port: u16,
    pub mtu: Option<u16>,
    pub ping_interval: u64,
    pub ping_timeout: u64,
    pub web_port: u16,
    pub web_no_ssl: bool,
    pub public_key: String,
    pub routes: Vec<Route>,
    pub routes6: Vec<Route>,
    pub dns_servers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
}

#[derive(Deserialize)]
struct RawConfig {
    address: Option<String>,
    address6: Option<String>,
    hostname: Option<String>,
    hostname6: Option<String>,
    gateway: Option<Ipv4Addr>,
    gateway6: Option<Ipv6Addr>,
    port: Option<u16>,
    mtu: Option<u16>,
    ping_interval: Option<u64>,
    ping_timeout: Option<u64>,
    web_port: Option<u16>,
    web_no_ssl: Option<bool>,
    public_key: Option<String>,
    routes: Option<Vec<Route>>,
    routes6: Option<Vec<Route>>,
    dns_servers: Option<Vec<IpAddr>>,
    search_domains: Option<Vec<String>>,
}

fn required<T>(value: Option<T>, name: &str) -> Result<T> {
    value.ok_or_else(|| Error::InvalidResponse(format!("configuration is missing {name}")))
}

impl WireGuardConfig {
    pub fn from_json(value: serde_json::Value) -> Result<Self> {
        let raw: RawConfig =
            serde_json::from_value(value).map_err(|err| Error::InvalidResponse(err.to_string()))?;
        let address: Cidr = required(raw.address, "address")?.parse()?;
        if !address.addr.is_ipv4() {
            return Err(Error::InvalidResponse("address must be IPv4".into()));
        }
        let address6 = raw
            .address6
            .filter(|a| !a.is_empty())
            .map(|a| a.parse::<Cidr>())
            .transpose()?;
        if address6.is_some_and(|a| !a.addr.is_ipv6()) {
            return Err(Error::InvalidResponse("address6 must be IPv6".into()));
        }
        let hostname = required(raw.hostname, "hostname")?;
        if hostname.is_empty() {
            return Err(Error::InvalidResponse(
                "configuration is missing hostname".into(),
            ));
        }
        let port = required(raw.port, "port")?;
        let web_port = required(raw.web_port, "web_port")?;
        if port == 0 || web_port == 0 {
            return Err(Error::InvalidResponse("port must be 1-65535".into()));
        }
        let public_key = required(raw.public_key, "public_key")?;
        if STANDARD.decode(&public_key).map(|k| k.len()) != Ok(32) {
            return Err(Error::InvalidResponse(
                "public_key is not a 32 byte key".into(),
            ));
        }
        let routes = raw.routes.unwrap_or_default();
        let routes6 = raw.routes6.unwrap_or_default();
        if routes.iter().any(|r| !r.network.addr.is_ipv4())
            || routes6.iter().any(|r| !r.network.addr.is_ipv6())
        {
            return Err(Error::InvalidResponse(
                "route has the wrong address family".into(),
            ));
        }
        Ok(Self {
            address,
            address6,
            hostname,
            hostname6: raw.hostname6.filter(|h| !h.is_empty()),
            gateway: required(raw.gateway, "gateway")?,
            gateway6: raw.gateway6,
            port,
            mtu: raw.mtu.filter(|m| *m != 0),
            ping_interval: raw.ping_interval.unwrap_or_default(),
            ping_timeout: raw.ping_timeout.unwrap_or_default(),
            web_port,
            web_no_ssl: raw.web_no_ssl.unwrap_or_default(),
            public_key,
            routes,
            routes6,
            dns_servers: raw.dns_servers.unwrap_or_default(),
            search_domains: raw.search_domains.unwrap_or_default(),
        })
    }

    pub fn keepalive_interval(&self) -> Duration {
        Duration::from_secs(match self.ping_interval {
            0 => 15,
            1..=4 => 5,
            other => other,
        })
    }

    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.hostname, self.port)
    }

    pub fn keepalive_base_url(&self) -> String {
        let scheme = if self.web_no_ssl { "http" } else { "https" };
        if self.web_port == 443 {
            format!("{scheme}://{}", self.gateway)
        } else {
            format!("{scheme}://{}:{}", self.gateway, self.web_port)
        }
    }
}

#[derive(Debug)]
pub struct WireGuardSession {
    pub keys: WireGuardKeys,
    pub config: WireGuardConfig,
}

#[derive(Clone)]
pub struct WireRequest {
    pub method: Method,
    pub path: String,
    pub body: String,
    headers: Vec<(String, String)>,
    timeout: Duration,
}

impl fmt::Debug for WireRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl WireRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn into_http(self, base_url: &str) -> Result<HttpRequest> {
        let mut url = Url::parse(base_url).map_err(|err| Error::InvalidUri(err.to_string()))?;
        url.set_path(&self.path);
        Ok(HttpRequest {
            method: self.method,
            url,
            headers: self.headers,
            body: Some(self.body),
            timeout: self.timeout,
        })
    }
}

#[derive(Serialize)]
struct Inner<'a> {
    device_id: &'a str,
    device_name: &'a str,
    device_key: &'a str,
    device_hostname: &'a str,
    platform: &'a str,
    client_ver: &'a str,
    mac_addr: &'a str,
    mac_addrs: &'a [String],
    token: &'a str,
    nonce: String,
    password: &'a str,
    timestamp: u64,
    wg_public_key: &'a str,
    public_address: &'a str,
    public_address6: &'a str,
    sso_token: &'a str,
}

#[derive(Serialize)]
struct Outer<'a> {
    data: &'a str,
    nonce: &'a str,
    public_key: &'a str,
    signature: &'a str,
    device_signature: &'a str,
}

struct Prepared {
    request: WireRequest,
    ephemeral: SecretKey,
    server_key: PublicKey,
    sync_secret: Secret,
}

fn load_private_key(pem: &Secret) -> Result<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs8_pem(pem.expose())
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem.expose()))
        .map_err(|_| Error::InvalidKey("profile private key"))
}

pub fn pss_salt_len(key: &RsaPrivateKey) -> usize {
    let em_len = (key.n().bits() - 1).div_ceil(8);
    em_len.saturating_sub(Sha512::output_size() + 2)
}

fn sign_digest(key: &RsaPrivateKey, digest: &[u8]) -> Result<Vec<u8>> {
    let scheme = Pss::new_with_salt::<Sha512>(pss_salt_len(key));
    key.sign_with_rng(&mut OsRng, scheme, digest)
        .map_err(|_| Error::InvalidKey("profile private key cannot sign"))
}

fn prepare(
    profile: &Profile,
    method: Method,
    wg_public_key: &str,
    device: &DeviceInfo,
    auth_token: Option<&str>,
    password: &str,
    timeout: Duration,
) -> Result<Prepared> {
    let header = &profile.header;
    for (value, name) in [
        (&header.organization_id, "organization_id"),
        (&header.user_id, "user_id"),
        (&header.server_id, "server_id"),
    ] {
        if value.is_empty() {
            return Err(Error::MissingField(name));
        }
    }
    let sync_token = header
        .sync_token
        .as_ref()
        .filter(|t| !t.is_empty())
        .ok_or(Error::MissingField("sync_token"))?;
    let sync_secret = header
        .sync_secret
        .as_ref()
        .filter(|s| !s.is_empty())
        .ok_or(Error::MissingField("sync_secret"))?;
    let box_key = header
        .server_box_public_key
        .as_deref()
        .ok_or(Error::MissingField("server_box_public_key"))?;
    let server_key = decode_box_public_key(box_key)?;
    let device_id = profile
        .device_id()
        .ok_or(Error::MissingField("device id"))?;
    let device_name = profile
        .device_name()
        .ok_or(Error::MissingField("device name"))?;
    let private_pem = profile
        .private_key_pem()
        .ok_or(Error::MissingField("private key"))?;
    let private_key = load_private_key(&private_pem)?;
    let auth_token = resolve_auth_token(auth_token)?;

    let inner = Inner {
        device_id,
        device_name,
        device_key: "",
        device_hostname: &device.hostname,
        platform: device.platform.as_str(),
        client_ver: &device.client_version,
        mac_addr: &device.mac_addr,
        mac_addrs: &device.mac_addrs,
        token: &auth_token,
        nonce: rng::alphanumeric(INNER_NONCE_LEN),
        password,
        timestamp: unix_now(),
        wg_public_key,
        public_address: &device.public_address,
        public_address6: &device.public_address6,
        sso_token: "",
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(&inner).map_err(|_| Error::Encrypt)?);

    let ephemeral = SecretKey::generate(&mut OsRng);
    let box_nonce = rng::random_bytes::<BOX_NONCE_LEN>();
    let cipher = SalsaBox::new(&server_key, &ephemeral)
        .encrypt(Nonce::from_slice(&box_nonce), plaintext.as_slice())
        .map_err(|_| Error::Encrypt)?;
    let data64 = STANDARD.encode(cipher);
    let nonce64 = STANDARD.encode(box_nonce);
    let public_key64 = STANDARD.encode(ephemeral.public_key().as_bytes());

    let digest = Sha512::digest(format!("{data64}&{nonce64}&{public_key64}"));
    let signature64 = STANDARD.encode(sign_digest(&private_key, &digest)?);

    let path = format!(
        "/key/wg/{}/{}/{}",
        header.organization_id, header.user_id, header.server_id
    );
    let auth = sign_request(
        sync_secret,
        sync_token.expose(),
        unix_now(),
        &generate_nonce(),
        method.as_str(),
        &path,
        &[&data64, &nonce64, &public_key64, &signature64],
    )?;
    let body = serde_json::to_string(&Outer {
        data: &data64,
        nonce: &nonce64,
        public_key: &public_key64,
        signature: &signature64,
        device_signature: "",
    })
    .map_err(|_| Error::Encrypt)?;

    let mut headers: Vec<(String, String)> = auth
        .headers()
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
    headers.push(("User-Agent".into(), VENDOR_USER_AGENT_CLIENT.into()));
    headers.push(("Content-Type".into(), "application/json".into()));

    Ok(Prepared {
        request: WireRequest {
            method,
            path,
            body,
            headers,
            timeout,
        },
        ephemeral,
        server_key,
        sync_secret: sync_secret.clone(),
    })
}

#[derive(Deserialize)]
struct ResponseEnvelope {
    data: String,
    nonce: String,
    signature: String,
}

fn open_envelope(prepared: &Prepared, response: &HttpResponse) -> Result<Vec<u8>> {
    if response.status != 200 {
        return Err(Error::Status(response.status));
    }
    let envelope: ResponseEnvelope = serde_json::from_slice(&response.body)
        .map_err(|err| Error::InvalidResponse(err.to_string()))?;
    let signed = format!("{}&{}", envelope.data, envelope.nonce);
    if !verify_hmac_base64(
        &prepared.sync_secret,
        signed.as_bytes(),
        &envelope.signature,
    ) {
        return Err(Error::ResponseSignature);
    }
    let data = STANDARD
        .decode(&envelope.data)
        .map_err(|_| Error::Decrypt)?;
    let nonce = STANDARD
        .decode(&envelope.nonce)
        .map_err(|_| Error::Decrypt)?;
    if nonce.len() != BOX_NONCE_LEN {
        return Err(Error::Decrypt);
    }
    SalsaBox::new(&prepared.server_key, &prepared.ephemeral)
        .decrypt(Nonce::from_slice(&nonce), data.as_slice())
        .map_err(|_| Error::Decrypt)
}

fn reject_sso(body: &[u8]) -> Result<()> {
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_slice(body)
        && (map.contains_key("sso_token") || map.contains_key("sso_url"))
    {
        return Err(Unsupported::Sso.into());
    }
    Ok(())
}

#[derive(Deserialize)]
struct RegistrationResult {
    #[serde(default)]
    allow: bool,
    #[serde(default)]
    configuration: Option<serde_json::Value>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    reg_key: Option<String>,
}

pub struct PendingRegistration {
    keys: WireGuardKeys,
    prepared: Prepared,
}

impl fmt::Debug for PendingRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingRegistration")
            .field("request", &self.prepared.request)
            .finish_non_exhaustive()
    }
}

impl PendingRegistration {
    pub fn start(profile: &Profile, input: &RegistrationInput<'_>) -> Result<Self> {
        Self::start_with_keys(profile, input, WireGuardKeys::generate())
    }

    pub fn start_with_keys(
        profile: &Profile,
        input: &RegistrationInput<'_>,
        keys: WireGuardKeys,
    ) -> Result<Self> {
        let password = password_for(&profile.header, input.pin, Transport::WireGuard)?;
        let prepared = prepare(
            profile,
            Method::POST,
            &keys.public_key_base64(),
            input.device,
            input.auth_token,
            password.expose(),
            REGISTER_TIMEOUT,
        )?;
        Ok(Self { keys, prepared })
    }

    pub fn request(&self) -> &WireRequest {
        &self.prepared.request
    }

    pub fn finish(self, response: &HttpResponse) -> Result<WireGuardSession> {
        if response.status == 200 {
            reject_sso(&response.body)?;
        }
        let plaintext = Zeroizing::new(open_envelope(&self.prepared, response)?);
        let result: RegistrationResult = serde_json::from_slice(&plaintext)
            .map_err(|err| Error::InvalidResponse(err.to_string()))?;
        if !result.allow {
            if result.reg_key.is_some() {
                return Err(Unsupported::DeviceAuth.into());
            }
            return Err(Error::Rejected {
                reason: result.reason,
            });
        }
        let configuration = result
            .configuration
            .ok_or_else(|| Error::InvalidResponse("configuration missing".into()))?;
        let config = WireGuardConfig::from_json(configuration)?;
        Ok(WireGuardSession {
            keys: self.keys,
            config,
        })
    }
}

fn candidate_hosts(profile: &Profile) -> Vec<String> {
    let mut hosts = profile.header.sync_hosts.clone();
    for remote in profile.remotes() {
        let host = if remote.host.contains(':') {
            format!("[{}]", remote.host)
        } else {
            remote.host
        };
        let url = format!("https://{host}");
        if !hosts.contains(&url) {
            hosts.push(url);
        }
    }
    hosts
}

pub async fn register_at(
    client: &ApiClient,
    base_url: &str,
    profile: &Profile,
    input: &RegistrationInput<'_>,
) -> Result<WireGuardSession> {
    let pending = PendingRegistration::start(profile, input)?;
    let request = pending.request().clone().into_http(base_url)?;
    let response = client.execute(request).await?;
    pending.finish(&response)
}

pub async fn register(
    client: &ApiClient,
    profile: &Profile,
    input: &RegistrationInput<'_>,
) -> Result<WireGuardSession> {
    let mut last = Error::NoSyncHosts;
    for host in candidate_hosts(profile) {
        match register_at(client, &host, profile, input).await {
            Ok(session) => return Ok(session),
            Err(err @ (Error::Http(_) | Error::Status(_) | Error::InvalidUri(_))) => last = err,
            Err(err) => return Err(err),
        }
    }
    Err(last)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Keepalive {
    pub status: bool,
    #[serde(default)]
    pub timestamp: i64,
}

pub struct PendingKeepalive {
    prepared: Prepared,
    base_url: String,
}

impl PendingKeepalive {
    pub fn start(
        profile: &Profile,
        session: &WireGuardSession,
        input: &KeepaliveInput<'_>,
    ) -> Result<Self> {
        let prepared = prepare(
            profile,
            Method::PUT,
            &session.keys.public_key_base64(),
            input.device,
            input.auth_token,
            "",
            KEEPALIVE_TIMEOUT,
        )?;
        Ok(Self {
            prepared,
            base_url: session.config.keepalive_base_url(),
        })
    }

    pub fn request(&self) -> &WireRequest {
        &self.prepared.request
    }

    pub fn http_request(&self) -> Result<HttpRequest> {
        self.prepared.request.clone().into_http(&self.base_url)
    }

    pub fn finish(self, response: &HttpResponse) -> Result<Keepalive> {
        let plaintext = open_envelope(&self.prepared, response)?;
        serde_json::from_slice(&plaintext).map_err(|err| Error::InvalidResponse(err.to_string()))
    }
}

pub async fn send_keepalive(
    client: &ApiClient,
    profile: &Profile,
    session: &WireGuardSession,
    input: &KeepaliveInput<'_>,
) -> Result<Keepalive> {
    let pending = PendingKeepalive::start(profile, session, input)?;
    let response = client.execute(pending.http_request()?).await?;
    pending.finish(&response)
}

#[cfg(test)]
mod tests;
