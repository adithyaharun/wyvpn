use crate::error::{Error, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn of_certificate(der: &[u8]) -> Self {
        Self(Sha256::digest(der).into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

impl FromStr for Fingerprint {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let hex: Vec<u8> = s.bytes().filter(|b| *b != b':').collect();
        if hex.len() != 64 {
            return Err(Error::InvalidKey("fingerprint must be 64 hex characters"));
        }
        let mut out = [0u8; 32];
        for (slot, pair) in out.iter_mut().zip(hex.chunks(2)) {
            let text = std::str::from_utf8(pair).map_err(|_| Error::InvalidKey("fingerprint"))?;
            *slot = u8::from_str_radix(text, 16).map_err(|_| Error::InvalidKey("fingerprint"))?;
        }
        Ok(Self(out))
    }
}

impl serde::Serialize for Fingerprint {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Fingerprint {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

pub type Pins = BTreeMap<String, Fingerprint>;

pub fn pin_key(host: &str, port: u16) -> String {
    let host = host.trim_matches(['[', ']']);
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip.to_canonical() {
            std::net::IpAddr::V6(ip) => format!("[{ip}]:{port}"),
            ip => format!("{ip}:{port}"),
        };
    }
    format!("{host}:{port}")
}

fn normalize_pins(pins: &Pins) -> (Pins, HashMap<String, Fingerprint>) {
    let mut merged: BTreeMap<String, (Fingerprint, bool)> = BTreeMap::new();
    let mut conflicts = HashMap::new();
    for (key, fingerprint) in pins {
        let normalized = key
            .rsplit_once(':')
            .and_then(|(host, port)| Some(pin_key(host, port.parse().ok()?)))
            .unwrap_or_else(|| key.clone());
        let canonical = normalized == *key;
        match merged.entry(normalized) {
            Entry::Vacant(slot) => {
                slot.insert((*fingerprint, canonical));
            }
            Entry::Occupied(mut slot) => {
                let (kept, kept_canonical) = *slot.get();
                let loser = if canonical && !kept_canonical {
                    slot.insert((*fingerprint, true));
                    kept
                } else {
                    *fingerprint
                };
                if kept != *fingerprint {
                    conflicts.insert(slot.key().clone(), loser);
                }
            }
        }
    }
    let pins = merged
        .into_iter()
        .map(|(key, (fingerprint, _))| (key, fingerprint))
        .collect();
    (pins, conflicts)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsPolicy {
    Verify,
    TrustOnFirstUse { pins: Pins },
    Strict { pins: Pins },
}

impl TlsPolicy {
    pub fn pinned(pins: Pins) -> Self {
        Self::TrustOnFirstUse { pins }
    }

    pub fn strict(pins: Pins) -> Self {
        Self::Strict { pins }
    }

    pub fn first_use() -> Self {
        Self::TrustOnFirstUse { pins: Pins::new() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsObservation {
    pub fingerprint: Fingerprint,
    pub verified_by_roots: bool,
}

#[derive(Debug, Default)]
struct State {
    observed: HashMap<String, TlsObservation>,
    mismatch: HashMap<String, (Fingerprint, Fingerprint)>,
    unpinned: HashSet<String>,
}

#[derive(Debug, Default)]
pub(crate) struct TlsState(Mutex<State>);

impl TlsState {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn observation(&self, key: &str) -> Option<TlsObservation> {
        self.lock().observed.get(key).copied()
    }

    pub(crate) fn take_unpinned(&self, key: &str) -> bool {
        self.lock().unpinned.remove(key)
    }

    pub(crate) fn take_mismatch(&self, key: &str) -> Option<(Fingerprint, Fingerprint)> {
        self.lock().mismatch.remove(key)
    }
}

pub(crate) type RootVerifier = Arc<dyn ServerCertVerifier>;

pub(crate) fn platform_verifier() -> Result<RootVerifier> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls_platform_verifier::Verifier::new(provider)
        .map(|verifier| Arc::new(verifier) as RootVerifier)
        .map_err(|err| Error::Tls(err.to_string()))
}

#[derive(Debug)]
struct PinningVerifier {
    inner: RootVerifier,
    policy: TlsPolicy,
    conflicts: HashMap<String, Fingerprint>,
    port: u16,
    state: Arc<TlsState>,
}

impl PinningVerifier {
    fn record(&self, key: String, fingerprint: Fingerprint, verified_by_roots: bool) {
        self.state.lock().observed.insert(
            key,
            TlsObservation {
                fingerprint,
                verified_by_roots,
            },
        );
    }
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let key = pin_key(&server_name.to_str(), self.port);
        let fingerprint = Fingerprint::of_certificate(end_entity);
        let roots = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        let (pins, strict) = match &self.policy {
            TlsPolicy::Verify => {
                if roots.is_ok() {
                    self.record(key, fingerprint, true);
                }
                return roots;
            }
            TlsPolicy::TrustOnFirstUse { pins } => (pins, false),
            TlsPolicy::Strict { pins } => (pins, true),
        };
        if let Some(pin) = pins.get(&key) {
            let disputed = self.conflicts.get(&key).copied();
            if *pin != fingerprint || disputed.is_some() {
                let expected = disputed.unwrap_or(*pin);
                self.state
                    .lock()
                    .mismatch
                    .insert(key, (expected, fingerprint));
                return Err(rustls::Error::InvalidCertificate(
                    CertificateError::ApplicationVerificationFailure,
                ));
            }
            let verified = roots.is_ok();
            self.record(key, fingerprint, verified);
            return Ok(ServerCertVerified::assertion());
        }
        if strict {
            if matches!(server_name, ServerName::IpAddress(_)) {
                self.state.lock().unpinned.insert(key);
                return Err(rustls::Error::InvalidCertificate(
                    CertificateError::ApplicationVerificationFailure,
                ));
            }
            if roots.is_ok() {
                self.record(key, fingerprint, true);
            }
            return roots;
        }
        let verified = roots.is_ok();
        self.record(key, fingerprint, verified);
        Ok(roots.unwrap_or_else(|_| ServerCertVerified::assertion()))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

pub(crate) fn client_config(
    policy: TlsPolicy,
    state: Arc<TlsState>,
    port: u16,
    inner: RootVerifier,
) -> Result<ClientConfig> {
    let (policy, conflicts) = match policy {
        TlsPolicy::Verify => (TlsPolicy::Verify, HashMap::new()),
        TlsPolicy::TrustOnFirstUse { pins } => {
            let (pins, conflicts) = normalize_pins(&pins);
            (TlsPolicy::TrustOnFirstUse { pins }, conflicts)
        }
        TlsPolicy::Strict { pins } => {
            let (pins, conflicts) = normalize_pins(&pins);
            (TlsPolicy::Strict { pins }, conflicts)
        }
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| Error::Tls(err.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinningVerifier {
            inner,
            policy,
            conflicts,
            port,
            state,
        }))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{ApiClient, HttpRequest, Method};
    use rustls::RootCertStore;
    use rustls::ServerConfig;
    use rustls::client::WebPkiServerVerifier;
    use rustls::pki_types::PrivateKeyDer;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use url::Url;

    #[test]
    fn fingerprint_round_trips_through_text() {
        let fp = Fingerprint::of_certificate(b"cert");
        let text = fp.to_string();
        assert_eq!(text.len(), 64);
        assert_eq!(text.parse::<Fingerprint>().unwrap(), fp);
        let colons = text
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(colons.parse::<Fingerprint>().unwrap(), fp);
        assert!("zz".parse::<Fingerprint>().is_err());
    }

    struct TestServer {
        port: u16,
        fingerprint: Fingerprint,
    }

    async fn serve(chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> u16 {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut buf = [0u8; 1024];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        port
    }

    async fn self_signed_server() -> TestServer {
        self_signed_server_for("127.0.0.1").await
    }

    async fn self_signed_server_for(name: &str) -> TestServer {
        let certified = rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
        let der = certified.cert.der().clone();
        let fingerprint = Fingerprint::of_certificate(&der);
        let key = PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();
        TestServer {
            port: serve(vec![der], key).await,
            fingerprint,
        }
    }

    async fn ca_signed_server() -> (TestServer, RootVerifier) {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
        let der = leaf.der().clone();
        let fingerprint = Fingerprint::of_certificate(&der);
        let key = PrivateKeyDer::try_from(leaf_key.serialize_der()).unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier: RootVerifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .unwrap();
        (
            TestServer {
                port: serve(vec![der], key).await,
                fingerprint,
            },
            verifier,
        )
    }

    fn pins(port: u16, fingerprint: Fingerprint) -> Pins {
        Pins::from([(pin_key("127.0.0.1", port), fingerprint)])
    }

    fn get(port: u16) -> HttpRequest {
        get_host("127.0.0.1", port)
    }

    fn get_host(host: &str, port: u16) -> HttpRequest {
        HttpRequest {
            method: Method::GET,
            url: Url::parse(&format!("https://{host}:{port}/")).unwrap(),
            headers: Vec::new(),
            body: None,
            timeout: Duration::from_secs(5),
        }
    }

    fn url(port: u16) -> Url {
        get(port).url
    }

    #[tokio::test]
    async fn self_signed_certificates_fail_normal_verification() {
        let server = self_signed_server().await;
        let client = ApiClient::new(TlsPolicy::Verify).unwrap();
        let err = client.execute(get(server.port)).await.unwrap_err();
        assert!(!matches!(err, Error::CertificateChanged { .. }));
    }

    #[tokio::test]
    async fn first_use_accepts_and_reports_the_fingerprint() {
        let server = self_signed_server().await;
        let client = ApiClient::new(TlsPolicy::first_use()).unwrap();
        let response = client.execute(get(server.port)).await.unwrap();
        assert_eq!(response.body, b"ok");
        let seen = client.tls_observation(&url(server.port)).unwrap();
        assert_eq!(seen.fingerprint, server.fingerprint);
        assert!(!seen.verified_by_roots);
    }

    #[tokio::test]
    async fn matching_pin_is_accepted() {
        let server = self_signed_server().await;
        let policy = TlsPolicy::pinned(pins(server.port, server.fingerprint));
        let client = ApiClient::new(policy).unwrap();
        assert_eq!(client.execute(get(server.port)).await.unwrap().status, 200);
    }

    #[tokio::test]
    async fn changed_certificate_needs_explicit_retrust() {
        let server = self_signed_server().await;
        let stale = Fingerprint::of_certificate(b"previous certificate");
        let client = ApiClient::new(TlsPolicy::pinned(pins(server.port, stale))).unwrap();
        match client.execute(get(server.port)).await.unwrap_err() {
            Error::CertificateChanged { expected, actual } => {
                assert_eq!(expected, stale.to_string());
                assert_eq!(actual, server.fingerprint.to_string());
            }
            other => panic!("unexpected {other:?}"),
        }
        let retrusted =
            ApiClient::new(TlsPolicy::pinned(pins(server.port, server.fingerprint))).unwrap();
        assert_eq!(
            retrusted.execute(get(server.port)).await.unwrap().status,
            200
        );
    }

    #[tokio::test]
    async fn pin_for_another_host_does_not_apply() {
        let server = self_signed_server().await;
        let other = Pins::from([(
            pin_key("127.0.0.1", server.port.wrapping_add(1)),
            Fingerprint::of_certificate(b"elsewhere"),
        )]);
        let client = ApiClient::new(TlsPolicy::pinned(other)).unwrap();
        assert_eq!(client.execute(get(server.port)).await.unwrap().status, 200);
    }

    #[tokio::test]
    async fn pin_on_a_hostname_is_matched_by_host_and_port() {
        let server = self_signed_server().await;
        let policy = TlsPolicy::pinned(Pins::from([(
            pin_key("localhost", server.port),
            server.fingerprint,
        )]));
        let client = ApiClient::new(policy).unwrap();
        let request = get_host("localhost", server.port);
        assert_eq!(client.execute(request).await.unwrap().status, 200);
    }

    #[tokio::test]
    async fn ca_signed_certificate_is_trusted_without_a_pin() {
        let (server, roots) = ca_signed_server().await;
        let client = ApiClient::with_verifier(TlsPolicy::Verify, roots);
        assert_eq!(client.execute(get(server.port)).await.unwrap().status, 200);
        let seen = client.tls_observation(&url(server.port)).unwrap();
        assert!(seen.verified_by_roots);
    }

    #[tokio::test]
    async fn ca_signed_certificate_cannot_bypass_an_existing_pin() {
        let (server, roots) = ca_signed_server().await;
        let stale = Fingerprint::of_certificate(b"previous certificate");
        let client =
            ApiClient::with_verifier(TlsPolicy::pinned(pins(server.port, stale)), roots.clone());
        match client.execute(get(server.port)).await.unwrap_err() {
            Error::CertificateChanged { expected, actual } => {
                assert_eq!(expected, stale.to_string());
                assert_eq!(actual, server.fingerprint.to_string());
            }
            other => panic!("unexpected {other:?}"),
        }
        let matching = ApiClient::with_verifier(
            TlsPolicy::pinned(pins(server.port, server.fingerprint)),
            roots,
        );
        assert_eq!(
            matching.execute(get(server.port)).await.unwrap().status,
            200
        );
    }

    #[tokio::test]
    async fn strict_refuses_an_unpinned_self_signed_dns_host() {
        let server = self_signed_server_for("localhost").await;
        let client = ApiClient::new(TlsPolicy::strict(Pins::new()))
            .unwrap();
        let err = client
            .execute(get_host("localhost", server.port))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Http(_)));
    }

    #[tokio::test]
    async fn strict_refuses_an_unpinned_ip_even_with_a_valid_chain() {
        let (server, roots) = ca_signed_server().await;
        let client = ApiClient::with_verifier(TlsPolicy::strict(Pins::new()), roots);
        let err = client.execute(get(server.port)).await.unwrap_err();
        match err {
            Error::PinRequired(host) => assert_eq!(host, pin_key("127.0.0.1", server.port)),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn strict_accepts_pinned_self_signed_hosts() {
        let server = self_signed_server().await;
        let client =
            ApiClient::new(TlsPolicy::strict(pins(server.port, server.fingerprint))).unwrap();
        assert_eq!(client.execute(get(server.port)).await.unwrap().status, 200);

        let named = self_signed_server_for("localhost").await;
        let policy = TlsPolicy::strict(Pins::from([(
            pin_key("localhost", named.port),
            named.fingerprint,
        )]));
        let client = ApiClient::new(policy).unwrap();
        let request = get_host("localhost", named.port);
        assert_eq!(client.execute(request).await.unwrap().status, 200);
    }

    #[tokio::test]
    async fn strict_pin_mismatch_is_reported() {
        let server = self_signed_server().await;
        let stale = Fingerprint::of_certificate(b"previous certificate");
        let client = ApiClient::new(TlsPolicy::strict(pins(server.port, stale))).unwrap();
        assert!(matches!(
            client.execute(get(server.port)).await.unwrap_err(),
            Error::CertificateChanged { .. }
        ));
    }

    #[test]
    fn pin_keys_agree_for_mapped_ipv6() {
        let canonical = pin_key("127.0.0.1", 443);
        assert_eq!(pin_key("[::ffff:7f00:1]", 443), canonical);
        assert_eq!(pin_key("::ffff:127.0.0.1", 443), canonical);
        assert_eq!(pin_key("[2001:db8::1]", 9443), "[2001:db8::1]:9443");
        assert_eq!(pin_key("Example.com", 443), "Example.com:443");
    }

    #[tokio::test]
    async fn pins_saved_under_the_mapped_ipv6_key_still_apply() {
        let server = self_signed_server().await;
        let old_key = format!("[::ffff:7f00:1]:{}", server.port);
        let matching = Pins::from([(old_key.clone(), server.fingerprint)]);
        let client = ApiClient::new(TlsPolicy::pinned(matching)).unwrap();
        assert_eq!(client.execute(get(server.port)).await.unwrap().status, 200);

        let stale = Fingerprint::of_certificate(b"previous certificate");
        let client = ApiClient::new(TlsPolicy::pinned(Pins::from([(old_key, stale)]))).unwrap();
        assert!(matches!(
            client.execute(get(server.port)).await.unwrap_err(),
            Error::CertificateChanged { .. }
        ));
    }

    #[tokio::test]
    async fn old_mapped_key_pin_works_under_strict() {
        let server = self_signed_server().await;
        let old_key = format!("[::ffff:7f00:1]:{}", server.port);
        let policy = TlsPolicy::strict(Pins::from([(old_key, server.fingerprint)]));
        let client = ApiClient::new(policy).unwrap();
        assert_eq!(client.execute(get(server.port)).await.unwrap().status, 200);
    }

    #[test]
    fn canonical_pin_wins_a_collision_with_the_same_fingerprint() {
        let fp = Fingerprint::of_certificate(b"cert");
        let pins = Pins::from([
            ("[::ffff:7f00:1]:443".to_owned(), fp),
            ("127.0.0.1:443".to_owned(), fp),
        ]);
        let (merged, conflicts) = normalize_pins(&pins);
        assert_eq!(merged, Pins::from([("127.0.0.1:443".to_owned(), fp)]));
        assert!(conflicts.is_empty());
    }

    #[test]
    fn colliding_pins_with_different_fingerprints_are_disputed() {
        let canonical = Fingerprint::of_certificate(b"canonical");
        let mapped = Fingerprint::of_certificate(b"mapped");
        let pins = Pins::from([
            ("[::ffff:7f00:1]:443".to_owned(), mapped),
            ("127.0.0.1:443".to_owned(), canonical),
        ]);
        let (merged, conflicts) = normalize_pins(&pins);
        assert_eq!(merged["127.0.0.1:443"], canonical);
        assert_eq!(conflicts["127.0.0.1:443"], mapped);
    }

    #[tokio::test]
    async fn conflicting_pins_for_one_canonical_key_are_a_mismatch() {
        let server = self_signed_server().await;
        let stale = Fingerprint::of_certificate(b"previous certificate");
        for policy in [TlsPolicy::pinned, TlsPolicy::strict] {
            let pins = Pins::from([
                (format!("[::ffff:7f00:1]:{}", server.port), stale),
                (pin_key("127.0.0.1", server.port), server.fingerprint),
            ]);
            let client = ApiClient::new(policy(pins)).unwrap();
            match client.execute(get(server.port)).await.unwrap_err() {
                Error::CertificateChanged { expected, actual } => {
                    assert_eq!(expected, stale.to_string());
                    assert_eq!(actual, server.fingerprint.to_string());
                }
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn agreeing_pins_for_one_canonical_key_still_connect() {
        let server = self_signed_server().await;
        let pins = Pins::from([
            (
                format!("[::ffff:7f00:1]:{}", server.port),
                server.fingerprint,
            ),
            (pin_key("127.0.0.1", server.port), server.fingerprint),
        ]);
        let client = ApiClient::new(TlsPolicy::strict(pins)).unwrap();
        assert_eq!(client.execute(get(server.port)).await.unwrap().status, 200);
    }

    #[test]
    fn url_and_verifier_pin_keys_agree() {
        let url = Url::parse("https://[::ffff:127.0.0.1]:8443/").unwrap();
        assert_eq!(
            crate::http::url_pin_key(&url).unwrap(),
            pin_key("::ffff:127.0.0.1", 8443)
        );
    }
}
