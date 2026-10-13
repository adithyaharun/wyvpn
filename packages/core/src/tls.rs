use crate::error::{Error, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
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
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsPolicy {
    Verify,
    TrustOnFirstUse { pins: Pins },
}

impl TlsPolicy {
    pub fn pinned(pins: Pins) -> Self {
        Self::TrustOnFirstUse { pins }
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
        let TlsPolicy::TrustOnFirstUse { pins } = &self.policy else {
            if roots.is_ok() {
                self.record(key, fingerprint, true);
            }
            return roots;
        };
        if let Some(pin) = pins.get(&key) {
            if *pin != fingerprint {
                self.state.lock().mismatch.insert(key, (*pin, fingerprint));
                return Err(rustls::Error::InvalidCertificate(
                    CertificateError::ApplicationVerificationFailure,
                ));
            }
            let verified = roots.is_ok();
            self.record(key, fingerprint, verified);
            return Ok(ServerCertVerified::assertion());
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
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| Error::Tls(err.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinningVerifier {
            inner,
            policy,
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
        let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
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
}
