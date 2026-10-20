use crate::error::{Error, Result};
use crate::tls::{RootVerifier, TlsObservation, TlsPolicy, TlsState, client_config, pin_key};
use crate::wireguard::blocked_ip;
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

pub use reqwest::Method;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

#[derive(Debug)]
struct BlockedResolution(String);

impl fmt::Display for BlockedResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} resolves only to blocked addresses", self.0)
    }
}

impl std::error::Error for BlockedResolution {}

fn permitted_addrs(
    host: &str,
    addrs: impl IntoIterator<Item = SocketAddr>,
) -> std::result::Result<Vec<SocketAddr>, BlockedResolution> {
    let allowed: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|addr| !blocked_ip(addr.ip()))
        .collect();
    if allowed.is_empty() {
        return Err(BlockedResolution(host.to_owned()));
    }
    Ok(allowed)
}

struct FilteringResolver;

impl Resolve for FilteringResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let found = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let allowed = permitted_addrs(&host, found)?;
            Ok(Box::new(allowed.into_iter()) as Addrs)
        })
    }
}

const MAX_BODY: usize = 8 * 1024 * 1024;

pub struct HttpRequest {
    pub method: Method,
    pub url: Url,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub timeout: Duration,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url.as_str())
            .field(
                "headers",
                &format_args!("<{} redacted>", self.headers.len()),
            )
            .finish_non_exhaustive()
    }
}

impl HttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

pub(crate) fn url_pin_key(url: &Url) -> Option<String> {
    Some(pin_key(url.host_str()?, url.port_or_known_default()?))
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ApiClient {
    clients: Arc<Mutex<HashMap<u16, reqwest::Client>>>,
    policy: TlsPolicy,
    verifier: RootVerifier,
    state: Arc<TlsState>,
    allow_http: bool,
    filter_resolved: bool,
}

impl ApiClient {
    pub fn new(policy: TlsPolicy) -> Result<Self> {
        Ok(Self::with_verifier(
            policy,
            crate::tls::platform_verifier()?,
        ))
    }

    pub(crate) fn with_verifier(policy: TlsPolicy, verifier: RootVerifier) -> Self {
        Self {
            clients: Arc::default(),
            filter_resolved: matches!(policy, TlsPolicy::Strict { .. }),
            policy,
            verifier,
            state: Arc::default(),
            allow_http: false,
        }
    }

    fn client_for(&self, port: u16) -> Result<reqwest::Client> {
        let mut clients = self
            .clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(client) = clients.get(&port) {
            return Ok(client.clone());
        }
        let config = client_config(
            self.policy.clone(),
            self.state.clone(),
            port,
            self.verifier.clone(),
        )?;
        let mut builder = reqwest::Client::builder()
            .use_preconfigured_tls(config)
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none());
        if self.filter_resolved {
            builder = builder.dns_resolver(Arc::new(FilteringResolver));
        }
        let client = builder.build()?;
        clients.insert(port, client.clone());
        Ok(client)
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn without_resolver_filter(mut self) -> Self {
        self.filter_resolved = false;
        self
    }

    #[must_use]
    pub fn allow_plain_http(mut self) -> Self {
        self.allow_http = true;
        self
    }

    pub fn tls_observation(&self, url: &Url) -> Option<TlsObservation> {
        self.state.observation(&url_pin_key(url)?)
    }

    pub async fn execute(&self, request: HttpRequest) -> Result<HttpResponse> {
        match request.url.scheme() {
            "https" => {}
            "http" if self.allow_http => {}
            _ => return Err(Error::InsecureScheme),
        }
        let key =
            url_pin_key(&request.url).ok_or_else(|| Error::InvalidUri("missing host".into()))?;
        let port = request.url.port_or_known_default().unwrap_or(443);
        let mut builder = self
            .client_for(port)?
            .request(request.method, request.url)
            .timeout(request.timeout);
        for (name, value) in request.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        match self.read(builder).await {
            Ok(response) => Ok(response),
            Err(err) => match self.state.take_mismatch(&key) {
                Some((expected, actual)) => Err(Error::CertificateChanged {
                    expected: expected.to_string(),
                    actual: actual.to_string(),
                }),
                None if self.state.take_unpinned(&key) => Err(Error::PinRequired(key)),
                None => Err(err),
            },
        }
    }

    async fn read(&self, builder: reqwest::RequestBuilder) -> Result<HttpResponse> {
        let mut response = builder.send().await?;
        let status = response.status().as_u16();
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            body.extend_from_slice(&chunk);
            if body.len() > MAX_BODY {
                return Err(Error::InvalidResponse("response body too large".into()));
            }
        }
        Ok(HttpResponse { status, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn addr(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), 443)
    }

    #[test]
    fn resolver_filter_drops_blocked_addresses_and_keeps_the_rest() {
        let kept = permitted_addrs(
            "vpn.example",
            [addr("127.0.0.1"), addr("203.0.113.9"), addr("::1")],
        )
        .unwrap();
        assert_eq!(kept, vec![addr("203.0.113.9")]);
    }

    #[test]
    fn resolver_filter_rejects_names_that_only_resolve_to_blocked_addresses() {
        for blocked in [
            "127.0.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
        ] {
            let err = permitted_addrs("evil.example", [addr(blocked)]).unwrap_err();
            assert_eq!(
                err.to_string(),
                "evil.example resolves only to blocked addresses"
            );
        }
        assert!(permitted_addrs("empty.example", []).is_err());
    }

    #[tokio::test]
    async fn filtering_resolver_refuses_localhost() {
        let name = Name::from_str("localhost").unwrap();
        let err = FilteringResolver.resolve(name).await.err().unwrap();
        assert!(err.to_string().contains("blocked addresses"), "{err}");
    }

    #[tokio::test]
    async fn only_strict_clients_filter_resolved_addresses() {
        let strict = ApiClient::new(TlsPolicy::strict(Default::default())).unwrap();
        assert!(strict.filter_resolved);
        for policy in [TlsPolicy::Verify, TlsPolicy::first_use()] {
            assert!(!ApiClient::new(policy).unwrap().filter_resolved);
        }
    }
}
