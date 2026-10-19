use crate::error::{Error, Result};
use crate::tls::{RootVerifier, TlsObservation, TlsPolicy, TlsState, client_config, pin_key};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

pub use reqwest::Method;

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
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(config)
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        clients.insert(port, client.clone());
        Ok(client)
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
