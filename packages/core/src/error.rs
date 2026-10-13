use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Unsupported {
    #[error("one-time password authentication is not supported yet")]
    Otp,
    #[error("PIN plus one-time password authentication is not supported yet")]
    PinOtp,
    #[error("single sign-on authentication is not supported yet")]
    Sso,
    #[error("device authentication is not supported yet")]
    DeviceAuth,
    #[error("password (external directory) authentication is not supported yet")]
    Password,
    #[error("servers with a dynamic firewall need pre-authentication, which is not supported yet")]
    DynamicFirewall,
    #[error("unrecognised password mode {0:?}")]
    UnknownMode(String),
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("profile has no JSON header")]
    MissingHeader,
    #[error("profile header is not valid: {0}")]
    MalformedHeader(String),
    #[error("profile is missing {0}")]
    MissingField(&'static str),
    #[error("invalid archive: {0}")]
    Archive(String),
    #[error("input exceeds {0} bytes")]
    TooLarge(usize),
    #[error("no profiles found")]
    NoProfiles,
    #[error("invalid URI: {0}")]
    InvalidUri(String),
    #[error("plain http is not allowed")]
    InsecureScheme,
    #[error("request failed: {0}")]
    Http(reqwest::Error),
    #[error("tls setup failed: {0}")]
    Tls(String),
    #[error(
        "server certificate changed (pinned {expected}, presented {actual}); explicit re-trust required"
    )]
    CertificateChanged { expected: String, actual: String },
    #[error("server returned status {0}")]
    Status(u16),
    #[error("server link or resource not found")]
    NotFound,
    #[error("user is disabled on the server")]
    Forbidden,
    #[error("server response signature mismatch")]
    ResponseSignature,
    #[error("invalid server response: {0}")]
    InvalidResponse(String),
    #[error("no sync hosts available")]
    NoSyncHosts,
    #[error("nonce longer than 32 characters")]
    NonceTooLong,
    #[error("request too long to sign")]
    RequestTooLong,
    #[error("{0}")]
    Unsupported(#[from] Unsupported),
    #[error("missing credential: {0}")]
    MissingCredential(&'static str),
    #[error("password too long for the server envelope")]
    PasswordTooLong,
    #[error("invalid key material: {0}")]
    InvalidKey(&'static str),
    #[error("encryption failed")]
    Encrypt,
    #[error("response could not be decrypted")]
    Decrypt,
    #[error("invalid OpenVPN config: {0}")]
    InvalidConfig(String),
    #[error("server rejected the request{}", .reason.as_deref().map(|r| format!(": {r}")).unwrap_or_default())]
    Rejected { reason: Option<String> },
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Self::Http(err.without_url())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn http_errors_do_not_leak_the_url() {
        let client = crate::http::ApiClient::new(crate::tls::TlsPolicy::Verify)
            .unwrap()
            .allow_plain_http();
        let request = crate::import::build_import_request(
            url::Url::parse("http://127.0.0.1:1/ku/bearer-link").unwrap(),
        );
        let err = client.execute(request).await.unwrap_err();
        assert!(matches!(err, Error::Http(_)));
        assert!(!err.to_string().contains("bearer-link"));
    }
}
