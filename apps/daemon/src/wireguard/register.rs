use thiserror::Error;
use wyvpn_core::auth::password_for;
use wyvpn_core::http::ApiClient;
use wyvpn_core::tls::{Pins, TlsPolicy};
use wyvpn_core::wireguard::{self, DeviceInfo, RegistrationInput, WireGuardSession};
use wyvpn_core::{Error as CoreError, Profile, Transport, Unsupported};
use wyvpn_ipc::{ErrorBody, ErrorCode};

use crate::control::core_error;

const STATUS_KEY_REUSED: u16 = 413;
const STATUS_SERVER_OFFLINE: u16 = 429;
const MAX_REASON_CHARS: usize = 200;

#[derive(Debug, Error)]
pub enum RegisterError {
    #[error("server denied the connection{}", reason_suffix(.reason.as_deref()))]
    Denied { reason: Option<String> },
    #[error("server rejected the WireGuard key as already used")]
    KeyReused,
    #[error("server instance is offline")]
    ServerOffline,
    #[error("registration request timed out")]
    Timeout,
    #[error("server requires plain http for the keepalive, which is refused")]
    InsecureKeepalive,
    #[error(transparent)]
    Core(CoreError),
}

fn reason_suffix(reason: Option<&str>) -> String {
    reason.map(|r| format!(": {r}")).unwrap_or_default()
}

fn sanitize_reason(reason: &str) -> Option<String> {
    let clean: String = reason
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_REASON_CHARS)
        .collect();
    let clean = clean.trim();
    (!clean.is_empty()).then(|| clean.to_owned())
}

impl From<CoreError> for RegisterError {
    fn from(err: CoreError) -> Self {
        match err {
            CoreError::Rejected { reason } => Self::Denied {
                reason: reason.as_deref().and_then(sanitize_reason),
            },
            CoreError::Status(STATUS_KEY_REUSED) => Self::KeyReused,
            CoreError::Status(STATUS_SERVER_OFFLINE) => Self::ServerOffline,
            CoreError::Http(ref inner) if inner.is_timeout() => Self::Timeout,
            other => Self::Core(other),
        }
    }
}

impl RegisterError {
    pub fn to_body(&self) -> ErrorBody {
        match self {
            Self::Denied { .. } => ErrorBody::new(ErrorCode::AuthFailed, self.to_string()),
            Self::Timeout => ErrorBody::new(ErrorCode::Timeout, self.to_string()),
            Self::KeyReused | Self::ServerOffline | Self::InsecureKeepalive => {
                ErrorBody::new(ErrorCode::Server, self.to_string())
            }
            Self::Core(err) => core_error(err),
        }
    }
}

pub fn https_client(pins: &Pins) -> Result<ApiClient, RegisterError> {
    Ok(ApiClient::new(TlsPolicy::pinned(pins.clone()))?)
}

pub fn ensure_supported(profile: &Profile, pin: Option<&str>) -> Result<(), RegisterError> {
    if profile.header.dynamic_firewall {
        return Err(CoreError::from(Unsupported::DynamicFirewall).into());
    }
    password_for(&profile.header, pin, Transport::WireGuard)?;
    Ok(())
}

pub async fn register(
    client: &ApiClient,
    profile: &Profile,
    device: &DeviceInfo,
    pin: Option<&str>,
) -> Result<WireGuardSession, RegisterError> {
    ensure_supported(profile, pin)?;
    let input = RegistrationInput {
        device,
        pin,
        auth_token: None,
    };
    let session = wireguard::register(client, profile, &input).await?;
    if session.config.web_no_ssl {
        return Err(RegisterError::InsecureKeepalive);
    }
    Ok(session)
}

#[cfg(test)]
mod tests;
