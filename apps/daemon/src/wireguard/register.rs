use std::time::Duration;

use tokio::time::Instant;

use thiserror::Error;
use wyvpn_core::http::ApiClient;
use wyvpn_core::tls::{Pins, TlsPolicy};
use wyvpn_core::wireguard::{
    self, BestError, DeviceInfo, RegistrationInput, WireGuardSession, registration_hosts,
};
use wyvpn_core::{Error as CoreError, Profile};
use wyvpn_ipc::{ErrorBody, ErrorCode, sanitize_text};

use crate::control::core_error;

const STATUS_KEY_REUSED: u16 = 413;
const STATUS_SERVER_OFFLINE: u16 = 429;
const MAX_TEXT_CHARS: usize = 256;
pub const TOTAL_DEADLINE: Duration = Duration::from_secs(30);
const PER_ATTEMPT: Duration = Duration::from_secs(10);

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
    let clean = sanitize_text(reason, MAX_TEXT_CHARS);
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
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Denied { .. } | Self::InsecureKeepalive | Self::Core(CoreError::Unsupported(_))
        )
    }

    pub fn to_body(&self) -> ErrorBody {
        let mut body = match self {
            Self::Denied { .. } => ErrorBody::new(ErrorCode::AuthFailed, self.to_string()),
            Self::Timeout => ErrorBody::new(ErrorCode::Timeout, self.to_string()),
            Self::KeyReused | Self::ServerOffline | Self::InsecureKeepalive => {
                ErrorBody::new(ErrorCode::Server, self.to_string())
            }
            Self::Core(err) => core_error(err),
        };
        body.message = sanitize_text(&body.message, MAX_TEXT_CHARS);
        body
    }
}

pub fn https_client(pins: &Pins) -> Result<ApiClient, RegisterError> {
    Ok(ApiClient::new(TlsPolicy::strict(pins.clone()))?)
}

#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub request: Duration,
    pub total: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            request: PER_ATTEMPT,
            total: TOTAL_DEADLINE,
        }
    }
}

pub async fn register(
    client: &ApiClient,
    profile: &Profile,
    device: &DeviceInfo,
    pin: Option<&str>,
) -> Result<WireGuardSession, RegisterError> {
    let hosts = registration_hosts(profile);
    register_hosts(client, &hosts, profile, device, pin, Timeouts::default()).await
}

pub async fn register_hosts(
    client: &ApiClient,
    hosts: &[String],
    profile: &Profile,
    device: &DeviceInfo,
    pin: Option<&str>,
    timeouts: Timeouts,
) -> Result<WireGuardSession, RegisterError> {
    wireguard::ensure_registrable(profile, pin)?;
    let input = RegistrationInput {
        device,
        pin,
        auth_token: None,
    };
    let deadline = Instant::now() + timeouts.total;
    let mut best = BestError::default();
    let mut session = None;
    for host in hosts {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let attempt = wireguard::register_at_with_timeout(
            client,
            host,
            profile,
            &input,
            timeouts.request.min(remaining),
        );
        match tokio::time::timeout_at(deadline, attempt).await {
            Ok(Ok(found)) => {
                session = Some(found);
                break;
            }
            Ok(Err(err)) => best.record(err)?,
            Err(_) => {
                return Err(if best.is_specific() {
                    best.into_error().into()
                } else {
                    RegisterError::Timeout
                });
            }
        }
    }
    let Some(session) = session else {
        return Err(best.into_error().into());
    };
    if session.config.web_no_ssl {
        return Err(RegisterError::InsecureKeepalive);
    }
    Ok(session)
}

#[cfg(test)]
mod tests;
