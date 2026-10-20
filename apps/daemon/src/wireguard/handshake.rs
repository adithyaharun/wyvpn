use std::time::Duration;

use super::backend::{PeerStats, SharedBackend};

pub const POLL_INTERVAL: Duration = Duration::from_millis(500);
pub const MAX_POLLS: u32 = 50;

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("handshake timeout: no handshake with the server within {} seconds", .waited.as_secs())]
    Timeout { waited: Duration },
    #[error("cannot read the tunnel statistics: {0}")]
    Stats(#[source] anyhow::Error),
}

pub async fn wait_for_handshake(backend: &SharedBackend) -> Result<PeerStats, HandshakeError> {
    wait_with(backend, POLL_INTERVAL, MAX_POLLS).await
}

pub async fn wait_with(
    backend: &SharedBackend,
    interval: Duration,
    polls: u32,
) -> Result<PeerStats, HandshakeError> {
    for _ in 0..polls {
        let stats = backend.stats().await.map_err(HandshakeError::Stats)?;
        if stats.handshake_age.is_some() {
            return Ok(stats);
        }
        tokio::time::sleep(interval).await;
    }
    Err(HandshakeError::Timeout {
        waited: interval * polls,
    })
}

#[cfg(test)]
mod tests {
    use tokio::time::Instant;
    use wyvpn_core::wireguard::WireGuardKeys;

    use super::*;
    use crate::wireguard::backend::fake::{Handle, pair};
    use crate::wireguard::backend::{BackendConfig, WgBackend};

    fn running() -> (SharedBackend, Handle) {
        let (mut backend, handle) = pair();
        let config = BackendConfig {
            address: "10.200.0.5/24".parse().unwrap(),
            address6: None,
            mtu: None,
            peer_public_key: base64_key(),
            endpoint: wyvpn_core::wireguard::Endpoint {
                host: wyvpn_core::wireguard::Host::Ip("203.0.113.9".parse().unwrap()),
                port: 51820,
            },
            allowed_ips: Vec::new(),
        };
        backend.up(&config, &WireGuardKeys::generate()).unwrap();
        (SharedBackend::new(Box::new(backend)), handle)
    }

    fn base64_key() -> wyvpn_core::wireguard::PeerKey {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .encode([7u8; 32])
            .parse()
            .unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn returns_as_soon_as_a_handshake_appears() {
        let (backend, handle) = running();
        let start = Instant::now();
        let setter = handle.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1200)).await;
            setter.with(|record| {
                record.stats.handshake_age = Some(Duration::from_secs(1));
                record.stats.rx_bytes = 148;
            });
        });
        let stats = wait_for_handshake(&backend).await.unwrap();
        assert_eq!(stats.rx_bytes, 148);
        assert_eq!(start.elapsed(), Duration::from_millis(1500));
        assert_eq!(handle.with(|record| record.stats_calls), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn an_existing_handshake_needs_one_poll() {
        let (backend, handle) = running();
        handle.with(|record| record.stats.handshake_age = Some(Duration::ZERO));
        wait_for_handshake(&backend).await.unwrap();
        assert_eq!(handle.with(|record| record.stats_calls), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn times_out_after_fifty_polls_and_twenty_five_seconds() {
        let (backend, handle) = running();
        let start = Instant::now();
        let err = wait_for_handshake(&backend).await.unwrap_err();
        assert!(matches!(err, HandshakeError::Timeout { .. }));
        assert_eq!(start.elapsed(), Duration::from_secs(25));
        assert_eq!(handle.with(|record| record.stats_calls), 50);
        assert!(err.to_string().contains("handshake timeout"));
        assert!(err.to_string().contains("25 seconds"));
    }

    #[tokio::test(start_paused = true)]
    async fn stats_failure_ends_the_wait_immediately() {
        let (backend, handle) = running();
        handle.with(|record| record.stats_fail = true);
        let err = wait_for_handshake(&backend).await.unwrap_err();
        assert!(matches!(err, HandshakeError::Stats(_)));
        assert_eq!(handle.with(|record| record.stats_calls), 1);
    }
}
