use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::Context;
use wyvpn_core::wireguard::{Cidr, Endpoint, Host, PeerKey, WireGuardKeys};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendConfig {
    pub address: Cidr,
    pub address6: Option<Cidr>,
    pub mtu: Option<u16>,
    pub peer_public_key: PeerKey,
    pub endpoint: Endpoint,
    pub allowed_ips: Vec<Cidr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerStats {
    pub handshake_age: Option<Duration>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

pub trait WgBackend: Send {
    fn up(&mut self, config: &BackendConfig, keys: &WireGuardKeys) -> anyhow::Result<Interface>;
    fn stats(&self) -> anyhow::Result<PeerStats>;
    fn down(&mut self) -> anyhow::Result<()>;
}

pub fn resolve_endpoint(endpoint: &Endpoint) -> io::Result<SocketAddr> {
    match &endpoint.host {
        Host::Ip(ip) => Ok(SocketAddr::new(ip.to_canonical(), endpoint.port)),
        Host::Dns(name) => {
            let mut addrs: Vec<SocketAddr> =
                (name.as_str(), endpoint.port).to_socket_addrs()?.collect();
            addrs.sort_by_key(SocketAddr::is_ipv6);
            addrs
                .into_iter()
                .next()
                .ok_or_else(|| io::Error::other("the endpoint host has no addresses"))
        }
    }
}

#[derive(Clone)]
pub struct SharedBackend(Arc<Mutex<Box<dyn WgBackend>>>);

impl SharedBackend {
    pub fn new(backend: Box<dyn WgBackend>) -> Self {
        Self(Arc::new(Mutex::new(backend)))
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut dyn WgBackend) -> R) -> R {
        let mut guard = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        f(guard.as_mut())
    }

    pub async fn stats(&self) -> anyhow::Result<PeerStats> {
        let shared = self.clone();
        tokio::task::spawn_blocking(move || shared.with(|backend| backend.stats()))
            .await
            .context("the stats task was interrupted")?
    }
}

#[cfg(test)]
pub mod fake {
    use std::sync::{Arc, Mutex, PoisonError};

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use wyvpn_core::wireguard::Host;

    use super::*;

    #[derive(Default)]
    pub struct Record {
        pub configs: Vec<BackendConfig>,
        pub public_keys_seen: Vec<String>,
        pub downs: usize,
        pub fail_up: Option<String>,
        pub stats: PeerStats,
        pub stats_fail: bool,
        pub stats_calls: usize,
        pub fail_down: bool,
        pub is_up: bool,
    }

    #[derive(Clone, Default)]
    pub struct Handle(Arc<Mutex<Record>>);

    impl Handle {
        pub fn with<T>(&self, f: impl FnOnce(&mut Record) -> T) -> T {
            f(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner))
        }
    }

    pub struct FakeBackend {
        handle: Handle,
    }

    pub fn pair() -> (FakeBackend, Handle) {
        let handle = Handle::default();
        (
            FakeBackend {
                handle: handle.clone(),
            },
            handle,
        )
    }

    impl WgBackend for FakeBackend {
        fn up(
            &mut self,
            config: &BackendConfig,
            keys: &WireGuardKeys,
        ) -> anyhow::Result<Interface> {
            self.handle.with(|record| {
                if let Some(reason) = record.fail_up.clone() {
                    anyhow::bail!(reason);
                }
                record.configs.push(config.clone());
                record.public_keys_seen.push(keys.public_key_base64());
                record.is_up = true;
                Ok(Interface {
                    name: "fake0".into(),
                })
            })
        }

        fn stats(&self) -> anyhow::Result<PeerStats> {
            self.handle.with(|record| {
                record.stats_calls += 1;
                if !record.is_up {
                    anyhow::bail!("interface is down");
                }
                if record.stats_fail {
                    anyhow::bail!("stats unavailable");
                }
                Ok(record.stats)
            })
        }

        fn down(&mut self) -> anyhow::Result<()> {
            self.handle.with(|record| {
                record.downs += 1;
                record.is_up = false;
                if record.fail_down {
                    anyhow::bail!("teardown failed");
                }
                Ok(())
            })
        }
    }

    fn config() -> BackendConfig {
        BackendConfig {
            address: "10.200.0.5/24".parse().unwrap(),
            address6: None,
            mtu: Some(1420),
            peer_public_key: STANDARD.encode([7u8; 32]).parse().unwrap(),
            endpoint: Endpoint {
                host: Host::Ip("203.0.113.9".parse().unwrap()),
                port: 51820,
            },
            allowed_ips: vec!["10.0.0.0/8".parse().unwrap()],
        }
    }

    #[test]
    fn fake_records_the_lifecycle() {
        let (mut backend, handle) = pair();
        let keys = WireGuardKeys::generate();
        assert!(backend.stats().is_err());

        let interface = backend.up(&config(), &keys).unwrap();
        assert_eq!(interface.name, "fake0");
        handle.with(|record| {
            assert_eq!(record.configs, vec![config()]);
            assert_eq!(record.public_keys_seen, vec![keys.public_key_base64()]);
            record.stats = PeerStats {
                handshake_age: Some(Duration::from_secs(3)),
                rx_bytes: 10,
                tx_bytes: 20,
            };
        });
        assert_eq!(backend.stats().unwrap().rx_bytes, 10);

        backend.down().unwrap();
        handle.with(|record| {
            assert_eq!(record.downs, 1);
            assert!(!record.is_up);
        });
        assert!(backend.stats().is_err());

        handle.with(|record| record.fail_down = true);
        assert!(backend.down().is_err());
        handle.with(|record| assert_eq!(record.downs, 2));
    }

    #[test]
    fn fake_can_refuse_to_come_up() {
        let (mut backend, handle) = pair();
        handle.with(|record| record.fail_up = Some("no tun device".into()));
        let err = backend
            .up(&config(), &WireGuardKeys::generate())
            .unwrap_err();
        assert_eq!(err.to_string(), "no tun device");
        handle.with(|record| assert!(!record.is_up && record.configs.is_empty()));
    }

    #[test]
    fn endpoint_resolution_prefers_ipv4_and_canonical_addresses() {
        let ip = Endpoint {
            host: Host::Ip("::ffff:203.0.113.9".parse().unwrap()),
            port: 51820,
        };
        assert_eq!(
            resolve_endpoint(&ip).unwrap(),
            "203.0.113.9:51820".parse::<SocketAddr>().unwrap()
        );
        let name = Endpoint {
            host: Host::Dns("localhost".into()),
            port: 7,
        };
        let resolved = resolve_endpoint(&name).unwrap();
        assert!(resolved.ip().is_loopback());
        assert_eq!(resolved.port(), 7);
    }

    #[tokio::test]
    async fn shared_backend_serves_stats_off_the_runtime_threads() {
        let (mut backend, handle) = pair();
        backend.up(&config(), &WireGuardKeys::generate()).unwrap();
        handle.with(|record| record.stats.rx_bytes = 42);
        let shared = SharedBackend::new(Box::new(backend));
        assert_eq!(shared.stats().await.unwrap().rx_bytes, 42);
        shared.with(|backend| backend.down()).unwrap();
        assert!(shared.stats().await.is_err());
    }
}
