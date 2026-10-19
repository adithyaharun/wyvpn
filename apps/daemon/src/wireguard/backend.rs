use std::time::Duration;

use wyvpn_core::wireguard::{Cidr, WireGuardKeys};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendConfig {
    pub address: Cidr,
    pub address6: Option<Cidr>,
    pub mtu: Option<u16>,
    pub peer_public_key: String,
    pub endpoint: String,
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
    fn down(&mut self);
}

#[cfg(test)]
pub mod fake {
    use std::sync::{Arc, Mutex, PoisonError};

    use super::*;

    #[derive(Default)]
    pub struct Record {
        pub configs: Vec<BackendConfig>,
        pub public_keys_seen: Vec<String>,
        pub downs: usize,
        pub fail_up: Option<String>,
        pub stats: PeerStats,
        pub stats_fail: bool,
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
                if !record.is_up {
                    anyhow::bail!("interface is down");
                }
                if record.stats_fail {
                    anyhow::bail!("stats unavailable");
                }
                Ok(record.stats)
            })
        }

        fn down(&mut self) {
            self.handle.with(|record| {
                record.downs += 1;
                record.is_up = false;
            });
        }
    }

    fn config() -> BackendConfig {
        BackendConfig {
            address: "10.200.0.5/24".parse().unwrap(),
            address6: None,
            mtu: Some(1420),
            peer_public_key: "peer".into(),
            endpoint: "203.0.113.9:51820".into(),
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

        backend.down();
        handle.with(|record| {
            assert_eq!(record.downs, 1);
            assert!(!record.is_up);
        });
        assert!(backend.stats().is_err());
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
}
