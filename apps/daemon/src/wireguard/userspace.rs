use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, bail};
use gotatun::device::{self, DefaultDeviceTransports, Device, DeviceTransports, Peer};
use gotatun::tun::tun_async_device::TunDevice;
use gotatun::tun::{IpRecv, IpSend};
use gotatun::udp::UdpTransportFactory;
use gotatun::udp::socket::UdpSocketFactory;
use gotatun::x25519::{PublicKey, StaticSecret};
use ipnetwork::IpNetwork;
use tokio::runtime::Handle;
use wyvpn_core::wireguard::{Cidr, WireGuardKeys};
use zeroize::Zeroize;

use super::backend::{BackendConfig, Interface, PeerStats, WgBackend, resolve_endpoint};
use super::netops::{LinkConfig, LinkOps};

const HANDSHAKE_KICK: Duration = Duration::from_millis(250);

struct Running {
    device: Device<DefaultDeviceTransports>,
    public_key: PublicKey,
}

pub struct UserspaceBackend {
    runtime: Handle,
    link: Box<dyn LinkOps>,
    running: Option<Running>,
}

impl UserspaceBackend {
    pub fn new(runtime: Handle, link: Box<dyn LinkOps>) -> Self {
        Self {
            runtime,
            link,
            running: None,
        }
    }

    fn create_tun() -> anyhow::Result<TunDevice> {
        let mut config = gotatun::tun::tun::Configuration::default();
        #[cfg(target_os = "linux")]
        config.tun_name(linux_tun_name());
        #[cfg(target_os = "macos")]
        config.platform_config(|platform| {
            platform.enable_routing(false);
        });
        #[cfg(windows)]
        {
            let dll = super::preflight::verified_wintun()?;
            config.tun_name(super::netops::WINDOWS_ADAPTER_NAME);
            config.platform_config(|platform| {
                platform.wintun_file(dll.as_os_str());
            });
        }
        let device = gotatun::tun::tun::create_as_async(&config)
            .context("cannot create the tunnel interface")?;
        TunDevice::from_tun_device(device).context("cannot use the tunnel interface")
    }
}

#[cfg(target_os = "linux")]
fn linux_tun_name() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::netops::LINUX_TUN_PREFIX;

    static NEXT_UNIT: AtomicU32 = AtomicU32::new(0);
    format!(
        "{LINUX_TUN_PREFIX}{}",
        NEXT_UNIT.fetch_add(1, Ordering::Relaxed) % 1000
    )
}

pub fn private_key(keys: &WireGuardKeys) -> StaticSecret {
    let mut bytes = *keys.private_bytes();
    let secret = StaticSecret::from(bytes);
    bytes.zeroize();
    std::hint::black_box(&mut bytes);
    secret
}

fn to_network(cidr: Cidr) -> anyhow::Result<IpNetwork> {
    IpNetwork::new(cidr.addr, cidr.prefix).with_context(|| format!("invalid network {cidr}"))
}

pub fn build_peer(config: &BackendConfig, endpoint: SocketAddr) -> anyhow::Result<Peer> {
    let mut peer =
        Peer::new(PublicKey::from(*config.peer_public_key.as_bytes())).with_endpoint(endpoint);
    for cidr in &config.allowed_ips {
        peer = peer.with_allowed_ip(to_network(*cidr)?);
    }
    Ok(peer)
}

async fn start_device<U: UdpTransportFactory, Tx: IpSend, Rx: IpRecv>(
    udp: U,
    tx: Tx,
    rx: Rx,
    secret: StaticSecret,
    peer: Peer,
) -> Result<Device<(U, Tx, Rx)>, device::Error> {
    device::build()
        .with_udp(udp)
        .with_ip_pair(tx, rx)
        .with_private_key(secret)
        .with_peer(peer)
        .build()
        .await
}

async fn kick_handshake<T: DeviceTransports>(device: &Device<T>, key: &PublicKey) {
    // force_handshake waits for completion without a deadline; the initiation is already sent
    let _ = tokio::time::timeout(HANDSHAKE_KICK, device.force_handshake(key)).await;
}

async fn read_stats<T: DeviceTransports>(device: &Device<T>, key: &PublicKey) -> Option<PeerStats> {
    device
        .read(async |view| {
            view.peers()
                .await
                .into_iter()
                .find(|entry| entry.peer.public_key == *key)
                .map(|entry| PeerStats {
                    handshake_age: entry.stats.last_handshake,
                    rx_bytes: entry.stats.rx_bytes as u64,
                    tx_bytes: entry.stats.tx_bytes as u64,
                })
        })
        .await
}

impl WgBackend for UserspaceBackend {
    fn up(&mut self, config: &BackendConfig, keys: &WireGuardKeys) -> anyhow::Result<Interface> {
        if self.running.is_some() {
            bail!("the interface is already up");
        }
        let _enter = self.runtime.enter();
        let endpoint =
            resolve_endpoint(&config.endpoint).context("cannot resolve the server address")?;
        let secret = private_key(keys);
        let peer = build_peer(config, endpoint)?;
        let public_key = peer.public_key;

        let tun = Self::create_tun()?;
        let name = tun.name().context("cannot read the interface name")?;
        let link = LinkConfig {
            address: config.address,
            address6: config.address6,
            mtu: config.mtu,
        };
        self.link
            .configure_link(&name, &link)
            .with_context(|| format!("cannot configure the interface {name}"))?;

        let device = self
            .runtime
            .block_on(start_device(
                UdpSocketFactory::default(),
                tun.clone(),
                tun,
                secret,
                peer,
            ))
            .context("cannot start WireGuard")?;
        self.runtime.block_on(kick_handshake(&device, &public_key));
        self.running = Some(Running { device, public_key });
        Ok(Interface { name })
    }

    fn stats(&self) -> anyhow::Result<PeerStats> {
        let running = self.running.as_ref().context("the interface is down")?;
        self.runtime
            .block_on(read_stats(&running.device, &running.public_key))
            .context("the peer is missing from the device")
    }

    fn down(&mut self) -> anyhow::Result<()> {
        if let Some(running) = self.running.take() {
            self.runtime.block_on(running.device.stop());
        }
        Ok(())
    }
}

impl Drop for UserspaceBackend {
    fn drop(&mut self) {
        let Some(running) = self.running.take() else {
            return;
        };
        let runtime = self.runtime.clone();
        let stop = move || runtime.block_on(running.device.stop());
        if Handle::try_current().is_ok() {
            std::thread::spawn(stop);
        } else {
            stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use gotatun::packet::{Ip, Packet, PacketBufPool};
    use gotatun::tun::MtuWatcher;
    use gotatun::udp::channel::new_udp_tun_channel;
    use wyvpn_core::wireguard::{Endpoint, Host};

    use super::*;

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
            allowed_ips: vec!["10.0.0.0/8".parse().unwrap(), "0.0.0.0/0".parse().unwrap()],
        }
    }

    #[derive(Clone)]
    struct NullTun;

    impl IpSend for NullTun {
        async fn send(&mut self, _packet: Packet<Ip>) -> io::Result<()> {
            Ok(())
        }
    }

    impl IpRecv for NullTun {
        async fn recv<'a>(
            &'a mut self,
            _pool: &mut PacketBufPool,
        ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
            pending::<io::Result<std::iter::Empty<Packet<Ip>>>>().await
        }

        fn mtu(&self) -> MtuWatcher {
            MtuWatcher::new(1420)
        }
    }

    #[test]
    fn private_key_matches_the_generated_public_key() {
        let keys = WireGuardKeys::generate();
        let secret = private_key(&keys);
        assert_eq!(
            STANDARD.encode(PublicKey::from(&secret).as_bytes()),
            keys.public_key_base64()
        );
    }

    #[test]
    fn peer_carries_key_endpoint_and_allowed_ips() {
        let endpoint: SocketAddr = "203.0.113.9:51820".parse().unwrap();
        let peer = build_peer(&config(), endpoint).unwrap();
        assert_eq!(peer.public_key.as_bytes(), &[7u8; 32]);
        assert_eq!(peer.endpoint, Some(endpoint));
        assert_eq!(peer.allowed_ips.len(), 2);
        assert!(
            peer.allowed_ips
                .iter()
                .any(|n| n.to_string() == "0.0.0.0/0")
        );
        assert_eq!(peer.keepalive, None);
    }

    #[tokio::test]
    async fn device_reports_a_pending_handshake_and_sends_an_initiation() {
        let (_tun_tx, mut observer, udp) = new_udp_tun_channel(
            8,
            Ipv4Addr::LOCALHOST,
            Ipv6Addr::UNSPECIFIED,
            MtuWatcher::new(1420),
        );
        let keys = WireGuardKeys::generate();
        let endpoint: SocketAddr = "203.0.113.9:51820".parse().unwrap();
        let peer = build_peer(&config(), endpoint).unwrap();
        let key = peer.public_key;
        let device = start_device(udp, NullTun, NullTun, private_key(&keys), peer)
            .await
            .unwrap();

        let stats = read_stats(&device, &key).await.unwrap();
        assert_eq!(stats.handshake_age, None);
        assert_eq!((stats.rx_bytes, stats.tx_bytes), (0, 0));

        kick_handshake(&device, &key).await;
        let mut pool = PacketBufPool::new(4);
        let sent = tokio::time::timeout(Duration::from_secs(2), observer.recv(&mut pool))
            .await
            .expect("an initiation should be sent")
            .unwrap()
            .next()
            .unwrap();
        assert!(!sent.into_bytes().is_empty());

        assert!(
            read_stats(&device, &PublicKey::from([9u8; 32]))
                .await
                .is_none()
        );
        device.stop().await;
    }
}
