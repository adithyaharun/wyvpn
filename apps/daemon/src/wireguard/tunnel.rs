use std::any::Any;
use std::io;
use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, anyhow};
use wyvpn_core::wireguard::{Cidr, Endpoint, Host, WireGuardConfig, WireGuardKeys};

use super::backend::{BackendConfig, SharedBackend, WgBackend, resolve_endpoint};
use super::dnsctl::{DnsControl, tunnel_dns};
use super::exec::SystemExec;
use super::netops::{Platform, Programs, RouteEntry, RouteOps, SystemNet};
use super::routes::{
    allowed_ips, already_present, bypass_entry, ensure_reachable, ipv6_unavailable, is_critical,
    needs_bypass, split_defaults, tunnel_entries, without_host,
};
use super::state::{StateStore, recover_routes};
use super::userspace::UserspaceBackend;

const IPV6_PROBE: std::net::IpAddr = std::net::IpAddr::V6(std::net::Ipv6Addr::new(
    0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888,
));

pub type Resolver = Box<dyn Fn(&Endpoint) -> io::Result<SocketAddr> + Send>;

pub struct Parts {
    pub backend: Box<dyn WgBackend>,
    pub routes: Box<dyn RouteOps>,
    pub dns: Box<dyn DnsControl>,
    pub store: StateStore,
    pub resolve: Resolver,
}

impl Parts {
    pub fn system(runtime: tokio::runtime::Handle, data_dir: &Path) -> anyhow::Result<Self> {
        let platform = Platform::current();
        let programs = Programs::locate(platform)?;
        let net =
            |programs: &Programs| SystemNet::new(SystemExec::default(), platform, programs.clone());
        #[cfg(unix)]
        let dns: Box<dyn DnsControl> = Box::new(super::dnsctl::NativeDns::new(data_dir));
        #[cfg(windows)]
        let dns: Box<dyn DnsControl> = Box::new(super::dnsctl::AdapterDns::new(
            SystemExec::default(),
            programs.clone(),
        ));
        Ok(Self {
            backend: Box::new(UserspaceBackend::new(runtime, Box::new(net(&programs)))),
            routes: Box::new(net(&programs)),
            dns,
            store: StateStore::new(data_dir),
            resolve: Box::new(resolve_endpoint),
        })
    }
}

pub struct Tunnel {
    backend: SharedBackend,
    interface: String,
    endpoint: SocketAddr,
    live: Option<Live>,
}

struct Live {
    backend: SharedBackend,
    routes: Box<dyn RouteOps>,
    dns: Box<dyn DnsControl>,
    store: StateStore,
    interface: String,
    installed: Vec<RouteEntry>,
    dns_applied: bool,
    held: Vec<Box<dyn Any + Send>>,
}

impl Tunnel {
    pub fn bring_up(
        parts: Parts,
        config: &WireGuardConfig,
        keys: &WireGuardKeys,
    ) -> anyhow::Result<Self> {
        let Parts {
            backend,
            mut routes,
            dns,
            store,
            resolve,
        } = parts;

        let endpoint = resolve(&config.endpoint()).context("cannot resolve the server address")?;
        recover_routes(&store, routes.as_mut(), Platform::current());
        let mut allowed = allowed_ips(&config.routes, &config.routes6);
        for (network, reason) in &allowed.skipped {
            tracing::warn!(%network, %reason, "skipping a route from the server");
        }
        ensure_reachable(&mut allowed.networks, config.gateway.into());
        let mut tunnel_networks = split_defaults(&allowed.networks);
        let bypass = if needs_bypass(&tunnel_networks, endpoint.ip()) {
            without_host(&mut tunnel_networks, endpoint.ip());
            let via = routes
                .route_to(endpoint.ip())
                .context("cannot find the current route to the server")?;
            Some(bypass_entry(endpoint.ip(), via))
        } else {
            None
        };

        let backend_config = BackendConfig {
            address: config.address,
            address6: config.address6,
            mtu: config.mtu,
            peer_public_key: config.public_key,
            endpoint: Endpoint {
                host: Host::Ip(endpoint.ip()),
                port: endpoint.port(),
            },
            allowed_ips: allowed.networks.clone(),
        };
        let backend = SharedBackend::new(backend);
        let interface = backend
            .with(|backend| backend.up(&backend_config, keys))?
            .name;

        let mut tunnel = Self {
            backend: backend.clone(),
            interface: interface.clone(),
            endpoint,
            live: Some(Live {
                backend,
                routes,
                dns,
                store,
                interface,
                installed: Vec::new(),
                dns_applied: false,
                held: Vec::new(),
            }),
        };
        if let Err(err) = tunnel.install_all(bypass, &tunnel_networks, config) {
            if let Err(cleanup) = tunnel.tear_down() {
                tracing::warn!(error = %format!("{cleanup:#}"), "cleanup after a failed bring-up was incomplete");
            }
            return Err(err);
        }
        Ok(tunnel)
    }

    fn install_all(
        &mut self,
        bypass: Option<RouteEntry>,
        tunnel_networks: &[Cidr],
        config: &WireGuardConfig,
    ) -> anyhow::Result<()> {
        let live = self.live_mut();
        let mut planned: Vec<(RouteEntry, bool)> = bypass.into_iter().map(|e| (e, true)).collect();
        planned.extend(
            tunnel_entries(tunnel_networks, &live.interface)
                .into_iter()
                .map(|e| (e, false)),
        );
        let plan: Vec<RouteEntry> = planned.iter().map(|(entry, _)| entry.clone()).collect();
        live.store
            .save(&live.interface, &plan)
            .context("cannot record the tunnel state")?;
        for (entry, is_bypass) in planned {
            live.install(entry, is_bypass)?;
        }
        live.persist()?;

        let dns_config = tunnel_dns(config);
        if !dns_config.is_empty() {
            live.dns_applied = true;
            if let Err(err) = live.dns.apply(&live.interface, &dns_config) {
                tracing::warn!(%err, "cannot apply dns");
            }
        }
        Ok(())
    }

    fn live_mut(&mut self) -> &mut Live {
        self.live
            .as_mut()
            .expect("the tunnel is live until torn down")
    }

    pub fn keep(&mut self, token: impl Send + 'static) {
        if let Some(live) = self.live.as_mut() {
            live.held.push(Box::new(token));
        }
    }

    pub fn backend(&self) -> SharedBackend {
        self.backend.clone()
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    pub fn tear_down(&mut self) -> anyhow::Result<()> {
        match self.live.take() {
            Some(live) => live.teardown(),
            None => Ok(()),
        }
    }
}

impl Live {
    fn persist(&self) -> anyhow::Result<()> {
        self.store
            .save(&self.interface, &self.installed)
            .context("cannot record the tunnel state")
    }

    fn no_ipv6_path(&mut self) -> bool {
        self.routes.route_to(IPV6_PROBE).is_err()
    }

    fn install(&mut self, entry: RouteEntry, bypass: bool) -> anyhow::Result<()> {
        let critical = bypass || is_critical(entry.network);
        match self.routes.add_route(&entry) {
            Ok(()) => self.installed.push(entry),
            Err(err) if bypass && already_present(&err) => {
                tracing::debug!(network = %entry.network, "route to the server already present");
            }
            Err(err)
                if critical
                    && !(entry.network.addr.is_ipv6()
                        && ipv6_unavailable(&err)
                        && self.no_ipv6_path()) =>
            {
                return Err(anyhow::Error::new(err)
                    .context(format!("cannot install the route {}", entry.network)));
            }
            Err(err) => {
                if already_present(&err) {
                    tracing::debug!(network = %entry.network, "route already present");
                } else {
                    tracing::warn!(%err, network = %entry.network, "cannot install a route");
                }
            }
        }
        Ok(())
    }

    fn teardown(mut self) -> anyhow::Result<()> {
        let mut failures = Vec::new();
        let mut keep_record = false;
        if self.dns_applied
            && let Err(err) = self.dns.restore()
        {
            failures.push(format!("dns: {err}"));
        }
        for route in self.installed.drain(..).rev() {
            if let Err(err) = self.routes.delete_route(&route) {
                keep_record = true;
                failures.push(format!("route {}: {err}", route.network));
            }
        }
        if let Err(err) = self.backend.with(|backend| backend.down()) {
            keep_record = true;
            failures.push(format!("interface: {err}"));
        }
        if !keep_record && let Err(err) = self.store.clear() {
            failures.push(format!("state record: {err}"));
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(
                "tunnel teardown was incomplete: {}",
                failures.join("; ")
            ))
        }
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        let Some(live) = self.live.take() else {
            return;
        };
        let run = move || {
            if let Err(err) = live.teardown() {
                tracing::warn!(%err, "tunnel cleanup failed");
            }
        };
        if tokio::runtime::Handle::try_current().is_ok() {
            super::background::spawn(run);
        } else {
            run();
        }
    }
}

#[cfg(test)]
mod tests {
    use wyvpn_core::wireguard::Cidr;

    use super::*;
    use crate::wireguard::backend::fake::{self, Handle};
    use crate::wireguard::dnsctl::fake::FakeDns;
    use crate::wireguard::netops::Via;
    use crate::wireguard::netops::fake::FakeNet;
    use crate::wireguard::testutil::{config, route};

    struct Rig {
        net: FakeNet,
        dns: FakeDns,
        data: tempfile::TempDir,
    }

    impl Rig {
        fn new() -> Self {
            Self {
                net: FakeNet::with_gateway("192.168.1.1", "en0"),
                dns: FakeDns::default(),
                data: tempfile::tempdir().unwrap(),
            }
        }

        fn parts_with(&self, backend: fake::FakeBackend) -> Parts {
            Parts {
                backend: Box::new(backend),
                routes: Box::new(self.net.clone()),
                dns: Box::new(self.dns.clone()),
                store: StateStore::new(self.data.path()),
                resolve: Box::new(super::super::backend::resolve_endpoint),
            }
        }

        fn record(&self) -> std::path::PathBuf {
            self.data.path().join("state/wg.json")
        }
    }

    fn up(rig: &Rig, config: &WireGuardConfig) -> (anyhow::Result<Tunnel>, Handle) {
        let (backend, handle) = fake::pair();
        let result = Tunnel::bring_up(rig.parts_with(backend), config, &WireGuardKeys::generate());
        (result, handle)
    }

    fn cidr(text: &str) -> Cidr {
        text.parse().unwrap()
    }

    #[test]
    fn full_tunnel_orders_bypass_before_split_defaults() {
        let rig = Rig::new();
        let mut cfg = config();
        cfg.routes = vec![route("0.0.0.0/0")];
        cfg.dns_servers = vec!["10.200.0.1".parse().unwrap()];
        let (tunnel, backend) = up(&rig, &cfg);
        let tunnel = tunnel.unwrap();
        assert_eq!(tunnel.interface(), "fake0");

        assert_eq!(
            rig.net.log(),
            [
                "route_to 203.0.113.9",
                "add 203.0.113.9/32 via 192.168.1.1 dev en0",
                "add 0.0.0.0/1 dev fake0",
                "add 128.0.0.0/1 dev fake0",
            ]
        );
        backend.with(|record| {
            let config = &record.configs[0];
            assert_eq!(config.allowed_ips, [cidr("0.0.0.0/0")]);
            assert_eq!(
                config.endpoint.host,
                Host::Ip("203.0.113.9".parse().unwrap())
            );
            assert_eq!(config.mtu, Some(1420));
        });
        assert_eq!(rig.dns.log(), ["apply fake0 [10.200.0.1]"]);
    }

    #[test]
    fn state_record_lists_interface_and_routes_but_no_keys() {
        let rig = Rig::new();
        let mut cfg = config();
        cfg.routes = vec![route("0.0.0.0/0")];
        let keys = WireGuardKeys::generate();
        let (backend, _) = fake::pair();
        let tunnel = Tunnel::bring_up(rig.parts_with(backend), &cfg, &keys).unwrap();
        let text = std::fs::read_to_string(rig.record()).unwrap();
        assert!(text.contains("\"interface\":\"fake0\""));
        assert!(text.contains("203.0.113.9/32"));
        assert!(text.contains("128.0.0.0/1"));
        assert!(!text.contains(&*keys.private_key_base64()));
        assert!(!text.contains(&keys.public_key_base64()));
        drop(tunnel);
        assert!(!rig.record().exists());
    }

    #[test]
    fn partial_routes_need_no_bypass() {
        let rig = Rig::new();
        let mut cfg = config();
        cfg.routes = vec![route("10.0.0.0/8"), route("172.16.0.0/12")];
        cfg.routes6 = vec![route("::/0")];
        let (tunnel, _) = up(&rig, &cfg);
        let _tunnel = tunnel.unwrap();
        assert_eq!(
            rig.net.log(),
            [
                "add 10.0.0.0/8 dev fake0",
                "add 172.16.0.0/12 dev fake0",
                "add ::/1 dev fake0",
                "add 8000::/1 dev fake0",
            ]
        );
    }

    #[test]
    fn an_uncovered_gateway_gets_its_own_route_and_allowed_ip() {
        let rig = Rig::new();
        let mut cfg = config();
        cfg.routes = vec![route("192.168.0.0/16")];
        let (tunnel, backend) = up(&rig, &cfg);
        let _tunnel = tunnel.unwrap();
        assert_eq!(
            rig.net.log(),
            [
                "add 192.168.0.0/16 dev fake0",
                "add 10.200.0.1/32 dev fake0"
            ]
        );
        backend.with(|record| {
            assert_eq!(
                record.configs[0].allowed_ips,
                [cidr("192.168.0.0/16"), cidr("10.200.0.1/32")]
            );
        });
    }

    #[test]
    fn invalid_and_net_gateway_routes_are_skipped_but_the_rest_apply() {
        let rig = Rig::new();
        let mut cfg = config();
        let mut excluded = route("192.168.0.0/16");
        excluded.net_gateway = true;
        cfg.routes = vec![excluded, route("127.0.0.0/8"), route("10.0.0.0/8")];
        let (tunnel, backend) = up(&rig, &cfg);
        let _tunnel = tunnel.unwrap();
        assert_eq!(rig.net.log(), ["add 10.0.0.0/8 dev fake0"]);
        backend.with(|record| assert_eq!(record.configs[0].allowed_ips, [cidr("10.0.0.0/8")]));
    }

    #[test]
    fn a_failing_ordinary_route_is_logged_and_skipped() {
        let rig = Rig::new();
        rig.net.lock().fail_add = vec!["10.0.0.0/8".into()];
        rig.net.lock().exists_on_add = vec!["172.16.0.0/12".into()];
        let mut cfg = config();
        cfg.routes = vec![
            route("10.0.0.0/8"),
            route("172.16.0.0/12"),
            route("192.168.0.0/16"),
        ];
        let (tunnel, _) = up(&rig, &cfg);
        let mut tunnel = tunnel.unwrap();
        tunnel.tear_down().unwrap();
        let log = rig.net.log();
        assert!(log.contains(&"del 192.168.0.0/16 dev fake0".to_owned()));
        assert!(!log.contains(&"del 10.0.0.0/8 dev fake0".to_owned()));
        assert!(!log.contains(&"del 172.16.0.0/12 dev fake0".to_owned()));
    }

    #[test]
    fn a_failing_default_route_aborts_and_cleans_up() {
        let rig = Rig::new();
        rig.net.lock().fail_add = vec!["128.0.0.0/1".into()];
        let mut cfg = config();
        cfg.routes = vec![route("0.0.0.0/0")];
        let (tunnel, backend) = up(&rig, &cfg);
        let err = tunnel.err().unwrap();
        assert!(format!("{err:#}").contains("128.0.0.0/1"));
        let log = rig.net.log();
        assert!(log.contains(&"del 0.0.0.0/1 dev fake0".to_owned()));
        assert!(log.contains(&"del 203.0.113.9/32 via 192.168.1.1 dev en0".to_owned()));
        backend.with(|record| {
            assert_eq!(record.downs, 1);
            assert!(!record.is_up);
        });
        assert!(!rig.record().exists());
    }

    #[test]
    fn a_failing_bypass_is_fatal_but_an_existing_one_is_not() {
        let rig = Rig::new();
        rig.net.lock().fail_add = vec!["203.0.113.9/32".into()];
        let mut cfg = config();
        cfg.routes = vec![route("0.0.0.0/0")];
        let (tunnel, backend) = up(&rig, &cfg);
        assert!(tunnel.is_err());
        assert!(!rig.net.log().iter().any(|line| line.contains("0.0.0.0/1")));
        backend.with(|record| assert_eq!(record.downs, 1));

        let rig = Rig::new();
        rig.net.lock().exists_on_add = vec!["203.0.113.9/32".into()];
        let (tunnel, _) = up(&rig, &cfg);
        let mut tunnel = tunnel.unwrap();
        tunnel.tear_down().unwrap();
        assert!(
            !rig.net
                .log()
                .iter()
                .any(|line| line.starts_with("del 203.0.113.9/32"))
        );
    }

    #[test]
    fn route_lookup_failure_stops_before_the_interface_exists() {
        let rig = Rig::new();
        rig.net.lock().via = None;
        let mut cfg = config();
        cfg.routes = vec![route("0.0.0.0/0")];
        let (tunnel, backend) = up(&rig, &cfg);
        assert!(tunnel.is_err());
        backend.with(|record| assert!(record.configs.is_empty()));
        assert_eq!(rig.net.log(), ["route_to 203.0.113.9"]);
    }

    #[test]
    fn backend_failure_touches_no_routes_dns_or_state() {
        let rig = Rig::new();
        let (backend, handle) = fake::pair();
        handle.with(|record| record.fail_up = Some("no tun device".into()));
        let mut cfg = config();
        cfg.routes = vec![route("10.0.0.0/8")];
        cfg.dns_servers = vec!["10.200.0.1".parse().unwrap()];
        let err = Tunnel::bring_up(rig.parts_with(backend), &cfg, &WireGuardKeys::generate())
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "no tun device");
        assert!(rig.net.log().is_empty());
        assert!(rig.dns.log().is_empty());
        assert!(!rig.record().exists());
    }

    #[test]
    fn dns_is_left_alone_without_servers_and_failures_are_not_fatal() {
        let rig = Rig::new();
        let mut cfg = config();
        cfg.search_domains = vec!["corp.example".into()];
        let (tunnel, _) = up(&rig, &cfg);
        let mut tunnel = tunnel.unwrap();
        tunnel.tear_down().unwrap();
        assert!(rig.dns.log().is_empty());

        let rig = Rig::new();
        rig.dns.set(|inner| inner.fail_apply = true);
        cfg.dns_servers = vec!["10.200.0.1".parse().unwrap()];
        let (tunnel, _) = up(&rig, &cfg);
        assert!(tunnel.is_ok());
    }

    #[test]
    fn tear_down_restores_dns_then_routes_then_the_interface_and_is_idempotent() {
        let rig = Rig::new();
        let mut cfg = config();
        cfg.routes = vec![route("0.0.0.0/0")];
        cfg.dns_servers = vec!["10.200.0.1".parse().unwrap()];
        let (tunnel, backend) = up(&rig, &cfg);
        let mut tunnel = tunnel.unwrap();
        tunnel.tear_down().unwrap();
        tunnel.tear_down().unwrap();
        assert_eq!(rig.dns.log(), ["apply fake0 [10.200.0.1]", "restore"]);
        assert_eq!(
            rig.net.log()[4..],
            [
                "del 128.0.0.0/1 dev fake0",
                "del 0.0.0.0/1 dev fake0",
                "del 203.0.113.9/32 via 192.168.1.1 dev en0",
            ]
        );
        backend.with(|record| assert_eq!(record.downs, 1));
        assert!(!rig.record().exists());
    }

    #[test]
    fn drop_cleans_up_a_tunnel_that_was_never_stopped() {
        let rig = Rig::new();
        let mut cfg = config();
        cfg.routes = vec![route("10.0.0.0/8")];
        let (tunnel, backend) = up(&rig, &cfg);
        drop(tunnel.unwrap());
        assert!(
            rig.net
                .log()
                .contains(&"del 10.0.0.0/8 dev fake0".to_owned())
        );
        backend.with(|record| assert_eq!(record.downs, 1));
    }

    #[test]
    fn incomplete_teardown_keeps_the_record_for_recovery() {
        let rig = Rig::new();
        let mut cfg = config();
        cfg.routes = vec![route("10.0.0.0/8")];
        let (tunnel, backend) = up(&rig, &cfg);
        let mut tunnel = tunnel.unwrap();
        rig.net.lock().fail_delete = true;
        backend.with(|record| record.fail_down = true);
        let err = tunnel.tear_down().unwrap_err().to_string();
        assert!(err.contains("route 10.0.0.0/8"));
        assert!(err.contains("interface"));
        assert!(rig.record().exists());
        std::mem::forget(tunnel);
    }

    #[test]
    fn halves_pushed_by_the_server_are_installed_not_skipped() {
        let rig = Rig::new();
        let mut cfg = config();
        cfg.routes = vec![route("0.0.0.0/1"), route("128.0.0.0/1")];
        cfg.routes6 = vec![route("::/1"), route("8000::/1")];
        let (tunnel, _) = up(&rig, &cfg);
        let _tunnel = tunnel.unwrap();
        let log = rig.net.log();
        for half in ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"] {
            assert!(log.contains(&format!("add {half} dev fake0")), "{half}");
        }
    }

    #[test]
    fn ipv6_routes_are_optional_only_when_the_host_has_no_ipv6_path() {
        let failures = vec![
            (
                "::/1".to_owned(),
                "RTNETLINK answers: Address family not supported by protocol".to_owned(),
            ),
            (
                "8000::/1".to_owned(),
                "RTNETLINK answers: Operation not supported".to_owned(),
            ),
        ];
        let mut cfg = config();
        cfg.routes = vec![route("10.0.0.0/8")];
        cfg.routes6 = vec![route("::/0")];

        let rig = Rig::new();
        rig.net.lock().no_v6 = true;
        rig.net.lock().fail_add_with = failures.clone();
        let (tunnel, _) = up(&rig, &cfg);
        let mut tunnel = tunnel.unwrap();
        tunnel.tear_down().unwrap();
        assert!(
            !rig.net
                .log()
                .iter()
                .any(|line| line.starts_with("del ::/1"))
        );

        let rig = Rig::new();
        rig.net.lock().fail_add_with = failures;
        let (tunnel, _) = up(&rig, &cfg);
        assert!(tunnel.is_err());

        let rig = Rig::new();
        rig.net.lock().no_v6 = true;
        rig.net.lock().fail_add_with = vec![("::/1".into(), "permission denied".into())];
        let (tunnel, _) = up(&rig, &cfg);
        assert!(tunnel.is_err());
    }

    #[test]
    fn an_on_link_bypass_is_just_as_critical() {
        let rig = Rig::new();
        rig.net.lock().via = Some(Via::Interface("en0".into()));
        rig.net.lock().fail_add = vec!["203.0.113.9/32".into()];
        let mut cfg = config();
        cfg.routes = vec![route("0.0.0.0/0")];
        let (tunnel, backend) = up(&rig, &cfg);
        assert!(tunnel.is_err());
        backend.with(|record| assert_eq!(record.downs, 1));
    }

    #[test]
    fn the_endpoint_route_is_installed_once_even_if_the_server_lists_it() {
        let rig = Rig::new();
        let mut cfg = config();
        cfg.routes = vec![route("0.0.0.0/0"), route("203.0.113.9/32")];
        let (tunnel, _) = up(&rig, &cfg);
        let _tunnel = tunnel.unwrap();
        let adds = rig
            .net
            .log()
            .iter()
            .filter(|line| line.contains("203.0.113.9/32"))
            .count();
        assert_eq!(adds, 1);
    }

    #[test]
    fn the_state_record_holds_only_routes_that_were_installed() {
        let rig = Rig::new();
        rig.net.lock().fail_add = vec!["10.0.0.0/8".into()];
        let mut cfg = config();
        cfg.routes = vec![route("10.0.0.0/8"), route("172.16.0.0/12")];
        let (tunnel, _) = up(&rig, &cfg);
        let _tunnel = tunnel.unwrap();
        let text = std::fs::read_to_string(rig.record()).unwrap();
        assert!(text.contains("172.16.0.0/12"));
        assert!(!text.contains("10.0.0.0/8"));
    }

    #[test]
    fn a_leftover_record_is_recovered_before_the_new_tunnel_starts() {
        let rig = Rig::new();
        StateStore::new(rig.data.path())
            .save(
                "wyvpn9",
                &[RouteEntry {
                    network: cidr("198.51.100.0/24"),
                    via: Via::Gateway {
                        gateway: "192.168.1.1".parse().unwrap(),
                        dev: "en0".into(),
                    },
                }],
            )
            .unwrap();
        let mut cfg = config();
        cfg.routes = vec![route("10.0.0.0/8")];
        let (tunnel, _) = up(&rig, &cfg);
        let _tunnel = tunnel.unwrap();
        let log = rig.net.log();
        assert_eq!(log[0], "del 198.51.100.0/24 via 192.168.1.1 dev en0");
        let text = std::fs::read_to_string(rig.record()).unwrap();
        assert!(text.contains("fake0") && !text.contains("198.51.100.0"));
    }

    #[test]
    fn dns_names_are_resolved_before_bring_up() {
        let rig = Rig::new();
        let mut cfg = config();
        cfg.hostname = Host::Dns("vpn.example".into());
        cfg.routes = vec![route("0.0.0.0/0")];
        let (backend, handle) = fake::pair();
        let mut parts = rig.parts_with(backend);
        parts.resolve = Box::new(|endpoint| {
            assert_eq!(endpoint.host, Host::Dns("vpn.example".into()));
            Ok("198.51.100.7:51820".parse().unwrap())
        });
        let _tunnel = Tunnel::bring_up(parts, &cfg, &WireGuardKeys::generate()).unwrap();
        assert_eq!(rig.net.log()[0], "route_to 198.51.100.7");
        handle.with(|record| {
            assert_eq!(
                record.configs[0].endpoint.host,
                Host::Ip("198.51.100.7".parse().unwrap())
            );
        });
    }

    #[test]
    fn resolution_failure_is_reported() {
        let rig = Rig::new();
        let (backend, handle) = fake::pair();
        let mut parts = rig.parts_with(backend);
        parts.resolve = Box::new(|_| Err(io::Error::other("no such host")));
        let err = Tunnel::bring_up(parts, &config(), &WireGuardKeys::generate())
            .err()
            .unwrap();
        assert!(format!("{err:#}").contains("cannot resolve the server address"));
        handle.with(|record| assert!(record.configs.is_empty()));
    }
}
