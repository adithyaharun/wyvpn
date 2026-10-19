use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use wyvpn_core::wireguard::{Cidr, Route};

use super::netops::{RouteEntry, Via};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    NetGateway,
    Loopback,
    Multicast,
    Unspecified,
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NetGateway => "net_gateway routes are not supported",
            Self::Loopback => "loopback networks cannot be routed",
            Self::Multicast => "multicast networks cannot be routed",
            Self::Unspecified => "the unspecified address needs the default route form",
        })
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Allowed {
    pub networks: Vec<Cidr>,
    pub skipped: Vec<(Cidr, SkipReason)>,
}

pub fn masked(cidr: Cidr) -> Cidr {
    let addr = match cidr.addr {
        IpAddr::V4(ip) => {
            let mask = u32::MAX
                .checked_shl(32 - u32::from(cidr.prefix))
                .unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(ip) & mask))
        }
        IpAddr::V6(ip) => {
            let mask = u128::MAX
                .checked_shl(128 - u32::from(cidr.prefix))
                .unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(ip) & mask))
        }
    };
    Cidr {
        addr,
        prefix: cidr.prefix,
    }
}

pub fn contains(network: Cidr, ip: IpAddr) -> bool {
    let network = masked(network);
    match (network.addr, ip) {
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
            masked(Cidr {
                addr: ip,
                prefix: network.prefix,
            }) == network
        }
        _ => false,
    }
}

fn skip_reason(route: &Route) -> Option<SkipReason> {
    if route.net_gateway {
        return Some(SkipReason::NetGateway);
    }
    let Cidr { addr, prefix } = masked(route.network);
    match addr {
        IpAddr::V4(ip) if ip.is_loopback() && prefix >= 8 => Some(SkipReason::Loopback),
        IpAddr::V4(ip) if ip.is_multicast() && prefix >= 4 => Some(SkipReason::Multicast),
        IpAddr::V4(ip) if ip.octets()[0] == 0 && prefix >= 8 => Some(SkipReason::Unspecified),
        IpAddr::V6(ip) if ip.is_loopback() => Some(SkipReason::Loopback),
        IpAddr::V6(ip) if ip.is_multicast() && prefix >= 8 => Some(SkipReason::Multicast),
        IpAddr::V6(ip) if ip.is_unspecified() && prefix == 128 => Some(SkipReason::Unspecified),
        _ => None,
    }
}

pub fn allowed_ips(routes: &[Route], routes6: &[Route]) -> Allowed {
    let mut allowed = Allowed::default();
    for route in routes.iter().chain(routes6) {
        if let Some(reason) = skip_reason(route) {
            allowed.skipped.push((route.network, reason));
            continue;
        }
        let network = masked(route.network);
        if !allowed.networks.contains(&network) {
            allowed.networks.push(network);
        }
    }
    allowed
}

pub fn ensure_reachable(networks: &mut Vec<Cidr>, host: IpAddr) {
    let prefix = if host.is_ipv4() { 32 } else { 128 };
    let probe = Route {
        network: Cidr { addr: host, prefix },
        next_hop: None,
        metric: None,
        net_gateway: false,
    };
    if skip_reason(&probe).is_some() {
        return;
    }
    if !networks.iter().any(|network| contains(*network, host)) {
        let prefix = if host.is_ipv4() { 32 } else { 128 };
        networks.push(Cidr { addr: host, prefix });
    }
}

pub fn split_defaults(networks: &[Cidr]) -> Vec<Cidr> {
    let mut split = Vec::with_capacity(networks.len());
    let mut push = |network: Cidr| {
        if !split.contains(&network) {
            split.push(network);
        }
    };
    for network in networks {
        if network.prefix != 0 {
            push(*network);
            continue;
        }
        let halves: [IpAddr; 2] = match network.addr {
            IpAddr::V4(_) => [
                Ipv4Addr::new(0, 0, 0, 0).into(),
                Ipv4Addr::new(128, 0, 0, 0).into(),
            ],
            IpAddr::V6(_) => [
                Ipv6Addr::UNSPECIFIED.into(),
                Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0).into(),
            ],
        };
        for addr in halves {
            push(Cidr { addr, prefix: 1 });
        }
    }
    split
}

pub fn needs_bypass(tunnel_networks: &[Cidr], endpoint: IpAddr) -> bool {
    tunnel_networks
        .iter()
        .any(|network| contains(*network, endpoint))
}

pub fn without_host(networks: &mut Vec<Cidr>, host: IpAddr) {
    let prefix = if host.is_ipv4() { 32 } else { 128 };
    networks.retain(|network| !(network.prefix == prefix && network.addr == host));
}

pub fn is_critical(network: Cidr) -> bool {
    network.prefix <= 1
}

pub fn bypass_entry(endpoint: IpAddr, via: Via) -> RouteEntry {
    let prefix = if endpoint.is_ipv4() { 32 } else { 128 };
    RouteEntry {
        network: Cidr {
            addr: endpoint,
            prefix,
        },
        via,
    }
}

pub fn tunnel_entries(networks: &[Cidr], dev: &str) -> Vec<RouteEntry> {
    networks
        .iter()
        .map(|network| RouteEntry {
            network: *network,
            via: Via::Interface(dev.to_owned()),
        })
        .collect()
}

pub fn already_present(err: &std::io::Error) -> bool {
    let text = err.to_string();
    text.contains("File exists") || text.contains("already exists")
}

pub fn ipv6_unavailable(err: &std::io::Error) -> bool {
    let text = err.to_string().to_ascii_lowercase();
    [
        "address family not supported",
        "operation not supported",
        "ipv6 is disabled",
        "ipv6 is not",
    ]
    .iter()
    .any(|marker| text.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(text: &str) -> Cidr {
        text.parse().unwrap()
    }

    fn route(network: &str) -> Route {
        Route {
            network: cidr(network),
            next_hop: None,
            metric: None,
            net_gateway: false,
        }
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn masks_host_bits() {
        assert_eq!(masked(cidr("10.1.2.3/8")), cidr("10.0.0.0/8"));
        assert_eq!(masked(cidr("10.1.2.3/32")), cidr("10.1.2.3/32"));
        assert_eq!(masked(cidr("1.2.3.4/0")), cidr("0.0.0.0/0"));
        assert_eq!(masked(cidr("fd00:1:2::5/48")), cidr("fd00:1:2::/48"));
        assert_eq!(masked(cidr("::1/0")), cidr("::/0"));
    }

    #[test]
    fn containment_checks_family_and_prefix() {
        assert!(contains(cidr("203.0.113.0/24"), ip("203.0.113.9")));
        assert!(!contains(cidr("203.0.113.0/24"), ip("203.0.114.9")));
        assert!(contains(cidr("0.0.0.0/0"), ip("1.2.3.4")));
        assert!(!contains(cidr("0.0.0.0/0"), ip("2001:db8::1")));
        assert!(contains(cidr("2001:db8::/32"), ip("2001:db8::9")));
        assert!(contains(cidr("203.0.113.9/32"), ip("203.0.113.9")));
    }

    #[test]
    fn allowed_ips_skip_and_dedupe() {
        let mut gateway = route("192.168.0.0/16");
        gateway.net_gateway = true;
        let routes = [
            route("10.0.0.0/8"),
            gateway,
            route("10.1.1.1/8"),
            route("127.0.0.0/8"),
            route("224.0.0.0/4"),
            route("0.0.0.0/8"),
            route("0.0.0.0/0"),
        ];
        let routes6 = [route("::/0"), route("ff02::/16"), route("::/128")];
        let allowed = allowed_ips(&routes, &routes6);
        assert_eq!(
            allowed.networks,
            [cidr("10.0.0.0/8"), cidr("0.0.0.0/0"), cidr("::/0")]
        );
        assert_eq!(
            allowed.skipped,
            [
                (cidr("192.168.0.0/16"), SkipReason::NetGateway),
                (cidr("127.0.0.0/8"), SkipReason::Loopback),
                (cidr("224.0.0.0/4"), SkipReason::Multicast),
                (cidr("0.0.0.0/8"), SkipReason::Unspecified),
                (cidr("ff02::/16"), SkipReason::Multicast),
                (cidr("::/128"), SkipReason::Unspecified),
            ]
        );
    }

    #[test]
    fn the_gateway_is_added_only_when_no_route_covers_it() {
        let gateway = ip("10.200.0.1");
        let mut covered = vec![cidr("10.0.0.0/8")];
        ensure_reachable(&mut covered, gateway);
        assert_eq!(covered, [cidr("10.0.0.0/8")]);
        let mut bare = vec![cidr("192.168.0.0/16")];
        ensure_reachable(&mut bare, gateway);
        assert_eq!(bare, [cidr("192.168.0.0/16"), cidr("10.200.0.1/32")]);
        let mut empty = Vec::new();
        ensure_reachable(&mut empty, ip("fd00::1"));
        assert_eq!(empty, [cidr("fd00::1/128")]);
    }

    #[test]
    fn halves_of_the_address_space_are_not_mistaken_for_unspecified() {
        let allowed = allowed_ips(
            &[route("0.0.0.0/1"), route("128.0.0.0/1")],
            &[route("::/1"), route("8000::/1")],
        );
        assert!(allowed.skipped.is_empty());
        assert_eq!(
            allowed.networks,
            [
                cidr("0.0.0.0/1"),
                cidr("128.0.0.0/1"),
                cidr("::/1"),
                cidr("8000::/1")
            ]
        );
        let narrow = allowed_ips(
            &[route("0.1.2.0/24"), route("0.0.0.0/7")],
            &[route("::/64")],
        );
        assert_eq!(narrow.skipped.len(), 1);
        assert_eq!(narrow.networks, [cidr("0.0.0.0/7"), cidr("::/64")]);
    }

    #[test]
    fn unusable_gateways_are_not_routed() {
        let mut networks = Vec::new();
        ensure_reachable(&mut networks, ip("127.0.0.1"));
        ensure_reachable(&mut networks, ip("224.0.0.1"));
        assert!(networks.is_empty());
    }

    #[test]
    fn the_endpoint_host_route_is_removed_from_the_tunnel_networks() {
        let mut networks = vec![cidr("203.0.113.9/32"), cidr("10.0.0.0/8")];
        without_host(&mut networks, ip("203.0.113.9"));
        assert_eq!(networks, [cidr("10.0.0.0/8")]);
    }

    #[test]
    fn classifies_errors() {
        let exists = std::io::Error::other("The object already exists.");
        assert!(already_present(&exists));
        let no_v6 =
            std::io::Error::other("RTNETLINK answers: Address family not supported by protocol");
        assert!(ipv6_unavailable(&no_v6));
        assert!(ipv6_unavailable(&std::io::Error::other(
            "RTNETLINK answers: Operation not supported"
        )));
        assert!(!ipv6_unavailable(&std::io::Error::other("add failed")));
    }

    #[test]
    fn default_routes_become_halves() {
        let split = split_defaults(&[cidr("0.0.0.0/0"), cidr("10.0.0.0/8"), cidr("::/0")]);
        assert_eq!(
            split,
            [
                cidr("0.0.0.0/1"),
                cidr("128.0.0.0/1"),
                cidr("10.0.0.0/8"),
                cidr("::/1"),
                cidr("8000::/1"),
            ]
        );
        assert_eq!(
            split_defaults(&[cidr("0.0.0.0/1"), cidr("0.0.0.0/0")]),
            [cidr("0.0.0.0/1"), cidr("128.0.0.0/1")]
        );
    }

    #[test]
    fn bypass_only_when_the_endpoint_would_loop() {
        let endpoint = ip("203.0.113.9");
        assert!(needs_bypass(
            &split_defaults(&[cidr("0.0.0.0/0")]),
            endpoint
        ));
        assert!(!needs_bypass(
            &split_defaults(&[cidr("10.0.0.0/8")]),
            endpoint
        ));
        assert!(!needs_bypass(&split_defaults(&[cidr("::/0")]), endpoint));
        assert!(needs_bypass(&[cidr("203.0.0.0/8")], endpoint));
        assert!(needs_bypass(
            &split_defaults(&[cidr("::/0")]),
            ip("2001:db8::9")
        ));
    }

    #[test]
    fn entries_and_criticality() {
        let entries = tunnel_entries(&[cidr("10.0.0.0/8")], "utun4");
        assert_eq!(entries[0].via, Via::Interface("utun4".into()));
        let bypass = bypass_entry(ip("2001:db8::9"), Via::Interface("en0".into()));
        assert_eq!(bypass.network, cidr("2001:db8::9/128"));
        assert!(is_critical(cidr("128.0.0.0/1")));
        assert!(!is_critical(cidr("10.0.0.0/8")));
    }

    #[test]
    fn recognises_an_existing_route() {
        let err = std::io::Error::other("route: writing to routing socket: File exists");
        assert!(already_present(&err));
        assert!(!already_present(&std::io::Error::other("no such device")));
    }
}
