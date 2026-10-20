use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use wyvpn_core::wireguard::{Host, Route, WireGuardConfig};

pub fn route(network: &str) -> Route {
    Route {
        network: network.parse().unwrap(),
        next_hop: None,
        metric: None,
        net_gateway: false,
    }
}

pub fn config() -> WireGuardConfig {
    WireGuardConfig {
        address: "10.200.0.5/24".parse().unwrap(),
        address6: None,
        hostname: Host::Ip("203.0.113.9".parse().unwrap()),
        hostname6: None,
        gateway: "10.200.0.1".parse().unwrap(),
        gateway6: None,
        port: 51820,
        mtu: Some(1420),
        ping_interval: 30,
        ping_timeout: 120,
        web_port: 443,
        web_no_ssl: false,
        public_key: STANDARD.encode([7u8; 32]).parse().unwrap(),
        routes: Vec::new(),
        routes6: Vec::new(),
        dns_servers: Vec::new(),
        search_domains: Vec::new(),
    }
}
