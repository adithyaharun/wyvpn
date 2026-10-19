use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use wyvpn_core::wireguard::Cidr;

use super::exec::Exec;
use crate::openvpn::binary::{BinaryError, Trust, resolve_trusted};

pub const LINUX_TUN_PREFIX: &str = "wyvpn";
pub const WINDOWS_ADAPTER_NAME: &str = "WyVPN";
const MAX_NAME_LEN: usize = 15;
const LINUX_IP: [&str; 4] = ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"];
const MACOS_IFCONFIG: [&str; 1] = ["/sbin/ifconfig"];
const MACOS_ROUTE: [&str; 1] = ["/sbin/route"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    Linux,
    Windows,
}

impl Platform {
    pub const fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(windows) {
            Self::Windows
        } else {
            Self::Linux
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Via {
    Interface(String),
    Gateway { gateway: IpAddr, dev: String },
}

impl Via {
    pub fn dev(&self) -> &str {
        match self {
            Self::Interface(dev) | Self::Gateway { dev, .. } => dev,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub network: Cidr,
    pub via: Via,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkConfig {
    pub address: Cidr,
    pub address6: Option<Cidr>,
    pub mtu: Option<u16>,
}

pub trait LinkOps: Send {
    fn configure_link(&mut self, dev: &str, link: &LinkConfig) -> io::Result<()>;
    fn remove_link(&mut self, dev: &str) -> io::Result<()>;
}

pub trait RouteOps: Send {
    fn route_to(&mut self, dest: IpAddr) -> io::Result<Via>;
    fn add_route(&mut self, route: &RouteEntry) -> io::Result<()>;
    fn delete_route(&mut self, route: &RouteEntry) -> io::Result<()>;
}

pub fn is_own_linux_interface(name: &str) -> bool {
    name.strip_prefix(LINUX_TUN_PREFIX)
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("{tool} was not found; searched {}", .searched.join(", "))]
    Missing {
        tool: &'static str,
        searched: Vec<String>,
    },
    #[error("{tool} cannot be trusted: {reason}")]
    Untrusted { tool: &'static str, reason: String },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Programs {
    pub ip: String,
    pub ifconfig: String,
    pub route: String,
    pub netsh: String,
}

fn locate_tool(tool: &'static str, candidates: &[&str]) -> Result<String, ToolError> {
    for candidate in candidates {
        match resolve_trusted(Path::new(candidate), &Trust::root()) {
            Ok(path) => return Ok(path.display().to_string()),
            Err(BinaryError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {}
            Err(other) => {
                return Err(ToolError::Untrusted {
                    tool,
                    reason: other.to_string(),
                });
            }
        }
    }
    Err(ToolError::Missing {
        tool,
        searched: candidates.iter().map(|path| (*path).to_owned()).collect(),
    })
}

fn netsh_path() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    format!(r"{root}\System32\netsh.exe")
}

impl Programs {
    pub fn locate(platform: Platform) -> Result<Self, ToolError> {
        let mut programs = Self::default();
        match platform {
            Platform::Linux => programs.ip = locate_tool("ip", &LINUX_IP)?,
            Platform::MacOs => {
                programs.ifconfig = locate_tool("ifconfig", &MACOS_IFCONFIG)?;
                programs.route = locate_tool("route", &MACOS_ROUTE)?;
            }
            Platform::Windows => programs.netsh = netsh_path(),
        }
        Ok(programs)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    pub program: String,
    pub args: Vec<String>,
}

fn cmd<const N: usize>(program: &str, args: [String; N]) -> Cmd {
    Cmd {
        program: program.to_owned(),
        args: args.into(),
    }
}

fn s(text: &str) -> String {
    text.to_owned()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteOp {
    Add,
    Delete,
}

fn is_v6(ip: IpAddr) -> bool {
    ip.is_ipv6()
}

fn ipv4_mask(prefix: u8) -> Ipv4Addr {
    Ipv4Addr::from(
        u32::MAX
            .checked_shl(32 - u32::from(prefix.min(32)))
            .unwrap_or(0),
    )
}

fn scoped_gateway(gateway: IpAddr, dev: &str) -> String {
    match gateway {
        IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80 => format!("{v6}%{dev}"),
        other => other.to_string(),
    }
}

pub fn link_commands(
    platform: Platform,
    programs: &Programs,
    dev: &str,
    link: &LinkConfig,
) -> Vec<Cmd> {
    let mut commands = Vec::new();
    match platform {
        Platform::MacOs => {
            let tool = &programs.ifconfig;
            commands.push(cmd(
                tool,
                [
                    s(dev),
                    s("inet"),
                    link.address.to_string(),
                    link.address.addr.to_string(),
                    s("alias"),
                ],
            ));
            if let Some(v6) = link.address6 {
                commands.push(cmd(
                    tool,
                    [
                        s(dev),
                        s("inet6"),
                        v6.addr.to_string(),
                        s("prefixlen"),
                        v6.prefix.to_string(),
                        s("alias"),
                    ],
                ));
            }
            if let Some(mtu) = link.mtu {
                commands.push(cmd(tool, [s(dev), s("mtu"), mtu.to_string()]));
            }
            commands.push(cmd(tool, [s(dev), s("up")]));
        }
        Platform::Linux => {
            let tool = &programs.ip;
            if let Some(mtu) = link.mtu {
                commands.push(cmd(
                    tool,
                    [
                        s("link"),
                        s("set"),
                        s("dev"),
                        s(dev),
                        s("mtu"),
                        mtu.to_string(),
                    ],
                ));
            }
            commands.push(cmd(
                tool,
                [
                    s("-4"),
                    s("address"),
                    s("add"),
                    link.address.to_string(),
                    s("dev"),
                    s(dev),
                ],
            ));
            if let Some(v6) = link.address6 {
                commands.push(cmd(
                    tool,
                    [
                        s("-6"),
                        s("address"),
                        s("add"),
                        v6.to_string(),
                        s("dev"),
                        s(dev),
                    ],
                ));
            }
            commands.push(cmd(tool, [s("link"), s("set"), s("up"), s("dev"), s(dev)]));
        }
        Platform::Windows => {
            let tool = &programs.netsh;
            commands.push(cmd(
                tool,
                [
                    s("interface"),
                    s("ipv4"),
                    s("set"),
                    s("address"),
                    format!("name={dev}"),
                    s("source=static"),
                    format!("address={}", link.address.addr),
                    format!("mask={}", ipv4_mask(link.address.prefix)),
                ],
            ));
            if let Some(v6) = link.address6 {
                commands.push(cmd(
                    tool,
                    [
                        s("interface"),
                        s("ipv6"),
                        s("add"),
                        s("address"),
                        format!("interface={dev}"),
                        format!("address={v6}"),
                        s("store=active"),
                    ],
                ));
            }
            if let Some(mtu) = link.mtu {
                for family in ["ipv4", "ipv6"] {
                    if family == "ipv6" && link.address6.is_none() {
                        continue;
                    }
                    commands.push(cmd(
                        tool,
                        [
                            s("interface"),
                            s(family),
                            s("set"),
                            s("subinterface"),
                            format!("interface={dev}"),
                            format!("mtu={mtu}"),
                            s("store=active"),
                        ],
                    ));
                }
            }
        }
    }
    commands
}

pub fn route_command(
    platform: Platform,
    programs: &Programs,
    op: RouteOp,
    entry: &RouteEntry,
) -> Cmd {
    let network = entry.network;
    let v6 = is_v6(network.addr);
    match platform {
        Platform::MacOs => {
            let verb = match op {
                RouteOp::Add => "add",
                RouteOp::Delete => "delete",
            };
            let family = if v6 { "-inet6" } else { "-inet" };
            let mut args = vec![s("-q"), s("-n"), s(verb), s(family), network.to_string()];
            match &entry.via {
                Via::Interface(dev) => {
                    args.push(s("-interface"));
                    args.push(dev.clone());
                }
                Via::Gateway { gateway, dev } => args.push(scoped_gateway(*gateway, dev)),
            }
            Cmd {
                program: programs.route.clone(),
                args,
            }
        }
        Platform::Linux => {
            let verb = match op {
                RouteOp::Add => "add",
                RouteOp::Delete => "del",
            };
            let mut args = vec![
                s(if v6 { "-6" } else { "-4" }),
                s("route"),
                s(verb),
                network.to_string(),
            ];
            if let Via::Gateway { gateway, .. } = &entry.via {
                args.push(s("via"));
                args.push(gateway.to_string());
            }
            args.push(s("dev"));
            args.push(entry.via.dev().to_owned());
            Cmd {
                program: programs.ip.clone(),
                args,
            }
        }
        Platform::Windows => {
            let verb = match op {
                RouteOp::Add => "add",
                RouteOp::Delete => "delete",
            };
            let next_hop = match &entry.via {
                Via::Interface(_) if v6 => "::".to_owned(),
                Via::Interface(_) => "0.0.0.0".to_owned(),
                Via::Gateway { gateway, .. } => gateway.to_string(),
            };
            cmd(
                &programs.netsh,
                [
                    s("interface"),
                    s(if v6 { "ipv6" } else { "ipv4" }),
                    s(verb),
                    s("route"),
                    format!("prefix={network}"),
                    format!("interface={}", entry.via.dev()),
                    format!("nexthop={next_hop}"),
                    s("store=active"),
                ],
            )
        }
    }
}

pub fn route_to_command(platform: Platform, programs: &Programs, dest: IpAddr) -> Option<Cmd> {
    let v6 = is_v6(dest);
    match platform {
        Platform::MacOs => Some(cmd(
            &programs.route,
            [
                s("-n"),
                s("get"),
                s(if v6 { "-inet6" } else { "-inet" }),
                dest.to_string(),
            ],
        )),
        Platform::Linux => Some(cmd(
            &programs.ip,
            [
                s(if v6 { "-6" } else { "-4" }),
                s("route"),
                s("get"),
                dest.to_string(),
            ],
        )),
        Platform::Windows => None,
    }
}

pub fn remove_link_command(platform: Platform, programs: &Programs, dev: &str) -> Option<Cmd> {
    match platform {
        Platform::Linux => Some(cmd(
            &programs.ip,
            [s("link"), s("delete"), s("dev"), s(dev)],
        )),
        Platform::MacOs | Platform::Windows => None,
    }
}

pub fn dns_commands(programs: &Programs, dev: &str, servers: &[IpAddr]) -> Vec<Cmd> {
    let mut commands = Vec::new();
    for family in ["ipv4", "ipv6"] {
        let wanted = |ip: &&IpAddr| is_v6(**ip) == (family == "ipv6");
        for (index, ip) in servers.iter().filter(wanted).enumerate() {
            let verb = if index == 0 { "set" } else { "add" };
            let mut args = vec![
                s("interface"),
                s(family),
                s(verb),
                s("dnsservers"),
                format!("name={dev}"),
                format!("address={ip}"),
                s("validate=no"),
            ];
            if index == 0 {
                args.push(s("source=static"));
            } else {
                args.push(format!("index={}", index + 1));
            }
            commands.push(Cmd {
                program: programs.netsh.clone(),
                args,
            });
        }
    }
    commands
}

fn clean_gateway(text: &str) -> Option<IpAddr> {
    text.split('%').next()?.trim().parse().ok()
}

fn parse_macos(output: &str) -> Option<Via> {
    let mut gateway = None;
    let mut dev = None;
    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "gateway" => gateway = clean_gateway(value),
            "interface" => dev = Some(value.trim().to_owned()),
            _ => {}
        }
    }
    let dev = dev.filter(|dev| valid_name(dev))?;
    Some(match gateway {
        Some(gateway) => Via::Gateway { gateway, dev },
        None => Via::Interface(dev),
    })
}

fn parse_linux(output: &str) -> Option<Via> {
    let mut tokens = output.split_whitespace();
    let mut gateway = None;
    let mut dev = None;
    while let Some(token) = tokens.next() {
        match token {
            "via" => gateway = tokens.next().and_then(clean_gateway),
            "dev" => dev = tokens.next().map(str::to_owned),
            _ => {}
        }
        if gateway.is_some() && dev.is_some() {
            break;
        }
    }
    let dev = dev.filter(|dev| valid_name(dev))?;
    Some(match gateway {
        Some(gateway) => Via::Gateway { gateway, dev },
        None => Via::Interface(dev),
    })
}

pub fn parse_route_to(platform: Platform, output: &str) -> Option<Via> {
    match platform {
        Platform::MacOs => parse_macos(output),
        Platform::Linux => parse_linux(output),
        Platform::Windows => None,
    }
}

pub struct SystemNet<E> {
    exec: E,
    platform: Platform,
    programs: Programs,
}

impl<E: Exec> SystemNet<E> {
    pub fn new(exec: E, platform: Platform, programs: Programs) -> Self {
        Self {
            exec,
            platform,
            programs,
        }
    }

    fn run(&self, command: &Cmd) -> io::Result<String> {
        let args: Vec<&str> = command.args.iter().map(String::as_str).collect();
        self.exec.run(&command.program, &args)
    }
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("invalid {what}"))
}

impl<E: Exec> LinkOps for SystemNet<E> {
    fn configure_link(&mut self, dev: &str, link: &LinkConfig) -> io::Result<()> {
        if !valid_name(dev) {
            return Err(invalid("interface name"));
        }
        for command in link_commands(self.platform, &self.programs, dev, link) {
            self.run(&command)?;
        }
        Ok(())
    }

    fn remove_link(&mut self, dev: &str) -> io::Result<()> {
        if !valid_name(dev) {
            return Err(invalid("interface name"));
        }
        match remove_link_command(self.platform, &self.programs, dev) {
            Some(command) => self.run(&command).map(drop),
            None => Ok(()),
        }
    }
}

impl<E: Exec> RouteOps for SystemNet<E> {
    fn route_to(&mut self, dest: IpAddr) -> io::Result<Via> {
        let Some(command) = route_to_command(self.platform, &self.programs, dest) else {
            return best_route(dest);
        };
        let output = self.run(&command)?;
        parse_route_to(self.platform, &output)
            .ok_or_else(|| io::Error::other("cannot read the current route to the endpoint"))
    }

    fn add_route(&mut self, route: &RouteEntry) -> io::Result<()> {
        check_route(route)?;
        let command = route_command(self.platform, &self.programs, RouteOp::Add, route);
        self.run(&command).map(drop)
    }

    fn delete_route(&mut self, route: &RouteEntry) -> io::Result<()> {
        check_route(route)?;
        let command = route_command(self.platform, &self.programs, RouteOp::Delete, route);
        self.run(&command).map(drop)
    }
}

fn check_route(route: &RouteEntry) -> io::Result<()> {
    if valid_name(route.via.dev()) {
        Ok(())
    } else {
        Err(invalid("interface name"))
    }
}

#[cfg(windows)]
fn best_route(dest: IpAddr) -> io::Result<Via> {
    windows_best_route::lookup(dest)
}

#[cfg(not(windows))]
fn best_route(_dest: IpAddr) -> io::Result<Via> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "route lookup needs the Windows IP helper",
    ))
}

#[cfg(windows)]
mod windows_best_route {
    use std::io;
    use std::mem::zeroed;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::ptr::null;

    use windows_sys::Win32::NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2};
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_INET};

    use super::Via;

    pub fn lookup(dest: IpAddr) -> io::Result<Via> {
        // SAFETY: zeroed plain-data structs, and every pointer outlives the call
        unsafe {
            let mut destination: SOCKADDR_INET = zeroed();
            match dest {
                IpAddr::V4(ip) => {
                    destination.Ipv4.sin_family = AF_INET;
                    destination.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
                }
                IpAddr::V6(ip) => {
                    destination.Ipv6.sin6_family = AF_INET6;
                    destination.Ipv6.sin6_addr.u.Byte = ip.octets();
                }
            }
            let mut row: MIB_IPFORWARD_ROW2 = zeroed();
            let mut source: SOCKADDR_INET = zeroed();
            let status = GetBestRoute2(null(), 0, null(), &destination, 0, &mut row, &mut source);
            if status != 0 {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            let dev = row.InterfaceIndex.to_string();
            let next_hop = row.NextHop;
            let gateway = match next_hop.si_family {
                AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
                    next_hop.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
                ))),
                AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(next_hop.Ipv6.sin6_addr.u.Byte))),
                _ => None,
            };
            Ok(match gateway.filter(|ip| !ip.is_unspecified()) {
                Some(gateway) => Via::Gateway { gateway, dev },
                None => Via::Interface(dev),
            })
        }
    }
}

#[cfg(test)]
pub mod fake {
    use std::io;
    use std::net::IpAddr;
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

    use super::{LinkConfig, LinkOps, RouteEntry, RouteOps, Via};

    #[derive(Default)]
    pub struct Inner {
        pub log: Vec<String>,
        pub via: Option<Via>,
        pub fail_add: Vec<String>,
        pub fail_delete: bool,
        pub fail_link: bool,
        pub exists_on_add: Vec<String>,
    }

    #[derive(Clone, Default)]
    pub struct FakeNet(Arc<Mutex<Inner>>);

    pub fn describe(route: &RouteEntry) -> String {
        match &route.via {
            Via::Interface(dev) => format!("{} dev {dev}", route.network),
            Via::Gateway { gateway, dev } => format!("{} via {gateway} dev {dev}", route.network),
        }
    }

    impl FakeNet {
        pub fn with_gateway(gateway: &str, dev: &str) -> Self {
            let net = Self::default();
            net.lock().via = Some(Via::Gateway {
                gateway: gateway.parse().unwrap(),
                dev: dev.to_owned(),
            });
            net
        }

        pub fn lock(&self) -> MutexGuard<'_, Inner> {
            self.0.lock().unwrap_or_else(PoisonError::into_inner)
        }

        pub fn log(&self) -> Vec<String> {
            self.lock().log.clone()
        }
    }

    impl LinkOps for FakeNet {
        fn configure_link(&mut self, dev: &str, link: &LinkConfig) -> io::Result<()> {
            let mut inner = self.lock();
            inner.log.push(format!("link {dev} {}", link.address));
            if inner.fail_link {
                return Err(io::Error::other("link failed"));
            }
            Ok(())
        }

        fn remove_link(&mut self, dev: &str) -> io::Result<()> {
            self.lock().log.push(format!("remove_link {dev}"));
            Ok(())
        }
    }

    impl RouteOps for FakeNet {
        fn route_to(&mut self, dest: IpAddr) -> io::Result<Via> {
            let mut inner = self.lock();
            inner.log.push(format!("route_to {dest}"));
            inner
                .via
                .clone()
                .ok_or_else(|| io::Error::other("no route"))
        }

        fn add_route(&mut self, route: &RouteEntry) -> io::Result<()> {
            let mut inner = self.lock();
            inner.log.push(format!("add {}", describe(route)));
            let network = route.network.to_string();
            if inner.exists_on_add.contains(&network) {
                return Err(io::Error::other(
                    "route: writing to routing socket: File exists",
                ));
            }
            if inner.fail_add.contains(&network) {
                return Err(io::Error::other("add failed"));
            }
            Ok(())
        }

        fn delete_route(&mut self, route: &RouteEntry) -> io::Result<()> {
            let mut inner = self.lock();
            inner.log.push(format!("del {}", describe(route)));
            if inner.fail_delete {
                return Err(io::Error::other("delete failed"));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wireguard::exec::fake::FakeExec;

    fn cidr(text: &str) -> Cidr {
        text.parse().unwrap()
    }

    fn programs() -> Programs {
        Programs {
            ip: "/usr/sbin/ip".into(),
            ifconfig: "/sbin/ifconfig".into(),
            route: "/sbin/route".into(),
            netsh: r"C:\Windows\System32\netsh.exe".into(),
        }
    }

    fn link() -> LinkConfig {
        LinkConfig {
            address: cidr("10.200.0.5/24"),
            address6: Some(cidr("fd00::5/64")),
            mtu: Some(1420),
        }
    }

    fn lines(commands: Vec<Cmd>) -> Vec<String> {
        commands
            .into_iter()
            .map(|c| format!("{} {}", c.program, c.args.join(" ")))
            .collect()
    }

    #[test]
    fn macos_link_commands() {
        assert_eq!(
            lines(link_commands(
                Platform::MacOs,
                &programs(),
                "utun4",
                &link()
            )),
            [
                "/sbin/ifconfig utun4 inet 10.200.0.5/24 10.200.0.5 alias",
                "/sbin/ifconfig utun4 inet6 fd00::5 prefixlen 64 alias",
                "/sbin/ifconfig utun4 mtu 1420",
                "/sbin/ifconfig utun4 up",
            ]
        );
    }

    #[test]
    fn linux_link_commands_skip_unset_options() {
        let bare = LinkConfig {
            address: cidr("10.200.0.5/24"),
            address6: None,
            mtu: None,
        };
        assert_eq!(
            lines(link_commands(Platform::Linux, &programs(), "wyvpn0", &bare)),
            [
                "/usr/sbin/ip -4 address add 10.200.0.5/24 dev wyvpn0",
                "/usr/sbin/ip link set up dev wyvpn0",
            ]
        );
        assert_eq!(
            lines(link_commands(
                Platform::Linux,
                &programs(),
                "wyvpn0",
                &link()
            )),
            [
                "/usr/sbin/ip link set dev wyvpn0 mtu 1420",
                "/usr/sbin/ip -4 address add 10.200.0.5/24 dev wyvpn0",
                "/usr/sbin/ip -6 address add fd00::5/64 dev wyvpn0",
                "/usr/sbin/ip link set up dev wyvpn0",
            ]
        );
    }

    #[test]
    fn windows_link_commands_use_a_mask() {
        let lines = lines(link_commands(
            Platform::Windows,
            &programs(),
            "WyVPN",
            &link(),
        ));
        assert!(lines[0].ends_with(
            "interface ipv4 set address name=WyVPN source=static address=10.200.0.5 mask=255.255.255.0"
        ));
        assert!(lines[1].ends_with(
            "interface ipv6 add address interface=WyVPN address=fd00::5/64 store=active"
        ));
        assert!(
            lines[2]
                .ends_with("interface ipv4 set subinterface interface=WyVPN mtu=1420 store=active")
        );
        assert!(
            lines[3]
                .ends_with("interface ipv6 set subinterface interface=WyVPN mtu=1420 store=active")
        );
    }

    #[test]
    fn route_commands_per_platform() {
        let device = RouteEntry {
            network: cidr("0.0.0.0/1"),
            via: Via::Interface("utun4".into()),
        };
        let bypass = RouteEntry {
            network: cidr("203.0.113.9/32"),
            via: Via::Gateway {
                gateway: "192.168.1.1".parse().unwrap(),
                dev: "en0".into(),
            },
        };
        let v6 = RouteEntry {
            network: cidr("8000::/1"),
            via: Via::Interface("utun4".into()),
        };
        let line = |platform, op, entry: &RouteEntry| {
            lines(vec![route_command(platform, &programs(), op, entry)])
                .pop()
                .unwrap()
        };
        assert_eq!(
            line(Platform::MacOs, RouteOp::Add, &device),
            "/sbin/route -q -n add -inet 0.0.0.0/1 -interface utun4"
        );
        assert_eq!(
            line(Platform::MacOs, RouteOp::Delete, &bypass),
            "/sbin/route -q -n delete -inet 203.0.113.9/32 192.168.1.1"
        );
        assert_eq!(
            line(Platform::MacOs, RouteOp::Add, &v6),
            "/sbin/route -q -n add -inet6 8000::/1 -interface utun4"
        );
        assert_eq!(
            line(Platform::Linux, RouteOp::Add, &device),
            "/usr/sbin/ip -4 route add 0.0.0.0/1 dev utun4"
        );
        assert_eq!(
            line(Platform::Linux, RouteOp::Add, &bypass),
            "/usr/sbin/ip -4 route add 203.0.113.9/32 via 192.168.1.1 dev en0"
        );
        assert_eq!(
            line(Platform::Linux, RouteOp::Delete, &v6),
            "/usr/sbin/ip -6 route del 8000::/1 dev utun4"
        );
        assert!(line(Platform::Windows, RouteOp::Add, &device).ends_with(
            "interface ipv4 add route prefix=0.0.0.0/1 interface=utun4 nexthop=0.0.0.0 store=active"
        ));
        assert!(line(Platform::Windows, RouteOp::Delete, &v6).ends_with(
            "interface ipv6 delete route prefix=8000::/1 interface=utun4 nexthop=:: store=active"
        ));
    }

    #[test]
    fn link_local_gateways_carry_their_scope_on_macos() {
        let entry = RouteEntry {
            network: cidr("2001:db8::9/128"),
            via: Via::Gateway {
                gateway: "fe80::1".parse().unwrap(),
                dev: "en0".into(),
            },
        };
        let command = route_command(Platform::MacOs, &programs(), RouteOp::Add, &entry);
        assert_eq!(command.args.last().unwrap(), "fe80::1%en0");
    }

    #[test]
    fn parses_the_current_route() {
        let macos = "   route to: 203.0.113.9\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY>\n";
        assert_eq!(
            parse_route_to(Platform::MacOs, macos),
            Some(Via::Gateway {
                gateway: "192.168.1.1".parse().unwrap(),
                dev: "en0".into()
            })
        );
        let on_link = "    gateway: link#14\n  interface: en0\n";
        assert_eq!(
            parse_route_to(Platform::MacOs, on_link),
            Some(Via::Interface("en0".into()))
        );
        let scoped = "    gateway: fe80::1%en0\n  interface: en0\n";
        assert_eq!(
            parse_route_to(Platform::MacOs, scoped),
            Some(Via::Gateway {
                gateway: "fe80::1".parse().unwrap(),
                dev: "en0".into()
            })
        );
        let linux = "203.0.113.9 via 192.168.1.1 dev eth0 src 192.168.1.50 uid 0 \n    cache \n";
        assert_eq!(
            parse_route_to(Platform::Linux, linux),
            Some(Via::Gateway {
                gateway: "192.168.1.1".parse().unwrap(),
                dev: "eth0".into()
            })
        );
        assert_eq!(
            parse_route_to(Platform::Linux, "192.168.1.7 dev eth0 src 192.168.1.50\n"),
            Some(Via::Interface("eth0".into()))
        );
        assert_eq!(parse_route_to(Platform::Linux, "RTNETLINK answers\n"), None);
        assert_eq!(
            parse_route_to(Platform::Linux, "1.2.3.4 dev -evil src 1.1.1.1\n"),
            None
        );
    }

    #[test]
    fn windows_dns_sets_then_adds_per_family() {
        let servers: Vec<IpAddr> = ["10.0.0.1", "fd00::1", "10.0.0.2"]
            .iter()
            .map(|ip| ip.parse().unwrap())
            .collect();
        let lines = lines(dns_commands(&programs(), "WyVPN", &servers));
        assert_eq!(lines.len(), 3);
        assert!(lines[0].ends_with(
            "interface ipv4 set dnsservers name=WyVPN address=10.0.0.1 validate=no source=static"
        ));
        assert!(lines[1].ends_with(
            "interface ipv4 add dnsservers name=WyVPN address=10.0.0.2 validate=no index=2"
        ));
        assert!(lines[2].ends_with(
            "interface ipv6 set dnsservers name=WyVPN address=fd00::1 validate=no source=static"
        ));
    }

    #[test]
    fn masks_cover_the_range() {
        assert_eq!(ipv4_mask(0), Ipv4Addr::UNSPECIFIED);
        assert_eq!(ipv4_mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(ipv4_mask(32), Ipv4Addr::BROADCAST);
    }

    #[test]
    fn names_are_checked_before_any_command_runs() {
        let exec = FakeExec::default();
        let mut net = SystemNet::new(exec.clone(), Platform::Linux, programs());
        assert!(net.configure_link("-bad", &link()).is_err());
        assert!(net.remove_link("a b").is_err());
        let entry = RouteEntry {
            network: cidr("10.0.0.0/8"),
            via: Via::Interface("x y".into()),
        };
        assert!(net.add_route(&entry).is_err());
        assert!(exec.calls().is_empty());
    }

    #[test]
    fn system_net_runs_the_built_commands() {
        let exec = FakeExec::default();
        exec.respond(
            "route get",
            "203.0.113.9 via 192.168.1.1 dev eth0 src 192.168.1.50\n",
        );
        let mut net = SystemNet::new(exec.clone(), Platform::Linux, programs());
        net.configure_link("wyvpn0", &link()).unwrap();
        assert_eq!(
            net.route_to("203.0.113.9".parse().unwrap()).unwrap(),
            Via::Gateway {
                gateway: "192.168.1.1".parse().unwrap(),
                dev: "eth0".into()
            }
        );
        net.remove_link("wyvpn0").unwrap();
        let lines = exec.lines();
        assert_eq!(lines.first().unwrap(), "ip link set dev wyvpn0 mtu 1420");
        assert!(lines.contains(&"ip -4 route get 203.0.113.9".to_owned()));
        assert_eq!(lines.last().unwrap(), "ip link delete dev wyvpn0");
    }

    #[test]
    fn route_lookup_failure_is_reported() {
        let exec = FakeExec::default();
        exec.respond("route get", "garbage");
        let mut net = SystemNet::new(exec, Platform::Linux, programs());
        assert!(net.route_to("203.0.113.9".parse().unwrap()).is_err());
    }
}

#[cfg(test)]
mod own_tests {
    use super::*;

    #[test]
    fn recognises_only_our_linux_names() {
        assert!(is_own_linux_interface("wyvpn0"));
        assert!(is_own_linux_interface("wyvpn123"));
        assert!(!is_own_linux_interface("wyvpn"));
        assert!(!is_own_linux_interface("wyvpnx"));
        assert!(!is_own_linux_interface("wg0"));
        assert!(!is_own_linux_interface("utun4"));
    }
}
