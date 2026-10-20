use std::io;
use std::net::IpAddr;

use wyvpn_core::wireguard::WireGuardConfig;

const MAX_ENTRIES: usize = 8;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunnelDns {
    pub servers: Vec<IpAddr>,
    pub search: Vec<String>,
}

impl TunnelDns {
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }
}

pub fn tunnel_dns(config: &WireGuardConfig) -> TunnelDns {
    let mut servers: Vec<IpAddr> = Vec::new();
    for ip in &config.dns_servers {
        let usable = !ip.is_unspecified() && !ip.is_multicast();
        if usable && !servers.contains(ip) && servers.len() < MAX_ENTRIES {
            servers.push(*ip);
        }
    }
    TunnelDns {
        servers,
        search: config.search_domains.clone(),
    }
}

pub trait DnsControl: Send {
    fn apply(&mut self, dev: &str, dns: &TunnelDns) -> io::Result<()>;
    fn restore(&mut self) -> io::Result<()>;
}

#[cfg(unix)]
pub use native::NativeDns;

#[cfg(unix)]
mod native {
    use std::io;
    use std::path::Path;

    use super::{DnsControl, MAX_ENTRIES, TunnelDns};
    use crate::dns::{Dns, DnsSettings, clean_name};

    pub struct NativeDns(Dns);

    impl NativeDns {
        pub fn new(data_dir: &Path) -> Self {
            Self(Dns::new(data_dir))
        }
    }

    pub fn settings_for(dns: &TunnelDns) -> DnsSettings {
        let mut search: Vec<String> = Vec::new();
        for name in dns.search.iter().filter_map(|name| clean_name(name)) {
            if search.len() < MAX_ENTRIES && !search.contains(&name) {
                search.push(name);
            }
        }
        DnsSettings {
            servers: dns.servers.clone(),
            domains: Vec::new(),
            search,
        }
    }

    impl DnsControl for NativeDns {
        fn apply(&mut self, dev: &str, dns: &TunnelDns) -> io::Result<()> {
            self.0.apply(dev, &settings_for(dns))
        }

        fn restore(&mut self) -> io::Result<()> {
            self.0.restore()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn search_domains_are_cleaned_and_capped() {
            let mut search: Vec<String> = ["Corp.Example.", "corp.example", "bad name", "-x.com"]
                .into_iter()
                .map(str::to_owned)
                .collect();
            search.extend((0..20).map(|i| format!("d{i}.example")));
            let settings = settings_for(&TunnelDns {
                servers: vec!["10.0.0.1".parse().unwrap()],
                search,
            });
            assert_eq!(settings.search[0], "corp.example");
            assert_eq!(settings.search.len(), MAX_ENTRIES);
            assert!(settings.domains.is_empty());
            assert!(!settings.search.iter().any(|n| n.contains(' ')));
        }
    }
}

#[cfg(any(windows, test))]
pub struct AdapterDns<E> {
    exec: E,
    programs: super::netops::Programs,
}

#[cfg(any(windows, test))]
impl<E: super::exec::Exec> AdapterDns<E> {
    pub fn new(exec: E, programs: super::netops::Programs) -> Self {
        Self { exec, programs }
    }
}

#[cfg(any(windows, test))]
impl<E: super::exec::Exec> DnsControl for AdapterDns<E> {
    fn apply(&mut self, dev: &str, dns: &TunnelDns) -> io::Result<()> {
        if !super::netops::valid_name(dev) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid interface name",
            ));
        }
        for command in super::netops::dns_commands(&self.programs, dev, &dns.servers) {
            let args: Vec<&str> = command.args.iter().map(String::as_str).collect();
            self.exec.run(&command.program, &args)?;
        }
        Ok(())
    }

    fn restore(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub mod fake {
    use std::io;
    use std::sync::{Arc, Mutex, PoisonError};

    use super::{DnsControl, TunnelDns};

    #[derive(Default)]
    pub struct Inner {
        pub log: Vec<String>,
        pub fail_apply: bool,
        pub fail_restore: bool,
    }

    #[derive(Clone, Default)]
    pub struct FakeDns(pub Arc<Mutex<Inner>>);

    impl FakeDns {
        pub fn log(&self) -> Vec<String> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .log
                .clone()
        }

        pub fn set(&self, f: impl FnOnce(&mut Inner)) {
            f(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner));
        }
    }

    impl DnsControl for FakeDns {
        fn apply(&mut self, dev: &str, dns: &TunnelDns) -> io::Result<()> {
            let mut inner = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            inner.log.push(format!("apply {dev} {:?}", dns.servers));
            if inner.fail_apply {
                return Err(io::Error::other("apply failed"));
            }
            Ok(())
        }

        fn restore(&mut self) -> io::Result<()> {
            let mut inner = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            inner.log.push("restore".to_owned());
            if inner.fail_restore {
                return Err(io::Error::other("restore failed"));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wireguard::exec::fake::FakeExec;
    use crate::wireguard::netops::Programs;

    fn config(servers: &[&str], search: &[&str]) -> WireGuardConfig {
        let mut config = crate::wireguard::testutil::config();
        config.dns_servers = servers.iter().map(|ip| ip.parse().unwrap()).collect();
        config.search_domains = search.iter().map(|d| (*d).to_owned()).collect();
        config
    }

    #[test]
    fn unusable_and_duplicate_servers_are_dropped() {
        let dns = tunnel_dns(&config(
            &["10.0.0.1", "0.0.0.0", "224.0.0.1", "10.0.0.1", "fd00::1"],
            &["corp.example"],
        ));
        assert_eq!(
            dns.servers,
            ["10.0.0.1", "fd00::1"].map(|ip| ip.parse::<IpAddr>().unwrap())
        );
        assert_eq!(dns.search, ["corp.example"]);
        assert!(!dns.is_empty());
    }

    #[test]
    fn no_servers_means_nothing_to_apply() {
        assert!(tunnel_dns(&config(&[], &["corp.example"])).is_empty());
        assert!(tunnel_dns(&config(&["0.0.0.0"], &[])).is_empty());
    }

    #[test]
    fn adapter_dns_runs_netsh_and_restores_nothing() {
        let exec = FakeExec::default();
        let programs = Programs {
            netsh: r"C:\Windows\System32\netsh.exe".into(),
            ..Programs::default()
        };
        let mut dns = AdapterDns::new(exec.clone(), programs);
        let settings = TunnelDns {
            servers: vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()],
            search: vec![],
        };
        dns.apply("WyVPN", &settings).unwrap();
        assert_eq!(exec.calls().len(), 2);
        assert!(exec.lines()[0].starts_with("netsh.exe interface ipv4 set dnsservers"));
        dns.restore().unwrap();
        assert_eq!(exec.calls().len(), 2);
        assert!(dns.apply("-bad", &settings).is_err());
    }
}
