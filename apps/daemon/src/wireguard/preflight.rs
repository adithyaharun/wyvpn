use std::io;
#[cfg(windows)]
use std::path::PathBuf;

use super::netops::{Platform, Programs, ToolError};

#[derive(Debug, thiserror::Error)]
pub enum Unavailable {
    #[error("WireGuard needs root privileges to create the tunnel interface; run wyvpnd as root")]
    NeedsRoot,
    #[error(
        "WireGuard needs root or CAP_NET_ADMIN to create the tunnel interface; run wyvpnd as root"
    )]
    NeedsNetAdmin,
    #[error(
        "the tun device /dev/net/tun is missing; load the tun kernel module with `modprobe tun`"
    )]
    NoTunDevice,
    #[error("cannot open /dev/net/tun: {0}")]
    TunDeviceUnusable(io::Error),
    #[error("a network tool is unusable: {0}")]
    Tool(#[from] ToolError),
    #[error("wintun.dll is missing at {path}; reinstall WyVPN")]
    WintunMissing { path: String },
    #[error("wintun.dll at {path} is not trusted ({reason}); reinstall WyVPN")]
    WintunUntrusted { path: String, reason: String },
}

pub trait Probe {
    fn is_root(&self) -> bool;
    fn has_net_admin(&self) -> bool;
    fn open_tun_node(&self) -> io::Result<()>;
    fn tools(&self, platform: Platform) -> Result<(), ToolError>;
    fn wintun(&self) -> Result<(), Unavailable>;
}

pub fn check(platform: Platform, probe: &impl Probe) -> Result<(), Unavailable> {
    match platform {
        Platform::Linux => {
            if !probe.is_root() && !probe.has_net_admin() {
                return Err(Unavailable::NeedsNetAdmin);
            }
            match probe.open_tun_node() {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    return Err(Unavailable::NoTunDevice);
                }
                Err(err) => return Err(Unavailable::TunDeviceUnusable(err)),
            }
            probe.tools(platform)?;
        }
        Platform::MacOs => {
            if !probe.is_root() {
                return Err(Unavailable::NeedsRoot);
            }
            probe.tools(platform)?;
        }
        Platform::Windows => probe.wintun()?,
    }
    Ok(())
}

pub fn cap_net_admin(status: &str) -> bool {
    const CAP_NET_ADMIN: u32 = 12;
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
        .is_some_and(|caps| caps & (1 << CAP_NET_ADMIN) != 0)
}

#[cfg(windows)]
fn wintun_path() -> anyhow::Result<PathBuf> {
    use anyhow::Context;

    let exe = std::env::current_exe().context("cannot locate the daemon executable")?;
    let dir = exe
        .parent()
        .context("the daemon executable has no directory")?;
    Ok(dir.join("wintun.dll"))
}

pub struct SystemProbe;

#[cfg(windows)]
pub fn verified_wintun() -> Result<PathBuf, Unavailable> {
    use crate::openvpn::binary::Check;

    let path = wintun_path().map_err(|err| Unavailable::WintunMissing {
        path: err.to_string(),
    })?;
    let shown = path.display().to_string();
    if !path.is_file() {
        return Err(Unavailable::WintunMissing { path: shown });
    }
    match crate::openvpn::signature::verify_wintun(&path) {
        Check::Pass | Check::Skip(_) => Ok(path),
        Check::Fail(reason) => Err(Unavailable::WintunUntrusted {
            path: shown,
            reason,
        }),
    }
}

impl Probe for SystemProbe {
    #[cfg(unix)]
    fn is_root(&self) -> bool {
        nix::unistd::geteuid().is_root()
    }

    #[cfg(not(unix))]
    fn is_root(&self) -> bool {
        false
    }

    fn has_net_admin(&self) -> bool {
        std::fs::read_to_string("/proc/self/status").is_ok_and(|status| cap_net_admin(&status))
    }

    fn open_tun_node(&self) -> io::Result<()> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map(drop)
    }

    fn tools(&self, platform: Platform) -> Result<(), ToolError> {
        Programs::locate(platform).map(drop)
    }

    #[cfg(windows)]
    fn wintun(&self) -> Result<(), Unavailable> {
        verified_wintun().map(drop)
    }

    #[cfg(not(windows))]
    fn wintun(&self) -> Result<(), Unavailable> {
        Ok(())
    }
}

pub fn check_system() -> Result<(), Unavailable> {
    check(Platform::current(), &SystemProbe)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        root: bool,
        net_admin: bool,
        tun: fn() -> io::Result<()>,
        tools: bool,
        wintun: Option<&'static str>,
    }

    impl Default for Fake {
        fn default() -> Self {
            Self {
                root: true,
                net_admin: false,
                tun: || Ok(()),
                tools: true,
                wintun: None,
            }
        }
    }

    impl Probe for Fake {
        fn is_root(&self) -> bool {
            self.root
        }

        fn has_net_admin(&self) -> bool {
            self.net_admin
        }

        fn open_tun_node(&self) -> io::Result<()> {
            (self.tun)()
        }

        fn tools(&self, _platform: Platform) -> Result<(), ToolError> {
            if self.tools {
                Ok(())
            } else {
                Err(ToolError::Missing {
                    tool: "ip",
                    searched: vec!["/usr/sbin/ip".into()],
                })
            }
        }

        fn wintun(&self) -> Result<(), Unavailable> {
            match self.wintun {
                None => Ok(()),
                Some("missing") => Err(Unavailable::WintunMissing {
                    path: r"C:\wyvpn\wintun.dll".into(),
                }),
                Some(reason) => Err(Unavailable::WintunUntrusted {
                    path: r"C:\wyvpn\wintun.dll".into(),
                    reason: reason.into(),
                }),
            }
        }
    }

    #[test]
    fn linux_ready_as_root_or_with_net_admin() {
        assert!(check(Platform::Linux, &Fake::default()).is_ok());
        let capable = Fake {
            root: false,
            net_admin: true,
            ..Fake::default()
        };
        assert!(check(Platform::Linux, &capable).is_ok());
    }

    #[test]
    fn linux_without_privilege_names_what_is_needed() {
        let fake = Fake {
            root: false,
            ..Fake::default()
        };
        let err = check(Platform::Linux, &fake).unwrap_err();
        assert!(matches!(err, Unavailable::NeedsNetAdmin));
        assert!(err.to_string().contains("CAP_NET_ADMIN"));
    }

    #[test]
    fn linux_missing_tun_device_suggests_modprobe() {
        let fake = Fake {
            tun: || Err(io::ErrorKind::NotFound.into()),
            ..Fake::default()
        };
        let err = check(Platform::Linux, &fake).unwrap_err();
        assert!(matches!(err, Unavailable::NoTunDevice));
        assert!(err.to_string().contains("modprobe tun"));
    }

    #[test]
    fn linux_unusable_tun_device_keeps_the_os_error() {
        let fake = Fake {
            tun: || Err(io::ErrorKind::PermissionDenied.into()),
            ..Fake::default()
        };
        let err = check(Platform::Linux, &fake).unwrap_err();
        assert!(matches!(err, Unavailable::TunDeviceUnusable(_)));
        assert!(err.to_string().contains("/dev/net/tun"));
    }

    #[test]
    fn missing_network_tool_is_reported() {
        let fake = Fake {
            tools: false,
            ..Fake::default()
        };
        let err = check(Platform::Linux, &fake).unwrap_err();
        assert!(err.to_string().contains("/usr/sbin/ip"));
        assert!(check(Platform::MacOs, &fake).is_err());
    }

    #[test]
    fn macos_needs_root() {
        let fake = Fake {
            root: false,
            net_admin: true,
            ..Fake::default()
        };
        let err = check(Platform::MacOs, &fake).unwrap_err();
        assert!(matches!(err, Unavailable::NeedsRoot));
        assert!(check(Platform::MacOs, &Fake::default()).is_ok());
    }

    #[test]
    fn windows_reports_missing_and_untrusted_wintun() {
        assert!(check(Platform::Windows, &Fake::default()).is_ok());
        let missing = Fake {
            wintun: Some("missing"),
            ..Fake::default()
        };
        let err = check(Platform::Windows, &missing).unwrap_err();
        assert!(err.to_string().contains("wintun.dll is missing"));
        let untrusted = Fake {
            wintun: Some("untrusted publisher"),
            ..Fake::default()
        };
        let err = check(Platform::Windows, &untrusted).unwrap_err();
        assert!(err.to_string().contains("untrusted publisher"));
    }

    #[test]
    fn parses_effective_capabilities() {
        let with = "Name:\twyvpnd\nCapEff:\t0000000000001000\n";
        let without = "Name:\twyvpnd\nCapEff:\t0000000000000000\n";
        assert!(cap_net_admin(with));
        assert!(!cap_net_admin(without));
        assert!(!cap_net_admin("nothing useful"));
    }
}
