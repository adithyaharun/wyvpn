#[cfg(unix)]
mod report;
#[cfg(unix)]
pub use report::{DnsSettings, HookPhase, clean_name, parse_foreign_options, phase_of};

#[cfg(unix)]
mod linux;
#[cfg(unix)]
mod listener;
#[cfg(unix)]
mod macos;
#[cfg(unix)]
pub use listener::{HookListener, SOCKET_NAME};
#[cfg(unix)]
pub use unix::{Dns, Runner, recover};

#[cfg(all(test, unix))]
mod testutil;

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::io::{self, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use serde::{Deserialize, Serialize};

    use super::report::{DnsSettings, valid_dev};
    use super::{linux, macos};
    use crate::storage::{prepare_dir, remove_if_present, write_atomic};

    const STATE_DIR: &str = "state";
    const RECORD_NAME: &str = "dns.json";
    const LEGACY_RECORD_NAME: &str = "dns-state.json";

    pub trait Runner {
        fn run(&self, program: &str, args: &[&str], stdin: Option<&str>) -> io::Result<String>;
    }

    pub struct SystemRunner;

    impl Runner for SystemRunner {
        fn run(&self, program: &str, args: &[&str], stdin: Option<&str>) -> io::Result<String> {
            let mut child = Command::new(program)
                .args(args)
                .env_clear()
                .stdin(if stdin.is_some() {
                    Stdio::piped()
                } else {
                    Stdio::null()
                })
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()?;
            if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
                pipe.write_all(input.as_bytes())?;
            }
            let output = child.wait_with_output()?;
            if !output.status.success() {
                return Err(io::Error::other(format!(
                    "{program} exited with {}",
                    output.status
                )));
            }
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Platform {
        MacOs,
        Linux,
    }

    impl Platform {
        pub const fn current() -> Self {
            if cfg!(target_os = "macos") {
                Self::MacOs
            } else {
                Self::Linux
            }
        }
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum Record {
        Scutil { saved: macos::Saved },
        Resolved { dev: String },
        ResolvConf { original: linux::Original },
    }

    pub struct Dns<R = SystemRunner> {
        runner: R,
        root: PathBuf,
        data_dir: PathBuf,
        platform: Platform,
    }

    impl Dns {
        pub fn new(data_dir: &Path) -> Self {
            Self::with_parts(SystemRunner, "/".into(), data_dir, Platform::current())
        }
    }

    impl<R: Runner> Dns<R> {
        pub fn with_parts(runner: R, root: PathBuf, data_dir: &Path, platform: Platform) -> Self {
            Self {
                runner,
                root,
                data_dir: data_dir.to_owned(),
                platform,
            }
        }

        fn record_path(&self) -> PathBuf {
            self.state_dir().join(RECORD_NAME)
        }

        fn state_dir(&self) -> PathBuf {
            self.data_dir.join(STATE_DIR)
        }

        fn save(&self, record: &Record) -> io::Result<()> {
            let bytes = serde_json::to_vec(record).map_err(io::Error::other)?;
            let dir = self.state_dir();
            prepare_dir(&dir)?;
            write_atomic(&dir, RECORD_NAME, &bytes)
        }

        fn load(&self) -> io::Result<Option<Record>> {
            match fs::read(self.record_path()) {
                Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "corrupt dns state record")
                }),
                Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(err) => Err(err),
            }
        }

        pub fn apply(&self, dev: &str, settings: &DnsSettings) -> io::Result<()> {
            if settings.servers.is_empty() {
                return Ok(());
            }
            if !valid_dev(dev) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid device",
                ));
            }
            if self.record_path().exists() {
                let _ = self.restore();
            }
            let result = self.apply_inner(dev, settings);
            if result.is_err() {
                let _ = self.restore();
            }
            result
        }

        fn apply_inner(&self, dev: &str, settings: &DnsSettings) -> io::Result<()> {
            match self.platform {
                Platform::MacOs => {
                    let saved = macos::prepare(&self.runner, dev)?;
                    self.save(&Record::Scutil {
                        saved: saved.clone(),
                    })?;
                    macos::activate(&self.runner, &saved, settings)
                }
                Platform::Linux if linux::resolved_active(&self.root) => {
                    self.save(&Record::Resolved {
                        dev: dev.to_owned(),
                    })?;
                    linux::resolved_apply(&self.runner, dev, settings)
                }
                Platform::Linux => {
                    let original = linux::resolv_conf_backup(&self.root)?;
                    self.save(&Record::ResolvConf { original })?;
                    linux::resolv_conf_write(&self.root, settings)
                }
            }
        }

        pub fn restore(&self) -> io::Result<()> {
            let record = match self.load() {
                Ok(Some(record)) => record,
                Ok(None) => return Ok(()),
                Err(err) => {
                    remove_if_present(&self.record_path())?;
                    return Err(err);
                }
            };
            let result = match &record {
                Record::Scutil { saved } => macos::restore(&self.runner, saved),
                Record::Resolved { dev } => linux::resolved_revert(&self.runner, dev),
                Record::ResolvConf { original } => linux::resolv_conf_restore(&self.root, original),
            };
            remove_if_present(&self.record_path())?;
            result
        }
    }

    fn adopt_legacy_record(data_dir: &Path) -> io::Result<()> {
        let legacy = data_dir.join(LEGACY_RECORD_NAME);
        if !legacy.exists() {
            return Ok(());
        }
        let dns = Dns::new(data_dir);
        if dns.record_path().exists() {
            remove_if_present(&legacy)?;
            return Ok(());
        }
        prepare_dir(&dns.state_dir())?;
        fs::rename(&legacy, dns.record_path())
    }

    pub fn recover(data_dir: &Path) {
        if let Err(err) = adopt_legacy_record(data_dir) {
            tracing::warn!(%err, "cannot migrate the dns state record");
        }
        if let Err(err) = Dns::new(data_dir).restore() {
            tracing::warn!(%err, "cannot restore dns left by a previous run");
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::dns::testutil::{FakeRunner, mkdirs};

        fn record(data: &Path) -> PathBuf {
            data.join(STATE_DIR).join(RECORD_NAME)
        }

        fn settings() -> DnsSettings {
            DnsSettings {
                servers: vec!["10.0.0.1".parse().unwrap()],
                domains: vec!["corp.example".into()],
                search: vec![],
            }
        }

        fn resolv_root(stub: bool) -> tempfile::TempDir {
            let root = tempfile::tempdir().unwrap();
            mkdirs(root.path(), "etc");
            fs::write(
                root.path().join("etc/resolv.conf"),
                if stub {
                    "nameserver 127.0.0.53\n"
                } else {
                    "nameserver 192.168.1.1\n"
                },
            )
            .unwrap();
            if stub {
                mkdirs(root.path(), "run/systemd/resolve");
                mkdirs(root.path(), "usr/bin");
                fs::write(root.path().join("usr/bin/resolvectl"), b"").unwrap();
            }
            root
        }

        fn dns(
            runner: FakeRunner,
            root: &Path,
            data: &Path,
            platform: Platform,
        ) -> Dns<FakeRunner> {
            Dns::with_parts(runner, root.to_owned(), data, platform)
        }

        #[test]
        fn linux_resolved_apply_and_restore() {
            let root = resolv_root(true);
            let data = tempfile::tempdir().unwrap();
            let dns = dns(
                FakeRunner::default(),
                root.path(),
                data.path(),
                Platform::Linux,
            );
            dns.apply("tun0", &settings()).unwrap();
            assert!(record(data.path()).exists());
            assert_eq!(dns.runner.calls()[0].args, ["dns", "tun0", "10.0.0.1"]);
            dns.restore().unwrap();
            assert!(!record(data.path()).exists());
            assert!(
                dns.runner
                    .calls()
                    .iter()
                    .any(|c| c.args == ["revert", "tun0"])
            );
        }

        #[test]
        fn linux_resolv_conf_apply_and_restore() {
            let root = resolv_root(false);
            let data = tempfile::tempdir().unwrap();
            let dns = dns(
                FakeRunner::default(),
                root.path(),
                data.path(),
                Platform::Linux,
            );
            dns.apply("tun0", &settings()).unwrap();
            let conf = root.path().join("etc/resolv.conf");
            assert!(
                fs::read_to_string(&conf)
                    .unwrap()
                    .contains("nameserver 10.0.0.1")
            );
            assert!(dns.runner.calls().is_empty());
            dns.restore().unwrap();
            assert_eq!(
                fs::read_to_string(&conf).unwrap(),
                "nameserver 192.168.1.1\n"
            );
            assert!(!record(data.path()).exists());
        }

        #[test]
        fn macos_apply_and_restore_through_record() {
            let runner = FakeRunner::default();
            runner.respond(
                "show State:/Network/Global/IPv4",
                "<dictionary> {\n  PrimaryService : P1\n}\n",
            );
            let data = tempfile::tempdir().unwrap();
            let dns = dns(
                runner,
                Path::new("/nonexistent"),
                data.path(),
                Platform::MacOs,
            );
            dns.apply("utun2", &settings()).unwrap();
            assert!(record(data.path()).exists());
            dns.restore().unwrap();
            assert!(!record(data.path()).exists());
            let calls = dns.runner.calls();
            let last = calls
                .iter()
                .rev()
                .find_map(|c| c.stdin.clone().filter(|s| s.starts_with("remove")))
                .unwrap();
            assert!(last.contains("remove State:/Network/Service/wyvpn-utun2/DNS"));
            assert!(last.contains("remove State:/Network/Service/P1/DNS"));
        }

        #[test]
        fn crash_recovery_restores_and_removes_record() {
            let root = resolv_root(false);
            let data = tempfile::tempdir().unwrap();
            dns(
                FakeRunner::default(),
                root.path(),
                data.path(),
                Platform::Linux,
            )
            .apply("tun0", &settings())
            .unwrap();

            let fresh = dns(
                FakeRunner::default(),
                root.path(),
                data.path(),
                Platform::Linux,
            );
            fresh.restore().unwrap();
            assert_eq!(
                fs::read_to_string(root.path().join("etc/resolv.conf")).unwrap(),
                "nameserver 192.168.1.1\n"
            );
            assert!(!record(data.path()).exists());
            fresh.restore().unwrap();
        }

        #[test]
        fn failed_apply_rolls_back() {
            let root = resolv_root(true);
            let data = tempfile::tempdir().unwrap();
            let runner = FakeRunner::default();
            runner.fail_on("default-route");
            let dns = dns(runner, root.path(), data.path(), Platform::Linux);
            assert!(dns.apply("tun0", &settings()).is_err());
            assert!(!record(data.path()).exists());
            assert!(
                dns.runner
                    .calls()
                    .iter()
                    .any(|c| c.args == ["revert", "tun0"])
            );
        }

        #[test]
        fn corrupt_record_is_discarded() {
            let data = tempfile::tempdir().unwrap();
            fs::create_dir_all(data.path().join(STATE_DIR)).unwrap();
            fs::write(record(data.path()), b"{").unwrap();
            let dns = dns(
                FakeRunner::default(),
                Path::new("/nonexistent"),
                data.path(),
                Platform::Linux,
            );
            assert!(dns.restore().is_err());
            assert!(!record(data.path()).exists());
        }

        #[test]
        fn profile_summaries_ignore_the_dns_record() {
            use crate::state::ProfileSource;
            use crate::storage::{FileProfiles, tests::stored};

            let root = resolv_root(false);
            let data = tempfile::tempdir().unwrap();
            let store = FileProfiles::open(data.path().to_owned()).unwrap();
            store.save(&stored()).unwrap();
            dns(
                FakeRunner::default(),
                root.path(),
                data.path(),
                Platform::Linux,
            )
            .apply("tun0", &settings())
            .unwrap();
            assert!(record(data.path()).exists());
            assert_eq!(store.summaries().len(), 1);
        }

        #[test]
        fn legacy_record_is_adopted() {
            let data = tempfile::tempdir().unwrap();
            let legacy = data.path().join(LEGACY_RECORD_NAME);
            fs::write(&legacy, b"{}").unwrap();
            adopt_legacy_record(data.path()).unwrap();
            assert!(!legacy.exists());
            assert_eq!(fs::read(record(data.path())).unwrap(), b"{}");
        }

        #[test]
        fn rejects_bad_device_and_ignores_empty_servers() {
            let data = tempfile::tempdir().unwrap();
            let dns = dns(
                FakeRunner::default(),
                Path::new("/nonexistent"),
                data.path(),
                Platform::Linux,
            );
            assert!(dns.apply("tun0 x", &settings()).is_err());
            dns.apply("tun0", &DnsSettings::default()).unwrap();
            assert!(dns.runner.calls().is_empty());
        }
    }
}
