use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::Runner;
use super::report::{DnsSettings, valid_dev};

const RESOLVECTL: &str = "/usr/bin/resolvectl";
const MAX_SEARCH: usize = 6;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Original {
    Missing,
    File { contents: String },
    Symlink { target: String },
}

fn resolv_conf(root: &Path) -> PathBuf {
    root.join("etc/resolv.conf")
}

pub fn resolved_active(root: &Path) -> bool {
    if !root.join("run/systemd/resolve").is_dir() {
        return false;
    }
    if !["usr/bin/resolvectl", "bin/resolvectl"]
        .iter()
        .any(|tool| root.join(tool).exists())
    {
        return false;
    }
    let path = resolv_conf(root);
    if let Ok(target) = fs::read_link(&path) {
        return target.to_string_lossy().contains("systemd/resolve");
    }
    fs::read_to_string(path)
        .is_ok_and(|text| text.contains("127.0.0.53") || text.contains("systemd-resolved"))
}

pub fn resolved_apply(runner: &impl Runner, dev: &str, settings: &DnsSettings) -> io::Result<()> {
    if !valid_dev(dev) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid device",
        ));
    }
    let servers: Vec<String> = settings.servers.iter().map(ToString::to_string).collect();
    let mut dns = vec!["dns", dev];
    dns.extend(servers.iter().map(String::as_str));
    runner.run(RESOLVECTL, &dns, None)?;

    let mut domain = vec!["domain", dev, "~."];
    domain.extend(
        settings
            .domains
            .iter()
            .chain(&settings.search)
            .map(String::as_str),
    );
    runner.run(RESOLVECTL, &domain, None)?;
    runner.run(RESOLVECTL, &["default-route", dev, "true"], None)?;
    let _ = runner.run(RESOLVECTL, &["flush-caches"], None);
    Ok(())
}

pub fn resolved_revert(runner: &impl Runner, dev: &str) -> io::Result<()> {
    if !valid_dev(dev) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid device",
        ));
    }
    runner.run(RESOLVECTL, &["revert", dev], None)?;
    let _ = runner.run(RESOLVECTL, &["flush-caches"], None);
    Ok(())
}

pub fn resolv_conf_backup(root: &Path) -> io::Result<Original> {
    let path = resolv_conf(root);
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_symlink() => Ok(Original::Symlink {
            target: fs::read_link(&path)?.to_string_lossy().into_owned(),
        }),
        Ok(_) => Ok(Original::File {
            contents: fs::read_to_string(&path)?,
        }),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Original::Missing),
        Err(err) => Err(err),
    }
}

fn render(settings: &DnsSettings) -> String {
    let mut text = String::from("# managed by wyvpnd\n");
    for server in &settings.servers {
        text.push_str(&format!("nameserver {server}\n"));
    }
    let search: Vec<&str> = settings
        .domains
        .iter()
        .chain(&settings.search)
        .map(String::as_str)
        .take(MAX_SEARCH)
        .collect();
    if !search.is_empty() {
        text.push_str(&format!("search {}\n", search.join(" ")));
    }
    text
}

fn replace_with(path: &Path, place: impl FnOnce(&Path) -> io::Result<()>) -> io::Result<()> {
    let temp = path.with_extension("wyvpn-tmp");
    let _ = fs::remove_file(&temp);
    let result = place(&temp).and_then(|()| fs::rename(&temp, path));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

pub fn resolv_conf_write(root: &Path, settings: &DnsSettings) -> io::Result<()> {
    let text = render(settings);
    replace_with(&resolv_conf(root), |temp| {
        fs::write(temp, &text)?;
        fs::set_permissions(temp, fs::Permissions::from_mode(0o644))
    })
}

pub fn resolv_conf_restore(root: &Path, original: &Original) -> io::Result<()> {
    let path = resolv_conf(root);
    match original {
        Original::Missing => match fs::remove_file(&path) {
            Err(err) if err.kind() != io::ErrorKind::NotFound => Err(err),
            _ => Ok(()),
        },
        Original::File { contents } => replace_with(&path, |temp| {
            fs::write(temp, contents)?;
            fs::set_permissions(temp, fs::Permissions::from_mode(0o644))
        }),
        Original::Symlink { target } => {
            replace_with(&path, |temp| std::os::unix::fs::symlink(target, temp))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::testutil::{FakeRunner, mkdirs};

    fn settings() -> DnsSettings {
        DnsSettings {
            servers: vec!["10.0.0.1".parse().unwrap(), "fd00::1".parse().unwrap()],
            domains: vec!["corp.example".into()],
            search: vec!["eng.example".into()],
        }
    }

    fn root_with_resolved(resolv: &str) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        mkdirs(root.path(), "run/systemd/resolve");
        mkdirs(root.path(), "usr/bin");
        fs::write(root.path().join("usr/bin/resolvectl"), b"").unwrap();
        mkdirs(root.path(), "etc");
        fs::write(root.path().join("etc/resolv.conf"), resolv).unwrap();
        root
    }

    #[test]
    fn detects_resolved_stub() {
        let root = root_with_resolved("nameserver 127.0.0.53\n");
        assert!(resolved_active(root.path()));
        let plain = root_with_resolved("nameserver 192.168.1.1\n");
        assert!(!resolved_active(plain.path()));
        let no_tool = root_with_resolved("nameserver 127.0.0.53\n");
        fs::remove_file(no_tool.path().join("usr/bin/resolvectl")).unwrap();
        assert!(!resolved_active(no_tool.path()));
    }

    #[test]
    fn detects_resolved_symlink() {
        let root = root_with_resolved("");
        let conf = root.path().join("etc/resolv.conf");
        fs::remove_file(&conf).unwrap();
        std::os::unix::fs::symlink("../run/systemd/resolve/stub-resolv.conf", &conf).unwrap();
        assert!(resolved_active(root.path()));
    }

    #[test]
    fn resolvectl_commands() {
        let runner = FakeRunner::default();
        resolved_apply(&runner, "tun0", &settings()).unwrap();
        let calls: Vec<Vec<String>> = runner.calls().iter().map(|c| c.args.clone()).collect();
        assert_eq!(calls[0], ["dns", "tun0", "10.0.0.1", "fd00::1"]);
        assert_eq!(
            calls[1],
            ["domain", "tun0", "~.", "corp.example", "eng.example"]
        );
        assert_eq!(calls[2], ["default-route", "tun0", "true"]);
        assert!(runner.calls().iter().all(|c| c.program == RESOLVECTL));

        let runner = FakeRunner::default();
        let bare = DnsSettings {
            domains: vec![],
            search: vec![],
            ..settings()
        };
        resolved_apply(&runner, "tun0", &bare).unwrap();
        assert_eq!(runner.calls()[1].args, ["domain", "tun0", "~."]);

        let runner = FakeRunner::default();
        resolved_revert(&runner, "tun0").unwrap();
        assert_eq!(runner.calls()[0].args, ["revert", "tun0"]);
        assert!(resolved_revert(&runner, "tun0 --evil").is_err());
    }

    #[test]
    fn resolv_conf_round_trip_for_file() {
        let root = root_with_resolved("nameserver 192.168.1.1\n");
        let original = resolv_conf_backup(root.path()).unwrap();
        resolv_conf_write(root.path(), &settings()).unwrap();
        let text = fs::read_to_string(root.path().join("etc/resolv.conf")).unwrap();
        assert_eq!(
            text,
            "# managed by wyvpnd\nnameserver 10.0.0.1\nnameserver fd00::1\nsearch corp.example eng.example\n"
        );
        resolv_conf_restore(root.path(), &original).unwrap();
        assert_eq!(
            fs::read_to_string(root.path().join("etc/resolv.conf")).unwrap(),
            "nameserver 192.168.1.1\n"
        );
    }

    #[test]
    fn resolv_conf_round_trip_for_symlink_and_missing() {
        let root = root_with_resolved("");
        let conf = root.path().join("etc/resolv.conf");
        fs::remove_file(&conf).unwrap();
        std::os::unix::fs::symlink("/elsewhere/resolv.conf", &conf).unwrap();
        let original = resolv_conf_backup(root.path()).unwrap();
        resolv_conf_write(root.path(), &settings()).unwrap();
        assert!(
            !fs::symlink_metadata(&conf)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        resolv_conf_restore(root.path(), &original).unwrap();
        assert_eq!(
            fs::read_link(&conf).unwrap().to_string_lossy(),
            "/elsewhere/resolv.conf"
        );

        fs::remove_file(&conf).unwrap();
        let original = resolv_conf_backup(root.path()).unwrap();
        assert_eq!(original, Original::Missing);
        resolv_conf_write(root.path(), &settings()).unwrap();
        resolv_conf_restore(root.path(), &original).unwrap();
        assert!(!conf.exists());
    }
}
