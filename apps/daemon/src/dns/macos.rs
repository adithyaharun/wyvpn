use std::io;

use serde::{Deserialize, Serialize};

use super::Runner;
use super::report::{DnsSettings, valid_dev};

const SCUTIL: &str = "/usr/sbin/scutil";
const DSCACHEUTIL: &str = "/usr/bin/dscacheutil";
const KILLALL: &str = "/usr/bin/killall";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Val {
    Str(String),
    Arr(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimaryBackup {
    pub id: String,
    pub previous: Option<Vec<(String, Val)>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Saved {
    pub service: String,
    pub primary: Option<PrimaryBackup>,
}

fn dns_key(id: &str) -> String {
    format!("State:/Network/Service/{id}/DNS")
}

fn valid_service_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 80
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn quote(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some("\"\"".into());
    }
    let plain = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'-' | b'_' | b'%');
    if value.bytes().all(plain) {
        return Some(value.to_owned());
    }
    let safe = value
        .bytes()
        .all(|b| b >= 0x20 && b != 0x7f && !matches!(b, b'"' | b'\\'));
    safe.then(|| format!("\"{value}\""))
}

fn add_array(script: &mut String, key: &str, values: &[String]) {
    let quoted: Vec<String> = values.iter().filter_map(|v| quote(v)).collect();
    if valid_key(key) && !quoted.is_empty() {
        script.push_str(&format!("d.add {key} * {}\n", quoted.join(" ")));
    }
}

fn parse_dict(output: &str) -> Option<Vec<(String, Val)>> {
    if output.contains("No such key") || !output.contains("<dictionary>") {
        return None;
    }
    let mut entries = Vec::new();
    let mut depth = 0usize;
    let mut array: Option<(String, Vec<String>)> = None;
    for line in output.lines().map(str::trim) {
        if line.ends_with('{') {
            depth += 1;
            if depth == 2 {
                if let Some((key, rest)) = line.split_once(" : ") {
                    if rest.starts_with("<array>") {
                        array = Some((key.to_owned(), Vec::new()));
                    }
                }
            }
        } else if line == "}" {
            if depth == 2 {
                if let Some((key, items)) = array.take() {
                    entries.push((key, Val::Arr(items)));
                }
            }
            depth = depth.saturating_sub(1);
        } else if let Some((key, value)) = line.split_once(" : ") {
            match (depth, array.as_mut()) {
                (1, _) => entries.push((key.to_owned(), Val::Str(value.to_owned()))),
                (2, Some((_, items))) => items.push(value.to_owned()),
                _ => {}
            }
        }
    }
    Some(entries)
}

fn show(runner: &impl Runner, key: &str) -> Option<Vec<(String, Val)>> {
    let out = runner
        .run(SCUTIL, &[], Some(&format!("show {key}\n")))
        .ok()?;
    parse_dict(&out)
}

pub fn prepare(runner: &impl Runner, dev: &str) -> io::Result<Saved> {
    if !valid_dev(dev) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid device",
        ));
    }
    let service = format!("wyvpn-{dev}");
    let primary = show(runner, "State:/Network/Global/IPv4")
        .and_then(|entries| {
            entries.into_iter().find_map(|(key, val)| match val {
                Val::Str(id) if key == "PrimaryService" && valid_service_id(&id) => Some(id),
                _ => None,
            })
        })
        .map(|id| PrimaryBackup {
            previous: show(runner, &dns_key(&id)),
            id,
        });
    Ok(Saved { service, primary })
}

fn flush(runner: &impl Runner) {
    let _ = runner.run(DSCACHEUTIL, &["-flushcache"], None);
    let _ = runner.run(KILLALL, &["-HUP", "mDNSResponder"], None);
}

pub fn activate(runner: &impl Runner, saved: &Saved, settings: &DnsSettings) -> io::Result<()> {
    let names: Vec<String> = settings
        .domains
        .iter()
        .chain(&settings.search)
        .cloned()
        .collect();
    let servers: Vec<String> = settings.servers.iter().map(ToString::to_string).collect();

    let mut script = String::from("d.init\n");
    add_array(&mut script, "ServerAddresses", &servers);
    add_array(&mut script, "SearchDomains", &names);
    let matching = if names.is_empty() {
        vec![String::new()]
    } else {
        names.clone()
    };
    add_array(&mut script, "SupplementalMatchDomains", &matching);
    script.push_str(&format!("set {}\n", dns_key(&saved.service)));

    if let Some(primary) = &saved.primary {
        script.push_str("d.init\n");
        add_array(&mut script, "ServerAddresses", &servers);
        add_array(&mut script, "SearchDomains", &names);
        script.push_str(&format!("set {}\n", dns_key(&primary.id)));
    }
    let result = runner.run(SCUTIL, &[], Some(&script)).map(drop);
    flush(runner);
    result
}

pub fn restore(runner: &impl Runner, saved: &Saved) -> io::Result<()> {
    let mut script = String::new();
    if valid_service_id(&saved.service) {
        script.push_str(&format!("remove {}\n", dns_key(&saved.service)));
    }
    if let Some(primary) = saved.primary.as_ref().filter(|p| valid_service_id(&p.id)) {
        match &primary.previous {
            Some(entries) => {
                script.push_str("d.init\n");
                for (key, val) in entries {
                    match val {
                        Val::Arr(items) => add_array(&mut script, key, items),
                        Val::Str(value) => {
                            if let (true, Some(value)) = (valid_key(key), quote(value)) {
                                script.push_str(&format!("d.add {key} {value}\n"));
                            }
                        }
                    }
                }
                script.push_str(&format!("set {}\n", dns_key(&primary.id)));
            }
            None => script.push_str(&format!("remove {}\n", dns_key(&primary.id))),
        }
    }
    let result = if script.is_empty() {
        Ok(())
    } else {
        runner.run(SCUTIL, &[], Some(&script)).map(drop)
    };
    flush(runner);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::testutil::FakeRunner;

    const GLOBAL: &str = "<dictionary> {\n  PrimaryInterface : en0\n  PrimaryService : AAAA-1111\n  Router : 192.168.1.1\n}\n";
    const PREVIOUS: &str = "<dictionary> {\n  DomainName : lan\n  ServerAddresses : <array> {\n    0 : 192.168.1.1\n    1 : 8.8.8.8\n  }\n  SearchDomains : <array> {\n    0 : lan\n  }\n}\n";

    fn settings() -> DnsSettings {
        DnsSettings {
            servers: vec!["10.0.0.1".parse().unwrap()],
            domains: vec!["corp.example".into()],
            search: vec!["eng.example".into()],
        }
    }

    fn runner() -> FakeRunner {
        let runner = FakeRunner::default();
        runner.respond("show State:/Network/Global/IPv4", GLOBAL);
        runner.respond("show State:/Network/Service/AAAA-1111/DNS", PREVIOUS);
        runner
    }

    #[test]
    fn parses_scutil_output() {
        let dict = parse_dict(PREVIOUS).unwrap();
        assert_eq!(dict[0], ("DomainName".into(), Val::Str("lan".into())));
        assert_eq!(
            dict[1],
            (
                "ServerAddresses".into(),
                Val::Arr(vec!["192.168.1.1".into(), "8.8.8.8".into()])
            )
        );
        assert!(parse_dict("  No such key\n").is_none());
    }

    #[test]
    fn apply_writes_own_key_and_overrides_primary() {
        let runner = runner();
        let saved = prepare(&runner, "utun4").unwrap();
        assert_eq!(saved.service, "wyvpn-utun4");
        assert_eq!(saved.primary.as_ref().unwrap().id, "AAAA-1111");
        activate(&runner, &saved, &settings()).unwrap();
        let calls = runner.calls();
        let script = &calls
            .iter()
            .find(|c| c.stdin.as_deref().is_some_and(|s| s.starts_with("d.init")))
            .unwrap()
            .stdin
            .clone()
            .unwrap();
        assert_eq!(
            script,
            "d.init\n\
             d.add ServerAddresses * 10.0.0.1\n\
             d.add SearchDomains * corp.example eng.example\n\
             d.add SupplementalMatchDomains * corp.example eng.example\n\
             set State:/Network/Service/wyvpn-utun4/DNS\n\
             d.init\n\
             d.add ServerAddresses * 10.0.0.1\n\
             d.add SearchDomains * corp.example eng.example\n\
             set State:/Network/Service/AAAA-1111/DNS\n"
        );
        assert!(calls.iter().any(|c| c.program == "/usr/bin/dscacheutil"));
        assert!(calls.iter().any(|c| c.program == "/usr/bin/killall"));
        assert!(calls.iter().all(|c| c.program.starts_with('/')));
    }

    #[test]
    fn match_everything_without_domains() {
        let runner = FakeRunner::default();
        let saved = prepare(&runner, "utun4").unwrap();
        assert!(saved.primary.is_none());
        let only_servers = DnsSettings {
            servers: vec!["10.0.0.1".parse().unwrap()],
            ..DnsSettings::default()
        };
        activate(&runner, &saved, &only_servers).unwrap();
        let script = runner.calls().last().map(|_| ()).and(
            runner
                .calls()
                .iter()
                .find_map(|c| c.stdin.clone().filter(|s| s.starts_with("d.init"))),
        );
        assert!(
            script
                .unwrap()
                .contains("SupplementalMatchDomains * \"\"\n")
        );
    }

    #[test]
    fn restore_removes_key_and_puts_back_previous() {
        let runner = runner();
        let saved = prepare(&runner, "utun4").unwrap();
        restore(&runner, &saved).unwrap();
        let script = runner
            .calls()
            .iter()
            .rev()
            .find_map(|c| c.stdin.clone().filter(|s| s.starts_with("remove")))
            .unwrap();
        assert_eq!(
            script,
            "remove State:/Network/Service/wyvpn-utun4/DNS\n\
             d.init\n\
             d.add DomainName lan\n\
             d.add ServerAddresses * 192.168.1.1 8.8.8.8\n\
             d.add SearchDomains * lan\n\
             set State:/Network/Service/AAAA-1111/DNS\n"
        );
    }

    #[test]
    fn restore_removes_override_when_there_was_no_previous_key() {
        let runner = FakeRunner::default();
        runner.respond("show State:/Network/Global/IPv4", GLOBAL);
        let saved = prepare(&runner, "tun0").unwrap();
        restore(&runner, &saved).unwrap();
        let script = runner
            .calls()
            .iter()
            .rev()
            .find_map(|c| c.stdin.clone().filter(|s| s.starts_with("remove")))
            .unwrap();
        assert!(script.ends_with("remove State:/Network/Service/AAAA-1111/DNS\n"));
    }

    #[test]
    fn tampered_record_values_cannot_inject_commands() {
        let runner = FakeRunner::default();
        let saved = Saved {
            service: "x\nquit".into(),
            primary: Some(PrimaryBackup {
                id: "ok-1".into(),
                previous: Some(vec![
                    (
                        "ServerAddresses".into(),
                        Val::Arr(vec!["a\nremove Foo".into()]),
                    ),
                    ("Bad Key\nx".into(), Val::Str("v".into())),
                ]),
            }),
        };
        restore(&runner, &saved).unwrap();
        let script = runner
            .calls()
            .iter()
            .find_map(|c| c.stdin.clone().filter(|s| s.contains("d.init")))
            .unwrap();
        assert_eq!(script, "d.init\nset State:/Network/Service/ok-1/DNS\n");
    }
}
