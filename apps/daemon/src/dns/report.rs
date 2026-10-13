use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub const MAX_ENTRIES: usize = 8;
const MAX_NAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;
const MAX_DEV_LEN: usize = 15;
const MAX_OPTION_LEN: usize = 256;
const MAX_INDEX_DIGITS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HookPhase {
    Up,
    Down,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsSettings {
    #[serde(default)]
    pub servers: Vec<IpAddr>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub search: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookReport {
    pub phase: HookPhase,
    pub dev: String,
    #[serde(default)]
    pub dns: DnsSettings,
}

pub fn phase_of(script_type: &str) -> Option<HookPhase> {
    match script_type {
        "up" | "up-restart" => Some(HookPhase::Up),
        "down" | "down-pre" => Some(HookPhase::Down),
        _ => None,
    }
}

pub fn valid_dev(dev: &str) -> bool {
    !dev.is_empty()
        && dev.len() <= MAX_DEV_LEN
        && !dev.starts_with('-')
        && dev
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

pub fn clean_name(raw: &str) -> Option<String> {
    let name = raw.strip_suffix('.').unwrap_or(raw);
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return None;
    }
    let ok = name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    ok.then(|| name.to_ascii_lowercase())
}

fn usable_server(ip: &IpAddr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast()
}

fn push_unique<T: PartialEq>(list: &mut Vec<T>, item: T) {
    if list.len() < MAX_ENTRIES && !list.contains(&item) {
        list.push(item);
    }
}

pub fn sanitize(report: HookReport) -> HookReport {
    let mut dns = DnsSettings::default();
    for ip in report.dns.servers.into_iter().filter(usable_server) {
        push_unique(&mut dns.servers, ip);
    }
    for name in report.dns.domains.iter().filter_map(|n| clean_name(n)) {
        push_unique(&mut dns.domains, name);
    }
    for name in report.dns.search.iter().filter_map(|n| clean_name(n)) {
        push_unique(&mut dns.search, name);
    }
    HookReport {
        phase: report.phase,
        dev: if valid_dev(&report.dev) {
            report.dev
        } else {
            String::new()
        },
        dns,
    }
}

pub fn parse_foreign_options(vars: impl IntoIterator<Item = (String, String)>) -> HookReport {
    let mut phase = None;
    let mut dev = String::new();
    let mut options: Vec<(u32, String)> = Vec::new();
    for (key, value) in vars {
        match key.as_str() {
            "script_type" => phase = phase_of(&value),
            "dev" => dev = value,
            _ => {
                let Some(index) = key.strip_prefix("foreign_option_") else {
                    continue;
                };
                if index.is_empty()
                    || index.len() > MAX_INDEX_DIGITS
                    || !index.bytes().all(|b| b.is_ascii_digit())
                {
                    continue;
                }
                if let Ok(index) = index.parse() {
                    options.push((index, value));
                }
            }
        }
    }
    options.sort_by_key(|(index, _)| *index);

    let mut raw = DnsSettings::default();
    for (_, option) in &options {
        if option.len() > MAX_OPTION_LEN {
            continue;
        }
        let mut parts = option.split_whitespace();
        let (Some("dhcp-option"), Some(kind), Some(value), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        match kind.to_ascii_uppercase().as_str() {
            "DNS" | "DNS6" => {
                if let Ok(ip) = value.parse() {
                    raw.servers.push(ip);
                }
            }
            "DOMAIN" => raw.domains.push(value.to_owned()),
            "DOMAIN-SEARCH" => raw.search.push(value.to_owned()),
            _ => {}
        }
    }
    sanitize(HookReport {
        phase: phase.unwrap_or(HookPhase::Down),
        dev,
        dns: raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn parses_valid_options_in_numeric_order() {
        let report = parse_foreign_options(vars(&[
            ("script_type", "up"),
            ("dev", "utun4"),
            ("foreign_option_10", "dhcp-option DNS 10.0.0.2"),
            ("foreign_option_2", "dhcp-option DNS 10.0.0.1"),
            ("foreign_option_3", "dhcp-option DOMAIN Corp.Example."),
            ("foreign_option_4", "dhcp-option DOMAIN-SEARCH a.example"),
            ("foreign_option_5", "dhcp-option DNS6 fd00::1"),
            ("foreign_option_6", "dhcp-option DNS 10.0.0.1"),
            ("foreign_option_7", "dhcp-option PROXY_HTTP 1.2.3.4"),
        ]));
        assert_eq!(report.phase, HookPhase::Up);
        assert_eq!(report.dev, "utun4");
        assert_eq!(
            report.dns.servers,
            ["10.0.0.1", "fd00::1", "10.0.0.2"].map(|s| s.parse::<IpAddr>().unwrap())
        );
        assert_eq!(report.dns.domains, ["corp.example"]);
        assert_eq!(report.dns.search, ["a.example"]);
    }

    #[test]
    fn down_is_the_fallback_phase() {
        assert_eq!(
            parse_foreign_options(vars(&[("script_type", "route-up")])).phase,
            HookPhase::Down
        );
        assert_eq!(phase_of("down"), Some(HookPhase::Down));
        assert_eq!(phase_of("nonsense"), None);
    }

    #[test]
    fn drops_hostile_values() {
        let long = format!("dhcp-option DOMAIN {}.example", "a".repeat(64));
        let report = parse_foreign_options(vars(&[
            ("script_type", "up"),
            ("dev", "tun0; rm -rf /"),
            ("foreign_option_1", "dhcp-option DNS 10.0.0.1; reboot"),
            ("foreign_option_2", "dhcp-option DNS not-an-ip"),
            ("foreign_option_3", "dhcp-option DNS 0.0.0.0"),
            ("foreign_option_4", "dhcp-option DNS ff02::1"),
            ("foreign_option_5", "dhcp-option DNS fe80::1%eth0"),
            ("foreign_option_6", "dhcp-option DOMAIN evil.com\nset x"),
            ("foreign_option_7", "dhcp-option DOMAIN a\"b.com"),
            ("foreign_option_8", "dhcp-option DOMAIN -bad.com"),
            ("foreign_option_9", "dhcp-option DOMAIN a..com"),
            ("foreign_option_10", "dhcp-option DOMAIN $(id).com"),
            ("foreign_option_11", long.as_str()),
            ("foreign_option_12", "dhcp-option DOMAIN-SEARCH x y"),
            ("foreign_option_99999", "dhcp-option DNS 1.1.1.1"),
            ("foreign_option_x", "dhcp-option DNS 1.1.1.1"),
            ("foreign_option_13", "other DNS 1.1.1.1"),
        ]));
        assert_eq!(report.dev, "");
        assert!(report.dns.servers.is_empty());
        assert!(report.dns.domains.is_empty());
        assert!(report.dns.search.is_empty());
    }

    #[test]
    fn caps_counts_and_option_length() {
        let mut items: Vec<(String, String)> = (1..=40)
            .map(|i| {
                (
                    format!("foreign_option_{i}"),
                    format!("dhcp-option DNS 10.0.0.{i}"),
                )
            })
            .collect();
        items.push((
            "foreign_option_50".into(),
            format!("dhcp-option DOMAIN {}", "a".repeat(400)),
        ));
        let report = parse_foreign_options(items);
        assert_eq!(report.dns.servers.len(), MAX_ENTRIES);
        assert!(report.dns.domains.is_empty());
    }

    #[test]
    fn device_names_are_restricted() {
        assert!(valid_dev("utun12"));
        assert!(valid_dev("tun0"));
        assert!(!valid_dev(""));
        assert!(!valid_dev("-x"));
        assert!(!valid_dev("a b"));
        assert!(!valid_dev("averyveryverylongname"));
        assert!(!valid_dev("a/b"));
    }

    #[test]
    fn json_round_trip() {
        let report = parse_foreign_options(vars(&[
            ("script_type", "up"),
            ("dev", "tun0"),
            ("foreign_option_1", "dhcp-option DNS 10.0.0.1"),
            ("foreign_option_2", "dhcp-option DOMAIN corp.example"),
        ]));
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"up\""));
        let back: HookReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn sanitize_revalidates_wire_data() {
        let report = sanitize(HookReport {
            phase: HookPhase::Up,
            dev: "bad dev".into(),
            dns: DnsSettings {
                servers: vec!["0.0.0.0".parse().unwrap(), "9.9.9.9".parse().unwrap()],
                domains: vec!["ok.example".into(), "bad name".into()],
                search: vec![],
            },
        });
        assert_eq!(report.dev, "");
        assert_eq!(report.dns.servers.len(), 1);
        assert_eq!(report.dns.domains, ["ok.example"]);
    }
}
