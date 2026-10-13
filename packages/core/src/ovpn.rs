use crate::auth::version_setenv_line;
use crate::error::{Error, Result};
use crate::profile::Profile;
use crate::secret::Secret;
use std::collections::HashMap;
use zeroize::Zeroizing;

const MAX_INPUT_LEN: usize = 1 << 20;
const MAX_LINE_LEN: usize = 256;

const NUMERIC: [&str; 11] = [
    "verb",
    "mute",
    "ping",
    "ping-exit",
    "hand-window",
    "server-poll-timeout",
    "reneg-sec",
    "sndbuf",
    "rcvbuf",
    "mssfix",
    "fragment",
];
const TUN_MTU: &str = "tun-mtu";

const PROTOCOLS: [&str; 9] = [
    "udp",
    "udp4",
    "udp6",
    "tcp",
    "tcp4",
    "tcp6",
    "tcp-client",
    "tcp4-client",
    "tcp6-client",
];
const REDIRECT_FLAGS: [&str; 8] = [
    "local",
    "def1",
    "bypass-dhcp",
    "autolocal",
    "bypass-dns",
    "ipv6",
    "!ipv4",
    "block-local",
];
const COMPRESSION: [&str; 3] = ["lzo", "lz4", "lz4-v2"];
const COMP_LZO: [&str; 3] = ["yes", "no", "adaptive"];

const CBC_CIPHERS: [&str; 2] = ["AES-128-CBC", "AES-256-CBC"];
const AEAD_CIPHERS: [&str; 3] = ["AES-128-GCM", "AES-256-GCM", "CHACHA20-POLY1305"];
const KNOWN_CIPHERS: [&str; 5] = [
    "AES-128-CBC",
    "AES-256-CBC",
    "AES-128-GCM",
    "AES-256-GCM",
    "CHACHA20-POLY1305",
];

const BLOCK_ORDER: [&str; 5] = ["ca", "tls-auth", "tls-crypt", "cert", "key"];

pub struct RenderOptions<'a> {
    pub client_version: &'a str,
    pub dco: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Remote {
    host: String,
    port: Option<u16>,
    proto: Option<&'static str>,
}

#[derive(Default)]
struct Parsed {
    device_id: Option<String>,
    device_name: Option<String>,
    dev: Option<&'static str>,
    dev_type: Option<&'static str>,
    default_proto: Option<&'static str>,
    remotes: Vec<Remote>,
    nobind: bool,
    persist_tun: bool,
    remote_cert_tls: bool,
    block_outside_dns: bool,
    auth_user_pass: bool,
    cipher: Option<String>,
    auth: Option<String>,
    data_ciphers: Option<Vec<&'static str>>,
    numbers: HashMap<&'static str, u32>,
    tun_mtu: Option<u32>,
    redirect: Option<Vec<&'static str>>,
    compress: Option<Option<&'static str>>,
    comp_lzo: Option<Option<&'static str>>,
    key_direction: Option<&'static str>,
    blocks: HashMap<&'static str, Zeroizing<String>>,
}

fn invalid(line: usize, what: &str) -> Error {
    Error::InvalidConfig(format!("line {line}: {what}"))
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(c, '.' | '-' | '_' | ':' | '/' | '+' | '=' | ',' | '@' | '%')
}

fn token(value: Option<&str>, line: usize, what: &str) -> Result<String> {
    match value {
        Some(v) if !v.is_empty() && v.chars().all(is_token_char) => Ok(v.to_owned()),
        _ => Err(invalid(line, what)),
    }
}

fn number(value: Option<&str>, line: usize, what: &str) -> Result<u32> {
    value
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| invalid(line, what))
}

fn pick(options: &[&'static str], value: &str) -> Option<&'static str> {
    options
        .iter()
        .copied()
        .find(|option| option.eq_ignore_ascii_case(value))
}

fn clean_line(raw: &str) -> String {
    raw.chars()
        .filter_map(|c| match c {
            '\t' => Some(' '),
            c if c.is_ascii_alphanumeric() => Some(c),
            ' ' | '.' | '-' | '_' | ':' | '/' | '+' | '=' | ',' | '@' | '%' | '!' => Some(c),
            _ => None,
        })
        .take(MAX_LINE_LEN)
        .collect()
}

fn clean_block_line(raw: &str) -> String {
    raw.chars()
        .filter(|c| {
            c.is_ascii_alphanumeric() || matches!(c, ' ' | '+' | '/' | '=' | '-' | '_' | '.' | ':')
        })
        .take(MAX_LINE_LEN)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn block_tag(trimmed: &str) -> Option<&str> {
    let inner = trimmed.strip_prefix('<')?.strip_suffix('>')?;
    (!inner.is_empty()
        && !inner.starts_with('/')
        && inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
    .then_some(inner)
}

fn parse(text: &str) -> Result<Parsed> {
    let mut parsed = Parsed::default();
    let mut lines = text.lines().enumerate();
    while let Some((index, raw)) = lines.next() {
        let number_of_line = index + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(tag) = block_tag(trimmed) {
            let close = format!("</{tag}>");
            let mut body = Zeroizing::new(String::new());
            let mut closed = false;
            for (_, inner) in lines.by_ref() {
                if inner.trim() == close {
                    closed = true;
                    break;
                }
                let cleaned = clean_block_line(inner);
                if !cleaned.is_empty() {
                    body.push_str(&cleaned);
                    body.push('\n');
                }
            }
            if !closed {
                return Err(invalid(number_of_line, "unterminated inline block"));
            }
            if let Some(name) = BLOCK_ORDER.iter().copied().find(|name| *name == tag) {
                parsed.blocks.entry(name).or_insert(body);
            }
            continue;
        }
        let cleaned = clean_line(trimmed);
        let mut parts = cleaned.split_whitespace();
        let Some(name) = parts.next() else { continue };
        let name = name.trim_start_matches('-');
        apply(&mut parsed, name, &mut parts, number_of_line)?;
    }
    Ok(parsed)
}

fn apply<'a>(
    parsed: &mut Parsed,
    name: &str,
    args: &mut impl Iterator<Item = &'a str>,
    line: usize,
) -> Result<()> {
    match name {
        "setenv" => {
            let key = args.next();
            let value = args.next();
            match key {
                Some("UV_ID") => {
                    parsed.device_id = Some(token(value, line, "invalid UV_ID value")?);
                }
                Some("UV_NAME") => {
                    parsed.device_name = Some(token(value, line, "invalid UV_NAME value")?);
                }
                _ => {}
            }
        }
        "dev" => {
            let value = args.next().unwrap_or_default();
            parsed.dev = if value.starts_with("tun") {
                Some("tun")
            } else if value.starts_with("tap") {
                Some("tap")
            } else {
                return Err(invalid(line, "invalid dev value"));
            };
        }
        "dev-type" => {
            parsed.dev_type = Some(
                pick(&["tun", "tap"], args.next().unwrap_or_default())
                    .ok_or_else(|| invalid(line, "invalid dev-type value"))?,
            );
        }
        "proto" => {
            parsed.default_proto = Some(
                pick(&PROTOCOLS, args.next().unwrap_or_default())
                    .ok_or_else(|| invalid(line, "invalid proto value"))?,
            );
        }
        "remote" => {
            let host = token(args.next(), line, "invalid remote host")?;
            if !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'))
            {
                return Err(invalid(line, "invalid remote host"));
            }
            let port = args
                .next()
                .map(|p| p.parse().map_err(|_| invalid(line, "invalid remote port")))
                .transpose()?;
            let proto = args
                .next()
                .map(|p| {
                    pick(&PROTOCOLS, p).ok_or_else(|| invalid(line, "invalid remote protocol"))
                })
                .transpose()?;
            parsed.remotes.push(Remote { host, port, proto });
        }
        "nobind" => parsed.nobind = true,
        "persist-tun" => parsed.persist_tun = true,
        "push-peer-info" => {}
        "auth-user-pass" => parsed.auth_user_pass = true,
        "block-outside-dns" => parsed.block_outside_dns = true,
        "remote-cert-tls" => parsed.remote_cert_tls = args.next() == Some("server"),
        "cipher" => parsed.cipher = Some(token(args.next(), line, "invalid cipher")?),
        "auth" => parsed.auth = Some(token(args.next(), line, "invalid auth digest")?),
        "data-ciphers" => {
            let value = token(args.next(), line, "invalid data-ciphers")?;
            parsed.data_ciphers = Some(
                value
                    .split(':')
                    .filter_map(|cipher| pick(&KNOWN_CIPHERS, cipher))
                    .collect(),
            );
        }
        "ping-restart" | "ping-exit" => {
            parsed.numbers.insert(
                "ping-exit",
                number(args.next(), line, "invalid ping value")?,
            );
        }
        TUN_MTU => parsed.tun_mtu = Some(number(args.next(), line, "invalid tun-mtu value")?),
        "redirect-gateway" => {
            parsed.redirect = Some(
                args.filter_map(|flag| pick(&REDIRECT_FLAGS, flag))
                    .collect(),
            );
        }
        "compress" => {
            parsed.compress = Some(args.next().and_then(|v| pick(&COMPRESSION, v)));
        }
        "comp-lzo" => {
            parsed.comp_lzo = Some(args.next().and_then(|v| pick(&COMP_LZO, v)));
        }
        "key-direction" => {
            parsed.key_direction = Some(
                pick(&["0", "1"], args.next().unwrap_or_default())
                    .ok_or_else(|| invalid(line, "invalid key-direction value"))?,
            );
        }
        other => {
            if let Some(key) = NUMERIC.iter().copied().find(|key| *key == other) {
                let value = number(args.next(), line, "invalid numeric value")?;
                parsed.numbers.insert(key, value);
            }
        }
    }
    Ok(())
}

fn normalise_ciphers(listed: Option<&[&'static str]>, dco: bool) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    let mut push = |cipher: &'static str| {
        if !out.contains(&cipher) && !(dco && CBC_CIPHERS.contains(&cipher)) {
            out.push(cipher);
        }
    };
    match listed {
        Some(list) => {
            list.iter().copied().for_each(&mut push);
            AEAD_CIPHERS.iter().copied().for_each(&mut push);
        }
        None => {
            AEAD_CIPHERS.iter().copied().for_each(&mut push);
            ["AES-256-CBC", "AES-128-CBC"]
                .into_iter()
                .for_each(&mut push);
        }
    }
    out
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

fn push_optional(out: &mut String, name: &str, value: Option<&str>) {
    match value {
        Some(value) => push_line(out, &format!("{name} {value}")),
        None => push_line(out, name),
    }
}

fn push_number(out: &mut String, parsed: &Parsed, key: &str) {
    if let Some(value) = parsed.numbers.get(key) {
        push_line(out, &format!("{key} {value}"));
    }
}

pub fn render(profile: &Profile, options: &RenderOptions<'_>) -> Result<Secret> {
    let text = profile.ovpn.expose();
    if text.len() > MAX_INPUT_LEN {
        return Err(Error::TooLarge(MAX_INPUT_LEN));
    }
    let parsed = parse(text)?;
    let id = parsed
        .device_id
        .as_deref()
        .ok_or(Error::MissingField("UV_ID"))?;
    let name = parsed
        .device_name
        .as_deref()
        .ok_or(Error::MissingField("UV_NAME"))?;
    token(Some(options.client_version), 0, "invalid client version")?;

    let mut out = String::new();
    push_line(&mut out, &format!("setenv UV_ID {id}"));
    push_line(&mut out, &format!("setenv UV_NAME {name}"));
    push_line(&mut out, &version_setenv_line(options.client_version));
    push_line(&mut out, "client");
    if let Some(dev) = parsed.dev.or(parsed.dev_type) {
        push_line(&mut out, &format!("dev {dev}"));
    }
    if let Some(dev_type) = parsed.dev_type.or(parsed.dev) {
        push_line(&mut out, &format!("dev-type {dev_type}"));
    }
    push_line(&mut out, "connect-retry-max 1");

    let mut remotes: Vec<Remote> = Vec::new();
    for remote in &parsed.remotes {
        let remote = Remote {
            proto: remote.proto.or(parsed.default_proto),
            ..remote.clone()
        };
        if !remotes.contains(&remote) {
            remotes.push(remote);
        }
    }
    let has_server_key = profile
        .header
        .server_box_public_key
        .as_deref()
        .is_some_and(|key| !key.is_empty())
        || !profile.header.server_public_key.is_empty();
    if has_server_key && remotes.len() == 1 {
        push_line(&mut out, "remap-usr1 SIGTERM");
    }
    for remote in &remotes {
        let mut line = format!("remote {}", remote.host);
        match (remote.port, remote.proto) {
            (Some(port), Some(proto)) => line.push_str(&format!(" {port} {proto}")),
            (None, Some(proto)) => line.push_str(&format!(" 1194 {proto}")),
            (Some(port), None) => line.push_str(&format!(" {port}")),
            (None, None) => {}
        }
        push_line(&mut out, &line);
    }
    if parsed.nobind {
        push_line(&mut out, "nobind");
    }
    if parsed.persist_tun {
        push_line(&mut out, "persist-tun");
    }
    if parsed.data_ciphers.is_none()
        && let Some(cipher) = &parsed.cipher
    {
        push_line(&mut out, &format!("cipher {cipher}"));
    }
    if let Some(auth) = &parsed.auth {
        push_line(&mut out, &format!("auth {auth}"));
    }
    push_number(&mut out, &parsed, "verb");
    push_number(&mut out, &parsed, "mute");
    push_line(&mut out, "push-peer-info");
    for key in [
        "ping",
        "ping-exit",
        "hand-window",
        "server-poll-timeout",
        "reneg-sec",
    ] {
        push_number(&mut out, &parsed, key);
    }
    if let Some(flags) = &parsed.redirect {
        let mut line = String::from("redirect-gateway");
        for flag in flags {
            line.push(' ');
            line.push_str(flag);
        }
        push_line(&mut out, &line);
    }
    for key in ["sndbuf", "rcvbuf", "mssfix", "fragment"] {
        push_number(&mut out, &parsed, key);
    }
    if let Some(mtu) = parsed.tun_mtu {
        push_line(&mut out, &format!("{TUN_MTU} {mtu}"));
    }
    if parsed.remote_cert_tls {
        push_line(&mut out, "remote-cert-tls server");
    }
    if let Some(compress) = parsed.compress {
        push_optional(&mut out, "compress", compress);
    }
    if let Some(comp_lzo) = parsed.comp_lzo {
        push_optional(&mut out, "comp-lzo", comp_lzo);
    }
    if parsed.block_outside_dns {
        push_line(&mut out, "ignore-unknown-option block-outside-dns");
        push_line(&mut out, "block-outside-dns");
    }
    if parsed.auth_user_pass {
        push_line(&mut out, "auth-user-pass");
    }
    if let Some(direction) = parsed.key_direction {
        push_line(&mut out, &format!("key-direction {direction}"));
    }
    push_line(&mut out, "pull-filter ignore \"ping-restart\"");
    if !cfg!(target_os = "linux") {
        push_line(&mut out, "pull-filter ignore \"dhcp-option DOMAIN-ROUTE\"");
    }
    if !options.dco {
        push_line(&mut out, "ignore-unknown-option disable-dco");
        push_line(&mut out, "disable-dco");
    }
    let ciphers = normalise_ciphers(parsed.data_ciphers.as_deref(), options.dco);
    push_line(&mut out, &format!("data-ciphers \"{}\"", ciphers.join(":")));
    for tag in BLOCK_ORDER {
        if let Some(body) = parsed.blocks.get(tag) {
            push_line(&mut out, &format!("<{tag}>"));
            out.push_str(body);
            push_line(&mut out, &format!("</{tag}>"));
        }
    }
    Ok(Secret::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::ProfileHeader;
    use proptest::prelude::*;

    const INPUT: &str = include_str!("testdata/ovpn_input.conf");
    const EXPECTED: &str = include_str!("testdata/ovpn_expected.conf");
    const EXPECTED_DCO: &str = include_str!("testdata/ovpn_expected_dco.conf");

    fn profile_with(body: &str, header: ProfileHeader) -> Profile {
        Profile {
            header,
            ovpn: Secret::new(body),
        }
    }

    fn keyed_header() -> ProfileHeader {
        ProfileHeader {
            server_box_public_key: Some("AAAA".into()),
            ..ProfileHeader::default()
        }
    }

    fn opts(dco: bool) -> RenderOptions<'static> {
        RenderOptions {
            client_version: "1.2.3",
            dco,
        }
    }

    fn render_text(body: &str) -> String {
        let full = format!("setenv UV_ID id1\nsetenv UV_NAME name1\n{body}\n");
        render(&profile_with(&full, ProfileHeader::default()), &opts(false))
            .unwrap()
            .expose()
            .to_owned()
    }

    fn lines(text: &str) -> Vec<&str> {
        text.lines().collect()
    }

    fn expected(text: &str) -> String {
        let text = text.replace("{VERSION_LINE}", &version_setenv_line("1.2.3"));
        if cfg!(target_os = "linux") {
            text.replace("pull-filter ignore \"dhcp-option DOMAIN-ROUTE\"\n", "")
        } else {
            text
        }
    }

    #[test]
    fn golden_without_dco() {
        let out = render(&profile_with(INPUT, keyed_header()), &opts(false)).unwrap();
        assert_eq!(out.expose(), expected(EXPECTED));
    }

    #[test]
    fn golden_with_dco() {
        let out = render(&profile_with(INPUT, keyed_header()), &opts(true)).unwrap();
        assert_eq!(out.expose(), expected(EXPECTED_DCO));
    }

    #[test]
    fn dangerous_directives_are_dropped() {
        let cases = [
            "up /bin/sh",
            "down /bin/sh",
            "script-security 3",
            "route 10.0.0.0 255.0.0.0",
            "route-up /bin/sh",
            "route-pre-down /bin/sh",
            "dhcp-option DNS 1.1.1.1",
            "plugin /lib/x.so",
            "management 127.0.0.1 1",
            "log /tmp/x",
            "log-append /tmp/x",
            "cd /",
            "config /etc/x",
            "tls-verify /bin/sh",
            "ipchange /bin/sh",
            "learn-address /bin/sh",
            "auth-user-pass-verify /bin/sh",
            "client-connect /bin/sh",
            "daemon",
            "writepid /tmp/pid",
            "chroot /",
        ];
        for case in cases {
            let name = case.split(' ').next().unwrap();
            let out = render_text(case);
            let dropped = !lines(&out)
                .iter()
                .any(|line| line.split(' ').next() == Some(name));
            assert!(dropped, "{case} leaked into:\n{out}");
        }
    }

    #[test]
    fn push_peer_info_is_always_emitted_once() {
        for body in ["client", "client\npush-peer-info"] {
            let out = render_text(body);
            let count = lines(&out)
                .iter()
                .filter(|line| **line == "push-peer-info")
                .count();
            assert_eq!(count, 1, "{body}");
        }
    }

    #[test]
    fn auth_user_pass_file_is_dropped() {
        let out = render_text("auth-user-pass /etc/shadow");
        assert!(lines(&out).contains(&"auth-user-pass"));
        assert!(!out.contains("shadow"));
    }

    #[test]
    fn unknown_directive_is_dropped_without_error() {
        let out = render_text("frobnicate 1 2 3");
        assert!(!out.contains("frobnicate"));
    }

    #[test]
    fn config_never_contains_management_or_scripts() {
        let out = render(&profile_with(INPUT, keyed_header()), &opts(false)).unwrap();
        for line in out.expose().lines() {
            let name = line.split(' ').next().unwrap();
            assert!(
                !matches!(name, "management" | "up" | "down" | "script-security"),
                "{line}"
            );
        }
    }

    #[test]
    fn ping_restart_becomes_ping_exit() {
        let out = render_text("ping-restart 60");
        let all = lines(&out);
        assert!(all.contains(&"ping-exit 60"));
        assert!(all.contains(&"pull-filter ignore \"ping-restart\""));
        assert!(!all.iter().any(|line| line.starts_with("ping-restart")));
        assert!(all.contains(&"connect-retry-max 1"));
    }

    #[test]
    fn identity_lines_are_present() {
        let out = render_text("");
        assert!(out.contains("setenv UV_ID id1\n"));
        assert!(out.contains("setenv UV_NAME name1\n"));
        assert!(out.contains(&version_setenv_line("1.2.3")));
    }

    #[test]
    fn missing_identity_is_an_error() {
        let profile = profile_with("client\n", ProfileHeader::default());
        assert!(matches!(
            render(&profile, &opts(false)),
            Err(Error::MissingField("UV_ID"))
        ));
    }

    #[test]
    fn profile_supplied_version_line_is_replaced() {
        let out = render_text(&format!(
            "setenv {} 9.9.9",
            crate::vendor::VENDOR_VERSION_ENV
        ));
        assert!(!out.contains("9.9.9"));
    }

    #[test]
    fn data_ciphers_default_and_dco() {
        let out = render_text("");
        assert!(out.contains(
            "data-ciphers \"AES-128-GCM:AES-256-GCM:CHACHA20-POLY1305:AES-256-CBC:AES-128-CBC\""
        ));
        let full = "setenv UV_ID id1\nsetenv UV_NAME n\n";
        let out = render(&profile_with(full, ProfileHeader::default()), &opts(true)).unwrap();
        assert!(
            out.expose()
                .contains("data-ciphers \"AES-128-GCM:AES-256-GCM:CHACHA20-POLY1305\"")
        );
        assert!(!out.expose().contains("disable-dco"));
    }

    #[test]
    fn data_ciphers_are_deduplicated_and_complete() {
        let out = render_text("data-ciphers aes-256-gcm:AES-256-GCM:AES-256-CBC");
        assert!(
            out.contains(
                "data-ciphers \"AES-256-GCM:AES-256-CBC:AES-128-GCM:CHACHA20-POLY1305\"\n"
            )
        );
        assert!(!out.lines().any(|line| line.starts_with("cipher ")));
    }

    #[test]
    fn cipher_line_only_without_data_ciphers() {
        assert!(render_text("cipher AES-256-CBC").contains("\ncipher AES-256-CBC\n"));
    }

    #[test]
    fn remap_usr1_needs_server_key_and_single_remote() {
        let single = "setenv UV_ID a\nsetenv UV_NAME b\nremote h.example.com 1194 udp\n";
        let double = format!("{single}remote h2.example.com 1194 udp\n");
        let repeated = format!("{single}remote h.example.com 1194 udp\n");
        let has = |body: &str, header: ProfileHeader| {
            render(&profile_with(body, header), &opts(false))
                .unwrap()
                .expose()
                .contains("remap-usr1 SIGTERM\n")
        };
        assert!(has(single, keyed_header()));
        assert!(has(&repeated, keyed_header()));
        assert!(!has(&double, keyed_header()));
        assert!(!has(single, ProfileHeader::default()));
        let rsa = ProfileHeader {
            server_public_key: vec!["x".into()],
            ..ProfileHeader::default()
        };
        assert!(has(single, rsa));
    }

    #[test]
    fn auth_user_pass_never_has_a_file_argument() {
        let out = render_text("auth-user-pass /root/creds");
        assert!(lines(&out).contains(&"auth-user-pass"));
        assert!(!out.contains("creds"));
    }

    #[test]
    fn injection_in_re_emitted_values_is_rejected() {
        let cases = [
            "remote host;up 1194",
            "remote \"a b\" 1194 udp",
            "remote h 1194 udp\\nup x",
            "cipher AES\"\npull-filter",
            "setenv UV_ID a\"b",
            "remote h 99999 udp",
            "remote h 1194 bogus",
            "ping x",
            "dev \"tun",
        ];
        for case in cases {
            let full = format!("setenv UV_ID id1\nsetenv UV_NAME name1\n{case}\n");
            let result = render(&profile_with(&full, ProfileHeader::default()), &opts(false));
            if let Ok(out) = result {
                for line in out.expose().lines() {
                    let name = line.split(' ').next().unwrap();
                    assert!(
                        !matches!(name, "up" | "pull-filter")
                            || line.starts_with("pull-filter ignore \""),
                        "{case}: {line}"
                    );
                }
            }
        }
    }

    #[test]
    fn hostile_client_version_is_rejected() {
        let profile = profile_with(
            "setenv UV_ID a\nsetenv UV_NAME b\n",
            ProfileHeader::default(),
        );
        let bad = RenderOptions {
            client_version: "1.0\nup x",
            dco: false,
        };
        assert!(matches!(
            render(&profile, &bad),
            Err(Error::InvalidConfig(_))
        ));
    }

    #[test]
    fn long_lines_are_truncated() {
        let long = format!("verb 3{}", " ".repeat(300));
        let out = render_text(&format!("remote {} 1194 udp\n{long}", "a".repeat(400)));
        assert!(out.lines().all(|line| line.len() <= MAX_LINE_LEN + 32));
    }

    #[test]
    fn unsafe_characters_are_stripped() {
        let out = render_text("verb 3\u{0}\u{7f}\u{202e}");
        assert!(out.contains("\nverb 3\n"));
    }

    #[test]
    fn inline_block_cannot_inject_directives() {
        let body = "<ca>\nAAAA\n</ca>\n<key>\nBBBB\n</ca>\nup /bin/sh\n";
        assert!(matches!(
            render(
                &profile_with(
                    &format!("setenv UV_ID a\nsetenv UV_NAME b\n{body}"),
                    ProfileHeader::default()
                ),
                &opts(false)
            ),
            Err(Error::InvalidConfig(_))
        ));
        let out = render_text("<ca>\nAAAA\n<up>\n</ca>\n<up>\nx\n</up>\nup y");
        assert!(!out.lines().any(|line| line.starts_with("up ")));
        assert!(!out.contains("<up>"));
    }

    #[test]
    fn oversized_input_is_rejected() {
        let big = "a\n".repeat(MAX_INPUT_LEN);
        assert!(matches!(
            render(&profile_with(&big, ProfileHeader::default()), &opts(false)),
            Err(Error::TooLarge(_))
        ));
    }

    #[test]
    fn domain_route_filter_is_skipped_only_on_linux() {
        let out = render_text("");
        assert_eq!(
            out.contains("dhcp-option DOMAIN-ROUTE"),
            !cfg!(target_os = "linux")
        );
    }

    proptest! {
        #[test]
        fn never_panics_on_strings(body in ".*") {
            let profile = profile_with(&body, keyed_header());
            let _ = render(&profile, &opts(false));
        }

        #[test]
        fn never_panics_on_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let body = String::from_utf8_lossy(&bytes).into_owned();
            let _ = render(&profile_with(&body, ProfileHeader::default()), &opts(true));
        }

        #[test]
        fn never_panics_on_directive_soup(
            body in proptest::collection::vec(
                "(remote|dev|data-ciphers|ping-restart|setenv|<ca>|</ca>|<key>|redirect-gateway|compress|[a-z-]{1,12}) [ -~]{0,40}",
                0..30,
            )
        ) {
            let text = format!("setenv UV_ID a\nsetenv UV_NAME b\n{}", body.join("\n"));
            let _ = render(&profile_with(&text, keyed_header()), &opts(false));
        }

        #[test]
        fn output_has_no_forbidden_directives(body in "[ -~\n]{0,400}") {
            let text = format!("setenv UV_ID a\nsetenv UV_NAME b\n{body}");
            if let Ok(out) = render(&profile_with(&text, ProfileHeader::default()), &opts(false)) {
                let mut in_block = false;
                for line in out.expose().lines() {
                    if line.starts_with("</") { in_block = false; continue; }
                    if line.starts_with('<') { in_block = true; continue; }
                    if in_block { continue; }
                    let name = line.split(' ').next().unwrap();
                    prop_assert!(!matches!(name, "up" | "down" | "script-security" | "management" | "plugin" | "route" | "log" | "cd" | "config"), "{}", line);
                }
            }
        }
    }
}
