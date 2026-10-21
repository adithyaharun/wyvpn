use wyvpn_ipc::{AuthMode, ConnectionState, ConnectionStatus, ProfileSummary, Transport};

use crate::view::StatusView;

const MAX_FIELD_CHARS: usize = 256;

pub fn sanitize(text: &str) -> String {
    wyvpn_ipc::sanitize_text(text, MAX_FIELD_CHARS)
}

pub fn sanitize_profile(mut profile: ProfileSummary) -> ProfileSummary {
    for field in [
        &mut profile.id,
        &mut profile.name,
        &mut profile.server_name,
        &mut profile.server_host,
        &mut profile.user,
    ] {
        *field = sanitize(field);
    }
    profile.imported_name = profile.imported_name.as_deref().map(sanitize);
    profile
}

pub fn sanitize_status(mut status: ConnectionStatus) -> ConnectionStatus {
    status.profile_id = sanitize(&status.profile_id);
    status.profile_name = sanitize(&status.profile_name);
    status.tunnel_ip = status.tunnel_ip.as_deref().map(sanitize);
    status.local_ip = status.local_ip.as_deref().map(sanitize);
    status.server_endpoint = status.server_endpoint.as_deref().map(sanitize);
    if let Some(error) = &mut status.error {
        error.message = sanitize(&error.message);
    }
    status
}

fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let widths: Vec<usize> = (0..headers.len())
        .map(|i| {
            rows.iter()
                .map(|row| row[i].chars().count())
                .chain([headers[i].len()])
                .max()
                .unwrap_or(0)
        })
        .collect();
    let line = |cells: Vec<&str>| {
        let padded: Vec<String> = cells
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect();
        format!("{}\n", padded.join("  ").trim_end())
    };
    let mut out = line(headers.to_vec());
    for row in rows {
        out.push_str(&line(row.iter().map(String::as_str).collect()));
    }
    out
}

pub fn transport_name(transport: Transport) -> &'static str {
    match transport {
        Transport::WireGuard => "wireguard",
        Transport::OpenVpn => "openvpn",
    }
}

fn auth_name(mode: AuthMode) -> &'static str {
    match mode {
        AuthMode::None => "none",
        AuthMode::Pin => "pin",
        AuthMode::Otp => "otp",
        AuthMode::PinOtp => "pin+otp",
        AuthMode::Sso => "sso",
    }
}

fn state_name(state: ConnectionState) -> &'static str {
    match state {
        ConnectionState::Disconnected => "disconnected",
        ConnectionState::Connecting => "connecting",
        ConnectionState::Connected => "connected",
        ConnectionState::Disconnecting => "disconnecting",
        ConnectionState::Error => "error",
    }
}

fn duration(secs: u64) -> String {
    format!("{}h{:02}m{:02}s", secs / 3600, secs / 60 % 60, secs % 60)
}

fn bytes(count: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = count as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{count} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn profiles_table(profiles: &[ProfileSummary]) -> String {
    if profiles.is_empty() {
        return "No profiles.\n".into();
    }
    let rows: Vec<Vec<String>> = profiles
        .iter()
        .map(|p| {
            vec![
                p.name.clone(),
                p.id.clone(),
                format!("{} ({})", p.server_name, p.server_host),
                p.user.clone(),
                auth_name(p.auth_mode).into(),
                p.transports
                    .iter()
                    .map(|t| transport_name(*t))
                    .collect::<Vec<_>>()
                    .join(","),
            ]
        })
        .collect();
    table(
        &["NAME", "ID", "SERVER", "USER", "AUTH", "TRANSPORTS"],
        &rows,
    )
}

pub fn connected_line(status: &ConnectionStatus) -> String {
    let ip = status.tunnel_ip.as_deref().unwrap_or("-");
    let transport = status
        .transport
        .map_or_else(String::new, |t| format!(" ({})", transport_name(t)));
    match &status.server_endpoint {
        Some(endpoint) => format!("connected{transport}: {ip} via {endpoint}"),
        None => format!("connected{transport}: {ip}"),
    }
}

pub fn renamed_line(profile: &ProfileSummary, reset: bool) -> String {
    if reset {
        format!("reset to imported name: {}", profile.name)
    } else {
        format!("renamed: {}", profile.name)
    }
}

pub fn status_table(views: &[StatusView]) -> String {
    if views.is_empty() {
        return "No profiles.\n".into();
    }
    let dash = || "-".to_owned();
    let rows: Vec<Vec<String>> = views
        .iter()
        .map(|v| {
            vec![
                v.status.profile_name.clone(),
                state_name(v.status.state).into(),
                v.status
                    .transport
                    .map_or_else(dash, |t| transport_name(t).into()),
                v.status.tunnel_ip.clone().unwrap_or_else(dash),
                v.status.local_ip.clone().unwrap_or_else(dash),
                v.status.server_endpoint.clone().unwrap_or_else(dash),
                v.uptime_secs.map_or_else(dash, duration),
                bytes(v.status.rx_bytes),
                bytes(v.status.tx_bytes),
            ]
        })
        .collect();
    table(
        &[
            "NAME",
            "STATE",
            "TRANSPORT",
            "TUNNEL IP",
            "LOCAL IP",
            "SERVER",
            "UPTIME",
            "RX",
            "TX",
        ],
        &rows,
    )
}

#[cfg(test)]
mod tests {
    use wyvpn_ipc::{ErrorBody, ErrorCode};

    use super::*;

    #[test]
    fn sanitize_strips_terminal_and_bidi_controls_and_caps_length() {
        assert_eq!(sanitize("a\x1b[31mred\x07\u{9b}2J\n\tb"), "a[31mred2Jb");
        assert_eq!(sanitize("x\u{202E}evil\u{200B}"), "xevil");
        let long = sanitize(&"a".repeat(1000));
        assert_eq!(long.chars().count(), MAX_FIELD_CHARS + 1);
        assert!(long.ends_with('…'));
        assert_eq!(
            sanitize(&"a".repeat(MAX_FIELD_CHARS)).chars().count(),
            MAX_FIELD_CHARS
        );
    }

    #[test]
    fn profile_and_status_fields_are_sanitized() {
        let profile = sanitize_profile(ProfileSummary {
            id: "p\x1b1".into(),
            name: "Of\x1b]0;pwn\x07fice".into(),
            server_name: "gw".into(),
            server_host: "h".into(),
            user: "alice\r".into(),
            auth_mode: AuthMode::Pin,
            transports: vec![],
            imported_name: Some("Im\x1bported".into()),
        });
        assert_eq!(profile.imported_name.as_deref(), Some("Imported"));
        assert_eq!(profile.name, "Of]0;pwnfice");
        assert_eq!(profile.id, "p1");
        assert_eq!(profile.user, "alice");
        let status = sanitize_status(ConnectionStatus {
            tunnel_ip: Some("10.0.0.2\x1b[2J".into()),
            local_ip: Some("192.168.1.5\x1b[2J".into()),
            server_endpoint: Some("h\x1b[2J:1".into()),
            error: Some(ErrorBody::new(ErrorCode::Server, "bad\x1b[2J")),
            ..ConnectionStatus::disconnected("p1")
        });
        assert_eq!(status.server_endpoint.as_deref(), Some("h[2J:1"));
        assert_eq!(status.error.unwrap().message, "bad[2J");
        assert_eq!(status.tunnel_ip.as_deref(), Some("10.0.0.2[2J"));
        assert_eq!(status.local_ip.as_deref(), Some("192.168.1.5[2J"));
    }

    #[test]
    fn formats() {
        assert_eq!(duration(3725), "1h02m05s");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1536), "1.5 KiB");
    }

    #[test]
    fn connected_line_names_the_transport() {
        let status = ConnectionStatus {
            tunnel_ip: Some("10.0.0.2".into()),
            transport: Some(Transport::WireGuard),
            ..ConnectionStatus::disconnected("p")
        };
        assert_eq!(connected_line(&status), "connected (wireguard): 10.0.0.2");
    }
}
