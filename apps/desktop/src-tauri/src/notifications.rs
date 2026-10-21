use wyvpn_ipc::{ConnectionState, ErrorCode, Event};

use crate::error::sanitize;
use crate::settings::Settings;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Connected,
    Dropped,
    Disconnected,
    AuthFailed,
    Failed,
    PinNeeded,
    MissingDefault,
    ApprovalNeeded,
    UpdateAvailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub kind: Kind,
    pub title: String,
    pub body: String,
}

pub struct Context<'a> {
    pub settings: &'a Settings,
    pub name: &'a str,
    pub tunnel_ip: Option<&'a str>,
    pub window_visible: bool,
    pub user_disconnected: bool,
    pub drop_notified: bool,
}

impl Notification {
    fn new(kind: Kind, title: &str, body: String) -> Self {
        Self {
            kind,
            title: title.to_owned(),
            body,
        }
    }

    pub fn connected(name: &str, tunnel_ip: Option<&str>) -> Self {
        let body = match tunnel_ip.filter(|ip| !ip.is_empty()) {
            Some(ip) => format!("{name} ({})", sanitize(ip)),
            None => name.to_owned(),
        };
        Self::new(Kind::Connected, "Connected", format!("Connected to {body}"))
    }

    pub fn missing_default() -> Self {
        Self::new(
            Kind::MissingDefault,
            "Auto-connect skipped",
            "The default profile no longer exists".to_owned(),
        )
    }

    pub fn update_available(version: &str) -> Self {
        Self::new(
            Kind::UpdateAvailable,
            "Update available",
            format!("WyVPN {} is available", sanitize(version)),
        )
    }

    pub fn approval_needed() -> Self {
        Self::new(
            Kind::ApprovalNeeded,
            "Approve WyVPN",
            "Allow WyVPN in the background in System Settings to connect.".to_owned(),
        )
    }
}

pub fn decide(prev: ConnectionState, event: &Event, ctx: &Context) -> Option<Notification> {
    if !ctx.settings.notifications {
        return None;
    }
    let name = ctx.name;
    match event {
        Event::CredentialsRequired { .. } if !ctx.window_visible => Some(Notification::new(
            Kind::PinNeeded,
            "PIN needed",
            format!("PIN needed for {name}"),
        )),
        Event::StateChanged { state, error, .. } => match state {
            ConnectionState::Connected if prev != ConnectionState::Connected => {
                Some(Notification::connected(name, ctx.tunnel_ip))
            }
            ConnectionState::Connecting
                if prev == ConnectionState::Connected && !ctx.drop_notified =>
            {
                Some(Notification::new(
                    Kind::Dropped,
                    "Connection dropped",
                    format!("Reconnecting to {name}"),
                ))
            }
            ConnectionState::Disconnected
                if matches!(
                    prev,
                    ConnectionState::Connected | ConnectionState::Connecting
                ) && !ctx.user_disconnected =>
            {
                Some(Notification::new(
                    Kind::Disconnected,
                    "Disconnected",
                    format!("Disconnected from {name}"),
                ))
            }
            ConnectionState::Error if prev != ConnectionState::Error => match error {
                Some(body) if body.code == ErrorCode::AuthFailed => Some(Notification::new(
                    Kind::AuthFailed,
                    "Authentication failed",
                    format!("Could not sign in to {name}"),
                )),
                Some(body) => Some(Notification::new(
                    Kind::Failed,
                    "Connection failed",
                    sanitize(&body.message),
                )),
                None => Some(Notification::new(
                    Kind::Failed,
                    "Connection failed",
                    format!("Could not connect to {name}"),
                )),
            },
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyvpn_ipc::{AuthMode, ErrorBody};

    fn state(state: ConnectionState) -> Event {
        Event::StateChanged {
            profile_id: "p".into(),
            state,
            error: None,
        }
    }

    fn failed(code: ErrorCode, message: &str) -> Event {
        Event::StateChanged {
            profile_id: "p".into(),
            state: ConnectionState::Error,
            error: Some(ErrorBody::new(code, message)),
        }
    }

    fn pin() -> Event {
        Event::CredentialsRequired {
            profile_id: "p".into(),
            mode: AuthMode::Pin,
        }
    }

    struct Case {
        settings: Settings,
        window_visible: bool,
        user_disconnected: bool,
        drop_notified: bool,
    }

    impl Case {
        fn new() -> Self {
            Self {
                settings: Settings::default(),
                window_visible: false,
                user_disconnected: false,
                drop_notified: false,
            }
        }

        fn run(&self, prev: ConnectionState, event: &Event) -> Option<Notification> {
            decide(
                prev,
                event,
                &Context {
                    settings: &self.settings,
                    name: "Office",
                    tunnel_ip: Some("10.0.0.2"),
                    window_visible: self.window_visible,
                    user_disconnected: self.user_disconnected,
                    drop_notified: self.drop_notified,
                },
            )
        }
    }

    use ConnectionState::{Connected, Connecting, Disconnected};

    #[test]
    fn connected_names_the_profile_and_tunnel_ip() {
        let note = Case::new()
            .run(Connecting, &state(Connected))
            .expect("notification");
        assert_eq!(note.kind, Kind::Connected);
        assert!(note.body.contains("Office") && note.body.contains("10.0.0.2"));
        assert!(Case::new().run(Connected, &state(Connected)).is_none());
    }

    #[test]
    fn drop_fires_once_across_repeated_retries() {
        let mut case = Case::new();
        let first = case.run(Connected, &state(Connecting)).expect("drop");
        assert_eq!(first.kind, Kind::Dropped);
        case.drop_notified = true;
        assert!(case.run(Connected, &state(Connecting)).is_none());
        for _ in 0..3 {
            assert!(case.run(Connecting, &state(Connecting)).is_none());
        }
        assert_eq!(
            case.run(Connecting, &state(Connected)).unwrap().kind,
            Kind::Connected
        );
    }

    #[test]
    fn user_disconnect_is_silent() {
        let mut case = Case::new();
        case.user_disconnected = true;
        assert!(case.run(Connected, &state(Disconnected)).is_none());
    }

    #[test]
    fn unrequested_disconnect_notifies() {
        let note = Case::new()
            .run(Connected, &state(Disconnected))
            .expect("notification");
        assert_eq!(note.kind, Kind::Disconnected);
        assert!(note.body.contains("Office"));
        assert!(
            Case::new()
                .run(Disconnected, &state(Disconnected))
                .is_none()
        );
    }

    #[test]
    fn auth_failure_has_its_own_notification() {
        let note = Case::new()
            .run(Connecting, &failed(ErrorCode::AuthFailed, "bad pin 1234"))
            .expect("notification");
        assert_eq!(note.kind, Kind::AuthFailed);
        assert!(!note.body.contains("1234"));
    }

    #[test]
    fn other_errors_carry_the_cleaned_message() {
        let note = Case::new()
            .run(
                Connecting,
                &failed(ErrorCode::Server, "tls\u{1b}[31m handshake\nfailed"),
            )
            .expect("notification");
        assert_eq!(note.kind, Kind::Failed);
        assert_eq!(note.title, "Connection failed");
        assert_eq!(note.body, "tls[31m handshakefailed");
    }

    #[test]
    fn nothing_is_produced_when_notifications_are_off() {
        let mut case = Case::new();
        case.settings.notifications = false;
        for (prev, event) in [
            (Connecting, state(Connected)),
            (Connected, state(Connecting)),
            (Connected, state(Disconnected)),
            (Connecting, failed(ErrorCode::AuthFailed, "x")),
            (Disconnected, pin()),
        ] {
            assert!(case.run(prev, &event).is_none());
        }
    }

    #[test]
    fn approval_needed_points_at_system_settings() {
        let note = Notification::approval_needed();
        assert_eq!(note.kind, Kind::ApprovalNeeded);
        assert_eq!(note.title, "Approve WyVPN");
        assert_eq!(
            note.body,
            "Allow WyVPN in the background in System Settings to connect."
        );
    }

    #[test]
    fn pin_needed_only_while_the_window_is_hidden() {
        let mut case = Case::new();
        let note = case.run(Connecting, &pin()).expect("notification");
        assert_eq!(note.kind, Kind::PinNeeded);
        assert_eq!(note.body, "PIN needed for Office");
        case.window_visible = true;
        assert!(case.run(Connecting, &pin()).is_none());
    }
}
