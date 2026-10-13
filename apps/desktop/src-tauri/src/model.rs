use wyvpn_ipc::{ConnectionState, ConnectionStatus, Event, ProfileSummary};

use serde::Serialize;

use crate::bridge::{BridgeMsg, DaemonAvailability};
use crate::client::Mismatch;
use crate::error::sanitize;
use crate::service::ServiceStatus;

pub const COPY_TUNNEL_IP: &str = "copy_tunnel_ip";
pub const APPROVE_SERVICE: &str = "approve_service";
const MENU_NAME_CHARS: usize = 40;

#[derive(Debug, Default, Clone)]
pub struct Model {
    pub available: bool,
    pub profiles: Vec<ProfileSummary>,
    pub statuses: Vec<ConnectionStatus>,
    pub profiles_loaded: bool,
    pub statuses_loaded: bool,
    pub daemon_status: DaemonStatus,
    pub setup: Option<ServiceStatus>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonStatus {
    Available,
    #[default]
    Unreachable,
    Starting,
    Incompatible,
    NotPermitted,
    NeedsSetup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AvailabilityPayload {
    pub available: bool,
    pub socket: String,
    pub status: DaemonStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mismatch: Option<Mismatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup: Option<ServiceStatus>,
}

impl AvailabilityPayload {
    pub fn new(
        socket: &str,
        availability: &DaemonAvailability,
        service: Option<ServiceStatus>,
    ) -> Self {
        let pending_setup = service.filter(|status| *status != ServiceStatus::Enabled);
        let (status, mismatch, setup) = match availability {
            DaemonAvailability::Available => (DaemonStatus::Available, None, None),
            DaemonAvailability::Incompatible(mismatch) => {
                (DaemonStatus::Incompatible, Some(mismatch.clone()), None)
            }
            DaemonAvailability::NotPermitted => (DaemonStatus::NotPermitted, None, None),
            DaemonAvailability::Unreachable => match (service, pending_setup) {
                (_, Some(status)) => (DaemonStatus::NeedsSetup, None, Some(status)),
                (Some(_), None) => (DaemonStatus::Starting, None, None),
                (None, None) => (DaemonStatus::Unreachable, None, None),
            },
        };
        Self {
            available: status == DaemonStatus::Available,
            socket: socket.to_owned(),
            status,
            mismatch,
            setup,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconState {
    Disconnected,
    Connecting,
    Connected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Info(String),
    Action {
        id: String,
        label: String,
        enabled: bool,
    },
    Separator,
}

impl Model {
    pub fn approval_pending(&self) -> bool {
        self.daemon_status == DaemonStatus::NeedsSetup
            && self.setup == Some(ServiceStatus::RequiresApproval)
    }

    pub fn set_daemon_state(&mut self, payload: &AvailabilityPayload) -> bool {
        let changed = self.daemon_status != payload.status || self.setup != payload.setup;
        self.daemon_status = payload.status;
        self.setup = payload.setup;
        changed
    }

    pub fn apply(&mut self, msg: &BridgeMsg) {
        match msg {
            BridgeMsg::Subscribed => {}
            BridgeMsg::Availability(availability) => {
                self.available = availability.is_available();
                if !self.available {
                    self.statuses.clear();
                    self.statuses_loaded = false;
                }
            }
            BridgeMsg::Statuses(statuses) => {
                self.statuses.clone_from(statuses);
                self.statuses_loaded = true;
            }
            BridgeMsg::Profiles(profiles) => {
                self.profiles.clone_from(profiles);
                self.profiles_loaded = true;
            }
            BridgeMsg::Event(Event::StateChanged {
                profile_id,
                state,
                error,
            }) => {
                let index = self
                    .statuses
                    .iter()
                    .position(|status| &status.profile_id == profile_id)
                    .unwrap_or_else(|| {
                        self.statuses
                            .push(ConnectionStatus::disconnected(profile_id.clone()));
                        self.statuses.len() - 1
                    });
                let status = &mut self.statuses[index];
                status.state = *state;
                status.error.clone_from(error);
                status.awaiting = None;
                if matches!(
                    state,
                    ConnectionState::Disconnected | ConnectionState::Error
                ) {
                    status.tunnel_ip = None;
                }
            }
            BridgeMsg::Event(Event::CredentialsRequired { profile_id, mode }) => {
                if let Some(status) = self
                    .statuses
                    .iter_mut()
                    .find(|status| &status.profile_id == profile_id)
                {
                    status.awaiting = Some(*mode);
                }
            }
            BridgeMsg::Event(_) => {}
        }
    }

    pub fn loaded(&self) -> bool {
        self.available && self.profiles_loaded && self.statuses_loaded
    }

    pub fn session_in_progress(&self) -> bool {
        self.active().is_some() || self.statuses.iter().any(|status| status.awaiting.is_some())
    }

    pub fn tunnel_ip(&self, profile_id: &str) -> Option<String> {
        self.statuses
            .iter()
            .find(|status| status.profile_id == profile_id)
            .and_then(|status| status.tunnel_ip.clone())
            .filter(|ip| !ip.is_empty())
    }

    pub fn connected_tunnel_ip(&self) -> Option<String> {
        self.active()
            .filter(|status| status.state == ConnectionState::Connected)
            .and_then(|status| status.tunnel_ip.clone())
            .filter(|ip| !ip.is_empty())
    }

    pub fn plain_name(&self, profile_id: &str) -> String {
        let name = self.raw_name(profile_id);
        sanitize(if name.trim().is_empty() {
            profile_id
        } else {
            name
        })
    }

    pub fn is_awaiting(&self, profile_id: &str) -> bool {
        self.statuses
            .iter()
            .any(|status| status.profile_id == profile_id && status.awaiting.is_some())
    }

    pub fn state_of(&self, profile_id: &str) -> ConnectionState {
        self.statuses
            .iter()
            .find(|status| status.profile_id == profile_id)
            .map_or(ConnectionState::Disconnected, |status| status.state)
    }

    fn active(&self) -> Option<&ConnectionStatus> {
        self.statuses.iter().find(|status| {
            !matches!(
                status.state,
                ConnectionState::Disconnected | ConnectionState::Error
            )
        })
    }

    pub fn icon_state(&self) -> IconState {
        if !self.available {
            return IconState::Disconnected;
        }
        match self.active().map(|status| status.state) {
            Some(ConnectionState::Connected) => IconState::Connected,
            Some(_) => IconState::Connecting,
            None => IconState::Disconnected,
        }
    }

    fn raw_name(&self, profile_id: &str) -> &str {
        self.profiles
            .iter()
            .find(|profile| profile.id == profile_id)
            .map(|profile| profile.name.as_str())
            .or_else(|| {
                self.statuses
                    .iter()
                    .find(|status| status.profile_id == profile_id)
                    .map(|status| status.profile_name.as_str())
            })
            .unwrap_or_default()
    }

    fn display_name(&self, profile_id: &str) -> String {
        let name = self.raw_name(profile_id);
        menu_label(if name.trim().is_empty() {
            profile_id
        } else {
            name
        })
    }

    fn state_line(&self) -> String {
        if !self.available {
            return match self.daemon_status {
                DaemonStatus::Starting => "Service starting…",
                DaemonStatus::NeedsSetup if self.approval_pending() => "Approval needed",
                _ => "Service not running",
            }
            .to_owned();
        }
        let Some(active) = self.active() else {
            return "Disconnected".to_owned();
        };
        let name = self.display_name(&active.profile_id);
        match active.state {
            ConnectionState::Connected => match active.tunnel_ip.as_deref() {
                Some(ip) if !ip.is_empty() => {
                    format!("Connected to {name} ({})", menu_label(ip))
                }
                _ => format!("Connected to {name}"),
            },
            ConnectionState::Disconnecting => format!("Disconnecting from {name}"),
            _ => format!("Connecting to {name}"),
        }
    }

    pub fn menu_entries(&self) -> Vec<Entry> {
        let mut entries = vec![Entry::Info(self.state_line())];
        if self.approval_pending() {
            entries.push(Entry::Action {
                id: APPROVE_SERVICE.to_owned(),
                label: "Approve Background Service…".to_owned(),
                enabled: true,
            });
        }
        if self.connected_tunnel_ip().is_some() {
            entries.push(Entry::Action {
                id: COPY_TUNNEL_IP.to_owned(),
                label: "Copy tunnel IP".to_owned(),
                enabled: true,
            });
        }
        entries.push(Entry::Separator);
        let busy = self.active().map(|status| status.profile_id.as_str());
        for profile in &self.profiles {
            let name = self.display_name(&profile.id);
            let state = self.state_of(&profile.id);
            let (verb, id_prefix, enabled) = match state {
                ConnectionState::Disconnected | ConnectionState::Error => {
                    ("Connect", "connect", self.available && busy.is_none())
                }
                ConnectionState::Disconnecting => ("Disconnect", "disconnect", false),
                _ => ("Disconnect", "disconnect", self.available),
            };
            entries.push(Entry::Action {
                id: format!("{id_prefix}:{}", profile.id),
                label: format!("{verb} {name}"),
                enabled,
            });
        }
        if !self.profiles.is_empty() {
            entries.push(Entry::Separator);
        }
        entries.push(Entry::Action {
            id: "open".to_owned(),
            label: "Open WyVPN".to_owned(),
            enabled: true,
        });
        entries.push(Entry::Action {
            id: "quit".to_owned(),
            label: "Quit".to_owned(),
            enabled: true,
        });
        entries
    }
}

fn menu_label(text: &str) -> String {
    let clean = sanitize(text);
    let shortened = if clean.chars().count() > MENU_NAME_CHARS {
        let mut short: String = clean.chars().take(MENU_NAME_CHARS).collect();
        short.push('…');
        short
    } else {
        clean
    };
    if cfg!(windows) {
        escape_mnemonic(&shortened, '&')
    } else if cfg!(target_os = "linux") {
        escape_mnemonic(&shortened, '_')
    } else {
        shortened
    }
}

fn escape_mnemonic(text: &str, marker: char) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        out.push(c);
        if c == marker {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyvpn_ipc::{AuthMode, ErrorBody, ErrorCode, Transport};

    fn profile(id: &str, name: &str) -> ProfileSummary {
        ProfileSummary {
            id: id.into(),
            name: name.into(),
            server_name: String::new(),
            server_host: String::new(),
            user: String::new(),
            auth_mode: AuthMode::Pin,
            transports: vec![Transport::OpenVpn],
            imported_name: None,
        }
    }

    fn model() -> Model {
        Model {
            available: true,
            profiles: vec![profile("a", "Office"), profile("b", "Lab\u{202e}x")],
            statuses: vec![],
            ..Model::default()
        }
    }

    fn labels(model: &Model) -> Vec<(String, bool)> {
        model
            .menu_entries()
            .into_iter()
            .filter_map(|entry| match entry {
                Entry::Action { label, enabled, .. } => Some((label, enabled)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn approval_entry_shows_only_while_approval_is_pending() {
        let has_approval = |model: &Model| {
            model
                .menu_entries()
                .iter()
                .any(|entry| matches!(entry, Entry::Action { id, .. } if id == APPROVE_SERVICE))
        };
        let mut model = model();
        assert!(!has_approval(&model));
        model.available = false;
        model.daemon_status = DaemonStatus::NeedsSetup;
        model.setup = Some(ServiceStatus::NotRegistered);
        assert!(!has_approval(&model));
        model.setup = Some(ServiceStatus::RequiresApproval);
        assert!(has_approval(&model));
        assert_eq!(
            model.menu_entries()[1],
            Entry::Action {
                id: APPROVE_SERVICE.into(),
                label: "Approve Background Service…".into(),
                enabled: true,
            }
        );
    }

    #[test]
    fn state_line_reflects_the_daemon_status_when_unavailable() {
        let mut model = Model::default();
        let line = |model: &Model| model.menu_entries()[0].clone();
        assert_eq!(line(&model), Entry::Info("Service not running".into()));
        model.daemon_status = DaemonStatus::Starting;
        assert_eq!(line(&model), Entry::Info("Service starting…".into()));
        model.daemon_status = DaemonStatus::NeedsSetup;
        model.setup = Some(ServiceStatus::NotRegistered);
        assert_eq!(line(&model), Entry::Info("Service not running".into()));
        model.setup = Some(ServiceStatus::RequiresApproval);
        assert_eq!(line(&model), Entry::Info("Approval needed".into()));
    }

    #[test]
    fn daemon_state_change_is_reported_once() {
        let mut model = Model::default();
        let payload = AvailabilityPayload::new(
            "/s",
            &DaemonAvailability::Unreachable,
            Some(ServiceStatus::RequiresApproval),
        );
        assert!(model.set_daemon_state(&payload));
        assert!(model.approval_pending());
        assert!(!model.set_daemon_state(&payload));
        let enabled = AvailabilityPayload::new(
            "/s",
            &DaemonAvailability::Unreachable,
            Some(ServiceStatus::Enabled),
        );
        assert!(model.set_daemon_state(&enabled));
        assert!(!model.approval_pending());
    }

    #[test]
    fn idle_menu_offers_connect_with_sanitized_names() {
        let model = model();
        assert_eq!(model.icon_state(), IconState::Disconnected);
        assert_eq!(model.menu_entries()[0], Entry::Info("Disconnected".into()));
        assert_eq!(
            labels(&model),
            vec![
                ("Connect Office".into(), true),
                ("Connect Labx".into(), true),
                ("Open WyVPN".into(), true),
                ("Quit".into(), true),
            ]
        );
    }

    #[test]
    fn connected_state_shows_ip_and_disconnect() {
        let mut model = model();
        model.apply(&BridgeMsg::Statuses(vec![ConnectionStatus {
            state: ConnectionState::Connected,
            tunnel_ip: Some("10.0.0.2".into()),
            ..ConnectionStatus::disconnected("a")
        }]));
        assert_eq!(model.icon_state(), IconState::Connected);
        assert_eq!(
            model.menu_entries()[0],
            Entry::Info("Connected to Office (10.0.0.2)".into())
        );
        let labels = labels(&model);
        assert_eq!(labels[0], ("Copy tunnel IP".into(), true));
        assert_eq!(labels[1], ("Disconnect Office".into(), true));
        assert_eq!(labels[2], ("Connect Labx".into(), false));
    }

    #[test]
    fn copy_item_only_while_connected_with_an_ip() {
        let mut model = model();
        let has_copy = |model: &Model| labels(model).iter().any(|(l, _)| l == "Copy tunnel IP");
        let status = |state, ip: Option<&str>| {
            BridgeMsg::Statuses(vec![ConnectionStatus {
                state,
                tunnel_ip: ip.map(str::to_owned),
                ..ConnectionStatus::disconnected("a")
            }])
        };
        model.apply(&status(ConnectionState::Connecting, Some("10.0.0.2")));
        assert!(!has_copy(&model));
        model.apply(&status(ConnectionState::Connected, None));
        assert!(!has_copy(&model));
        model.apply(&status(ConnectionState::Connected, Some("10.0.0.2")));
        assert!(has_copy(&model));
        assert_eq!(model.connected_tunnel_ip().as_deref(), Some("10.0.0.2"));
    }

    #[test]
    fn events_drive_connecting_and_error_states() {
        let mut model = model();
        let change = |state, error| {
            BridgeMsg::Event(Event::StateChanged {
                profile_id: "a".into(),
                state,
                error,
            })
        };
        model.apply(&change(ConnectionState::Connecting, None));
        assert_eq!(model.icon_state(), IconState::Connecting);
        model.apply(&change(
            ConnectionState::Error,
            Some(ErrorBody::new(ErrorCode::AuthFailed, "bad")),
        ));
        assert_eq!(model.icon_state(), IconState::Disconnected);
        assert_eq!(labels(&model)[0], ("Connect Office".into(), true));
    }

    #[test]
    fn mnemonic_markers_are_doubled() {
        assert_eq!(escape_mnemonic("R&D & co", '&'), "R&&D && co");
        assert_eq!(escape_mnemonic("my_vpn_", '_'), "my__vpn__");
        assert_eq!(escape_mnemonic("R&D_x", '_'), "R&D__x");
        assert_eq!(escape_mnemonic("plain", '&'), "plain");
    }

    #[test]
    fn menu_label_escapes_for_the_current_platform() {
        let label = menu_label("R&D_lab");
        if cfg!(windows) {
            assert_eq!(label, "R&&D_lab");
        } else if cfg!(target_os = "linux") {
            assert_eq!(label, "R&D__lab");
        } else {
            assert_eq!(label, "R&D_lab");
        }
    }

    #[test]
    fn profile_snapshots_replace_the_list() {
        let mut model = model();
        model.apply(&BridgeMsg::Profiles(vec![profile("c", "New")]));
        assert_eq!(labels(&model)[0], ("Connect New".into(), true));
    }

    #[test]
    fn credentials_prompt_marks_awaiting_until_the_state_moves() {
        let mut model = model();
        model.apply(&BridgeMsg::Statuses(vec![ConnectionStatus::disconnected(
            "a",
        )]));
        model.apply(&BridgeMsg::Event(Event::CredentialsRequired {
            profile_id: "a".into(),
            mode: AuthMode::Pin,
        }));
        assert_eq!(model.statuses[0].awaiting, Some(AuthMode::Pin));
        model.apply(&BridgeMsg::Event(Event::StateChanged {
            profile_id: "a".into(),
            state: ConnectionState::Connecting,
            error: None,
        }));
        assert_eq!(model.statuses[0].awaiting, None);
    }

    #[test]
    fn unavailable_disables_profiles() {
        let mut model = model();
        model.apply(&BridgeMsg::Availability(DaemonAvailability::Unreachable));
        assert_eq!(
            model.menu_entries()[0],
            Entry::Info("Service not running".into())
        );
        let labels = labels(&model);
        assert!(!labels[0].1 && !labels[1].1);
        assert!(labels[2].1 && labels[3].1);
    }

    #[test]
    fn availability_payload_is_backwards_compatible_and_typed() {
        let json = |availability, service| {
            serde_json::to_value(AvailabilityPayload::new("/s", &availability, service)).unwrap()
        };
        assert_eq!(
            json(DaemonAvailability::Available, None),
            serde_json::json!({"available": true, "socket": "/s", "status": "available"})
        );
        assert_eq!(
            json(DaemonAvailability::Unreachable, None),
            serde_json::json!({"available": false, "socket": "/s", "status": "unreachable"})
        );
        assert_eq!(
            json(DaemonAvailability::Unreachable, None)["status"],
            "unreachable"
        );
        let starting = json(
            DaemonAvailability::Unreachable,
            Some(ServiceStatus::Enabled),
        );
        assert_eq!(starting["status"], "starting");
        assert_eq!(starting["available"], false);
        assert!(starting.get("setup").is_none());
        let setup = json(
            DaemonAvailability::Unreachable,
            Some(ServiceStatus::RequiresApproval),
        );
        assert_eq!(setup["status"], "needs_setup");
        assert_eq!(setup["setup"], "requires_approval");
        assert_eq!(setup["available"], false);
        assert_eq!(
            json(DaemonAvailability::NotPermitted, None)["status"],
            "not_permitted"
        );
        let mismatch = json(
            DaemonAvailability::Incompatible(Mismatch {
                client_version: "0.1.0".into(),
                client_protocol: 1,
                daemon_version: Some("0.0.9".into()),
                daemon_protocol: Some(2),
            }),
            Some(ServiceStatus::NotRegistered),
        );
        assert_eq!(mismatch["status"], "incompatible");
        assert_eq!(mismatch["mismatch"]["daemon_version"], "0.0.9");
        assert!(mismatch.get("setup").is_none());
    }
}
