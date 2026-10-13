use crate::model::Model;
use crate::settings::Settings;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Wait,
    Skip,
    Connect(String),
    MissingProfile,
}

pub fn decide(model: &Model, settings: &Settings, done: bool) -> Decision {
    if done || !model.loaded() {
        return Decision::Wait;
    }
    let Some(id) = settings.auto_connect_profile_id.as_deref() else {
        return Decision::Skip;
    };
    if model.session_in_progress() {
        return Decision::Skip;
    }
    if model.profiles.iter().any(|profile| profile.id == id) {
        Decision::Connect(id.to_owned())
    } else {
        Decision::MissingProfile
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::{BridgeMsg, DaemonAvailability};
    use wyvpn_ipc::{AuthMode, ConnectionState, ConnectionStatus, ProfileSummary, Transport};

    fn profile(id: &str) -> ProfileSummary {
        ProfileSummary {
            id: id.into(),
            name: id.into(),
            server_name: String::new(),
            server_host: String::new(),
            user: String::new(),
            auth_mode: AuthMode::Pin,
            transports: vec![Transport::OpenVpn],
            imported_name: None,
        }
    }

    fn ready() -> Model {
        let mut model = Model::default();
        model.apply(&BridgeMsg::Availability(DaemonAvailability::Available));
        model.apply(&BridgeMsg::Profiles(vec![profile("a"), profile("b")]));
        model.apply(&BridgeMsg::Statuses(vec![ConnectionStatus::disconnected(
            "a",
        )]));
        model
    }

    fn with_default(id: &str) -> Settings {
        Settings {
            auto_connect_profile_id: Some(id.into()),
            ..Settings::default()
        }
    }

    #[test]
    fn fires_on_first_availability_once_everything_is_loaded() {
        let settings = with_default("a");
        let mut model = Model::default();
        assert_eq!(decide(&model, &settings, false), Decision::Wait);
        model.apply(&BridgeMsg::Availability(DaemonAvailability::Available));
        model.apply(&BridgeMsg::Profiles(vec![profile("a")]));
        assert_eq!(decide(&model, &settings, false), Decision::Wait);
        model.apply(&BridgeMsg::Statuses(vec![]));
        assert_eq!(
            decide(&model, &settings, false),
            Decision::Connect("a".into())
        );
    }

    #[test]
    fn never_fires_again_after_it_has_run() {
        let settings = with_default("a");
        let mut model = ready();
        assert_eq!(decide(&model, &settings, true), Decision::Wait);
        model.apply(&BridgeMsg::Availability(DaemonAvailability::Unreachable));
        model.apply(&BridgeMsg::Availability(DaemonAvailability::Available));
        model.apply(&BridgeMsg::Statuses(vec![]));
        assert_eq!(decide(&model, &settings, true), Decision::Wait);
    }

    #[test]
    fn waits_again_after_the_daemon_drops_until_reloaded() {
        let settings = with_default("a");
        let mut model = ready();
        model.apply(&BridgeMsg::Availability(DaemonAvailability::Unreachable));
        assert_eq!(decide(&model, &settings, false), Decision::Wait);
        model.apply(&BridgeMsg::Availability(DaemonAvailability::Available));
        assert_eq!(decide(&model, &settings, false), Decision::Wait);
    }

    #[test]
    fn skipped_when_a_session_is_active() {
        let settings = with_default("a");
        for state in [ConnectionState::Connecting, ConnectionState::Connected] {
            let mut model = ready();
            model.apply(&BridgeMsg::Statuses(vec![ConnectionStatus {
                state,
                ..ConnectionStatus::disconnected("b")
            }]));
            assert_eq!(decide(&model, &settings, false), Decision::Skip);
        }
        let mut model = ready();
        model.statuses[0].awaiting = Some(AuthMode::Pin);
        assert_eq!(decide(&model, &settings, false), Decision::Skip);
    }

    #[test]
    fn missing_default_profile_is_reported_not_connected() {
        assert_eq!(
            decide(&ready(), &with_default("gone"), false),
            Decision::MissingProfile
        );
    }

    #[test]
    fn no_default_profile_skips() {
        assert_eq!(
            decide(&ready(), &Settings::default(), false),
            Decision::Skip
        );
    }
}
