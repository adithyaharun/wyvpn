use std::fmt;

use serde::Serialize;

use crate::about;

pub const NOTES_MAX_BYTES: usize = 8 * 1024;
const DATE_MAX_CHARS: usize = 64;
const VERSION_MAX_CHARS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub version: String,
    pub notes: Option<String>,
    pub date: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Offer {
    pub version: String,
    pub notes: String,
    pub date: Option<String>,
    pub installable: bool,
    pub release_url: String,
}

impl Offer {
    pub fn new(found: Found, installable: bool) -> Self {
        let version = sanitize_version(&found.version);
        Self {
            release_url: about::release_url(&version),
            version,
            notes: sanitize_notes(found.notes.as_deref().unwrap_or_default()),
            date: found
                .date
                .map(|date| wyvpn_ipc::sanitize_text(&date, DATE_MAX_CHARS)),
            installable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum UpdateState {
    Idle,
    Checking,
    UpToDate,
    Available(Offer),
    Dismissed(Offer),
    Disconnecting {
        version: String,
    },
    Downloading {
        version: String,
        received: u64,
        total: Option<u64>,
    },
    Installing {
        version: String,
    },
    Relaunching {
        version: String,
    },
    Failed {
        message: String,
    },
}

impl UpdateState {
    pub fn offer(&self) -> Option<&Offer> {
        match self {
            Self::Available(offer) | Self::Dismissed(offer) => Some(offer),
            _ => None,
        }
    }

    pub fn installing(&self) -> bool {
        matches!(
            self,
            Self::Disconnecting { .. }
                | Self::Downloading { .. }
                | Self::Installing { .. }
                | Self::Relaunching { .. }
        )
    }

    pub fn busy(&self) -> bool {
        matches!(self, Self::Checking) || self.installing()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(any(target_os = "macos", target_os = "windows")), allow(dead_code))]
pub enum Event {
    BeginCheck,
    Found { offer: Offer, manual: bool },
    NoUpdate,
    CheckFailed { message: String, manual: bool },
    Dismiss,
    BeginInstall,
    Disconnected,
    Progress { received: u64, total: Option<u64> },
    Downloaded,
    Installed,
    InstallFailed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejected(pub &'static str);

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

#[derive(Debug, Clone)]
pub struct Machine {
    state: UpdateState,
    resume: UpdateState,
    dismissed: Option<String>,
    dismissed_while_checking: bool,
}

impl Default for Machine {
    fn default() -> Self {
        Self {
            state: UpdateState::Idle,
            resume: UpdateState::Idle,
            dismissed: None,
            dismissed_while_checking: false,
        }
    }
}

impl Machine {
    pub fn state(&self) -> &UpdateState {
        &self.state
    }

    pub fn apply(&mut self, event: Event) -> Result<UpdateState, Rejected> {
        let next = self.next(event)?;
        self.state = next.clone();
        Ok(next)
    }

    fn next(&mut self, event: Event) -> Result<UpdateState, Rejected> {
        let checking = matches!(self.state, UpdateState::Checking);
        match event {
            Event::BeginCheck => {
                if self.state.busy() {
                    return Err(Rejected("an update is already in progress"));
                }
                self.resume = self.state.clone();
                self.dismissed_while_checking = false;
                Ok(UpdateState::Checking)
            }
            Event::Found { offer, manual } if checking => {
                let same = self.dismissed.as_deref() == Some(offer.version.as_str());
                let seen = same && (!manual || self.dismissed_while_checking);
                self.dismissed_while_checking = false;
                Ok(if seen {
                    UpdateState::Dismissed(offer)
                } else {
                    UpdateState::Available(offer)
                })
            }
            Event::NoUpdate if checking => {
                self.dismissed_while_checking = false;
                Ok(UpdateState::UpToDate)
            }
            Event::CheckFailed { message, manual } if checking => {
                self.dismissed_while_checking = false;
                Ok(if manual {
                    UpdateState::Failed { message }
                } else {
                    match &self.resume {
                        UpdateState::Available(offer)
                            if self.dismissed.as_deref() == Some(offer.version.as_str()) =>
                        {
                            UpdateState::Dismissed(offer.clone())
                        }
                        other => other.clone(),
                    }
                })
            }
            Event::Dismiss if checking => match self.resume.offer() {
                Some(offer) => {
                    self.dismissed = Some(offer.version.clone());
                    self.dismissed_while_checking = true;
                    Ok(UpdateState::Checking)
                }
                None => Err(Rejected("there is no update to dismiss")),
            },
            Event::Dismiss => match &self.state {
                UpdateState::Available(offer) => {
                    self.dismissed = Some(offer.version.clone());
                    Ok(UpdateState::Dismissed(offer.clone()))
                }
                _ => Err(Rejected("there is no update to dismiss")),
            },
            Event::BeginInstall => match self.state.offer() {
                Some(offer) if offer.installable => Ok(UpdateState::Disconnecting {
                    version: offer.version.clone(),
                }),
                Some(_) => Err(Rejected(
                    "this update is installed with the system packages",
                )),
                None => Err(Rejected("there is no update to install")),
            },
            Event::Disconnected => match &self.state {
                UpdateState::Disconnecting { version } => Ok(UpdateState::Downloading {
                    version: version.clone(),
                    received: 0,
                    total: None,
                }),
                _ => Err(Rejected("the update is not waiting for a disconnect")),
            },
            Event::Progress { received, total } => match &self.state {
                UpdateState::Downloading { version, .. } => Ok(UpdateState::Downloading {
                    version: version.clone(),
                    received,
                    total,
                }),
                _ => Err(Rejected("no download is running")),
            },
            Event::Downloaded => match &self.state {
                UpdateState::Downloading { version, .. } => Ok(UpdateState::Installing {
                    version: version.clone(),
                }),
                _ => Err(Rejected("no download is running")),
            },
            Event::Installed => match &self.state {
                UpdateState::Installing { version } => Ok(UpdateState::Relaunching {
                    version: version.clone(),
                }),
                _ => Err(Rejected("no install is running")),
            },
            Event::InstallFailed(message) => {
                if self.state.installing() && !matches!(self.state, UpdateState::Relaunching { .. })
                {
                    Ok(UpdateState::Failed { message })
                } else {
                    Err(Rejected("no install is running"))
                }
            }
            _ => Err(Rejected("an update check is not running")),
        }
    }
}

fn parse_version(raw: &str) -> Result<semver::Version, String> {
    semver::Version::parse(raw.trim().trim_start_matches('v'))
        .map_err(|_| "the update feed has an invalid version".to_owned())
}

pub fn newer_than(offered: &str, running: &str) -> Result<Option<String>, String> {
    let offered = parse_version(offered)?;
    let running = parse_version(running)?;
    Ok((offered > running).then(|| offered.to_string()))
}

fn sanitize_version(version: &str) -> String {
    wyvpn_ipc::sanitize_text(version, VERSION_MAX_CHARS)
}

pub fn sanitize_notes(notes: &str) -> String {
    let lines: Vec<String> = notes
        .lines()
        .map(|line| wyvpn_ipc::sanitize_text(line, NOTES_MAX_BYTES))
        .collect();
    let joined = lines.join("\n");
    let trimmed = joined.trim();
    if trimmed.len() <= NOTES_MAX_BYTES {
        return trimmed.to_owned();
    }
    let mut end = NOTES_MAX_BYTES;
    while !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    let mut capped = trimmed[..end].trim_end().to_owned();
    capped.push('…');
    capped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(version: &str) -> Offer {
        Offer::new(
            Found {
                version: version.into(),
                notes: Some("notes".into()),
                date: None,
            },
            true,
        )
    }

    fn found(machine: &mut Machine, version: &str, manual: bool) -> UpdateState {
        machine.apply(Event::BeginCheck).unwrap();
        machine
            .apply(Event::Found {
                offer: offer(version),
                manual,
            })
            .unwrap()
    }

    #[test]
    fn check_without_update_ends_up_to_date() {
        let mut machine = Machine::default();
        assert_eq!(machine.state(), &UpdateState::Idle);
        assert_eq!(
            machine.apply(Event::BeginCheck).unwrap(),
            UpdateState::Checking
        );
        assert_eq!(
            machine.apply(Event::NoUpdate).unwrap(),
            UpdateState::UpToDate
        );
    }

    #[test]
    fn check_with_update_becomes_available() {
        let mut machine = Machine::default();
        assert_eq!(
            found(&mut machine, "0.2.0", false),
            UpdateState::Available(offer("0.2.0"))
        );
    }

    #[test]
    fn manual_check_failure_is_reported() {
        let mut machine = Machine::default();
        machine.apply(Event::BeginCheck).unwrap();
        let state = machine
            .apply(Event::CheckFailed {
                message: "offline".into(),
                manual: true,
            })
            .unwrap();
        assert_eq!(
            state,
            UpdateState::Failed {
                message: "offline".into()
            }
        );
    }

    #[test]
    fn automatic_check_failure_restores_the_previous_state() {
        let mut machine = Machine::default();
        let available = found(&mut machine, "0.2.0", false);
        machine.apply(Event::BeginCheck).unwrap();
        let state = machine
            .apply(Event::CheckFailed {
                message: "offline".into(),
                manual: false,
            })
            .unwrap();
        assert_eq!(state, available);
    }

    #[test]
    fn later_dismisses_the_offer() {
        let mut machine = Machine::default();
        found(&mut machine, "0.2.0", false);
        assert_eq!(
            machine.apply(Event::Dismiss).unwrap(),
            UpdateState::Dismissed(offer("0.2.0"))
        );
        assert!(machine.apply(Event::Dismiss).is_err());
    }

    #[test]
    fn dismissed_version_is_not_prompted_again_by_an_automatic_check() {
        let mut machine = Machine::default();
        found(&mut machine, "0.2.0", false);
        machine.apply(Event::Dismiss).unwrap();
        assert_eq!(
            found(&mut machine, "0.2.0", false),
            UpdateState::Dismissed(offer("0.2.0"))
        );
        assert_eq!(
            found(&mut machine, "0.2.0", true),
            UpdateState::Available(offer("0.2.0"))
        );
    }

    #[test]
    fn dismissing_during_a_recheck_keeps_the_returning_offer_dismissed() {
        let mut machine = Machine::default();
        found(&mut machine, "0.2.0", false);
        machine.apply(Event::BeginCheck).unwrap();
        assert_eq!(
            machine.apply(Event::Dismiss).unwrap(),
            UpdateState::Checking
        );
        let state = machine
            .apply(Event::Found {
                offer: offer("0.2.0"),
                manual: true,
            })
            .unwrap();
        assert_eq!(state, UpdateState::Dismissed(offer("0.2.0")));
        assert_eq!(
            found(&mut machine, "0.2.0", true),
            UpdateState::Available(offer("0.2.0"))
        );
    }

    #[test]
    fn dismissing_during_a_failed_recheck_restores_a_dismissed_offer() {
        let mut machine = Machine::default();
        found(&mut machine, "0.2.0", false);
        machine.apply(Event::BeginCheck).unwrap();
        machine.apply(Event::Dismiss).unwrap();
        let state = machine
            .apply(Event::CheckFailed {
                message: "x".into(),
                manual: false,
            })
            .unwrap();
        assert_eq!(state, UpdateState::Dismissed(offer("0.2.0")));
    }

    #[test]
    fn dismissing_during_a_first_check_is_rejected() {
        let mut machine = Machine::default();
        machine.apply(Event::BeginCheck).unwrap();
        assert!(machine.apply(Event::Dismiss).is_err());
        assert_eq!(machine.state(), &UpdateState::Checking);
    }

    #[test]
    fn newer_version_than_the_dismissed_one_is_prompted_again() {
        let mut machine = Machine::default();
        found(&mut machine, "0.2.0", false);
        machine.apply(Event::Dismiss).unwrap();
        assert_eq!(
            found(&mut machine, "0.3.0", false),
            UpdateState::Available(offer("0.3.0"))
        );
    }

    #[test]
    fn install_walks_through_every_step() {
        let mut machine = Machine::default();
        found(&mut machine, "0.2.0", false);
        let version = || "0.2.0".to_owned();
        assert_eq!(
            machine.apply(Event::BeginInstall).unwrap(),
            UpdateState::Disconnecting { version: version() }
        );
        assert_eq!(
            machine.apply(Event::Disconnected).unwrap(),
            UpdateState::Downloading {
                version: version(),
                received: 0,
                total: None
            }
        );
        assert_eq!(
            machine
                .apply(Event::Progress {
                    received: 5,
                    total: Some(10)
                })
                .unwrap(),
            UpdateState::Downloading {
                version: version(),
                received: 5,
                total: Some(10)
            }
        );
        assert_eq!(
            machine.apply(Event::Downloaded).unwrap(),
            UpdateState::Installing { version: version() }
        );
        assert_eq!(
            machine.apply(Event::Installed).unwrap(),
            UpdateState::Relaunching { version: version() }
        );
    }

    #[test]
    fn install_can_start_from_a_dismissed_offer() {
        let mut machine = Machine::default();
        found(&mut machine, "0.2.0", false);
        machine.apply(Event::Dismiss).unwrap();
        assert!(machine.apply(Event::BeginInstall).is_ok());
    }

    #[test]
    fn a_failed_download_ends_in_failed() {
        let mut machine = Machine::default();
        found(&mut machine, "0.2.0", false);
        machine.apply(Event::BeginInstall).unwrap();
        machine.apply(Event::Disconnected).unwrap();
        let state = machine.apply(Event::InstallFailed("bad".into())).unwrap();
        assert_eq!(
            state,
            UpdateState::Failed {
                message: "bad".into()
            }
        );
        assert!(machine.apply(Event::BeginInstall).is_err());
    }

    #[test]
    fn a_check_while_busy_is_rejected_and_the_state_is_unchanged() {
        let mut machine = Machine::default();
        machine.apply(Event::BeginCheck).unwrap();
        assert!(machine.apply(Event::BeginCheck).is_err());
        assert_eq!(machine.state(), &UpdateState::Checking);
        let mut machine = Machine::default();
        found(&mut machine, "0.2.0", false);
        machine.apply(Event::BeginInstall).unwrap();
        let before = machine.state().clone();
        assert!(machine.apply(Event::BeginCheck).is_err());
        assert_eq!(machine.state(), &before);
    }

    #[test]
    fn install_without_an_offer_is_rejected() {
        for prepare in [
            Machine::default(),
            {
                let mut machine = Machine::default();
                machine.apply(Event::BeginCheck).unwrap();
                machine
            },
            {
                let mut machine = Machine::default();
                machine.apply(Event::BeginCheck).unwrap();
                machine.apply(Event::NoUpdate).unwrap();
                machine
            },
        ] {
            let mut machine = prepare;
            let before = machine.state().clone();
            assert!(machine.apply(Event::BeginInstall).is_err());
            assert_eq!(machine.state(), &before);
        }
    }

    #[test]
    fn notify_only_offers_cannot_be_installed() {
        let mut machine = Machine::default();
        machine.apply(Event::BeginCheck).unwrap();
        let notify_only = Offer::new(
            Found {
                version: "0.2.0".into(),
                notes: None,
                date: None,
            },
            false,
        );
        machine
            .apply(Event::Found {
                offer: notify_only,
                manual: true,
            })
            .unwrap();
        assert!(machine.apply(Event::BeginInstall).is_err());
    }

    #[test]
    fn out_of_order_events_are_rejected() {
        let mut machine = Machine::default();
        assert!(machine.apply(Event::Downloaded).is_err());
        assert!(machine.apply(Event::NoUpdate).is_err());
        assert!(machine.apply(Event::InstallFailed("x".into())).is_err());
        assert_eq!(machine.state(), &UpdateState::Idle);
    }

    #[test]
    fn notes_lose_control_characters_and_keep_lines() {
        let notes = sanitize_notes("  <b>Fixes</b>\x1b[31m red\r\n\u{202e}- one\x07\n- two  ");
        assert_eq!(notes, "<b>Fixes</b>[31m red\n- one\n- two");
    }

    #[test]
    fn long_notes_are_capped() {
        let notes = sanitize_notes(&"é".repeat(NOTES_MAX_BYTES));
        assert!(notes.len() <= NOTES_MAX_BYTES + '…'.len_utf8());
        assert!(notes.ends_with('…'));
        let many_lines = sanitize_notes(&"line\n".repeat(NOTES_MAX_BYTES));
        assert!(many_lines.ends_with('…'));
        assert!(many_lines.len() <= NOTES_MAX_BYTES + '…'.len_utf8());
        assert_eq!(sanitize_notes("short"), "short");
    }

    #[test]
    fn offer_links_to_the_release_page_and_cleans_its_fields() {
        let offer = Offer::new(
            Found {
                version: "1.2.3".into(),
                notes: None,
                date: Some("2026-10-21\u{1b}".into()),
            },
            true,
        );
        assert_eq!(offer.release_url, about::release_url("1.2.3"));
        assert_eq!(offer.notes, "");
        assert_eq!(offer.date.as_deref(), Some("2026-10-21"));
    }

    #[test]
    fn states_serialize_with_a_state_tag() {
        let json = serde_json::to_value(UpdateState::Available(offer("1.0.0"))).unwrap();
        assert_eq!(json["state"], "available");
        assert_eq!(json["version"], "1.0.0");
        assert_eq!(json["installable"], true);
        let json = serde_json::to_value(UpdateState::Downloading {
            version: "1.0.0".into(),
            received: 1,
            total: None,
        })
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({"state": "downloading", "version": "1.0.0", "received": 1, "total": null})
        );
        assert_eq!(
            serde_json::to_value(UpdateState::UpToDate).unwrap(),
            serde_json::json!({"state": "up_to_date"})
        );
    }
}
