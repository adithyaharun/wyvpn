use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::admin::AdminConfig;
use crate::egress::{Egress, RoutingTable};
use crate::launcher::Launcher;
use crate::log::SessionLog;
use crate::session::Manager;
use std::time::Duration;
use tokio::sync::broadcast;
use wyvpn_core::Profile;
use wyvpn_core::tls::Pins;
use wyvpn_ipc::{
    ConnectionState, ConnectionStatus, Event, LogLine, LogSource, ProfileSummary, Transport,
};

const LOG_BATCH: Duration = Duration::from_millis(250);

#[derive(Debug, Clone)]
pub struct StoredProfile {
    pub id: String,
    pub name: String,
    pub display_name: Option<String>,
    pub profile: Profile,
    pub tls_pins: Pins,
}

impl StoredProfile {
    pub fn summary(&self) -> ProfileSummary {
        summarize(
            &self.profile,
            &self.id,
            &self.name,
            self.display_name.as_deref(),
        )
    }
}

pub fn summarize(
    profile: &Profile,
    id: &str,
    name: &str,
    display_name: Option<&str>,
) -> ProfileSummary {
    let mut summary = profile.summary(id, display_name.unwrap_or(name));
    summary.imported_name = display_name.map(|_| name.to_owned());
    summary
}

pub trait ProfileSource: Send + Sync + 'static {
    fn summaries(&self) -> Vec<ProfileSummary>;
    fn load(&self, id: &str) -> io::Result<Option<StoredProfile>>;
    fn save(&self, stored: &StoredProfile) -> io::Result<()>;
    fn remove(&self, id: &str) -> io::Result<bool>;
}

#[cfg(test)]
#[derive(Default)]
pub struct MemoryProfiles {
    profiles: Mutex<std::collections::BTreeMap<String, StoredProfile>>,
}

#[cfg(test)]
impl MemoryProfiles {
    fn lock(&self) -> MutexGuard<'_, std::collections::BTreeMap<String, StoredProfile>> {
        self.profiles.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
impl ProfileSource for MemoryProfiles {
    fn summaries(&self) -> Vec<ProfileSummary> {
        self.lock().values().map(StoredProfile::summary).collect()
    }

    fn load(&self, id: &str) -> io::Result<Option<StoredProfile>> {
        Ok(self.lock().get(id).cloned())
    }

    fn save(&self, stored: &StoredProfile) -> io::Result<()> {
        self.lock().insert(stored.id.clone(), stored.clone());
        Ok(())
    }

    fn remove(&self, id: &str) -> io::Result<bool> {
        Ok(self.lock().remove(id).is_some())
    }
}

struct Runtime {
    status: ConnectionStatus,
}

pub struct State {
    pub source: Box<dyn ProfileSource>,
    pub events: broadcast::Sender<Event>,
    pub sessions: Manager,
    pub egress: Arc<dyn Egress>,
    pub admin: AdminConfig,
    profile_writes: Mutex<()>,
    log: Mutex<SessionLog>,
    runtime: Mutex<HashMap<String, Runtime>>,
}

impl State {
    pub fn with_launcher(source: impl ProfileSource, launcher: Arc<dyn Launcher>) -> Self {
        Self::with_egress(source, launcher, Arc::new(RoutingTable))
    }

    pub fn with_egress(
        source: impl ProfileSource,
        launcher: Arc<dyn Launcher>,
        egress: Arc<dyn Egress>,
    ) -> Self {
        Self {
            source: Box::new(source),
            events: broadcast::channel(64).0,
            sessions: Manager::new(launcher),
            egress,
            admin: AdminConfig::system(crate::storage::default_dir()),
            profile_writes: Mutex::default(),
            log: Mutex::default(),
            runtime: Mutex::default(),
        }
    }

    #[cfg(test)]
    pub fn with_admin(mut self, admin: AdminConfig) -> Self {
        self.admin = admin;
        self
    }

    #[cfg(test)]
    pub fn new(source: impl ProfileSource) -> Self {
        Self::with_egress(
            source,
            Arc::new(crate::launcher::Unavailable),
            Arc::new(crate::egress::fake::Scripted::steady("192.0.2.10")),
        )
    }

    pub fn lock_profiles(&self) -> MutexGuard<'_, ()> {
        self.profile_writes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn log_buffer(&self) -> MutexGuard<'_, SessionLog> {
        self.log.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn clear_log(&self, profile_id: &str) {
        self.log_buffer().clear(profile_id);
    }

    pub fn session_log(&self) -> (Option<String>, Vec<LogLine>) {
        self.log_buffer().snapshot()
    }

    pub fn log(self: &Arc<Self>, source: LogSource, text: &str) {
        if !self.log_buffer().push(source, text) {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            self.log_buffer().take_unpublished();
            return;
        };
        let state = Arc::clone(self);
        runtime.spawn(async move {
            tokio::time::sleep(LOG_BATCH).await;
            let batch = state.log_buffer().take_unpublished();
            if let Some((profile_id, lines)) = batch {
                state.publish(Event::Log { profile_id, lines });
            }
        });
    }

    fn runtime(&self) -> MutexGuard<'_, HashMap<String, Runtime>> {
        self.runtime.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn statuses(&self) -> Vec<ConnectionStatus> {
        let summaries = self.source.summaries();
        let awaiting: Vec<bool> = summaries
            .iter()
            .map(|profile| self.sessions.awaiting(&profile.id).is_some())
            .collect();
        let runtime = self.runtime();
        summaries
            .into_iter()
            .zip(awaiting)
            .map(|(profile, awaiting)| {
                let mut status = runtime.get(&profile.id).map_or_else(
                    || ConnectionStatus::disconnected(&profile.id),
                    |entry| entry.status.clone(),
                );
                status.profile_name = profile.name;
                status.awaiting = (awaiting && status.state == ConnectionState::Connecting)
                    .then_some(profile.auth_mode);
                status
            })
            .collect()
    }

    #[cfg(test)]
    pub fn connection_state(&self, id: &str) -> ConnectionState {
        self.runtime()
            .get(id)
            .map_or(ConnectionState::Disconnected, |entry| entry.status.state)
    }

    pub fn begin_connecting(&self, id: &str, transport: Transport) {
        let stale: Vec<String> = self
            .runtime()
            .iter()
            .filter(|(other, entry)| {
                other.as_str() != id && entry.status.state == ConnectionState::Error
            })
            .map(|(other, _)| other.clone())
            .collect();
        for other in stale {
            self.forget(&other);
        }
        self.update(id, ConnectionState::Connecting, |status| {
            *status = ConnectionStatus::disconnected(id);
            status.transport = Some(transport);
        });
    }

    pub fn reset(&self, id: &str) {
        self.update(id, ConnectionState::Disconnected, |status| {
            *status = ConnectionStatus::disconnected(id);
        });
    }

    pub fn forget(&self, id: &str) {
        let changed = self
            .runtime()
            .remove(id)
            .is_some_and(|entry| entry.status.state != ConnectionState::Disconnected);
        if changed {
            self.publish(Event::StateChanged {
                profile_id: id.to_owned(),
                state: ConnectionState::Disconnected,
                error: None,
            });
        }
    }

    #[cfg(test)]
    pub fn set_status(&self, status: ConnectionStatus) {
        self.runtime()
            .insert(status.profile_id.clone(), Runtime { status });
    }

    pub fn publish(&self, event: Event) {
        let _ = self.events.send(event);
    }

    pub fn update(
        &self,
        id: &str,
        state: ConnectionState,
        apply: impl FnOnce(&mut ConnectionStatus),
    ) {
        if let Some(event) = self.apply_update(id, state, apply) {
            self.publish(event);
        }
    }

    pub fn apply_update(
        &self,
        id: &str,
        state: ConnectionState,
        apply: impl FnOnce(&mut ConnectionStatus),
    ) -> Option<Event> {
        let (changed, error) = {
            let mut runtime = self.runtime();
            let entry = runtime.entry(id.to_owned()).or_insert_with(|| Runtime {
                status: ConnectionStatus::disconnected(id),
            });
            let previous = entry.status.state;
            entry.status.error = None;
            apply(&mut entry.status);
            entry.status.state = state;
            (previous != state, entry.status.error.clone())
        };
        changed.then(|| Event::StateChanged {
            profile_id: id.to_owned(),
            state,
            error,
        })
    }

    pub fn record_local_ip(&self, id: &str, local_ip: Option<std::net::IpAddr>) {
        if let Some(entry) = self.runtime().get_mut(id) {
            entry.status.local_ip = local_ip.map(|ip| ip.to_string());
        }
    }

    pub fn record_bytes(&self, id: &str, rx_bytes: u64, tx_bytes: u64) {
        if let Some(entry) = self.runtime().get_mut(id) {
            entry.status.rx_bytes = rx_bytes;
            entry.status.tx_bytes = tx_bytes;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connecting_another_profile_clears_a_stale_error() {
        let state = State::new(MemoryProfiles::default());
        state.set_status(ConnectionStatus {
            state: ConnectionState::Error,
            ..ConnectionStatus::disconnected("a")
        });
        let mut events = state.events.subscribe();

        state.begin_connecting("b", Transport::OpenVpn);

        assert_eq!(state.connection_state("a"), ConnectionState::Disconnected);
        assert_eq!(state.connection_state("b"), ConnectionState::Connecting);
        assert!(matches!(
            events.try_recv().unwrap(),
            Event::StateChanged { ref profile_id, state: ConnectionState::Disconnected, .. } if profile_id == "a"
        ));
    }
}
