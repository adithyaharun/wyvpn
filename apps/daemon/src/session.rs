use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, sleep_until, timeout};
use wyvpn_core::Profile;
use wyvpn_core::auth::openvpn_credentials;
use wyvpn_core::ovpn::{RenderOptions, render};
use wyvpn_core::wireguard;
use wyvpn_ipc::{
    ConnectionState, ConnectionStatus, ErrorBody, ErrorCode, Event, LogSource, Transport,
};
use zeroize::Zeroizing;

use crate::control::core_error;
use crate::egress::Egress;
use crate::launcher::{BoxFuture, LaunchRequest, Launched, Launcher, OpenVpnRequest, Running};
use crate::log::without_control;
use crate::openvpn::management::TunnelEvent;
use crate::state::{State, StoredProfile};
use crate::wireguard::launcher::WireGuardRequest;
use crate::wireguard::launcher::device_info;
use crate::wireguard::register::RegisterError;

const WATCHDOG: Duration = Duration::from_secs(60);
const BACKOFF: [Duration; 5] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(30),
];
const STATS_INTERVAL: Duration = Duration::from_secs(4);
const CREDENTIALS_TIMEOUT: Duration = Duration::from_secs(120);
const LAUNCH_GRACE: Duration = Duration::from_secs(5);
const PROBE_INTERVAL: Duration = Duration::from_secs(5);
const NETWORK_MISSES: u8 = 2;

enum Command {
    Stop,
}

struct Task {
    commands: mpsc::UnboundedSender<Command>,
    handle: Option<JoinHandle<()>>,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    reconnecting: Arc<AtomicBool>,
}

struct Slot {
    token: u64,
    profile_id: String,
    transport: Transport,
    auto_reconnect: Option<bool>,
    task: Option<Task>,
}

pub struct Manager {
    launcher: Arc<dyn Launcher>,
    slot: Mutex<Option<Slot>>,
    tokens: AtomicU64,
    closed: AtomicBool,
}

impl Manager {
    pub fn new(launcher: Arc<dyn Launcher>) -> Self {
        Self {
            launcher,
            slot: Mutex::new(None),
            tokens: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        }
    }

    fn slot(&self) -> MutexGuard<'_, Option<Slot>> {
        self.slot.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[cfg(any(target_os = "macos", test))]
    pub fn close_if_restartable(&self, restart_reconnecting: bool) -> bool {
        let slot = self.slot();
        let restartable = slot.as_ref().is_none_or(|held| {
            restart_reconnecting
                && held
                    .task
                    .as_ref()
                    .is_some_and(|task| task.reconnecting.load(Ordering::SeqCst))
        });
        if restartable {
            self.closed.store(true, Ordering::SeqCst);
        }
        restartable
    }

    pub fn claim(
        &self,
        profile_id: &str,
        transport: Transport,
        auto_reconnect: Option<bool>,
    ) -> Result<u64, ErrorBody> {
        let mut slot = self.slot();
        if self.closed.load(Ordering::SeqCst) {
            return Err(shutting_down());
        }
        match slot.as_ref() {
            Some(held) if held.profile_id != profile_id => {
                return Err(ErrorBody::new(
                    ErrorCode::InvalidState,
                    "another connection is active",
                ));
            }
            Some(Slot { task: Some(_), .. }) => {
                return Err(ErrorBody::new(
                    ErrorCode::InvalidState,
                    "profile is already connecting or connected",
                ));
            }
            _ => {}
        }
        let token = self.tokens.fetch_add(1, Ordering::Relaxed);
        *slot = Some(Slot {
            token,
            profile_id: profile_id.to_owned(),
            transport,
            auto_reconnect,
            task: None,
        });
        Ok(token)
    }

    pub fn expire_credentials(&self, state: &Arc<State>, token: u64) {
        let state = Arc::clone(state);
        tokio::spawn(async move {
            sleep(CREDENTIALS_TIMEOUT).await;
            let event = {
                let mut slot = state.sessions.slot();
                let Some(held) = slot
                    .as_ref()
                    .filter(|held| held.token == token && held.task.is_none())
                else {
                    return;
                };
                let id = held.profile_id.clone();
                *slot = None;
                state.log(LogSource::Daemon, "timed out waiting for credentials");
                settle(
                    &state,
                    &id,
                    Final::Failed(ErrorBody::new(
                        ErrorCode::Timeout,
                        "timed out waiting for credentials",
                    )),
                )
            };
            publish_all(&state, event);
        });
    }

    pub fn awaiting(&self, profile_id: &str) -> Option<Transport> {
        self.slot()
            .as_ref()
            .filter(|held| held.profile_id == profile_id && held.task.is_none())
            .map(|held| held.transport)
    }

    pub fn release(&self, profile_id: &str) {
        let mut slot = self.slot();
        if slot
            .as_ref()
            .is_some_and(|held| held.profile_id == profile_id && held.task.is_none())
        {
            *slot = None;
        }
    }

    pub fn start(
        &self,
        state: &Arc<State>,
        stored: StoredProfile,
        pin: Option<Zeroizing<String>>,
    ) -> Result<(), ErrorBody> {
        let mut slot = self.slot();
        if self.closed.load(Ordering::SeqCst) {
            return Err(shutting_down());
        }
        let held = slot
            .as_mut()
            .filter(|held| held.profile_id == stored.id && held.task.is_none())
            .ok_or_else(|| ErrorBody::new(ErrorCode::InvalidState, "no connection is pending"))?;
        let (commands, inbox) = mpsc::unbounded_channel();
        let reconnect =
            held.auto_reconnect.unwrap_or(true) && !stored.profile.header.disable_reconnect;
        let reconnecting = Arc::new(AtomicBool::new(false));
        let session = Session {
            state: Arc::clone(state),
            launcher: Arc::clone(&self.launcher),
            token: held.token,
            stored,
            transport: held.transport,
            pin,
            reconnect,
            commands: inbox,
            reconnecting: Arc::clone(&reconnecting),
        };
        held.task = Some(Task {
            reconnecting,
            commands,
            handle: Some(tokio::spawn(session.run())),
        });
        Ok(())
    }

    pub fn stop(&self, profile_id: &str) -> bool {
        let mut slot = self.slot();
        let Some(held) = slot.as_ref().filter(|held| held.profile_id == profile_id) else {
            return false;
        };
        let stopping = held
            .task
            .as_ref()
            .is_some_and(|task| task.commands.send(Command::Stop).is_ok());
        if !stopping {
            *slot = None;
        }
        stopping
    }

    pub async fn stop_and_wait(&self, profile_id: &str, timeout: Duration) {
        let handle = {
            let mut slot = self.slot();
            let Some(held) = slot.as_mut().filter(|held| held.profile_id == profile_id) else {
                return;
            };
            match held.task.as_mut() {
                Some(task) => {
                    let _ = task.commands.send(Command::Stop);
                    task.handle.take()
                }
                None => {
                    *slot = None;
                    None
                }
            }
        };
        if let Some(handle) = handle
            && tokio::time::timeout(timeout, handle).await.is_err()
        {
            tracing::warn!(profile_id, "session did not stop in time");
        }
    }

    fn finish(&self, state: &State, token: u64, outcome: Final) {
        let event = {
            let mut slot = self.slot();
            let Some(held) = slot.as_ref().filter(|held| held.token == token) else {
                return;
            };
            let id = held.profile_id.clone();
            *slot = None;
            settle(state, &id, outcome)
        };
        publish_all(state, event);
    }

    pub async fn shutdown(&self) {
        let handle = {
            let mut slot = self.slot();
            self.closed.store(true, Ordering::SeqCst);
            match slot.as_mut().map(|held| held.task.as_mut()) {
                Some(Some(task)) => {
                    let _ = task.commands.send(Command::Stop);
                    task.handle.take()
                }
                Some(None) => {
                    *slot = None;
                    None
                }
                None => None,
            }
        };
        if let Some(handle) = handle {
            let _ = handle.await;
        }
        let _ = tokio::task::spawn_blocking(|| {
            crate::wireguard::background::join_all(Duration::from_secs(5))
        })
        .await;
    }
}

fn shutting_down() -> ErrorBody {
    ErrorBody::new(ErrorCode::InvalidState, "the daemon is shutting down")
}

fn settle(state: &State, id: &str, outcome: Final) -> Option<Event> {
    match outcome {
        Final::Disconnected => state.apply_update(id, ConnectionState::Disconnected, |status| {
            *status = ConnectionStatus::disconnected(id);
        }),
        Final::Failed(error) => state.apply_update(id, ConnectionState::Error, |status| {
            clear_link(status);
            status.error = Some(error);
        }),
    }
}

fn publish_all(state: &State, event: Option<Event>) {
    if let Some(event) = event {
        state.publish(event);
    }
}

pub fn launch_request(
    stored: &StoredProfile,
    transport: Transport,
    pin: Option<&str>,
) -> Result<LaunchRequest, ErrorBody> {
    match transport {
        Transport::OpenVpn => openvpn_request(&stored.profile, pin).map(LaunchRequest::OpenVpn),
        Transport::WireGuard => {
            wireguard::ensure_registrable(&stored.profile, pin).map_err(|err| core_error(&err))?;
            Ok(LaunchRequest::WireGuard(Box::new(WireGuardRequest {
                profile: stored.profile.clone(),
                pins: stored.tls_pins.clone(),
                on_learned_pin: None,
                pin: pin.map(|pin| Zeroizing::new(pin.to_owned())),
                device: device_info(),
            })))
        }
    }
}

fn openvpn_request(profile: &Profile, pin: Option<&str>) -> Result<OpenVpnRequest, ErrorBody> {
    let config = render(
        profile,
        &RenderOptions {
            client_version: wyvpn_ipc::VERSION,
            dco: profile.header.ovpn_dco && !cfg!(target_os = "macos"),
        },
    )
    .map_err(|err| core_error(&err))?;
    let credentials = openvpn_credentials(profile, pin, None).map_err(|err| core_error(&err))?;
    Ok(OpenVpnRequest {
        config,
        credentials,
    })
}

enum Attempt {
    Stopped,
    AuthFailed,
    Refused(ErrorBody),
    Lost { network_changed: bool },
    Failed(ErrorBody),
}

enum Final {
    Disconnected,
    Failed(ErrorBody),
}

struct Session {
    state: Arc<State>,
    launcher: Arc<dyn Launcher>,
    token: u64,
    stored: StoredProfile,
    transport: Transport,
    pin: Option<Zeroizing<String>>,
    reconnect: bool,
    commands: mpsc::UnboundedReceiver<Command>,
    reconnecting: Arc<AtomicBool>,
}

struct EgressWatch {
    endpoint: SocketAddr,
    local_ip: Option<IpAddr>,
    misses: u8,
}

impl EgressWatch {
    fn new(remote: Option<&str>) -> Option<Self> {
        Some(Self {
            endpoint: remote?.parse().ok()?,
            local_ip: None,
            misses: 0,
        })
    }

    fn check(&mut self, egress: &dyn Egress) -> Result<(), Option<IpAddr>> {
        match egress.local_ip(self.endpoint) {
            Ok(ip) if self.local_ip.is_none_or(|known| known == ip) => {
                self.local_ip = Some(ip);
                self.misses = 0;
                Ok(())
            }
            Ok(_)
                if self
                    .local_ip
                    .is_some_and(|known| egress.still_assigned(known)) =>
            {
                self.misses = 0;
                Ok(())
            }
            other => {
                self.misses += 1;
                Err(other.ok())
            }
        }
    }
}

fn clear_link(status: &mut ConnectionStatus) {
    status.tunnel_ip = None;
    status.local_ip = None;
    status.server_endpoint = None;
    status.connected_since = None;
    status.last_handshake = None;
    status.rx_bytes = 0;
    status.tx_bytes = 0;
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

struct FinishGuard {
    state: Arc<State>,
    token: u64,
    outcome: Option<Final>,
}

impl Drop for FinishGuard {
    fn drop(&mut self) {
        let outcome = self.outcome.take().unwrap_or_else(|| {
            Final::Failed(ErrorBody::new(
                ErrorCode::Internal,
                "the session ended unexpectedly",
            ))
        });
        self.state.sessions.finish(&self.state, self.token, outcome);
    }
}

fn visible(message: &str) -> String {
    without_control(message).chars().take(200).collect()
}

impl Session {
    async fn run(mut self) {
        let mut guard = FinishGuard {
            state: Arc::clone(&self.state),
            token: self.token,
            outcome: None,
        };
        let outcome = self.drive().await;
        self.pin = None;
        match &outcome {
            Final::Disconnected => self.note("disconnected"),
            Final::Failed(error) => self.note(&format!("error: {}", visible(&error.message))),
        }
        guard.outcome = Some(outcome);
    }

    async fn drive(&mut self) -> Final {
        let mut reconnecting = false;
        let mut failures = 0;
        let mut immediate = false;
        loop {
            match self.attempt().await {
                Attempt::Stopped => return Final::Disconnected,
                Attempt::AuthFailed => {
                    return Final::Failed(ErrorBody::new(
                        ErrorCode::AuthFailed,
                        "the server rejected the credentials",
                    ));
                }
                Attempt::Refused(error) => return Final::Failed(error),
                Attempt::Lost { network_changed } => {
                    if !self.reconnect {
                        self.note("reconnect is off");
                        return Final::Disconnected;
                    }
                    reconnecting = true;
                    failures = 0;
                    immediate = network_changed;
                    self.mark_reconnecting();
                }
                Attempt::Failed(error) => {
                    if !reconnecting {
                        return Final::Failed(error);
                    }
                    let error = ErrorBody::new(error.code, visible(&error.message));
                    self.note(&format!("attempt failed: {}", error.message));
                    self.state
                        .update(&self.stored.id, ConnectionState::Connecting, |status| {
                            status.error = Some(error);
                        });
                }
            }
            if std::mem::take(&mut immediate) {
                self.note("reconnecting now");
                continue;
            }
            let delay = BACKOFF[failures.min(BACKOFF.len() - 1)];
            failures += 1;
            self.note(&format!(
                "reconnect attempt {failures} in {} s",
                delay.as_secs()
            ));
            tokio::select! {
                () = sleep(delay) => {}
                _ = self.commands.recv() => {
                    self.mark_disconnecting();
                    return Final::Disconnected;
                }
            }
        }
    }

    fn note(&self, text: &str) {
        self.state.log(LogSource::Daemon, text);
    }

    fn set_reconnecting(&self, value: bool) {
        let _slot = self.state.sessions.slot();
        self.reconnecting.store(value, Ordering::SeqCst);
    }

    fn mark_reconnecting(&self) {
        self.set_reconnecting(true);
        self.state
            .update(&self.stored.id, ConnectionState::Connecting, clear_link);
    }

    fn mark_disconnecting(&self) {
        self.note("disconnecting");
        self.state
            .update(&self.stored.id, ConnectionState::Disconnecting, |_| {});
    }

    async fn attempt(&mut self) -> Attempt {
        let deadline = Instant::now() + WATCHDOG;
        if let Some(pins) = self.state.stored_pins(&self.stored.id) {
            self.stored.tls_pins = pins;
        }
        let mut request = match launch_request(
            &self.stored,
            self.transport,
            self.pin.as_ref().map(|pin| pin.as_str()),
        ) {
            Ok(request) => request,
            Err(error) => return Attempt::Failed(error),
        };
        if let LaunchRequest::WireGuard(wireguard) = &mut request {
            let state = Arc::clone(&self.state);
            let id = self.stored.id.clone();
            wireguard.on_learned_pin = Some(Arc::new(move |key, fingerprint| {
                state.learn_pin(&id, key, fingerprint);
            }));
        }
        let launcher = Arc::clone(&self.launcher);
        let mut launch = launcher.launch(request);
        let launched = tokio::select! {
            launched = &mut launch => launched,
            _ = self.commands.recv() => {
                self.mark_disconnecting();
                reap(launch, &self.state).await;
                return Attempt::Stopped;
            }
            () = sleep_until(deadline) => {
                reap(launch, &self.state).await;
                self.note(&format!("not connected after {} seconds", WATCHDOG.as_secs()));
                return Attempt::Failed(ErrorBody::new(
                    ErrorCode::Timeout,
                    format!("not connected after {} seconds", WATCHDOG.as_secs()),
                ));
            }
        };
        let Launched {
            running,
            mut events,
        } = match launched {
            Ok(launched) => launched,
            Err(err) => {
                if let Some(refusal) = err.downcast_ref::<RegisterError>() {
                    let body = refusal.to_body();
                    self.note(&visible(&body.message));
                    return if refusal.is_terminal() {
                        Attempt::Refused(body)
                    } else {
                        Attempt::Failed(body)
                    };
                }
                tracing::warn!(profile = %self.stored.id, error = %format!("{err:#}"), "cannot start the tunnel");
                self.note(&format!(
                    "cannot start the tunnel: {}",
                    visible(&format!("{err:#}"))
                ));
                return Attempt::Failed(ErrorBody::new(
                    ErrorCode::Internal,
                    format!("cannot start the tunnel: {err:#}"),
                ));
            }
        };

        let id = self.stored.id.clone();
        let mut connected = false;
        let mut watch: Option<EgressWatch> = None;
        let mut next_probe = Instant::now();
        let mut last_stats: Option<Instant> = None;
        let outcome = loop {
            tokio::select! {
                _ = self.commands.recv() => break Attempt::Stopped,
                event = events.recv() => match event {
                    Some(TunnelEvent::Connected { tunnel_ip, remote }) => {
                        connected = true;
                        watch = EgressWatch::new(remote.as_deref());
                        if let Some(watch) = &mut watch {
                            let _ = watch.check(self.state.egress.as_ref());
                        }
                        next_probe = Instant::now() + PROBE_INTERVAL;
                        let local_ip = watch.as_ref().and_then(|watch| watch.local_ip);
                        self.note(&format!(
                            "connected, tunnel address {}",
                            tunnel_ip.as_deref().unwrap_or("unknown")
                        ));
                        self.set_reconnecting(false);
                        self.state.update(&id, ConnectionState::Connected, |status| {
                            status.tunnel_ip = tunnel_ip;
                            status.server_endpoint = remote;
                            status.local_ip = local_ip.map(|ip| ip.to_string());
                            status.connected_since = Some(unix_now());
                        });
                    }
                    Some(TunnelEvent::Log(line)) => self.state.log(LogSource::Tunnel, &line),
                    Some(TunnelEvent::Bytes { rx, tx }) => {
                        self.state.record_bytes(&id, rx, tx);
                        let now = Instant::now();
                        if connected && last_stats.is_none_or(|at| now - at >= STATS_INTERVAL) {
                            last_stats = Some(now);
                            self.state.publish(Event::Stats {
                                profile_id: id.clone(),
                                rx_bytes: rx,
                                tx_bytes: tx,
                            });
                        }
                    }
                    Some(TunnelEvent::Handshake(at)) => self.state.record_handshake(&id, at),
                    Some(TunnelEvent::State { .. }) => {}
                    Some(TunnelEvent::AuthFailed) => break Attempt::AuthFailed,
                    Some(TunnelEvent::Fatal(message)) => {
                        break self.dropped(connected, format!("tunnel process failed: {message}"));
                    }
                    Some(TunnelEvent::Exited(code)) => {
                        let reason = code.map_or_else(
                            || "tunnel process exited".to_owned(),
                            |code| format!("tunnel process exited with status {code}"),
                        );
                        break self.dropped(connected, reason);
                    }
                    None => break self.dropped(connected, "tunnel process exited".to_owned()),
                },
                () = sleep_until(next_probe), if watch.is_some() => {
                    next_probe = Instant::now() + PROBE_INTERVAL;
                    let Some(watch) = watch.as_mut() else { continue };
                    let previous = watch.local_ip;
                    match watch.check(self.state.egress.as_ref()) {
                        Ok(()) => self.state.record_local_ip(&id, watch.local_ip),
                        Err(now) if watch.misses >= NETWORK_MISSES => {
                            let describe = |ip: Option<IpAddr>| {
                                ip.map_or_else(|| "unreachable".to_owned(), |ip| ip.to_string())
                            };
                            self.note(&format!(
                                "network changed ({} to {}), restarting the tunnel",
                                describe(previous),
                                describe(now)
                            ));
                            break Attempt::Lost { network_changed: true };
                        }
                        Err(_) => {}
                    }
                }
                () = sleep_until(deadline), if !connected => {
                    self.note(&format!("not connected after {} seconds", WATCHDOG.as_secs()));
                    break Attempt::Failed(ErrorBody::new(
                        ErrorCode::Timeout,
                        format!("not connected after {} seconds", WATCHDOG.as_secs()),
                    ));
                }
            }
        };
        if matches!(outcome, Attempt::Stopped) {
            self.mark_disconnecting();
        }
        halt(running, &mut events, &self.state).await;
        outcome
    }

    fn dropped(&self, connected: bool, reason: String) -> Attempt {
        self.note(&visible(&reason));
        if connected {
            tracing::info!(profile = %self.stored.id, "tunnel dropped");
            Attempt::Lost {
                network_changed: false,
            }
        } else {
            Attempt::Failed(ErrorBody::new(ErrorCode::Server, reason))
        }
    }
}

async fn reap(launch: BoxFuture<'_, anyhow::Result<Launched>>, state: &Arc<State>) {
    if let Ok(Ok(Launched {
        running,
        mut events,
    })) = timeout(LAUNCH_GRACE, launch).await
    {
        halt(running, &mut events, state).await;
    }
}

async fn halt(
    running: Box<dyn Running>,
    events: &mut mpsc::Receiver<TunnelEvent>,
    state: &Arc<State>,
) {
    let stopped = running.stop();
    tokio::pin!(stopped);
    let mut open = true;
    loop {
        tokio::select! {
            () = &mut stopped => break,
            event = events.recv(), if open => match event {
                Some(TunnelEvent::Log(line)) => state.log(LogSource::Tunnel, &line),
                Some(_) => {}
                None => open = false,
            },
        }
    }
    while let Ok(event) = events.try_recv() {
        if let TunnelEvent::Log(line) = event {
            state.log(LogSource::Tunnel, &line);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use tokio::sync::broadcast;
    use wyvpn_ipc::{LogLine, Outcome, Request, Response, Sensitive};

    use super::*;
    use crate::admin::Peer;
    use crate::control::dispatch;
    use crate::egress::fake::Scripted;
    use crate::launcher::fake::{self, Process};
    use crate::state::MemoryProfiles;
    use crate::testdata;

    const A: &str = "p1";
    const B: &str = "p2";
    const PIN: &str = "1234";
    const LOCAL: &str = "192.168.1.20";
    const DISABLE_RECONNECT: (&str, &str) =
        ("\"wg\": true", "\"wg\": true, \"disable_reconnect\": true");

    struct Slow {
        inner: Arc<fake::Fake>,
        delay: Duration,
    }

    impl Launcher for Slow {
        fn launch(&self, request: LaunchRequest) -> BoxFuture<'_, anyhow::Result<Launched>> {
            Box::pin(async move {
                sleep(self.delay).await;
                self.inner.launch(request).await
            })
        }
    }

    struct FailsOnce {
        inner: Arc<fake::Fake>,
        fail_call: usize,
        calls: AtomicUsize,
    }

    impl Launcher for FailsOnce {
        fn launch(&self, request: LaunchRequest) -> BoxFuture<'_, anyhow::Result<Launched>> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == self.fail_call {
                return Box::pin(async { Err(anyhow::anyhow!("launch refused")) });
            }
            self.inner.launch(request)
        }
    }

    struct Panics;

    impl Launcher for Panics {
        fn launch(&self, _request: LaunchRequest) -> BoxFuture<'_, anyhow::Result<Launched>> {
            Box::pin(async { panic!("launcher exploded") })
        }
    }

    struct Rig {
        state: Arc<State>,
        launches: mpsc::UnboundedReceiver<Process>,
        events: broadcast::Receiver<Event>,
        egress: Arc<Scripted>,
    }

    fn save(state: &State, id: &str, modifiers: &[(&str, &str)]) {
        let profile = Profile::parse(&testdata::ovpn(modifiers)).unwrap();
        state
            .source
            .save(&StoredProfile {
                id: id.into(),
                name: id.into(),
                display_name: None,
                profile,
                tls_pins: Default::default(),
            })
            .unwrap();
    }

    fn connected() -> TunnelEvent {
        TunnelEvent::Connected {
            tunnel_ip: Some("10.8.0.2".into()),
            remote: Some("203.0.113.5:1194".into()),
        }
    }

    impl Rig {
        fn new(modifiers: &[(&str, &str)]) -> Self {
            Self::wrapping(modifiers, |fake| fake)
        }

        fn wrapping(
            modifiers: &[(&str, &str)],
            wrap: impl FnOnce(Arc<fake::Fake>) -> Arc<dyn Launcher>,
        ) -> Self {
            let (launcher, launches) = fake::pair();
            let egress = Arc::new(Scripted::steady(LOCAL));
            let state = Arc::new(State::with_egress(
                MemoryProfiles::default(),
                wrap(launcher),
                egress.clone(),
            ));
            save(&state, A, modifiers);
            save(&state, B, &[]);
            let events = state.events.subscribe();
            Self {
                state,
                launches,
                events,
                egress,
            }
        }

        async fn call(&self, request: Request) -> Outcome {
            dispatch(&self.state, &Peer::Unknown, request).await
        }

        async fn connect(&self, id: &str) -> Outcome {
            self.connect_with(id, None).await
        }

        async fn connect_with(&self, id: &str, auto_reconnect: Option<bool>) -> Outcome {
            self.call(Request::Connect {
                profile_id: id.into(),
                transport: Some(Transport::OpenVpn),
                auto_reconnect,
            })
            .await
        }

        async fn session_log(&self) -> (Option<String>, Vec<LogLine>) {
            match self.call(Request::SessionLog).await {
                Outcome::Result(Response::Log { profile_id, lines }) => (profile_id, lines),
                other => panic!("unexpected {other:?}"),
            }
        }

        async fn next_log(&mut self) -> (String, Vec<LogLine>) {
            loop {
                if let Event::Log { profile_id, lines } = self.events.recv().await.unwrap() {
                    return (profile_id, lines);
                }
            }
        }

        async fn submit(&self, id: &str) -> Outcome {
            self.call(Request::SubmitCredentials {
                profile_id: id.into(),
                pin: Some(Sensitive::new(PIN)),
                otp: None,
            })
            .await
        }

        async fn disconnect(&self, id: &str) -> Outcome {
            self.call(Request::Disconnect {
                profile_id: id.into(),
            })
            .await
        }

        async fn launch(&mut self, id: &str) -> Process {
            assert_eq!(self.connect(id).await, Outcome::Result(Response::Ok));
            assert_eq!(self.submit(id).await, Outcome::Result(Response::Ok));
            self.launches.recv().await.unwrap()
        }

        async fn connected(&mut self, id: &str) -> Process {
            let process = self.launch(id).await;
            process.send(connected()).await;
            self.until(ConnectionState::Connected).await;
            process
        }

        async fn next_state(&mut self) -> (ConnectionState, Option<ErrorBody>) {
            loop {
                if let Event::StateChanged { state, error, .. } = self.events.recv().await.unwrap()
                {
                    return (state, error);
                }
            }
        }

        async fn until(&mut self, wanted: ConnectionState) -> Option<ErrorBody> {
            loop {
                let (state, error) = self.next_state().await;
                if state == wanted {
                    return error;
                }
            }
        }

        async fn next_stats(&mut self) -> (u64, u64) {
            loop {
                if let Event::Stats {
                    rx_bytes, tx_bytes, ..
                } = self.events.recv().await.unwrap()
                {
                    return (rx_bytes, tx_bytes);
                }
            }
        }

        fn status(&self, id: &str) -> ConnectionStatus {
            self.state
                .statuses()
                .into_iter()
                .find(|status| status.profile_id == id)
                .unwrap()
        }

        fn idle(&mut self) -> bool {
            self.launches.try_recv().is_err() && self.state.sessions.slot().is_none()
        }
    }

    fn error_code(outcome: Outcome) -> ErrorCode {
        match outcome {
            Outcome::Error(error) => error.code,
            Outcome::Result(other) => panic!("expected error, got {other:?}"),
        }
    }

    async fn quiet_for(duration: Duration) {
        tokio::time::sleep(duration).await;
    }

    #[tokio::test(start_paused = true)]
    async fn connects_and_reports_status() {
        let mut rig = Rig::new(&[]);
        assert_eq!(rig.connect(A).await, Outcome::Result(Response::Ok));
        assert_eq!(rig.next_state().await.0, ConnectionState::Connecting);
        assert_eq!(rig.submit(A).await, Outcome::Result(Response::Ok));
        let process = rig.launches.recv().await.unwrap();
        assert!(process.credentials.is_some());
        assert_eq!(rig.status(A).state, ConnectionState::Connecting);

        process.send(connected()).await;
        assert_eq!(rig.next_state().await, (ConnectionState::Connected, None));
        let status = rig.status(A);
        assert_eq!(status.transport, Some(Transport::OpenVpn));
        assert_eq!(status.tunnel_ip.as_deref(), Some("10.8.0.2"));
        assert_eq!(status.server_endpoint.as_deref(), Some("203.0.113.5:1194"));
        assert!(status.connected_since.is_some_and(|since| since > 0));
        assert_eq!(status.error, None);
    }

    #[tokio::test(start_paused = true)]
    async fn stats_are_throttled() {
        let mut rig = Rig::new(&[]);
        let process = rig.connected(A).await;
        process.send(TunnelEvent::Bytes { rx: 10, tx: 20 }).await;
        assert_eq!(rig.next_stats().await, (10, 20));
        process.send(TunnelEvent::Bytes { rx: 30, tx: 40 }).await;
        while rig.status(A).rx_bytes != 30 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_secs(5)).await;
        process.send(TunnelEvent::Bytes { rx: 50, tx: 60 }).await;
        assert_eq!(rig.next_stats().await, (50, 60));
        let status = rig.status(A);
        assert_eq!((status.rx_bytes, status.tx_bytes), (50, 60));
    }

    #[tokio::test(start_paused = true)]
    async fn connect_without_pin_starts_immediately() {
        let mut rig = Rig::new(&[("\"password_mode\": \"pin\"", "\"password_mode\": null")]);
        assert_eq!(rig.connect(A).await, Outcome::Result(Response::Ok));
        let process = rig.launches.recv().await.unwrap();
        assert!(process.credentials.is_none());
        process.send(connected()).await;
        rig.until(ConnectionState::Connected).await;
    }

    #[tokio::test(start_paused = true)]
    async fn user_disconnect_stops_the_process() {
        let mut rig = Rig::new(&[]);
        let process = rig.connected(A).await;
        assert_eq!(rig.disconnect(A).await, Outcome::Result(Response::Ok));
        assert_eq!(rig.next_state().await.0, ConnectionState::Disconnecting);
        assert_eq!(rig.next_state().await.0, ConnectionState::Disconnected);
        assert!(process.stopped());
        let status = rig.status(A);
        assert_eq!(
            status,
            ConnectionStatus {
                profile_name: A.into(),
                ..ConnectionStatus::disconnected(A)
            }
        );
        quiet_for(Duration::from_secs(300)).await;
        assert!(rig.idle());
    }

    #[tokio::test(start_paused = true)]
    async fn auth_failure_stops_without_reconnect_and_drops_the_pin() {
        let mut rig = Rig::new(&[]);
        let process = rig.launch(A).await;
        process.send(TunnelEvent::AuthFailed).await;
        let error = rig.until(ConnectionState::Error).await.unwrap();
        assert_eq!(error.code, ErrorCode::AuthFailed);
        assert!(process.stopped());
        assert_eq!(rig.status(A).error, Some(error));
        quiet_for(Duration::from_secs(300)).await;
        assert!(rig.idle());
        assert_eq!(error_code(rig.submit(A).await), ErrorCode::InvalidState);

        assert_eq!(rig.connect(A).await, Outcome::Result(Response::Ok));
        assert_eq!(rig.state.sessions.awaiting(A), Some(Transport::OpenVpn));
        assert_eq!(rig.status(A).error, None);
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_times_out_after_sixty_seconds() {
        let mut rig = Rig::new(&[]);
        let process = rig.launch(A).await;
        let started = Instant::now();
        let error = rig.until(ConnectionState::Error).await.unwrap();
        assert_eq!(error.code, ErrorCode::Timeout);
        let elapsed = started.elapsed();
        assert!(elapsed >= WATCHDOG && elapsed < WATCHDOG + Duration::from_secs(1));
        assert!(process.stopped());
        quiet_for(Duration::from_secs(300)).await;
        assert!(rig.idle());
    }

    #[tokio::test(start_paused = true)]
    async fn failure_before_connecting_is_an_error_without_retry() {
        for event in [
            TunnelEvent::Fatal("boom".into()),
            TunnelEvent::Exited(Some(1)),
        ] {
            let mut rig = Rig::new(&[]);
            let process = rig.launch(A).await;
            process.send(event).await;
            let error = rig.until(ConnectionState::Error).await.unwrap();
            assert_eq!(error.code, ErrorCode::Server);
            assert!(process.stopped());
            quiet_for(Duration::from_secs(300)).await;
            assert!(rig.idle());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn launch_failure_is_an_error() {
        let state = Arc::new(State::with_launcher(
            MemoryProfiles::default(),
            fake::failing(),
        ));
        save(&state, A, &[]);
        let mut events = state.events.subscribe();
        let request = |request| async { dispatch(&state, &Peer::Unknown, request).await };
        request(Request::Connect {
            profile_id: A.into(),
            transport: Some(Transport::OpenVpn),
            auto_reconnect: None,
        })
        .await;
        let outcome = request(Request::SubmitCredentials {
            profile_id: A.into(),
            pin: Some(Sensitive::new(PIN)),
            otp: None,
        })
        .await;
        assert_eq!(outcome, Outcome::Result(Response::Ok));
        loop {
            if let Event::StateChanged {
                state: ConnectionState::Error,
                error,
                ..
            } = events.recv().await.unwrap()
            {
                assert_eq!(error.unwrap().code, ErrorCode::Internal);
                break;
            }
        }
        assert!(state.sessions.slot().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn link_drop_reconnects_with_fresh_credentials() {
        let mut rig = Rig::new(&[]);
        let first = rig.connected(A).await;
        first.send(TunnelEvent::Exited(Some(1))).await;
        assert_eq!(rig.next_state().await, (ConnectionState::Connecting, None));
        let status = rig.status(A);
        assert_eq!(status.tunnel_ip, None);
        assert_eq!(status.transport, Some(Transport::OpenVpn));
        let dropped = Instant::now();

        let second = rig.launches.recv().await.unwrap();
        let waited = dropped.elapsed();
        assert!(waited >= BACKOFF[0] && waited < BACKOFF[1]);
        assert!(first.stopped());
        assert_ne!(first.password(), second.password());
        second.send(connected()).await;
        assert_eq!(rig.next_state().await, (ConnectionState::Connected, None));

        second.send(TunnelEvent::Exited(None)).await;
        rig.until(ConnectionState::Connecting).await;
        let dropped = Instant::now();
        let third = rig.launches.recv().await.unwrap();
        let waited = dropped.elapsed();
        assert!(waited >= BACKOFF[0] && waited < BACKOFF[1]);
        assert_ne!(second.password(), third.password());
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_grows_then_caps_and_disconnect_cancels_it() {
        let mut rig = Rig::new(&[]);
        let first = rig.connected(A).await;
        first.send(TunnelEvent::Exited(Some(1))).await;
        rig.until(ConnectionState::Connecting).await;

        let mut waits = Vec::new();
        for _ in 0..BACKOFF.len() + 1 {
            let before = Instant::now();
            let process = rig.launches.recv().await.unwrap();
            waits.push(before.elapsed().as_secs());
            process.send(TunnelEvent::Exited(Some(1))).await;
        }
        assert_eq!(waits, [1, 2, 5, 10, 30, 30]);
        assert_eq!(rig.status(A).state, ConnectionState::Connecting);

        assert_eq!(rig.disconnect(A).await, Outcome::Result(Response::Ok));
        assert_eq!(rig.until(ConnectionState::Disconnecting).await, None);
        assert_eq!(rig.next_state().await.0, ConnectionState::Disconnected);
        quiet_for(Duration::from_secs(300)).await;
        assert!(rig.idle());
    }

    #[tokio::test(start_paused = true)]
    async fn reconnect_attempt_that_times_out_is_retried() {
        let mut rig = Rig::new(&[]);
        let first = rig.connected(A).await;
        first.send(TunnelEvent::Exited(Some(1))).await;
        let dropped = Instant::now();
        let second = rig.launches.recv().await.unwrap();
        let third = rig.launches.recv().await.unwrap();
        let elapsed = dropped.elapsed();
        assert!(second.stopped());
        assert!(elapsed >= BACKOFF[0] + WATCHDOG + BACKOFF[1]);
        assert_eq!(rig.status(A).state, ConnectionState::Connecting);
        third.send(connected()).await;
        rig.until(ConnectionState::Connected).await;
    }

    #[tokio::test(start_paused = true)]
    async fn auth_failure_while_reconnecting_ends_the_session() {
        let mut rig = Rig::new(&[]);
        let first = rig.connected(A).await;
        first.send(TunnelEvent::Exited(Some(1))).await;
        let second = rig.launches.recv().await.unwrap();
        second.send(TunnelEvent::AuthFailed).await;
        let error = rig.until(ConnectionState::Error).await.unwrap();
        assert_eq!(error.code, ErrorCode::AuthFailed);
        quiet_for(Duration::from_secs(300)).await;
        assert!(rig.idle());
    }

    #[tokio::test(start_paused = true)]
    async fn disabled_reconnect_ends_disconnected() {
        let mut rig = Rig::new(&[DISABLE_RECONNECT]);
        let process = rig.connected(A).await;
        process.send(TunnelEvent::Exited(Some(1))).await;
        assert_eq!(
            rig.next_state().await,
            (ConnectionState::Disconnected, None)
        );
        assert!(process.stopped());
        quiet_for(Duration::from_secs(300)).await;
        assert!(rig.idle());
    }

    #[tokio::test(start_paused = true)]
    async fn disconnect_while_awaiting_credentials_cancels_the_wait() {
        let mut rig = Rig::new(&[]);
        assert_eq!(rig.connect(A).await, Outcome::Result(Response::Ok));
        assert_eq!(rig.next_state().await.0, ConnectionState::Connecting);
        assert_eq!(rig.disconnect(A).await, Outcome::Result(Response::Ok));
        assert_eq!(rig.next_state().await.0, ConnectionState::Disconnected);
        assert_eq!(error_code(rig.submit(A).await), ErrorCode::InvalidState);
        assert!(rig.idle());
    }

    #[tokio::test(start_paused = true)]
    async fn connect_restarts_a_pending_credentials_wait() {
        let mut rig = Rig::new(&[]);
        assert_eq!(rig.connect(A).await, Outcome::Result(Response::Ok));
        assert_eq!(rig.connect(A).await, Outcome::Result(Response::Ok));
        assert_eq!(rig.submit(A).await, Outcome::Result(Response::Ok));
        rig.launches.recv().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn second_session_is_rejected() {
        let mut rig = Rig::new(&[]);
        assert_eq!(rig.connect(A).await, Outcome::Result(Response::Ok));
        assert_eq!(error_code(rig.connect(B).await), ErrorCode::InvalidState);
        assert_eq!(rig.submit(A).await, Outcome::Result(Response::Ok));
        let process = rig.launches.recv().await.unwrap();

        assert_eq!(error_code(rig.connect(B).await), ErrorCode::InvalidState);
        assert_eq!(error_code(rig.connect(A).await), ErrorCode::InvalidState);
        assert_eq!(rig.status(B).state, ConnectionState::Disconnected);

        rig.disconnect(A).await;
        rig.until(ConnectionState::Disconnected).await;
        assert!(process.stopped());
        assert_eq!(rig.connect(B).await, Outcome::Result(Response::Ok));
    }

    #[tokio::test(start_paused = true)]
    async fn pre_auth_profiles_fail_before_any_launch() {
        let variants = [
            ("\"wg\": true", "\"wg\": true, \"sso_auth\": true"),
            ("\"wg\": true", "\"wg\": true, \"device_auth\": true"),
            ("\"wg\": true", "\"wg\": false, \"dynamic_firewall\": true"),
        ];
        for modifier in variants {
            let mut rig = Rig::new(&[modifier]);
            assert_eq!(error_code(rig.connect(A).await), ErrorCode::UnsupportedAuth);
            assert_eq!(rig.status(A).state, ConnectionState::Disconnected);
            assert!(rig.idle());
            assert_eq!(rig.connect(B).await, Outcome::Result(Response::Ok));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_stops_the_running_session() {
        let mut rig = Rig::new(&[]);
        let process = rig.connected(A).await;
        rig.state.sessions.shutdown().await;
        assert!(process.stopped());
        assert_eq!(rig.status(A).state, ConnectionState::Disconnected);
        assert!(rig.idle());
    }

    #[tokio::test(start_paused = true)]
    async fn uninstall_wipes_data_only_after_the_session_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir(&data).unwrap();
        std::fs::write(data.join("p.json"), b"{}").unwrap();
        let mut rig = Rig::new(&[]);
        Arc::get_mut(&mut rig.state).unwrap().admin = crate::admin::AdminConfig {
            enabled: true,
            group: "admin".into(),
            bin_dir: dir.path().join("bin"),
            bundled_cli: dir.path().join("cli"),
            data_dir: data.clone(),
        };
        let process = rig.connected(A).await;
        let wipe = Request::Uninstall { remove_data: true };
        let admin = Peer::Fixed { admin: true };
        assert_eq!(
            dispatch(&rig.state, &admin, wipe).await,
            Outcome::Result(Response::Ok)
        );
        assert!(process.stopped());
        assert!(rig.idle());
        assert_eq!(rig.status(A).state, ConnectionState::Disconnected);
        assert_eq!(std::fs::read_dir(&data).unwrap().count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn status_reports_awaiting_only_while_credentials_are_pending() {
        let mut rig = Rig::new(&[]);
        assert_eq!(rig.status(A).awaiting, None);
        assert_eq!(rig.connect(A).await, Outcome::Result(Response::Ok));
        let waiting = rig.status(A);
        assert_eq!(waiting.state, ConnectionState::Connecting);
        assert_eq!(waiting.awaiting, Some(wyvpn_ipc::AuthMode::Pin));
        assert_eq!(rig.status(B).awaiting, None);

        assert_eq!(rig.submit(A).await, Outcome::Result(Response::Ok));
        rig.launches.recv().await.unwrap();
        assert_eq!(rig.status(A).awaiting, None);

        let mut rig = Rig::new(&[]);
        assert_eq!(rig.connect(A).await, Outcome::Result(Response::Ok));
        rig.until(ConnectionState::Error).await.unwrap();
        assert_eq!(rig.status(A).awaiting, None);
    }

    #[tokio::test(start_paused = true)]
    async fn unanswered_credentials_prompt_times_out() {
        let mut rig = Rig::new(&[]);
        assert_eq!(rig.connect(A).await, Outcome::Result(Response::Ok));
        let started = Instant::now();
        tokio::time::advance(CREDENTIALS_TIMEOUT - Duration::from_secs(1)).await;
        assert_eq!(rig.state.sessions.awaiting(A), Some(Transport::OpenVpn));

        let error = rig.until(ConnectionState::Error).await.unwrap();
        assert_eq!(error.code, ErrorCode::Timeout);
        assert!(started.elapsed() >= CREDENTIALS_TIMEOUT);
        assert!(rig.idle());
        assert_eq!(error_code(rig.submit(A).await), ErrorCode::InvalidState);
        assert_eq!(rig.connect(B).await, Outcome::Result(Response::Ok));
    }

    #[tokio::test(start_paused = true)]
    async fn answered_credentials_prompt_does_not_time_out() {
        let mut rig = Rig::new(&[]);
        let process = rig.connected(A).await;
        quiet_for(CREDENTIALS_TIMEOUT * 2).await;
        assert_eq!(rig.status(A).state, ConnectionState::Connected);
        assert!(!process.stopped());
    }

    #[tokio::test(start_paused = true)]
    async fn stop_during_a_slow_launch_stops_the_late_process() {
        let mut rig = Rig::wrapping(&[], |inner| {
            Arc::new(Slow {
                inner,
                delay: Duration::from_secs(3),
            })
        });
        assert_eq!(rig.connect(A).await, Outcome::Result(Response::Ok));
        assert_eq!(rig.submit(A).await, Outcome::Result(Response::Ok));
        tokio::task::yield_now().await;
        assert_eq!(rig.disconnect(A).await, Outcome::Result(Response::Ok));
        rig.until(ConnectionState::Disconnecting).await;
        rig.until(ConnectionState::Disconnected).await;
        let process = rig.launches.recv().await.unwrap();
        assert!(process.stopped());
        assert!(rig.idle());
    }

    #[tokio::test(start_paused = true)]
    async fn stop_during_a_hung_launch_is_bounded() {
        let mut rig = Rig::wrapping(&[], |inner| {
            Arc::new(Slow {
                inner,
                delay: Duration::from_secs(3600),
            })
        });
        assert_eq!(rig.connect(A).await, Outcome::Result(Response::Ok));
        assert_eq!(rig.submit(A).await, Outcome::Result(Response::Ok));
        tokio::task::yield_now().await;
        let stopped = Instant::now();
        assert_eq!(rig.disconnect(A).await, Outcome::Result(Response::Ok));
        rig.until(ConnectionState::Disconnected).await;
        assert!(stopped.elapsed() <= LAUNCH_GRACE + Duration::from_secs(1));
        assert!(rig.idle());
    }

    #[tokio::test(start_paused = true)]
    async fn panicking_session_releases_the_slot() {
        let mut rig = Rig::wrapping(&[], |_| Arc::new(Panics));
        assert_eq!(rig.connect(A).await, Outcome::Result(Response::Ok));
        assert_eq!(rig.submit(A).await, Outcome::Result(Response::Ok));
        let error = rig.until(ConnectionState::Error).await.unwrap();
        assert_eq!(error.code, ErrorCode::Internal);
        assert!(rig.idle());
        assert_eq!(rig.connect(B).await, Outcome::Result(Response::Ok));
    }

    #[tokio::test(start_paused = true)]
    async fn reconnect_failures_show_in_status_until_connected() {
        let mut rig = Rig::wrapping(&[], |inner| {
            Arc::new(FailsOnce {
                inner,
                fail_call: 1,
                calls: AtomicUsize::new(0),
            })
        });
        let first = rig.connected(A).await;
        first.send(TunnelEvent::Exited(Some(1))).await;
        rig.until(ConnectionState::Connecting).await;
        assert_eq!(rig.status(A).error, None);

        quiet_for(BACKOFF[0] + Duration::from_millis(100)).await;
        let status = rig.status(A);
        assert_eq!(status.state, ConnectionState::Connecting);
        let error = status.error.unwrap();
        assert_eq!(error.code, ErrorCode::Internal);
        assert!(error.message.contains("launch refused"));

        let third = rig.launches.recv().await.unwrap();
        third.send(connected()).await;
        assert_eq!(rig.until(ConnectionState::Connected).await, None);
        assert_eq!(rig.status(A).error, None);
    }

    #[tokio::test(start_paused = true)]
    async fn claim_after_shutdown_is_rejected() {
        let rig = Rig::new(&[]);
        rig.state.sessions.shutdown().await;
        assert_eq!(error_code(rig.connect(A).await), ErrorCode::InvalidState);
        assert!(rig.state.sessions.slot().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn local_ip_is_reported_after_connect_and_cleared_with_the_link() {
        let mut rig = Rig::new(&[]);
        let process = rig.connected(A).await;
        assert_eq!(rig.status(A).local_ip.as_deref(), Some(LOCAL));
        process.send(TunnelEvent::Exited(Some(1))).await;
        rig.until(ConnectionState::Connecting).await;
        assert_eq!(rig.status(A).local_ip, None);
    }

    #[tokio::test(start_paused = true)]
    async fn two_changed_probes_restart_the_tunnel_without_backoff() {
        let mut rig = Rig::new(&[]);
        let first = rig.connected(A).await;
        rig.egress.set("10.1.1.5");
        rig.until(ConnectionState::Connecting).await;
        let changed = Instant::now();
        let second = rig.launches.recv().await.unwrap();
        assert!(changed.elapsed() < BACKOFF[0]);
        assert!(first.stopped());
        assert_eq!(rig.status(A).local_ip, None);
        second.send(connected()).await;
        rig.until(ConnectionState::Connected).await;
        assert_eq!(rig.status(A).local_ip.as_deref(), Some("10.1.1.5"));

        rig.egress.set("172.16.0.9");
        rig.until(ConnectionState::Connecting).await;
        let third = rig.launches.recv().await.unwrap();
        third.send(TunnelEvent::Exited(Some(1))).await;
        let failed = Instant::now();
        rig.launches.recv().await.unwrap();
        assert!(failed.elapsed() >= BACKOFF[0]);
    }

    #[tokio::test(start_paused = true)]
    async fn changed_address_that_is_still_assigned_does_not_restart() {
        let mut rig = Rig::new(&[]);
        let process = rig.connected(A).await;
        rig.egress.keep_assigned(LOCAL);
        rig.egress.set("10.1.1.5");
        quiet_for(PROBE_INTERVAL * 6).await;
        assert_eq!(rig.status(A).state, ConnectionState::Connected);
        assert_eq!(rig.status(A).local_ip.as_deref(), Some(LOCAL));
        assert!(!process.stopped());
        assert!(rig.launches.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn tunnel_lines_queued_behind_a_failure_reach_the_log() {
        let mut rig = Rig::new(&[]);
        let process = rig.launch(A).await;
        process.send(TunnelEvent::AuthFailed).await;
        process.send(TunnelEvent::Log("AUTH_FAILED".into())).await;
        rig.until(ConnectionState::Error).await;
        let (_, lines) = rig.session_log().await;
        assert!(
            lines
                .iter()
                .any(|l| l.source == LogSource::Tunnel && l.text == "AUTH_FAILED")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn unreachable_route_twice_restarts_the_tunnel() {
        let mut rig = Rig::new(&[]);
        rig.connected(A).await;
        for _ in 0..2 {
            rig.egress.queue(Err(std::io::Error::other("unreachable")));
        }
        rig.until(ConnectionState::Connecting).await;
        rig.launches.recv().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn single_failed_probe_does_not_restart() {
        let mut rig = Rig::new(&[]);
        let process = rig.connected(A).await;
        rig.egress.queue(Err(std::io::Error::other("unreachable")));
        quiet_for(PROBE_INTERVAL * 6).await;
        assert_eq!(rig.status(A).state, ConnectionState::Connected);
        assert_eq!(rig.status(A).local_ip.as_deref(), Some(LOCAL));
        assert!(!process.stopped());
        assert!(rig.launches.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn reconnect_off_ends_disconnected_on_drop_and_network_change() {
        let mut rig = Rig::new(&[]);
        assert_eq!(
            rig.connect_with(A, Some(false)).await,
            Outcome::Result(Response::Ok)
        );
        assert_eq!(rig.submit(A).await, Outcome::Result(Response::Ok));
        let process = rig.launches.recv().await.unwrap();
        process.send(connected()).await;
        rig.until(ConnectionState::Connected).await;
        process.send(TunnelEvent::Exited(Some(1))).await;
        rig.until(ConnectionState::Disconnected).await;
        quiet_for(Duration::from_secs(300)).await;
        assert!(rig.idle());

        assert_eq!(
            rig.connect_with(A, Some(false)).await,
            Outcome::Result(Response::Ok)
        );
        assert_eq!(rig.submit(A).await, Outcome::Result(Response::Ok));
        let process = rig.launches.recv().await.unwrap();
        process.send(connected()).await;
        rig.until(ConnectionState::Connected).await;
        rig.egress.set("10.1.1.5");
        rig.until(ConnectionState::Disconnected).await;
        assert!(process.stopped());
        quiet_for(Duration::from_secs(300)).await;
        assert!(rig.idle());
    }

    #[tokio::test(start_paused = true)]
    async fn missing_or_true_auto_reconnect_keeps_reconnect_on() {
        for flag in [None, Some(true)] {
            let mut rig = Rig::new(&[]);
            assert_eq!(
                rig.connect_with(A, flag).await,
                Outcome::Result(Response::Ok)
            );
            assert_eq!(rig.submit(A).await, Outcome::Result(Response::Ok));
            let process = rig.launches.recv().await.unwrap();
            process.send(connected()).await;
            rig.until(ConnectionState::Connected).await;
            process.send(TunnelEvent::Exited(Some(1))).await;
            rig.until(ConnectionState::Connecting).await;
            rig.launches.recv().await.unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn profile_header_still_disables_reconnect_when_the_client_allows_it() {
        let mut rig = Rig::new(&[DISABLE_RECONNECT]);
        assert_eq!(
            rig.connect_with(A, Some(true)).await,
            Outcome::Result(Response::Ok)
        );
        assert_eq!(rig.submit(A).await, Outcome::Result(Response::Ok));
        let process = rig.launches.recv().await.unwrap();
        process.send(connected()).await;
        rig.until(ConnectionState::Connected).await;
        process.send(TunnelEvent::Exited(Some(1))).await;
        rig.until(ConnectionState::Disconnected).await;
    }

    #[tokio::test(start_paused = true)]
    async fn new_connect_clears_the_log_and_it_survives_the_session() {
        let mut rig = Rig::new(&[]);
        let process = rig.connected(A).await;
        process
            .send(TunnelEvent::Log("first session line".into()))
            .await;
        rig.next_log().await;
        assert_eq!(rig.disconnect(A).await, Outcome::Result(Response::Ok));
        rig.until(ConnectionState::Disconnected).await;
        quiet_for(Duration::from_secs(1)).await;
        let (profile_id, lines) = rig.session_log().await;
        assert_eq!(profile_id.as_deref(), Some(A));
        assert!(lines.iter().any(|line| line.text == "first session line"));
        assert!(lines.iter().any(|line| line.text == "disconnected"));

        assert_eq!(rig.connect(A).await, Outcome::Result(Response::Ok));
        let (_, lines) = rig.session_log().await;
        assert!(lines.iter().all(|line| line.text != "first session line"));
        assert_eq!(lines[0].seq, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn session_log_returns_lines_in_order_with_redaction() {
        let mut rig = Rig::new(&[]);
        let process = rig.connected(A).await;
        for text in ["one", "two\x1b", "auth-token SECRET"] {
            process.send(TunnelEvent::Log(text.into())).await;
        }
        let mut seen = 0;
        while seen < 3 {
            let (_, lines) = rig.next_log().await;
            seen += lines
                .iter()
                .filter(|line| line.source == LogSource::Tunnel)
                .count();
        }
        let (_, lines) = rig.session_log().await;
        let tunnel: Vec<&str> = lines
            .iter()
            .filter(|line| line.source == LogSource::Tunnel)
            .map(|line| line.text.as_str())
            .collect();
        assert_eq!(tunnel, ["one", "two", "auth-token [redacted]"]);
        assert!(lines.windows(2).all(|pair| pair[0].seq + 1 == pair[1].seq));
        assert!(lines.iter().any(|line| line.source == LogSource::Daemon));
        assert!(!format!("{lines:?}").contains(PIN));
    }

    #[tokio::test(start_paused = true)]
    async fn subscribers_receive_batched_log_events_with_increasing_sequence() {
        let mut rig = Rig::new(&[]);
        let process = rig.connected(A).await;
        let mut seqs = Vec::new();
        for round in 0..3 {
            for n in 0..20 {
                process
                    .send(TunnelEvent::Log(format!("r{round} l{n}")))
                    .await;
            }
            let (profile_id, lines) = rig.next_log().await;
            assert_eq!(profile_id, A);
            seqs.extend(lines.iter().map(|line| line.seq));
            quiet_for(Duration::from_millis(300)).await;
        }
        assert!(seqs.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(seqs.len() >= 60);
    }

    #[tokio::test(start_paused = true)]
    async fn log_batch_is_published_within_250ms() {
        let mut rig = Rig::new(&[]);
        let process = rig.connected(A).await;
        rig.next_log().await;
        let start = Instant::now();
        for n in 0..10 {
            process.send(TunnelEvent::Log(format!("l{n}"))).await;
        }
        rig.next_log().await;
        assert!(start.elapsed() <= Duration::from_millis(300));
    }

    #[tokio::test(start_paused = true)]
    async fn rename_updates_the_active_status_name() {
        let mut rig = Rig::new(&[]);
        rig.connected(A).await;
        let outcome = rig
            .call(Request::RenameProfile {
                profile_id: A.into(),
                name: " Home ".into(),
            })
            .await;
        assert!(matches!(outcome, Outcome::Result(Response::Profile { .. })));
        assert_eq!(rig.status(A).profile_name, "Home");
        assert_eq!(rig.status(A).state, ConnectionState::Connected);
    }

    #[test]
    fn an_empty_manager_is_restartable_and_closes() {
        let rig = Rig::new(&[]);
        assert!(rig.state.sessions.close_if_restartable(true));
        let error = rig
            .state
            .sessions
            .claim(A, Transport::OpenVpn, None)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidState);
        assert!(error.message.contains("shutting down"));
    }

    #[test]
    fn waiting_for_credentials_is_not_restartable() {
        let rig = Rig::new(&[]);
        rig.state
            .sessions
            .claim(A, Transport::OpenVpn, None)
            .unwrap();
        assert!(!rig.state.sessions.close_if_restartable(true));
        assert!(!rig.state.sessions.closed.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn an_initial_connect_and_a_live_tunnel_are_not_restartable() {
        let mut rig = Rig::new(&[]);
        let process = rig.launch(A).await;
        assert!(!rig.state.sessions.close_if_restartable(true));
        process.send(connected()).await;
        rig.until(ConnectionState::Connected).await;
        assert!(!rig.state.sessions.close_if_restartable(true));
        assert!(!rig.state.sessions.closed.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn a_reconnecting_session_is_restartable() {
        let mut rig = Rig::new(&[]);
        let process = rig.connected(A).await;
        process.send(TunnelEvent::Exited(Some(1))).await;
        rig.until(ConnectionState::Connecting).await;
        assert!(!rig.state.sessions.close_if_restartable(false));
        assert!(!rig.state.sessions.closed.load(Ordering::SeqCst));
        assert!(rig.state.sessions.close_if_restartable(true));
        assert!(rig.state.sessions.closed.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn a_reconnected_session_is_not_restartable() {
        let mut rig = Rig::new(&[]);
        let process = rig.connected(A).await;
        process.send(TunnelEvent::Exited(Some(1))).await;
        rig.until(ConnectionState::Connecting).await;
        let relaunched = rig.launches.recv().await.unwrap();
        relaunched.send(connected()).await;
        rig.until(ConnectionState::Connected).await;
        assert!(!rig.state.sessions.close_if_restartable(true));
        assert!(!rig.state.sessions.closed.load(Ordering::SeqCst));
    }

    mod wireguard {
        use std::sync::atomic::Ordering;

        use super::*;
        use crate::wireguard::launcher::testing::Fakes;
        use wyvpn_core::tls::Fingerprint;

        struct WgRig {
            rig: Rig,
            fakes: Arc<Fakes>,
        }

        impl WgRig {
            fn new() -> Self {
                let fakes = Arc::new(Fakes::new());
                let launcher = Arc::new(fakes.launcher());
                let rig = Rig::wrapping(&[], |_| launcher);
                Self { rig, fakes }
            }

            async fn start(&self) {
                let connect = self
                    .rig
                    .call(Request::Connect {
                        profile_id: A.into(),
                        transport: Some(Transport::WireGuard),
                        auto_reconnect: None,
                    })
                    .await;
                assert_eq!(connect, Outcome::Result(Response::Ok));
                assert_eq!(self.rig.submit(A).await, Outcome::Result(Response::Ok));
            }

            async fn backend(&self, index: usize) {
                while self.fakes.backend_count() <= index {
                    sleep(Duration::from_millis(10)).await;
                }
                self.fakes.handshake(index, 100, 200);
            }

            async fn connected(&mut self, index: usize) {
                if index == 0 {
                    self.start().await;
                }
                self.backend(index).await;
                self.rig.until(ConnectionState::Connected).await;
            }
        }

        #[tokio::test(start_paused = true)]
        async fn connects_reports_status_and_stops_cleanly() {
            let mut wg = WgRig::new();
            wg.connected(0).await;
            let status = wg.rig.status(A);
            assert_eq!(status.transport, Some(Transport::WireGuard));
            assert_eq!(status.tunnel_ip.as_deref(), Some("10.200.0.5"));
            assert_eq!(status.server_endpoint.as_deref(), Some("203.0.113.9:51820"));
            assert!(status.last_handshake.is_some());
            assert!(status.connected_since.is_some());

            let stats = wg.rig.next_stats().await;
            assert_eq!(stats, (100, 200));

            assert_eq!(wg.rig.disconnect(A).await, Outcome::Result(Response::Ok));
            wg.rig.until(ConnectionState::Disconnected).await;
            wg.fakes
                .backend(0)
                .with(|record| assert_eq!(record.downs, 1));
            assert!(
                wg.fakes
                    .net
                    .log()
                    .contains(&"del 10.0.0.0/8 dev fake0".to_owned())
            );
            assert_eq!(wg.fakes.dns.log().last().unwrap(), "restore");
            assert_eq!(wg.fakes.live_sessions(), 0);
            assert!(wg.rig.idle());
        }

        #[tokio::test(start_paused = true)]
        async fn keepalive_failure_reconnects_with_a_new_key() {
            let mut wg = WgRig::new();
            wg.fakes.pinger.push(Ok(true));
            wg.fakes.pinger.push(Ok(false));
            wg.connected(0).await;
            wg.rig.until(ConnectionState::Connecting).await;
            let lost = Instant::now();
            assert_eq!(wg.rig.status(A).last_handshake, None);

            wg.backend(1).await;
            wg.rig.until(ConnectionState::Connected).await;
            assert!(lost.elapsed() >= BACKOFF[0]);
            assert_eq!(wg.fakes.registrations.load(Ordering::SeqCst), 2);
            let key = |index| {
                wg.fakes
                    .backend(index)
                    .with(|r| r.public_keys_seen[0].clone())
            };
            assert_ne!(key(0), key(1));
            wg.fakes
                .backend(0)
                .with(|record| assert_eq!(record.downs, 1));
        }

        #[tokio::test(start_paused = true)]
        async fn a_learned_pin_is_saved_and_enforced_on_reconnect() {
            let mut wg = WgRig::new();
            let key = "203.0.113.9:8000".to_owned();
            let fingerprint = Fingerprint::of_certificate(b"learned");
            *wg.fakes.learned.lock().unwrap() = Some((key.clone(), fingerprint));
            wg.fakes.pinger.push(Ok(true));
            wg.fakes.pinger.push(Ok(false));
            wg.connected(0).await;
            let stored = wg.rig.state.source.load(A).unwrap().unwrap();
            assert_eq!(stored.tls_pins[&key], fingerprint);

            wg.rig.until(ConnectionState::Connecting).await;
            wg.backend(1).await;
            wg.rig.until(ConnectionState::Connected).await;
            let seen = wg.fakes.seen_pins.lock().unwrap();
            assert_eq!(seen.len(), 2);
            assert!(!seen[0].contains_key(&key));
            assert_eq!(seen[1][&key], fingerprint);
        }

        #[tokio::test(start_paused = true)]
        async fn a_denial_while_reconnecting_ends_the_session_without_retry() {
            let mut wg = WgRig::new();
            wg.fakes.pinger.push(Ok(true));
            wg.fakes.pinger.push(Ok(false));
            wg.connected(0).await;
            wg.fakes.deny.store(true, Ordering::SeqCst);
            let error = wg.rig.until(ConnectionState::Error).await.unwrap();
            assert_eq!(error.code, ErrorCode::AuthFailed);
            assert!(error.message.contains("no access"), "{}", error.message);
            quiet_for(Duration::from_secs(300)).await;
            assert_eq!(wg.fakes.registrations.load(Ordering::SeqCst), 2);
            assert!(wg.rig.idle());
        }

        #[tokio::test(start_paused = true)]
        async fn a_network_change_restarts_the_tunnel_without_backoff() {
            let mut wg = WgRig::new();
            wg.connected(0).await;
            assert_eq!(wg.rig.status(A).local_ip.as_deref(), Some(LOCAL));
            wg.rig.egress.set("10.1.1.5");
            wg.rig.until(ConnectionState::Connecting).await;
            let changed = Instant::now();
            wg.backend(1).await;
            wg.rig.until(ConnectionState::Connected).await;
            assert!(changed.elapsed() < BACKOFF[0]);
            assert_eq!(wg.rig.status(A).local_ip.as_deref(), Some("10.1.1.5"));
            wg.fakes
                .backend(0)
                .with(|record| assert_eq!(record.downs, 1));
        }

        #[tokio::test(start_paused = true)]
        async fn no_handshake_fails_with_a_timeout_before_the_watchdog() {
            let mut wg = WgRig::new();
            wg.start().await;
            let started = Instant::now();
            let error = wg.rig.until(ConnectionState::Error).await.unwrap();
            assert_eq!(error.code, ErrorCode::Server);
            assert!(
                error.message.contains("handshake timeout"),
                "{}",
                error.message
            );
            assert!(started.elapsed() < WATCHDOG);
            wg.fakes
                .backend(0)
                .with(|record| assert_eq!(record.downs, 1));
            quiet_for(Duration::from_secs(300)).await;
            assert!(wg.rig.idle());
        }

        #[tokio::test(start_paused = true)]
        async fn slow_registration_ends_in_its_own_error_before_the_watchdog() {
            let mut wg = WgRig::new();
            *wg.fakes.register_delay.lock().unwrap() = Duration::from_secs(3600);
            wg.start().await;
            let started = Instant::now();
            let error = wg.rig.until(ConnectionState::Error).await.unwrap();
            assert_eq!(error.code, ErrorCode::Timeout);
            assert_eq!(error.message, "registration request timed out");
            assert!(started.elapsed() < WATCHDOG);
            assert_eq!(wg.fakes.backend_count(), 0);
        }

        #[tokio::test(start_paused = true)]
        async fn an_unavailable_backend_is_an_actionable_error() {
            let mut wg = WgRig::new();
            wg.fakes.unavailable.store(true, Ordering::SeqCst);
            wg.start().await;
            let error = wg.rig.until(ConnectionState::Error).await.unwrap();
            assert!(error.message.contains("root"), "{}", error.message);
            assert_eq!(wg.fakes.registrations.load(Ordering::SeqCst), 0);
        }
    }
}
