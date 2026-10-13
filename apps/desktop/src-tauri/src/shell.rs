use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_notification::NotificationExt;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};
use wyvpn_ipc::{ConnectionState, ConnectionStatus, Event, ProfileSummary, Request};

use crate::autoconnect::{self, Decision};
use crate::bridge::{Bridge, BridgeMsg, DaemonAvailability, EventConfig};
use crate::error::sanitize;
use crate::model::{AvailabilityPayload, COPY_TUNNEL_IP, DaemonStatus, Model};
use crate::notifications::{self, Kind, Notification};
use crate::retry::RetryStore;
use crate::service;
use crate::settings::Settings;
use crate::tray::{self, Rendered};

pub const MAIN_WINDOW: &str = "main";
pub const EVENT_CHANNEL: &str = "daemon://event";
pub const AVAILABILITY_CHANNEL: &str = "daemon://availability";
pub const STATUSES_CHANNEL: &str = "daemon://statuses";
pub const PROFILES_CHANNEL: &str = "daemon://profiles";
pub const LICENSES_CHANNEL: &str = "app://open-licenses";
pub const DEFAULT_MISSING_CHANNEL: &str = "app://default-profile-missing";
const USER_DISCONNECT_WINDOW: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StartupNotice {
    pub profile_id: String,
}

pub struct Ctx {
    pub bridge: Arc<Bridge>,
    pub model: Mutex<Model>,
    pub rendered: Rendered,
    pub tray_ok: AtomicBool,
    pub retry: RetryStore,
    settings: Mutex<Settings>,
    settings_path: Option<PathBuf>,
    user_disconnects: Mutex<HashMap<String, Instant>>,
    drop_notified: Mutex<HashSet<String>>,
    auto_connect_done: AtomicBool,
    auto_connect_pending: Mutex<Option<String>>,
    subscribed: AtomicBool,
    startup_notice: Mutex<Option<StartupNotice>>,
    issued: AtomicU64,
    applied: AtomicU64,
}

impl Ctx {
    pub fn new(bridge: Arc<Bridge>, settings_path: Option<PathBuf>) -> Self {
        let settings = settings_path
            .as_deref()
            .map(Settings::load)
            .unwrap_or_default();
        Self {
            bridge,
            model: Mutex::new(Model::default()),
            rendered: Rendered::default(),
            tray_ok: AtomicBool::new(false),
            retry: RetryStore::default(),
            settings: Mutex::new(settings),
            settings_path,
            user_disconnects: Mutex::default(),
            drop_notified: Mutex::default(),
            auto_connect_done: AtomicBool::new(false),
            auto_connect_pending: Mutex::default(),
            subscribed: AtomicBool::new(false),
            startup_notice: Mutex::default(),
            issued: AtomicU64::new(0),
            applied: AtomicU64::new(0),
        }
    }

    fn ticket(&self) -> u64 {
        self.issued.fetch_add(1, Ordering::SeqCst) + 1
    }

    fn supersede(&self) {
        let ticket = self.ticket();
        self.applied.store(ticket, Ordering::SeqCst);
    }

    pub fn model(&self) -> MutexGuard<'_, Model> {
        self.model.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn settings(&self) -> Settings {
        self.settings
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn store_settings(&self, settings: Settings) -> std::io::Result<()> {
        let path = self
            .settings_path
            .as_deref()
            .ok_or_else(|| std::io::Error::other("no config directory"))?;
        settings.save(path)?;
        *self.settings.lock().unwrap_or_else(PoisonError::into_inner) = settings;
        Ok(())
    }

    pub fn mark_user_disconnect(&self, profile_id: &str) {
        let mut marks = self
            .user_disconnects
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        marks.retain(|_, at| at.elapsed() < USER_DISCONNECT_WINDOW);
        marks.insert(profile_id.to_owned(), Instant::now());
    }

    fn user_disconnected(&self, profile_id: &str) -> bool {
        self.user_disconnects
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(profile_id)
            .is_some_and(|at| at.elapsed() < USER_DISCONNECT_WINDOW)
    }

    fn drop_notified(&self) -> MutexGuard<'_, HashSet<String>> {
        self.drop_notified
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn take_auto_connect_pending(&self, profile_id: &str) -> bool {
        let mut pending = self
            .auto_connect_pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if pending.as_deref() == Some(profile_id) {
            *pending = None;
            return true;
        }
        false
    }

    fn pending_auto_connect(&self) -> Option<String> {
        self.auto_connect_pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn settle_auto_connect(&self, event: &Event) {
        if let Event::StateChanged {
            profile_id, state, ..
        } = event
            && *state != ConnectionState::Connecting
        {
            self.take_auto_connect_pending(profile_id);
        }
    }

    fn awaiting_pending_event(&self, statuses: &[ConnectionStatus]) -> Option<Event> {
        let pending = self.pending_auto_connect()?;
        statuses
            .iter()
            .find(|status| status.profile_id == pending)
            .and_then(|status| status.awaiting)
            .map(|mode| Event::CredentialsRequired {
                profile_id: pending,
                mode,
            })
    }

    pub fn take_startup_notice(&self) -> Option<StartupNotice> {
        self.startup_notice
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    pub fn availability_payload(&self) -> AvailabilityPayload {
        let availability = self.bridge.availability();
        let service = (availability == DaemonAvailability::Unreachable && service::applicable())
            .then(service::status);
        AvailabilityPayload::new(self.bridge.socket(), &availability, service)
    }
}

pub fn sync_tray(app: &AppHandle) {
    let ctx = app.state::<Ctx>();
    let model = ctx.model().clone();
    tray::update(app, &model, &ctx.rendered);
}

pub fn show_main(app: &AppHandle) {
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
    tauri::async_runtime::spawn(refresh(app.clone()));
}

pub fn show_licenses(app: &AppHandle) {
    show_main(app);
    let _ = app.emit(LICENSES_CHANNEL, ());
}

pub fn hide_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        let _ = window.hide();
    }
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(tauri::ActivationPolicy::Accessory);
}

pub fn on_menu(app: &AppHandle, id: &str) {
    match id {
        "open" => show_main(app),
        "quit" => app.exit(0),
        COPY_TUNNEL_IP => {
            let ip = app.state::<Ctx>().model().connected_tunnel_ip();
            if let Some(ip) = ip
                && let Err(error) = app.clipboard().write_text(sanitize(&ip))
            {
                tracing::warn!("copy tunnel ip failed: {error}");
            }
        }
        _ => {
            let (action, profile_id) = id.split_once(':').unwrap_or((id, ""));
            let request = match action {
                "connect" => app
                    .state::<Ctx>()
                    .settings()
                    .connect_request(profile_id.to_owned()),
                "disconnect" => {
                    app.state::<Ctx>().mark_user_disconnect(profile_id);
                    Request::Disconnect {
                        profile_id: profile_id.to_owned(),
                    }
                }
                _ => return,
            };
            let connecting = action == "connect";
            if connecting {
                show_main(app);
            }
            let bridge = app.state::<Ctx>().bridge.clone();
            let handle = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(error) = bridge.ok(request).await {
                    tracing::warn!("tray action failed: {}", error.code);
                    show_main(&handle);
                }
            });
        }
    }
}

pub async fn refresh(app: AppHandle) {
    let ctx = app.state::<Ctx>();
    let ticket = ctx.ticket();
    let bridge = ctx.bridge.clone();
    let profiles = bridge.list_profiles().await.ok();
    let statuses = bridge.statuses().await.ok();
    let (profiles_changed, statuses_changed) = {
        let mut model = ctx.model();
        if ticket <= ctx.applied.load(Ordering::SeqCst) {
            return;
        }
        ctx.applied.store(ticket, Ordering::SeqCst);
        model.profiles_loaded |= profiles.is_some();
        model.statuses_loaded |= statuses.is_some();
        let profiles_changed = profiles.filter(|profiles| model.profiles != *profiles);
        let statuses_changed = statuses.filter(|statuses| model.statuses != *statuses);
        if let Some(profiles) = &profiles_changed {
            model.profiles.clone_from(profiles);
        }
        if let Some(statuses) = &statuses_changed {
            model.statuses.clone_from(statuses);
        }
        (profiles_changed, statuses_changed)
    };
    emit_changes(&app, profiles_changed, statuses_changed);
    sync_tray(&app);
    check_auto_connect(&app);
}

pub async fn refresh_profiles(app: &AppHandle) {
    let ctx = app.state::<Ctx>();
    let ticket = ctx.ticket();
    let Ok(profiles) = ctx.bridge.list_profiles().await else {
        return;
    };
    let changed = {
        let mut model = ctx.model();
        if ticket <= ctx.applied.load(Ordering::SeqCst) {
            return;
        }
        ctx.applied.store(ticket, Ordering::SeqCst);
        let changed = model.profiles != profiles;
        model.profiles.clone_from(&profiles);
        changed
    };
    if changed {
        let _ = app.emit(PROFILES_CHANNEL, &profiles);
    }
    sync_tray(app);
}

fn emit_changes(
    app: &AppHandle,
    profiles: Option<Vec<ProfileSummary>>,
    statuses: Option<Vec<ConnectionStatus>>,
) {
    if let Some(profiles) = profiles {
        let _ = app.emit(PROFILES_CHANNEL, &profiles);
    }
    if let Some(statuses) = statuses {
        let _ = app.emit(STATUSES_CHANNEL, &statuses);
    }
}

pub fn refreshes_profiles(msg: &BridgeMsg) -> bool {
    matches!(msg, BridgeMsg::Event(Event::ProfilesChanged))
}

pub fn start_visible(tray_ok: bool, autostarted: bool) -> bool {
    !tray_ok || !autostarted
}

fn window_visible(app: &AppHandle) -> bool {
    app.get_webview_window(MAIN_WINDOW)
        .and_then(|window| window.is_visible().ok())
        .unwrap_or(false)
}

fn notify(app: &AppHandle, note: &Notification) {
    if let Err(error) = app
        .notification()
        .builder()
        .title(&note.title)
        .body(&note.body)
        .show()
    {
        tracing::warn!("notification failed: {error}");
    }
}

fn plan_notification(
    ctx: &Ctx,
    model: &Model,
    event: &Event,
    window_visible: bool,
) -> Option<Notification> {
    let (Event::StateChanged { profile_id, .. } | Event::CredentialsRequired { profile_id, .. }) =
        event
    else {
        return None;
    };
    if matches!(event, Event::CredentialsRequired { .. }) && model.is_awaiting(profile_id) {
        return None;
    }
    let mut drop_notified = ctx.drop_notified();
    if matches!(
        event,
        Event::StateChanged {
            state: ConnectionState::Connected,
            ..
        }
    ) {
        drop_notified.remove(profile_id);
    }
    let settings = ctx.settings();
    let name = model.plain_name(profile_id);
    let tunnel_ip = model.tunnel_ip(profile_id);
    let note = notifications::decide(
        model.state_of(profile_id),
        event,
        &notifications::Context {
            settings: &settings,
            name: &name,
            tunnel_ip: tunnel_ip.as_deref(),
            window_visible,
            user_disconnected: ctx.user_disconnected(profile_id),
            drop_notified: drop_notified.contains(profile_id),
        },
    );
    if note.as_ref().is_some_and(|note| note.kind == Kind::Dropped) {
        drop_notified.insert(profile_id.clone());
    }
    note
}

pub fn check_auto_connect(app: &AppHandle) {
    let ctx = app.state::<Ctx>();
    let settings = ctx.settings();
    if !ctx.subscribed.load(Ordering::SeqCst) {
        return;
    }
    let decision = {
        let model = ctx.model();
        let decision = autoconnect::decide(
            &model,
            &settings,
            ctx.auto_connect_done.load(Ordering::SeqCst),
        );
        if decision != Decision::Wait {
            ctx.auto_connect_done.store(true, Ordering::SeqCst);
        }
        decision
    };
    match decision {
        Decision::Wait | Decision::Skip => {}
        Decision::MissingProfile => {
            if let Some(profile_id) = settings.auto_connect_profile_id.clone() {
                let notice = StartupNotice { profile_id };
                let _ = app.emit(DEFAULT_MISSING_CHANNEL, &notice);
                *ctx.startup_notice
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = Some(notice);
            }
            if settings.notifications {
                notify(app, &Notification::missing_default());
            } else {
                show_main(app);
            }
        }
        Decision::Connect(profile_id) => {
            *ctx.auto_connect_pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(profile_id.clone());
            let bridge = ctx.bridge.clone();
            let handle = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(error) = bridge
                    .ok(settings.connect_request(profile_id.clone()))
                    .await
                {
                    tracing::warn!("auto-connect failed: {}", error.code);
                    handle.state::<Ctx>().take_auto_connect_pending(&profile_id);
                }
            });
        }
    }
}

fn changes_model(msg: &BridgeMsg) -> bool {
    match msg {
        BridgeMsg::Event(event) => matches!(event, Event::StateChanged { .. }),
        BridgeMsg::Subscribed => false,
        _ => true,
    }
}

pub async fn consume(app: AppHandle, mut rx: UnboundedReceiver<BridgeMsg>) {
    while let Some(msg) = rx.recv().await {
        let ctx = app.state::<Ctx>();
        if let BridgeMsg::Event(event @ Event::Log { .. }) = &msg {
            let _ = app.emit(EVENT_CHANNEL, event);
            continue;
        }
        let awaiting = match &msg {
            BridgeMsg::Statuses(statuses) => ctx.awaiting_pending_event(statuses),
            _ => None,
        };
        let visible = window_visible(&app);
        let (profiles_changed, note) = {
            let mut model = ctx.model();
            let note = match &msg {
                BridgeMsg::Event(event) => plan_notification(&ctx, &model, event, visible),
                BridgeMsg::Statuses(_) => awaiting
                    .as_ref()
                    .and_then(|event| plan_notification(&ctx, &model, event, visible)),
                _ => None,
            };
            let changed =
                matches!(&msg, BridgeMsg::Profiles(profiles) if model.profiles != *profiles);
            model.apply(&msg);
            if changes_model(&msg) {
                ctx.supersede();
            }
            (changed, note)
        };
        match &msg {
            BridgeMsg::Subscribed => ctx.subscribed.store(true, Ordering::SeqCst),
            BridgeMsg::Availability(availability) => {
                if !availability.is_available() {
                    ctx.subscribed.store(false, Ordering::SeqCst);
                }
                let payload = ctx.availability_payload();
                let _ = app.emit(AVAILABILITY_CHANNEL, &payload);
                if payload.status == DaemonStatus::NeedsSetup {
                    show_main(&app);
                }
                if ctx.bridge.is_available() {
                    tauri::async_runtime::spawn(refresh(app.clone()));
                }
            }
            BridgeMsg::Event(event) => {
                let _ = app.emit(EVENT_CHANNEL, event);
                ctx.settle_auto_connect(event);
                match event {
                    Event::StateChanged {
                        profile_id,
                        state: ConnectionState::Connected,
                        ..
                    } => {
                        let handle = app.clone();
                        let profile_id = profile_id.clone();
                        let notify_connected = note.is_some();
                        tauri::async_runtime::spawn(async move {
                            refresh(handle.clone()).await;
                            if notify_connected {
                                let ctx = handle.state::<Ctx>();
                                let (name, ip) = {
                                    let model = ctx.model();
                                    (model.plain_name(&profile_id), model.tunnel_ip(&profile_id))
                                };
                                notify(&handle, &Notification::connected(&name, ip.as_deref()));
                            }
                        });
                    }
                    Event::CredentialsRequired { profile_id, .. }
                        if ctx.take_auto_connect_pending(profile_id) =>
                    {
                        show_main(&app);
                    }
                    _ => {}
                }
                if refreshes_profiles(&msg) {
                    let handle = app.clone();
                    tauri::async_runtime::spawn(async move { refresh_profiles(&handle).await });
                }
            }
            BridgeMsg::Statuses(statuses) => {
                let _ = app.emit(STATUSES_CHANNEL, statuses);
                if let Some(Event::CredentialsRequired { profile_id, .. }) = &awaiting
                    && ctx.take_auto_connect_pending(profile_id)
                {
                    show_main(&app);
                }
            }
            BridgeMsg::Profiles(profiles) => {
                if profiles_changed {
                    let _ = app.emit(PROFILES_CHANNEL, profiles);
                }
            }
        }
        if let Some(note) = note.filter(|note| note.kind != Kind::Connected) {
            notify(&app, &note);
        }
        sync_tray(&app);
        check_auto_connect(&app);
    }
}

pub fn start_events(app: &AppHandle) {
    let (tx, rx) = unbounded_channel();
    let bridge = app.state::<Ctx>().bridge.clone();
    tauri::async_runtime::spawn(async move {
        bridge.run_events(tx, EventConfig::default()).await;
    });
    tauri::async_runtime::spawn(consume(app.clone(), rx));
}

pub fn probe(app: &AppHandle) {
    tauri::async_runtime::block_on(async {
        let ctx = app.state::<Ctx>();
        let bridge = ctx.bridge.clone();
        let probe = async {
            let profiles = bridge.list_profiles().await.ok()?;
            let statuses = bridge.statuses().await.ok()?;
            Some((profiles, statuses))
        };
        if let Ok(Some((profiles, statuses))) =
            tokio::time::timeout(Duration::from_millis(1500), probe).await
        {
            bridge.set_available(true);
            let mut model = ctx.model();
            model.available = true;
            model.profiles = profiles;
            model.statuses = statuses;
            model.profiles_loaded = true;
            model.statuses_loaded = true;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_autostart_with_a_tray_starts_hidden() {
        assert!(!start_visible(true, true));
        assert!(start_visible(false, true));
        assert!(start_visible(true, false));
        assert!(start_visible(false, false));
    }

    #[test]
    fn only_profiles_changed_triggers_a_profile_refresh() {
        assert!(refreshes_profiles(&BridgeMsg::Event(
            Event::ProfilesChanged
        )));
        assert!(!refreshes_profiles(&BridgeMsg::Availability(
            DaemonAvailability::Available
        )));
        assert!(!refreshes_profiles(&BridgeMsg::Event(Event::Unknown)));
    }

    fn ctx() -> Ctx {
        Ctx::new(Arc::new(Bridge::new("unused".into())), None)
    }

    fn state(profile_id: &str, state: ConnectionState) -> Event {
        Event::StateChanged {
            profile_id: profile_id.into(),
            state,
            error: None,
        }
    }

    fn set_pending(ctx: &Ctx, id: &str) {
        *ctx.auto_connect_pending.lock().unwrap() = Some(id.into());
    }

    #[test]
    fn pending_auto_connect_settles_on_any_non_connecting_state() {
        for settled in [
            ConnectionState::Connected,
            ConnectionState::Disconnected,
            ConnectionState::Error,
        ] {
            let ctx = ctx();
            set_pending(&ctx, "a");
            ctx.settle_auto_connect(&state("b", settled));
            assert_eq!(ctx.pending_auto_connect().as_deref(), Some("a"));
            ctx.settle_auto_connect(&state("a", ConnectionState::Connecting));
            assert_eq!(ctx.pending_auto_connect().as_deref(), Some("a"));
            ctx.settle_auto_connect(&state("a", settled));
            assert_eq!(ctx.pending_auto_connect(), None);
        }
    }

    #[test]
    fn awaiting_snapshot_for_the_pending_profile_acts_like_credentials_required() {
        let ctx = ctx();
        let awaiting = |id: &str| ConnectionStatus {
            awaiting: Some(wyvpn_ipc::AuthMode::Pin),
            ..ConnectionStatus::disconnected(id)
        };
        assert!(ctx.awaiting_pending_event(&[awaiting("a")]).is_none());
        set_pending(&ctx, "a");
        assert!(ctx.awaiting_pending_event(&[awaiting("b")]).is_none());
        assert!(
            ctx.awaiting_pending_event(&[ConnectionStatus::disconnected("a")])
                .is_none()
        );
        let event = ctx.awaiting_pending_event(&[awaiting("a")]);
        assert!(matches!(
            &event,
            Some(Event::CredentialsRequired { profile_id, .. }) if profile_id == "a"
        ));
        assert!(ctx.take_auto_connect_pending("a"));
        assert!(ctx.awaiting_pending_event(&[awaiting("a")]).is_none());
    }

    #[test]
    fn credentials_required_is_not_notified_twice_for_one_prompt() {
        let ctx = ctx();
        let mut model = Model::default();
        let event = Event::CredentialsRequired {
            profile_id: "a".into(),
            mode: wyvpn_ipc::AuthMode::Pin,
        };
        model.apply(&BridgeMsg::Statuses(vec![ConnectionStatus::disconnected(
            "a",
        )]));
        let first = plan_notification(&ctx, &model, &event, false);
        assert!(first.is_some_and(|note| note.kind == Kind::PinNeeded));
        model.apply(&BridgeMsg::Event(event.clone()));
        assert!(plan_notification(&ctx, &model, &event, false).is_none());
    }

    #[test]
    fn auto_connect_waits_for_the_subscription() {
        let ctx = ctx();
        assert!(!ctx.subscribed.load(Ordering::SeqCst));
        assert!(!changes_model(&BridgeMsg::Subscribed));
    }

    #[test]
    fn startup_notice_is_taken_once() {
        let ctx = ctx();
        assert_eq!(ctx.take_startup_notice(), None);
        *ctx.startup_notice.lock().unwrap() = Some(StartupNotice {
            profile_id: "p".into(),
        });
        assert_eq!(
            ctx.take_startup_notice().map(|notice| notice.profile_id),
            Some("p".into())
        );
        assert_eq!(ctx.take_startup_notice(), None);
    }
}
