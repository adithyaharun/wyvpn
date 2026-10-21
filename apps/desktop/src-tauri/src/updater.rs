#[cfg(any(target_os = "linux", test))]
mod linux;
mod schedule;
#[cfg(any(target_os = "macos", target_os = "windows", test))]
mod session;
mod state;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_opener::OpenerExt;

use crate::error::CmdError;
use crate::notifications::Notification;
use crate::shell::{self, Ctx};

pub use state::{Event, Found, Offer, UpdateState};
use state::{Machine, Rejected};

pub const UPDATE_CHANNEL: &str = "app://update";
pub const PROMPT_CHANNEL: &str = "app://update-prompt";

const INSTALLABLE: bool = cfg!(any(target_os = "macos", target_os = "windows"));

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub type Pending = tauri_plugin_updater::Update;
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub type Pending = ();

pub struct Updater<P> {
    machine: Mutex<Machine>,
    pending: Mutex<Option<P>>,
    notified: Mutex<Option<String>>,
    issued: AtomicU64,
    published: Mutex<u64>,
    last_success: AtomicU64,
}

impl<P> Default for Updater<P> {
    fn default() -> Self {
        Self {
            machine: Mutex::default(),
            pending: Mutex::default(),
            notified: Mutex::default(),
            issued: AtomicU64::new(0),
            published: Mutex::new(0),
            last_success: AtomicU64::new(0),
        }
    }
}

impl<P> Updater<P> {
    fn machine(&self) -> MutexGuard<'_, Machine> {
        self.machine.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn pending(&self) -> MutexGuard<'_, Option<P>> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn state(&self) -> UpdateState {
        self.machine().state().clone()
    }

    fn set_pending(&self, pending: P) {
        *self.pending() = Some(pending);
    }

    #[cfg(any(target_os = "macos", target_os = "windows", test))]
    fn take_pending(&self) -> Option<P> {
        self.pending().take()
    }

    fn apply(
        &self,
        event: Event,
        publish: impl FnOnce(&UpdateState),
    ) -> Result<UpdateState, Rejected> {
        let (next, ticket) = {
            let mut machine = self.machine();
            let next = machine.apply(event)?;
            if matches!(
                next,
                UpdateState::Idle | UpdateState::UpToDate | UpdateState::Failed { .. }
            ) {
                self.pending().take();
            }
            (next, self.issued.fetch_add(1, Ordering::SeqCst) + 1)
        };
        let mut published = self
            .published
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if ticket > *published {
            *published = ticket;
            publish(&next);
        }
        Ok(next)
    }

    fn record_success(&self, now: u64) {
        self.last_success.store(now, Ordering::SeqCst);
    }

    fn last_success(&self) -> Option<u64> {
        Some(self.last_success.load(Ordering::SeqCst)).filter(|at| *at != 0)
    }

    fn plan_notification(
        &self,
        notifications: bool,
        window_visible: bool,
        version: &str,
    ) -> Option<Notification> {
        let mut last = self.notified.lock().unwrap_or_else(PoisonError::into_inner);
        let note = notification_for(notifications, window_visible, version, last.as_deref())?;
        *last = Some(version.to_owned());
        Some(note)
    }
}

fn notification_for(
    notifications: bool,
    window_visible: bool,
    version: &str,
    last_notified: Option<&str>,
) -> Option<Notification> {
    (notifications && !window_visible && last_notified != Some(version))
        .then(|| Notification::update_available(version))
}

fn rejection(rejected: Rejected) -> CmdError {
    CmdError::invalid_request(&rejected.to_string())
}

fn transition(app: &AppHandle, event: Event) -> Result<UpdateState, Rejected> {
    let ctx = app.state::<Ctx>();
    ctx.updater.apply(event, |state| {
        ctx.model().set_update(state);
        let _ = app.emit(UPDATE_CHANNEL, state);
        shell::sync_tray(app);
    })
}

#[derive(Clone, Serialize)]
struct Prompt {
    outcome: &'static str,
}

fn prompt_outcome(state: &UpdateState) -> Option<&'static str> {
    match state {
        UpdateState::Available(_) | UpdateState::Dismissed(_) => Some("available"),
        UpdateState::UpToDate => Some("up_to_date"),
        UpdateState::Failed { .. } => Some("failed"),
        _ => None,
    }
}

pub fn current_state(app: &AppHandle) -> UpdateState {
    app.state::<Ctx>().updater.state()
}

pub async fn check(app: &AppHandle, manual: bool) -> Result<UpdateState, CmdError> {
    let ctx = app.state::<Ctx>();
    transition(app, Event::BeginCheck).map_err(rejection)?;
    let event = match lookup(app).await {
        Ok(Some((found, pending))) => {
            ctx.updater.set_pending(pending);
            Event::Found {
                offer: Offer::new(found, INSTALLABLE),
                manual,
            }
        }
        Ok(None) => Event::NoUpdate,
        Err(message) => {
            tracing::warn!("update check failed: {message}");
            Event::CheckFailed { message, manual }
        }
    };
    let succeeded = matches!(event, Event::Found { .. } | Event::NoUpdate);
    let state = transition(app, event).map_err(rejection)?;
    if succeeded {
        ctx.updater.record_success(now_secs());
    }
    if manual {
        if let Some(outcome) = prompt_outcome(&state) {
            let _ = app.emit(PROMPT_CHANNEL, Prompt { outcome });
        }
    } else if let UpdateState::Available(offer) = &state {
        let note = ctx.updater.plan_notification(
            ctx.settings().notifications,
            shell::window_visible(app),
            &offer.version,
        );
        if let Some(note) = note {
            shell::notify(app, &note);
        }
    }
    Ok(state)
}

pub fn dismiss(app: &AppHandle) -> Result<UpdateState, CmdError> {
    transition(app, Event::Dismiss).map_err(rejection)
}

pub fn open_page(app: &AppHandle) -> Result<(), CmdError> {
    let state = current_state(app);
    let offer = state
        .offer()
        .ok_or_else(|| CmdError::invalid_request("there is no update to open"))?;
    app.opener()
        .open_url(&offer.release_url, None::<&str>)
        .map_err(|_| CmdError::internal("could not open the browser"))
}

pub fn check_from_menu(app: &AppHandle) {
    shell::show_main(app);
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(error) = check(&app, true).await {
            tracing::warn!("manual update check rejected: {}", error.message);
        }
    });
}

pub fn install_from_menu(app: &AppHandle) {
    let state = current_state(app);
    match state.offer() {
        Some(offer) if offer.installable => {
            shell::show_main(app);
            let _ = app.emit(
                PROMPT_CHANNEL,
                Prompt {
                    outcome: "available",
                },
            );
        }
        Some(_) => {
            if let Err(error) = open_page(app) {
                tracing::warn!("opening the release page failed: {}", error.message);
            }
        }
        None => {}
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |elapsed| elapsed.as_secs().max(1))
}

pub async fn schedule(app: AppHandle) {
    schedule::run(
        schedule::FIRST_CHECK_DELAY,
        schedule::CHECK_POLL,
        schedule::CHECK_PERIOD,
        now_secs,
        || app.state::<Ctx>().updater.last_success(),
        || app.state::<Ctx>().settings().check_updates,
        || automatic_check(&app),
    )
    .await;
}

async fn automatic_check(app: &AppHandle) {
    if let Err(error) = check(app, false).await {
        tracing::warn!("automatic update check skipped: {}", error.message);
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn install(app: &AppHandle) -> Result<(), CmdError> {
    transition(app, Event::BeginInstall).map_err(rejection)?;
    tauri::async_runtime::spawn(run_install(app.clone()));
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn install(_app: &AppHandle) -> Result<(), CmdError> {
    Err(CmdError::invalid_request(
        "updates are installed with the system packages",
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[cfg(target_os = "linux")]
async fn lookup(app: &AppHandle) -> Result<Option<(Found, Pending)>, String> {
    let config = app.config().plugins.0.get("updater");
    let url = linux::endpoint(config)?;
    let body = tokio::time::timeout(CHECK_TIMEOUT, linux::fetch(&url))
        .await
        .map_err(|_| "the update server did not answer in time".to_owned())??;
    let running = app.package_info().version.to_string();
    Ok(linux::evaluate(&body, &running)?.map(|found| (found, ())))
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
async fn lookup(app: &AppHandle) -> Result<Option<(Found, Pending)>, String> {
    use tauri_plugin_updater::UpdaterExt;

    let builder = app.updater_builder().timeout(CHECK_TIMEOUT);
    #[cfg(windows)]
    let builder = {
        let handle = app.clone();
        builder.on_before_exit(move || {
            tracing::info!("handing over to the installer");
            handle.cleanup_before_exit();
        })
    };
    let updater = builder
        .build()
        .map_err(|error| describe(&error, Phase::Check))?;
    let Some(update) = updater
        .check()
        .await
        .map_err(|error| describe(&error, Phase::Check))?
    else {
        return Ok(None);
    };
    if state::newer_than(&update.version, &update.current_version)?.is_none() {
        return Ok(None);
    }
    let found = Found {
        version: update.version.clone(),
        notes: update.body.clone(),
        date: update
            .raw_json
            .get("pub_date")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
    };
    Ok(Some((found, update)))
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Check,
    Download,
    Install,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn describe(error: &tauri_plugin_updater::Error, phase: Phase) -> String {
    use tauri_plugin_updater::Error;

    tracing::warn!("updater error: {error}");
    match error {
        Error::Minisign(_)
        | Error::Base64(_)
        | Error::SignatureUtf8(_)
        | Error::SignedVersionMismatch { .. }
        | Error::MissingSignedVersion => {
            "The update could not be verified. Nothing was installed.".to_owned()
        }
        Error::Reqwest(_) | Error::Network(_) | Error::ReleaseNotFound => match phase {
            Phase::Check => "Could not reach the update server.".to_owned(),
            _ => "The update could not be downloaded. Nothing was installed.".to_owned(),
        },
        _ => match phase {
            Phase::Check => "The update check failed.".to_owned(),
            Phase::Download => {
                "The update could not be downloaded. Nothing was installed.".to_owned()
            }
            Phase::Install => "The update could not be installed. WyVPN is unchanged.".to_owned(),
        },
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
const DOWNLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);
#[cfg(any(target_os = "macos", target_os = "windows", test))]
const DOWNLOAD_STALL: std::time::Duration = std::time::Duration::from_secs(60);
#[cfg(any(target_os = "macos", target_os = "windows", test))]
const STALL_POLL: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(any(target_os = "macos", target_os = "windows", test))]
#[derive(Debug, PartialEq, Eq)]
struct Stalled;

#[cfg(any(target_os = "macos", target_os = "windows", test))]
struct Activity {
    base: tokio::time::Instant,
    last_ms: AtomicU64,
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
impl Activity {
    fn new() -> Self {
        Self {
            base: tokio::time::Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn touch(&self) {
        self.last_ms.store(self.elapsed_ms(), Ordering::SeqCst);
    }

    fn idle(&self) -> std::time::Duration {
        std::time::Duration::from_millis(
            self.elapsed_ms()
                .saturating_sub(self.last_ms.load(Ordering::SeqCst)),
        )
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
async fn guard_stall<T>(
    work: impl std::future::Future<Output = T>,
    activity: &Activity,
    stall: std::time::Duration,
    poll: std::time::Duration,
) -> Result<T, Stalled> {
    let watchdog = async {
        while activity.idle() < stall {
            tokio::time::sleep(poll).await;
        }
    };
    tokio::select! {
        output = work => Ok(output),
        () = watchdog => Err(Stalled),
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
struct Throttle {
    every: std::time::Duration,
    last: Option<std::time::Instant>,
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
impl Throttle {
    fn new(every: std::time::Duration) -> Self {
        Self { every, last: None }
    }

    fn admit(&mut self, now: std::time::Instant) -> bool {
        let due = self
            .last
            .is_none_or(|last| now.saturating_duration_since(last) >= self.every);
        if due {
            self.last = Some(now);
        }
        due
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
struct AppSession {
    app: AppHandle,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl session::Session for AppSession {
    fn reachable(&self) -> bool {
        self.app.state::<Ctx>().bridge.is_available()
    }

    fn active_profiles(&self) -> impl std::future::Future<Output = Vec<String>> + Send {
        let ctx = self.app.state::<Ctx>();
        let bridge = ctx.bridge.clone();
        let fallback = ctx.model().active_profile_ids();
        async move {
            match bridge.statuses().await {
                Ok(statuses) => crate::model::active_ids(&statuses),
                Err(_) => fallback,
            }
        }
    }

    fn mark_user_disconnect(&self, profile_id: &str) {
        self.app.state::<Ctx>().mark_user_disconnect(profile_id);
    }

    fn disconnect(
        &self,
        profile_id: String,
    ) -> impl std::future::Future<Output = Result<(), CmdError>> + Send {
        let bridge = self.app.state::<Ctx>().bridge.clone();
        async move {
            bridge
                .ok(wyvpn_ipc::Request::Disconnect { profile_id })
                .await
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
async fn run_install(app: AppHandle) {
    if let Err(message) = install_steps(&app).await {
        let _ = transition(&app, Event::InstallFailed(message));
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
async fn install_steps(app: &AppHandle) -> Result<(), String> {
    use std::time::{Duration, Instant};

    const PROGRESS_EVERY: Duration = Duration::from_millis(100);

    let step = |event| transition(app, event).map_err(|rejected| rejected.to_string());
    let session = AppSession { app: app.clone() };
    session::disconnect_all(
        &session,
        session::DISCONNECT_TIMEOUT,
        session::DISCONNECT_POLL,
    )
    .await
    .map_err(|_| "The VPN did not disconnect in time. Nothing was installed.".to_owned())?;
    step(Event::Disconnected)?;
    let ctx = app.state::<Ctx>();
    let mut update = ctx
        .updater
        .take_pending()
        .ok_or("The update is no longer available. Check for updates again.")?;
    update.timeout = Some(DOWNLOAD_TIMEOUT);
    let mut received = 0_u64;
    let mut throttle = Throttle::new(PROGRESS_EVERY);
    let activity = Activity::new();
    let download = update.download(
        |chunk, total| {
            activity.touch();
            received += chunk as u64;
            if throttle.admit(Instant::now()) {
                let _ = step(Event::Progress { received, total });
            }
        },
        || {},
    );
    let bytes = guard_stall(download, &activity, DOWNLOAD_STALL, STALL_POLL)
        .await
        .map_err(|_| "The download stalled. Nothing was installed.".to_owned())?
        .map_err(|error| describe(&error, Phase::Download))?;
    step(Event::Downloaded)?;
    ctx.mark_show_after_update(&update.version);
    let installed = tauri::async_runtime::spawn_blocking(move || update.install(bytes)).await;
    let installed = installed
        .map_err(|_| "The update could not be installed. WyVPN is unchanged.".to_owned())
        .and_then(|result| result.map_err(|error| describe(&error, Phase::Install)));
    if let Err(message) = installed {
        ctx.clear_show_after_update();
        return Err(message);
    }
    step(Event::Installed)?;
    relaunch(app);
    Ok(())
}

#[cfg(target_os = "macos")]
fn relaunch(app: &AppHandle) {
    app.restart();
}

#[cfg(windows)]
fn relaunch(app: &AppHandle) {
    app.exit(0);
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::time::{Duration, Instant};

    use super::*;

    fn offer(version: &str) -> Offer {
        Offer::new(
            Found {
                version: version.into(),
                notes: None,
                date: None,
            },
            true,
        )
    }

    fn available(updater: &Updater<u32>, pending: u32) {
        updater.apply(Event::BeginCheck, |_| {}).unwrap();
        updater.set_pending(pending);
        updater
            .apply(
                Event::Found {
                    offer: offer("0.2.0"),
                    manual: true,
                },
                |_| {},
            )
            .unwrap();
    }

    #[test]
    fn every_change_is_published_in_order() {
        let updater = Updater::<u32>::default();
        let seen = RefCell::new(Vec::new());
        for event in [Event::BeginCheck, Event::NoUpdate] {
            updater
                .apply(event, |state| seen.borrow_mut().push(state.clone()))
                .unwrap();
        }
        assert_eq!(
            *seen.borrow(),
            vec![UpdateState::Checking, UpdateState::UpToDate]
        );
        let published = RefCell::new(0);
        assert!(
            updater
                .apply(Event::Downloaded, |_| *published.borrow_mut() += 1)
                .is_err()
        );
        assert_eq!(*published.borrow(), 0);
    }

    #[test]
    fn a_failed_install_drops_the_pending_update() {
        let updater = Updater::<u32>::default();
        available(&updater, 7);
        updater.apply(Event::BeginInstall, |_| {}).unwrap();
        updater.apply(Event::Disconnected, |_| {}).unwrap();
        assert_eq!(updater.take_pending(), Some(7));
        updater.set_pending(8);
        updater
            .apply(Event::InstallFailed("bad".into()), |_| {})
            .unwrap();
        assert_eq!(updater.take_pending(), None);
    }

    #[test]
    fn no_update_found_drops_the_pending_update() {
        let updater = Updater::<u32>::default();
        available(&updater, 1);
        updater.apply(Event::BeginCheck, |_| {}).unwrap();
        updater.apply(Event::NoUpdate, |_| {}).unwrap();
        assert_eq!(updater.take_pending(), None);
    }

    #[test]
    fn dismissing_keeps_the_pending_update() {
        let updater = Updater::<u32>::default();
        available(&updater, 1);
        updater.apply(Event::Dismiss, |_| {}).unwrap();
        assert_eq!(updater.take_pending(), Some(1));
    }

    #[test]
    fn a_check_while_installing_is_rejected() {
        let updater = Updater::<u32>::default();
        available(&updater, 1);
        updater.apply(Event::BeginInstall, |_| {}).unwrap();
        let before = updater.state();
        assert!(updater.apply(Event::BeginCheck, |_| {}).is_err());
        assert_eq!(updater.state(), before);
    }

    #[test]
    fn the_notification_is_planned_once_per_version() {
        let updater = Updater::<u32>::default();
        assert!(updater.plan_notification(true, false, "0.2.0").is_some());
        assert!(updater.plan_notification(true, false, "0.2.0").is_none());
        assert!(updater.plan_notification(true, false, "0.3.0").is_some());
    }

    #[test]
    fn the_notification_needs_notifications_on_and_a_hidden_window() {
        let updater = Updater::<u32>::default();
        assert!(updater.plan_notification(false, false, "0.2.0").is_none());
        assert!(updater.plan_notification(true, true, "0.2.0").is_none());
        assert!(updater.plan_notification(true, false, "0.2.0").is_some());
    }

    #[test]
    fn prompts_follow_manual_check_outcomes() {
        assert_eq!(
            prompt_outcome(&UpdateState::Available(offer("1.0.0"))),
            Some("available")
        );
        assert_eq!(prompt_outcome(&UpdateState::UpToDate), Some("up_to_date"));
        assert_eq!(
            prompt_outcome(&UpdateState::Failed {
                message: String::new()
            }),
            Some("failed")
        );
        assert_eq!(prompt_outcome(&UpdateState::Checking), None);
    }

    #[test]
    fn progress_is_throttled_to_ten_per_second() {
        let mut throttle = Throttle::new(Duration::from_millis(100));
        let start = Instant::now();
        assert!(throttle.admit(start));
        assert!(!throttle.admit(start + Duration::from_millis(40)));
        assert!(!throttle.admit(start + Duration::from_millis(99)));
        assert!(throttle.admit(start + Duration::from_millis(100)));
        assert!(!throttle.admit(start + Duration::from_millis(150)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_download_is_cut_off() {
        let activity = Activity::new();
        let stall = Duration::from_secs(60);
        let started = tokio::time::Instant::now();
        let result = guard_stall(
            std::future::pending::<()>(),
            &activity,
            stall,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(result, Err(Stalled));
        assert!(started.elapsed() >= stall && started.elapsed() < stall * 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_but_moving_download_is_not_cut_off() {
        let activity = Activity::new();
        let work = async {
            for _ in 0..30 {
                tokio::time::sleep(Duration::from_secs(30)).await;
                activity.touch();
            }
            "done"
        };
        let result = guard_stall(
            work,
            &activity,
            Duration::from_secs(60),
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(result, Ok("done"));
    }

    #[test]
    fn the_wall_clock_is_never_zero() {
        assert!(now_secs() > 1_700_000_000);
    }

    #[test]
    fn success_is_recorded_for_the_scheduler() {
        let updater = Updater::<u32>::default();
        assert_eq!(updater.last_success(), None);
        updater.record_success(42);
        assert_eq!(updater.last_success(), Some(42));
    }

    #[test]
    fn a_stale_publish_never_overwrites_a_newer_one() {
        let updater = Updater::<u32>::default();
        let seen = RefCell::new(Vec::new());
        updater
            .apply(Event::BeginCheck, |s| seen.borrow_mut().push(s.clone()))
            .unwrap();
        *updater.published.lock().unwrap() = 99;
        updater
            .apply(Event::NoUpdate, |s| seen.borrow_mut().push(s.clone()))
            .unwrap();
        assert_eq!(*seen.borrow(), vec![UpdateState::Checking]);
        assert_eq!(updater.state(), UpdateState::UpToDate);
    }

    #[test]
    fn publishing_does_not_hold_the_state_lock() {
        let updater = Updater::<u32>::default();
        updater
            .apply(Event::BeginCheck, |_| {
                assert_eq!(updater.state(), UpdateState::Checking);
            })
            .unwrap();
    }

    #[test]
    fn newer_versions_are_compared_by_semver() {
        assert_eq!(
            state::newer_than("0.10.0", "0.9.9"),
            Ok(Some("0.10.0".into()))
        );
        assert_eq!(state::newer_than("0.1.2", "0.1.2"), Ok(None));
        assert_eq!(state::newer_than("0.1.1", "0.1.2"), Ok(None));
        assert_eq!(state::newer_than("0.1.2-rc.1", "0.1.2"), Ok(None));
        assert!(state::newer_than("garbage", "0.1.2").is_err());
        assert!(state::newer_than("0.2.0", "garbage").is_err());
    }

    fn config() -> serde_json::Value {
        serde_json::from_str(include_str!("../tauri.conf.json")).unwrap()
    }

    #[test]
    fn committed_config_has_one_https_github_endpoint() {
        let config = config();
        let endpoints = config["plugins"]["updater"]["endpoints"]
            .as_array()
            .unwrap();
        assert_eq!(
            endpoints,
            &[serde_json::json!(
                "https://github.com/adithyaharun/wyvpn/releases/latest/download/latest.json"
            )]
        );
    }

    #[test]
    fn committed_config_has_a_pubkey() {
        let config = config();
        let pubkey = config["plugins"]["updater"]["pubkey"].as_str().unwrap();
        assert!(!pubkey.trim().is_empty());
    }

    #[test]
    fn committed_config_keeps_transport_secure_and_artifacts_off() {
        let config = config();
        assert!(
            config["plugins"]["updater"]
                .get("dangerousInsecureTransportProtocol")
                .is_none()
        );
        assert!(config["bundle"].get("createUpdaterArtifacts").is_none());
        assert_eq!(
            config["plugins"]["updater"]["windows"]["installMode"],
            "passive"
        );
        assert_eq!(config["plugins"]["updater"]["requireSignedVersion"], true);
        let endpoint = linux::endpoint(config["plugins"].get("updater")).unwrap();
        assert_eq!(endpoint.scheme(), "https");
    }

    #[test]
    fn capability_grants_no_plugin_updater_or_process_access() {
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        let permissions = capability["permissions"].as_array().unwrap();
        assert!(permissions.iter().all(|permission| {
            let name = permission.as_str().unwrap();
            !name.starts_with("updater:") && !name.starts_with("process:")
        }));
        for command in [
            "update-state",
            "check-for-updates",
            "install-update",
            "dismiss-update",
            "open-update-page",
        ] {
            let allow = format!("allow-{command}");
            assert!(permissions.iter().any(|p| *p == allow.as_str()), "{allow}");
        }
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn plugin_errors_get_user_messages_without_internals() {
        use tauri_plugin_updater::Error;

        let network = describe(&Error::Network("https://x/secret".into()), Phase::Download);
        assert!(network.contains("downloaded") && !network.contains("secret"));
        let signature = describe(&Error::SignatureUtf8("zz".into()), Phase::Download);
        assert!(signature.contains("verified"));
        assert!(describe(&Error::EmptyEndpoints, Phase::Install).contains("unchanged"));
        assert!(describe(&Error::ReleaseNotFound, Phase::Check).contains("update server"));
    }
}
