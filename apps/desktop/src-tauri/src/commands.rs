use serde_json::Value;
use tauri::{AppHandle, State};
use tauri_plugin_autostart::ManagerExt as AutostartExt;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_notification::{NotificationExt, PermissionState};
use tauri_plugin_opener::OpenerExt;
use wyvpn_ipc::{
    ConnectionStatus, ImportSource, MAX_IMPORT_BYTES, ProfileSummary, Request, Sensitive, Transport,
};

use tauri::Manager;
use tauri::path::BaseDirectory;

use crate::about::{self, AppInfo, OpenVpnNotice, SupportTarget};
use crate::bridge::SessionLogReply;
use crate::chrome::{self, WindowChrome};
use crate::error::CmdError;
use crate::files::read_import_file;
use crate::model::AvailabilityPayload;
use crate::service::{self, ServiceStatus};
use crate::settings::Settings;
use crate::shell::{self, Ctx, StartupNotice};

type CmdResult<T> = Result<T, CmdError>;

#[tauri::command]
pub fn daemon_state(ctx: State<'_, Ctx>) -> AvailabilityPayload {
    ctx.availability_payload()
}

#[tauri::command]
pub async fn list_profiles(ctx: State<'_, Ctx>) -> CmdResult<Vec<ProfileSummary>> {
    ctx.bridge.list_profiles().await
}

#[tauri::command]
pub async fn status(ctx: State<'_, Ctx>) -> CmdResult<Vec<ConnectionStatus>> {
    ctx.bridge.statuses().await
}

#[tauri::command]
pub async fn import_file(
    app: AppHandle,
    ctx: State<'_, Ctx>,
    replace: bool,
) -> CmdResult<Option<Vec<ProfileSummary>>> {
    let dialog_app = app.clone();
    let picked = tauri::async_runtime::spawn_blocking(move || {
        dialog_app
            .dialog()
            .file()
            .add_filter("VPN profile", &["ovpn", "conf", "tar"])
            .blocking_pick_file()
    })
    .await
    .map_err(|_| CmdError::internal("file dialog failed"))?;
    let Some(picked) = picked else {
        return Ok(None);
    };
    let path = picked
        .into_path()
        .map_err(|_| CmdError::io("the selected item is not a local file"))?;
    let file =
        tauri::async_runtime::spawn_blocking(move || read_import_file(&path, MAX_IMPORT_BYTES))
            .await
            .map_err(|_| CmdError::internal("file read failed"))??;
    let imported = ctx
        .bridge
        .import(ImportSource::file(&file.name, &file.bytes), replace)
        .await;
    match imported {
        Ok(profiles) => {
            shell::refresh_profiles(&app).await;
            Ok(Some(profiles))
        }
        Err(error) if error.code == "already_exists" => Err(error.with_retry(ctx.retry.put(file))),
        Err(error) => Err(error),
    }
}

#[tauri::command]
pub async fn replace_import(
    app: AppHandle,
    ctx: State<'_, Ctx>,
    retry: String,
) -> CmdResult<Vec<ProfileSummary>> {
    let file = ctx
        .retry
        .take(&retry)
        .ok_or_else(|| CmdError::invalid_request("the import expired; choose the file again"))?;
    let profiles = ctx
        .bridge
        .import(ImportSource::file(&file.name, &file.bytes), true)
        .await?;
    shell::refresh_profiles(&app).await;
    Ok(profiles)
}

#[tauri::command]
pub async fn import_link(
    app: AppHandle,
    ctx: State<'_, Ctx>,
    link: String,
    replace: bool,
) -> CmdResult<Vec<ProfileSummary>> {
    if link.len() > MAX_IMPORT_BYTES {
        return Err(CmdError::too_large(MAX_IMPORT_BYTES));
    }
    let profiles = ctx.bridge.import(ImportSource::uri(link), replace).await?;
    shell::refresh_profiles(&app).await;
    Ok(profiles)
}

#[tauri::command]
pub async fn remove_profile(
    app: AppHandle,
    ctx: State<'_, Ctx>,
    profile_id: String,
) -> CmdResult<Value> {
    ctx.bridge.ok(Request::RemoveProfile { profile_id }).await?;
    shell::refresh_profiles(&app).await;
    Ok(Value::Null)
}

#[tauri::command]
pub async fn connect(
    ctx: State<'_, Ctx>,
    profile_id: String,
    transport: Option<Transport>,
) -> CmdResult<Value> {
    ctx.bridge
        .ok(ctx.settings().connect_request(profile_id, transport))
        .await?;
    Ok(Value::Null)
}

#[tauri::command]
pub async fn submit_pin(ctx: State<'_, Ctx>, profile_id: String, pin: String) -> CmdResult<Value> {
    let pin = Sensitive::new(pin);
    ctx.bridge
        .ok(Request::SubmitCredentials {
            profile_id,
            pin: Some(pin),
            otp: None,
        })
        .await?;
    Ok(Value::Null)
}

#[tauri::command]
pub async fn cancel_credentials(ctx: State<'_, Ctx>, profile_id: String) -> CmdResult<Value> {
    disconnect(ctx, profile_id).await
}

#[tauri::command]
pub async fn disconnect(ctx: State<'_, Ctx>, profile_id: String) -> CmdResult<Value> {
    ctx.mark_user_disconnect(&profile_id);
    ctx.bridge.ok(Request::Disconnect { profile_id }).await?;
    Ok(Value::Null)
}

#[tauri::command]
pub async fn rename_profile(
    app: AppHandle,
    ctx: State<'_, Ctx>,
    profile_id: String,
    name: String,
) -> CmdResult<ProfileSummary> {
    let profile = ctx.bridge.rename_profile(profile_id, name).await?;
    shell::refresh_profiles(&app).await;
    Ok(profile)
}

#[tauri::command]
pub async fn session_log(ctx: State<'_, Ctx>) -> CmdResult<SessionLogReply> {
    ctx.bridge.session_log().await
}

#[tauri::command]
pub fn take_startup_notice(ctx: State<'_, Ctx>) -> Option<StartupNotice> {
    ctx.take_startup_notice()
}

#[tauri::command]
pub fn get_settings(ctx: State<'_, Ctx>) -> Settings {
    ctx.settings()
}

#[tauri::command]
pub fn update_settings(
    app: AppHandle,
    ctx: State<'_, Ctx>,
    settings: Settings,
) -> CmdResult<Settings> {
    let settings = settings.normalized();
    let enabling = settings.notifications && !ctx.settings().notifications;
    ctx.store_settings(settings.clone())
        .map_err(|_| CmdError::io("could not save settings"))?;
    if enabling && let Err(error) = app.notification().request_permission() {
        tracing::warn!("notification permission request failed: {error}");
    }
    Ok(settings)
}

#[tauri::command]
pub fn notification_permission(app: AppHandle) -> CmdResult<&'static str> {
    let state = app
        .notification()
        .permission_state()
        .map_err(|_| CmdError::internal("could not read notification permission"))?;
    Ok(match state {
        PermissionState::Granted => "granted",
        PermissionState::Denied => "denied",
        _ => "prompt",
    })
}

#[tauri::command]
pub fn get_launch_at_login(app: AppHandle) -> CmdResult<bool> {
    app.autolaunch()
        .is_enabled()
        .map_err(|_| CmdError::internal("could not read the login item state"))
}

#[tauri::command]
pub fn set_launch_at_login(app: AppHandle, enabled: bool) -> CmdResult<bool> {
    let launcher = app.autolaunch();
    let changed = if enabled {
        launcher.enable()
    } else {
        launcher.disable()
    };
    changed.map_err(|_| CmdError::internal("could not change the login item"))?;
    launcher
        .is_enabled()
        .map_err(|_| CmdError::internal("could not read the login item state"))
}

#[tauri::command]
pub fn app_info(app: AppHandle) -> AppInfo {
    AppInfo::current(&app.package_info().version.to_string())
}

#[tauri::command]
pub fn open_support(app: AppHandle, target: String) -> CmdResult<Value> {
    let target = SupportTarget::parse(&target)
        .ok_or_else(|| CmdError::invalid_request("unknown support target"))?;
    let info = AppInfo::current(&app.package_info().version.to_string());
    let url = about::support_url(target, &info);
    app.opener()
        .open_url(url.as_str(), None::<&str>)
        .map_err(|_| CmdError::internal("could not open the browser"))?;
    Ok(Value::Null)
}

#[tauri::command]
pub fn service_status(ctx: State<'_, Ctx>, app: AppHandle) -> Option<ServiceStatus> {
    let status = service::applicable().then(service::status);
    ctx.refresh_service_state(&app);
    status
}

#[tauri::command]
pub async fn register_service(app: AppHandle) -> CmdResult<ServiceStatus> {
    if !service::applicable() {
        return Err(CmdError::invalid_request(
            "service setup is not needed here",
        ));
    }
    let status = tauri::async_runtime::spawn_blocking(|| {
        let current = service::status();
        if !current.should_register() {
            return Ok(current);
        }
        service::register().map_err(|message| CmdError::new("service_setup", &message))?;
        Ok(service::status())
    })
    .await
    .map_err(|_| CmdError::internal("service setup failed"))?;
    app.state::<Ctx>().refresh_service_state(&app);
    status
}

#[tauri::command]
pub fn window_chrome(window: tauri::WebviewWindow) -> Option<WindowChrome> {
    chrome::measure(&window)
}

#[tauri::command]
pub fn open_login_items() -> Value {
    service::open_login_items();
    Value::Null
}

#[tauri::command]
pub async fn third_party_licenses(app: AppHandle) -> String {
    let Ok(path) = app
        .path()
        .resolve(about::LICENSES_FILE, BaseDirectory::Resource)
    else {
        return about::LICENSES_MISSING.to_owned();
    };
    tauri::async_runtime::spawn_blocking(move || about::read_licenses(&path))
        .await
        .unwrap_or_else(|_| about::LICENSES_MISSING.to_owned())
}

#[tauri::command]
pub fn openvpn_notice(app: AppHandle) -> OpenVpnNotice {
    OpenVpnNotice::for_os(
        std::env::consts::OS,
        &app.package_info().version.to_string(),
    )
}
