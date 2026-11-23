mod about;
mod autoconnect;
mod bridge;
mod chrome;
mod client;
mod commands;
mod error;
mod files;
#[cfg(target_os = "macos")]
mod maintenance;
mod model;
mod notifications;
mod retry;
mod service;
mod settings;
mod shell;
mod tray;
mod updater;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use tauri::{Manager, WindowEvent};
use tauri_plugin_autostart::MacosLauncher;

use crate::bridge::Bridge;
use crate::shell::{Ctx, MAIN_WINDOW};

const AUTOSTART_ARG: &str = "--autostart";

#[cfg(target_os = "linux")]
fn tray_supported() -> bool {
    ["libayatana-appindicator3.so.1", "libappindicator3.so.1"]
        .iter()
        .any(|name| unsafe { libloading::Library::new(name) }.is_ok())
}

#[cfg(not(target_os = "linux"))]
fn tray_supported() -> bool {
    true
}

fn build_tray(app: &tauri::AppHandle) -> bool {
    if !tray_supported() {
        tracing::warn!("tray unavailable: appindicator library not found");
        return false;
    }
    let ctx = app.state::<Ctx>();
    let model = ctx.model().clone();
    let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tray::build(app, &model, &ctx.rendered, shell::on_menu)
    }));
    match attempt {
        Ok(Ok(_)) => true,
        Ok(Err(error)) => {
            tracing::warn!("tray unavailable: {error}");
            false
        }
        Err(_) => {
            tracing::warn!("tray unavailable");
            false
        }
    }
}

fn keeps_running(code: Option<i32>, tray_ok: bool) -> bool {
    code.is_none() && tray_ok
}

pub fn run() {
    let builder =
        tauri::Builder::default().plugin(tauri_plugin_single_instance::init(|app, _, _| {
            shell::show_main(app);
        }));
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    let builder = builder.plugin(tauri_plugin_updater::Builder::new().build());
    let result = builder
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec![AUTOSTART_ARG]),
        ))
        .invoke_handler(tauri::generate_handler![
            commands::daemon_state,
            commands::list_profiles,
            commands::status,
            commands::import_file,
            commands::import_link,
            commands::remove_profile,
            commands::connect,
            commands::submit_pin,
            commands::cancel_credentials,
            commands::disconnect,
            commands::replace_import,
            commands::rename_profile,
            commands::session_log,
            commands::get_settings,
            commands::update_settings,
            commands::notification_permission,
            commands::get_launch_at_login,
            commands::set_launch_at_login,
            commands::take_startup_notice,
            commands::take_window_requests,
            commands::app_info,
            commands::open_support,
            commands::service_status,
            commands::register_service,
            commands::repair_service,
            commands::service_error,
            commands::service_reapproval,
            commands::open_login_items,
            commands::third_party_licenses,
            commands::openvpn_notice,
            commands::window_chrome,
            commands::update_state,
            commands::check_for_updates,
            commands::install_update,
            commands::dismiss_update,
            commands::open_update_page,
        ])
        .on_window_event(|window, event| {
            if window.label() != MAIN_WINDOW {
                return;
            }
            if matches!(event, WindowEvent::Destroyed) {
                shell::main_window_destroyed(window.app_handle());
            }
            if let WindowEvent::CloseRequested { api, .. } = event {
                let app = window.app_handle();
                if app.state::<Ctx>().tray_ok.load(Ordering::Relaxed) {
                    api.prevent_close();
                    shell::hide_main(app);
                }
            }
        })
        .setup(|app| {
            let handle = app.handle().clone();
            let bridge = Arc::new(Bridge::new(wyvpn_ipc::socket_path()));
            let settings_path = handle
                .path()
                .app_config_dir()
                .ok()
                .map(|dir| dir.join("settings.json"));
            app.manage(Ctx::new(bridge, settings_path));
            #[cfg(target_os = "macos")]
            about::install_menu(&handle)?;
            shell::probe(&handle);
            let ctx = handle.state::<Ctx>();
            ctx.store_service_state(&handle);
            let approval_pending = ctx.model().approval_pending();
            let tray_ok = build_tray(&handle);
            ctx.tray_ok.store(tray_ok, Ordering::Relaxed);
            let after_update =
                ctx.take_show_after_update(&handle.package_info().version.to_string());
            let autostarted = !after_update && std::env::args().any(|arg| arg == AUTOSTART_ARG);
            if shell::start_visible(tray_ok, autostarted, approval_pending) {
                shell::show_main(&handle);
            } else {
                shell::hide_main(&handle);
            }
            shell::start_events(&handle);
            let reconcile = handle.clone();
            tauri::async_runtime::spawn_blocking(move || shell::reconcile_service(&reconcile));
            tauri::async_runtime::spawn(updater::schedule(handle.clone()));
            Ok(())
        })
        .build(tauri::generate_context!());
    let app = match result {
        Ok(app) => app,
        Err(error) => {
            eprintln!("wyvpn app failed: {error}");
            std::process::exit(1);
        }
    };
    app.run(|app, event| match event {
        tauri::RunEvent::ExitRequested { code, api, .. }
            if keeps_running(code, app.state::<Ctx>().tray_ok.load(Ordering::Relaxed)) =>
        {
            api.prevent_exit();
        }
        #[cfg(target_os = "macos")]
        tauri::RunEvent::Reopen { .. } => shell::show_main(app),
        _ => {}
    });
}

#[cfg(test)]
mod tests {
    use super::keeps_running;

    #[test]
    fn implicit_exit_with_a_tray_keeps_running() {
        assert!(keeps_running(None, true));
    }

    #[test]
    fn implicit_exit_without_a_tray_exits() {
        assert!(!keeps_running(None, false));
    }

    #[test]
    fn explicit_exit_with_a_tray_exits() {
        assert!(!keeps_running(Some(0), true));
    }

    #[test]
    fn main_window_is_created_on_demand() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let main = config["app"]["windows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|window| window["label"] == "main")
            .unwrap();
        assert_eq!(main["create"], false);
    }

    #[test]
    fn capability_allows_title_bar_double_click() {
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        let permissions = capability["permissions"].as_array().unwrap();
        assert!(
            permissions
                .iter()
                .any(|p| p == "core:window:allow-internal-toggle-maximize")
        );
    }
}
