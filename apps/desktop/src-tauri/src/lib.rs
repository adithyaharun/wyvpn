mod about;
mod autoconnect;
mod bridge;
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

pub fn run() {
    let result = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            shell::show_main(app);
        }))
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
            commands::app_info,
            commands::open_support,
            commands::service_status,
            commands::register_service,
            commands::open_login_items,
            commands::third_party_licenses,
            commands::openvpn_notice,
        ])
        .on_window_event(|window, event| {
            if window.label() != MAIN_WINDOW {
                return;
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
            let tray_ok = build_tray(&handle);
            let ctx = handle.state::<Ctx>();
            ctx.tray_ok.store(tray_ok, Ordering::Relaxed);
            let autostarted = std::env::args().any(|arg| arg == AUTOSTART_ARG);
            if shell::start_visible(tray_ok, autostarted) {
                shell::show_main(&handle);
            } else {
                shell::hide_main(&handle);
            }
            shell::start_events(&handle);
            Ok(())
        })
        .run(tauri::generate_context!());
    if let Err(error) = result {
        eprintln!("wyvpn app failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
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
