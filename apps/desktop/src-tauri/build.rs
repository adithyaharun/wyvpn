const COMMANDS: &[&str] = &[
    "daemon_state",
    "list_profiles",
    "status",
    "import_file",
    "replace_import",
    "import_link",
    "remove_profile",
    "connect",
    "submit_pin",
    "cancel_credentials",
    "disconnect",
    "rename_profile",
    "session_log",
    "get_settings",
    "update_settings",
    "notification_permission",
    "get_launch_at_login",
    "set_launch_at_login",
    "take_startup_notice",
    "app_info",
    "open_support",
    "service_status",
    "register_service",
    "open_login_items",
    "third_party_licenses",
    "openvpn_notice",
    "window_chrome",
    "update_state",
    "check_for_updates",
    "install_update",
    "dismiss_update",
    "open_update_page",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("failed to run tauri-build");
}
