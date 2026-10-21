use serde::Serialize;
use url::Url;

pub const REPOSITORY: &str = "https://github.com/adithyaharun/wyvpn";
pub const LICENSES_FILE: &str = "THIRD_PARTY_LICENSES";
pub const LICENSES_MISSING: &str = "Third-party license text is not available in this build.";
const LICENSES_MAX_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppInfo {
    pub version: String,
    pub os: String,
    pub arch: String,
}

impl AppInfo {
    pub fn current(version: &str) -> Self {
        Self {
            version: version.to_owned(),
            os: os_label(std::env::consts::OS),
            arch: std::env::consts::ARCH.to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenVpnNotice {
    pub license: &'static str,
    pub source_url: Option<String>,
}

impl OpenVpnNotice {
    pub fn for_os(os: &str, version: &str) -> Self {
        Self {
            license: "GPL-2.0",
            source_url: (os != "linux").then(|| release_url(version)),
        }
    }
}

pub fn release_url(version: &str) -> String {
    format!("{REPOSITORY}/releases/tag/v{version}")
}

pub fn read_licenses(path: &std::path::Path) -> String {
    let readable = std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.len() <= LICENSES_MAX_BYTES);
    if !readable {
        return LICENSES_MISSING.to_owned();
    }
    std::fs::read(path)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_else(|_| LICENSES_MISSING.to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportTarget {
    Project,
    Issue,
    OpenVpnSource,
}

impl SupportTarget {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "project" => Some(Self::Project),
            "issue" => Some(Self::Issue),
            "openvpn_source" => Some(Self::OpenVpnSource),
            _ => None,
        }
    }
}

pub fn os_label(os: &str) -> String {
    match os {
        "macos" => "macOS",
        "windows" => "Windows",
        "linux" => "Linux",
        other => other,
    }
    .to_owned()
}

pub fn support_url(target: SupportTarget, info: &AppInfo) -> Url {
    let repo = Url::parse(REPOSITORY).expect("repository url is valid");
    match target {
        SupportTarget::Project => repo,
        SupportTarget::OpenVpnSource => {
            Url::parse(&release_url(&info.version)).expect("release url is valid")
        }
        SupportTarget::Issue => {
            let body = format!(
                "**What happened**\n\n\n**Steps to reproduce**\n\n\n---\nWyVPN {}\n{} {}",
                info.version, info.os, info.arch
            );
            Url::parse_with_params(&format!("{REPOSITORY}/issues/new"), [("body", body)])
                .expect("issue url is valid")
        }
    }
}

#[cfg(target_os = "macos")]
const MENU_LICENSES: &str = "licenses";
#[cfg(target_os = "macos")]
const MENU_CHECK_UPDATES: &str = "menu_check_updates";
#[cfg(target_os = "macos")]
const MENU_INSTALL_CLI: &str = "install_cli";
#[cfg(target_os = "macos")]
const MENU_UNINSTALL: &str = "uninstall";

#[cfg(target_os = "macos")]
pub fn install_menu(app: &tauri::AppHandle) -> tauri::Result<()> {
    use tauri::menu::{AboutMetadata, Menu, MenuItem, PredefinedMenuItem, Submenu};

    let metadata = AboutMetadata {
        name: Some("WyVPN".to_owned()),
        version: Some(app.package_info().version.to_string()),
        short_version: Some(app.package_info().version.to_string()),
        website: Some(REPOSITORY.to_owned()),
        website_label: Some("GitHub".to_owned()),
        license: Some("MIT".to_owned()),
        icon: app.default_window_icon().cloned(),
        ..Default::default()
    };
    let app_menu = Submenu::with_items(
        app,
        "WyVPN",
        true,
        &[
            &PredefinedMenuItem::about(app, Some("About WyVPN"), Some(metadata))?,
            &MenuItem::with_id(
                app,
                MENU_CHECK_UPDATES,
                "Check for Updates…",
                true,
                None::<&str>,
            )?,
            &MenuItem::with_id(
                app,
                MENU_LICENSES,
                "Third-Party Licenses…",
                true,
                None::<&str>,
            )?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(
                app,
                MENU_INSTALL_CLI,
                "Install Command Line Tool…",
                true,
                None::<&str>,
            )?,
            &MenuItem::with_id(app, MENU_UNINSTALL, "Uninstall WyVPN…", true, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::services(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::hide(app, None)?,
            &PredefinedMenuItem::hide_others(app, None)?,
            &PredefinedMenuItem::show_all(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::quit(app, None)?,
        ],
    )?;
    let edit_menu = Submenu::with_items(
        app,
        "Edit",
        true,
        &[
            &PredefinedMenuItem::undo(app, None)?,
            &PredefinedMenuItem::redo(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::cut(app, None)?,
            &PredefinedMenuItem::copy(app, None)?,
            &PredefinedMenuItem::paste(app, None)?,
            &PredefinedMenuItem::select_all(app, None)?,
        ],
    )?;
    let window_menu = Submenu::with_items(
        app,
        "Window",
        true,
        &[
            &PredefinedMenuItem::minimize(app, None)?,
            &PredefinedMenuItem::close_window(app, None)?,
        ],
    )?;
    app.set_menu(Menu::with_items(
        app,
        &[&app_menu, &edit_menu, &window_menu],
    )?)?;
    app.on_menu_event(|app, event| match event.id().as_ref() {
        MENU_CHECK_UPDATES => crate::updater::check_from_menu(app),
        MENU_LICENSES => crate::shell::show_licenses(app),
        MENU_INSTALL_CLI => crate::maintenance::install_cli(app),
        MENU_UNINSTALL => crate::maintenance::uninstall(app),
        _ => {}
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> AppInfo {
        AppInfo {
            version: "1.2.3".to_owned(),
            os: "macOS".to_owned(),
            arch: "aarch64".to_owned(),
        }
    }

    #[test]
    fn issue_url_encodes_environment() {
        let url = support_url(SupportTarget::Issue, &info());
        assert_eq!(url.path(), "/adithyaharun/wyvpn/issues/new");
        let body = url
            .query_pairs()
            .find(|(key, _)| key == "body")
            .map(|(_, value)| value.into_owned())
            .unwrap();
        assert!(body.starts_with("**What happened**\n\n\n**Steps to reproduce**\n\n\n---\n"));
        assert!(body.contains("WyVPN 1.2.3\nmacOS aarch64"));
        assert!(!url.as_str().contains(' '));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn app_menu_and_tray_use_different_update_ids() {
        assert_ne!(MENU_CHECK_UPDATES, crate::model::CHECK_UPDATES);
    }

    #[test]
    fn project_url_is_repository() {
        let url = support_url(SupportTarget::Project, &info());
        assert_eq!(url.as_str().trim_end_matches('/'), REPOSITORY);
    }

    #[test]
    fn os_labels() {
        assert_eq!(os_label("macos"), "macOS");
        assert_eq!(os_label("windows"), "Windows");
        assert_eq!(os_label("linux"), "Linux");
        assert_eq!(os_label("freebsd"), "freebsd");
    }

    #[test]
    fn unknown_target_rejected() {
        assert_eq!(
            SupportTarget::parse("project"),
            Some(SupportTarget::Project)
        );
        assert_eq!(SupportTarget::parse("issue"), Some(SupportTarget::Issue));
        assert_eq!(SupportTarget::parse("https://example.com"), None);
        assert_eq!(SupportTarget::parse(""), None);
    }

    #[test]
    fn openvpn_source_is_the_release_page_except_on_linux() {
        let mac = OpenVpnNotice::for_os("macos", "1.2.3");
        assert_eq!(mac.license, "GPL-2.0");
        assert_eq!(
            mac.source_url.as_deref(),
            Some("https://github.com/adithyaharun/wyvpn/releases/tag/v1.2.3")
        );
        assert_eq!(OpenVpnNotice::for_os("linux", "1.2.3").source_url, None);
        let url = support_url(SupportTarget::OpenVpnSource, &info());
        assert_eq!(url.as_str(), release_url("1.2.3"));
        assert_eq!(
            SupportTarget::parse("openvpn_source"),
            Some(SupportTarget::OpenVpnSource)
        );
    }

    #[test]
    fn licenses_fall_back_when_the_file_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_licenses(&dir.path().join("none")), LICENSES_MISSING);
        assert_eq!(read_licenses(dir.path()), LICENSES_MISSING);
        let file = dir.path().join(LICENSES_FILE);
        std::fs::write(&file, "MIT License\nfoo").unwrap();
        assert_eq!(read_licenses(&file), "MIT License\nfoo");
    }
}
