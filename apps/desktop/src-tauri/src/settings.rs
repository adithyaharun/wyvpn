use std::fs;
use std::io::{self, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use wyvpn_ipc::{Request, Transport};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub auto_connect_profile_id: Option<String>,
    pub auto_reconnect: bool,
    pub notifications: bool,
    pub check_updates: bool,
    pub service_version: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_connect_profile_id: None,
            auto_reconnect: true,
            notifications: true,
            check_updates: true,
            service_version: None,
        }
    }
}

impl Settings {
    pub fn load(path: &Path) -> Self {
        fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut temp = path.as_os_str().to_owned();
        temp.push(".tmp");
        let temp = Path::new(&temp);
        write_durably(temp, &bytes)
            .and_then(|()| fs::rename(temp, path))
            .inspect_err(|_| {
                let _ = fs::remove_file(temp);
            })
    }

    pub fn normalized(mut self) -> Self {
        self.auto_connect_profile_id = self
            .auto_connect_profile_id
            .filter(|id| !id.trim().is_empty());
        self
    }

    pub fn keeping_service_version(mut self, current: &Settings) -> Self {
        self.service_version.clone_from(&current.service_version);
        self
    }

    pub fn connect_request(&self, profile_id: String, transport: Option<Transport>) -> Request {
        Request::Connect {
            profile_id,
            transport,
            auto_reconnect: Some(self.auto_reconnect),
        }
    }
}

const SHOW_AFTER_UPDATE_FILE: &str = "show-after-update";

fn show_after_update_path(settings_path: &Path) -> std::path::PathBuf {
    settings_path.with_file_name(SHOW_AFTER_UPDATE_FILE)
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
pub fn mark_show_after_update(settings_path: &Path, target_version: &str) -> io::Result<()> {
    let path = show_after_update_path(settings_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    write_durably(&path, target_version.trim_start_matches('v').as_bytes())
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
pub fn clear_show_after_update(settings_path: &Path) {
    let _ = fs::remove_file(show_after_update_path(settings_path));
}

pub fn take_show_after_update(settings_path: &Path, running_version: &str) -> bool {
    let path = show_after_update_path(settings_path);
    let target = fs::read_to_string(&path).ok();
    let _ = fs::remove_file(&path);
    target.is_some_and(|target| target.trim() == running_version.trim_start_matches('v'))
}

fn write_durably(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_gives_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::load(&dir.path().join("settings.json"));
        assert_eq!(settings, Settings::default());
        assert_eq!(settings.auto_connect_profile_id, None);
        assert!(settings.auto_reconnect && settings.notifications);
        assert!(settings.check_updates);
    }

    #[test]
    fn corrupt_file_gives_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, b"{not json").unwrap();
        assert_eq!(Settings::load(&path), Settings::default());
        fs::write(&path, b"{\"auto_reconnect\": \"yes\"}").unwrap();
        assert_eq!(Settings::load(&path), Settings::default());
    }

    #[test]
    fn partial_file_fills_missing_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, b"{\"notifications\": false}").unwrap();
        let settings = Settings::load(&path);
        assert!(!settings.notifications && settings.auto_reconnect);
    }

    #[test]
    fn save_then_load_round_trips_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("settings.json");
        let settings = Settings {
            auto_connect_profile_id: Some("p1".into()),
            auto_reconnect: false,
            notifications: false,
            check_updates: false,
            service_version: Some("0.1.0".into()),
        };
        settings.save(&path).unwrap();
        assert_eq!(Settings::load(&path), settings);
        let again = Settings {
            notifications: true,
            ..settings
        };
        again.save(&path).unwrap();
        assert_eq!(Settings::load(&path), again);
        let names: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("settings.json")]);
    }

    #[test]
    fn failed_save_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::create_dir(&path).unwrap();
        assert!(Settings::default().save(&path).is_err());
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("settings.json")]);
    }

    #[test]
    fn files_without_a_service_version_still_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, b"{\"auto_reconnect\": false}").unwrap();
        let settings = Settings::load(&path);
        assert_eq!(settings.service_version, None);
        assert!(!settings.auto_reconnect);
    }

    #[test]
    fn files_without_check_updates_default_it_on_and_keep_other_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(
            &path,
            b"{\"auto_reconnect\": false, \"notifications\": false, \"service_version\": \"0.1.0\"}",
        )
        .unwrap();
        let settings = Settings::load(&path);
        assert!(settings.check_updates);
        assert!(!settings.auto_reconnect && !settings.notifications);
        assert_eq!(settings.service_version.as_deref(), Some("0.1.0"));
    }

    #[test]
    fn check_updates_off_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let off = Settings {
            check_updates: false,
            ..Settings::default()
        };
        off.save(&path).unwrap();
        assert!(!Settings::load(&path).check_updates);
    }

    #[test]
    fn frontend_updates_cannot_change_the_service_version() {
        let current = Settings {
            service_version: Some("0.2.0".into()),
            ..Settings::default()
        };
        let incoming = Settings {
            notifications: false,
            service_version: None,
            ..Settings::default()
        };
        let merged = incoming.keeping_service_version(&current);
        assert_eq!(merged.service_version.as_deref(), Some("0.2.0"));
        assert!(!merged.notifications);
    }

    #[test]
    fn show_after_update_marker_is_one_shot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("settings.json");
        assert!(!take_show_after_update(&path, "0.2.0"));
        mark_show_after_update(&path, "0.2.0").unwrap();
        assert!(take_show_after_update(&path, "0.2.0"));
        assert!(!take_show_after_update(&path, "0.2.0"));
        mark_show_after_update(&path, "v0.2.0").unwrap();
        assert!(take_show_after_update(&path, "0.2.0"));
        mark_show_after_update(&path, "0.2.0").unwrap();
        clear_show_after_update(&path);
        assert!(!take_show_after_update(&path, "0.2.0"));
    }

    #[test]
    fn show_after_update_marker_is_ignored_and_removed_when_the_version_differs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        mark_show_after_update(&path, "0.2.0").unwrap();
        assert!(!take_show_after_update(&path, "0.1.2"));
        assert!(!take_show_after_update(&path, "0.2.0"));
    }

    #[test]
    fn blank_default_profile_normalizes_to_none() {
        let settings = Settings {
            auto_connect_profile_id: Some("  ".into()),
            ..Settings::default()
        };
        assert_eq!(settings.normalized().auto_connect_profile_id, None);
    }

    #[test]
    fn connect_request_carries_the_reconnect_setting() {
        let off = Settings {
            auto_reconnect: false,
            ..Settings::default()
        };
        assert!(matches!(
            off.connect_request("p".into(), None),
            Request::Connect {
                auto_reconnect: Some(false),
                ..
            }
        ));
        assert!(matches!(
            Settings::default().connect_request("p".into(), None),
            Request::Connect {
                auto_reconnect: Some(true),
                ..
            }
        ));
    }
}
