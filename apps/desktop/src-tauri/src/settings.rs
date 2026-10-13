use std::fs;
use std::io::{self, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use wyvpn_ipc::Request;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub auto_connect_profile_id: Option<String>,
    pub auto_reconnect: bool,
    pub notifications: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_connect_profile_id: None,
            auto_reconnect: true,
            notifications: true,
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

    pub fn connect_request(&self, profile_id: String) -> Request {
        Request::Connect {
            profile_id,
            transport: None,
            auto_reconnect: Some(self.auto_reconnect),
        }
    }
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
            off.connect_request("p".into()),
            Request::Connect {
                auto_reconnect: Some(false),
                ..
            }
        ));
        assert!(matches!(
            Settings::default().connect_request("p".into()),
            Request::Connect {
                auto_reconnect: Some(true),
                ..
            }
        ));
    }
}
