use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStatus {
    NotRegistered,
    Enabled,
    RequiresApproval,
    NotFound,
}

impl ServiceStatus {
    pub fn should_register(self) -> bool {
        matches!(self, Self::NotRegistered | Self::NotFound)
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::ServiceStatus;
    use objc2_foundation::NSString;
    use objc2_service_management::{SMAppService, SMAppServiceStatus};

    const PLIST: &str = "com.aprdth.wyvpn.daemon.plist";

    pub fn applicable() -> bool {
        !cfg!(debug_assertions)
            && std::env::current_exe()
                .is_ok_and(|path| path.to_string_lossy().contains(".app/Contents/MacOS/"))
    }

    fn with_service<R>(f: impl FnOnce(&SMAppService) -> R) -> R {
        let service =
            unsafe { SMAppService::daemonServiceWithPlistName(&NSString::from_str(PLIST)) };
        f(&service)
    }

    pub fn status() -> ServiceStatus {
        match with_service(|service| unsafe { service.status() }) {
            SMAppServiceStatus::Enabled => ServiceStatus::Enabled,
            SMAppServiceStatus::RequiresApproval => ServiceStatus::RequiresApproval,
            SMAppServiceStatus::NotFound => ServiceStatus::NotFound,
            _ => ServiceStatus::NotRegistered,
        }
    }

    pub fn register() -> Result<(), String> {
        with_service(|service| unsafe { service.registerAndReturnError() })
            .map_err(|error| error.localizedDescription().to_string())
    }

    pub fn unregister() -> Result<(), String> {
        with_service(|service| unsafe { service.unregisterAndReturnError() })
            .map_err(|error| error.localizedDescription().to_string())
    }

    pub fn open_login_items() {
        unsafe { SMAppService::openSystemSettingsLoginItems() };
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::ServiceStatus;

    pub fn applicable() -> bool {
        false
    }

    pub fn status() -> ServiceStatus {
        ServiceStatus::Enabled
    }

    pub fn register() -> Result<(), String> {
        Err("service registration is not supported on this system".to_owned())
    }

    pub fn unregister() -> Result<(), String> {
        Err("service registration is not supported on this system".to_owned())
    }

    pub fn open_login_items() {}
}

pub use imp::{applicable, open_login_items, register, status, unregister};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_missing_registrations_are_registered_automatically() {
        assert!(ServiceStatus::NotRegistered.should_register());
        assert!(ServiceStatus::NotFound.should_register());
        assert!(!ServiceStatus::RequiresApproval.should_register());
        assert!(!ServiceStatus::Enabled.should_register());
    }

    #[test]
    fn statuses_serialize_snake_case() {
        assert_eq!(
            serde_json::to_value(ServiceStatus::RequiresApproval).unwrap(),
            "requires_approval"
        );
    }

    #[test]
    fn tests_never_count_as_a_bundled_app() {
        assert!(!applicable());
    }
}
