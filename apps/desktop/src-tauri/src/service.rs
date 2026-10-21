use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchAction {
    Nothing,
    RecordVersion,
    Reregister,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registration {
    Done,
    NeedsApproval,
}

pub fn settle_registration(
    result: Result<(), String>,
    status: ServiceStatus,
) -> Result<Registration, String> {
    match result {
        _ if status == ServiceStatus::RequiresApproval => Ok(Registration::NeedsApproval),
        Ok(()) => Ok(Registration::Done),
        Err(message) => Err(message),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub enum JobState {
    Stale,
    Healthy,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    Unreachable,
    Current,
    Outdated,
}

impl Probe {
    pub fn from_version(daemon_version: &str, expected: &str) -> Self {
        if daemon_version == expected {
            Self::Current
        } else {
            Self::Outdated
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evidence {
    pub job: JobState,
    pub probe: Probe,
    pub session_active: bool,
}

impl Evidence {
    pub fn conclusive(self) -> bool {
        self.job == JobState::Stale || self.probe != Probe::Unreachable
    }
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn parse_job_state(output: &str, listed: bool) -> JobState {
    if !listed {
        return JobState::Unknown;
    }
    let value = |line: &str, key: &str| {
        line.trim()
            .strip_prefix(key)
            .and_then(|rest| rest.trim_start().strip_prefix('='))
            .map(|rest| rest.trim().to_owned())
    };
    let mut stale = false;
    let mut seen = false;
    for line in output.lines() {
        if line.contains("needs LWCR update") {
            stale = true;
        }
        if let Some(state) = value(line, "job state") {
            seen = true;
            stale |= state.contains("spawn failed");
        }
        if let Some(code) = value(line, "last exit code") {
            stale |= code.split(|c: char| c == ':' || c.is_whitespace()).next() == Some("78");
        }
    }
    match (stale, seen) {
        (true, _) => JobState::Stale,
        (false, true) => JobState::Healthy,
        (false, false) => JobState::Unknown,
    }
}

pub fn version_check_due(stored: Option<&str>, current: &str, status: ServiceStatus) -> bool {
    status == ServiceStatus::Enabled && stored != Some(current)
}

pub fn launch_action(
    stored: Option<&str>,
    current: &str,
    status: ServiceStatus,
    evidence: Evidence,
) -> LaunchAction {
    if !version_check_due(stored, current, status) {
        return LaunchAction::Nothing;
    }
    if evidence.probe == Probe::Current {
        return LaunchAction::RecordVersion;
    }
    let stale = evidence.job == JobState::Stale
        || evidence.probe == Probe::Outdated
        || evidence.job == JobState::Unknown;
    if !stale || evidence.session_active {
        LaunchAction::Nothing
    } else {
        LaunchAction::Reregister
    }
}

pub fn session_may_be_active(in_progress: bool, probe: Probe, statuses_loaded: bool) -> bool {
    in_progress || (probe != Probe::Unreachable && !statuses_loaded)
}

#[cfg(target_os = "macos")]
mod imp {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::{JobState, ServiceStatus, parse_job_state};
    use block2::RcBlock;
    use objc2_foundation::{NSError, NSString};
    use objc2_service_management::{SMAppService, SMAppServiceStatus, kSMErrorJobNotFound};

    const LABEL: &str = "com.aprdth.wyvpn.daemon";
    const LAUNCHCTL_TIMEOUT: Duration = Duration::from_secs(3);
    const UNREGISTER_TIMEOUT: Duration = Duration::from_secs(15);
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

    pub fn reregister() -> Result<(), String> {
        let (tx, rx) = mpsc::channel();
        let handler = RcBlock::new(move |error: *mut NSError| {
            let outcome = unsafe { error.as_ref() }
                .map(|error| (error.code(), error.localizedDescription().to_string()));
            let _ = tx.send(outcome);
        });
        with_service(|service| unsafe { service.unregisterWithCompletionHandler(&handler) });
        match rx.recv_timeout(UNREGISTER_TIMEOUT) {
            Ok(None) => {}
            Ok(Some((code, _))) if code == kSMErrorJobNotFound as isize => {}
            Ok(Some((_, message))) => return Err(message),
            Err(_) => {
                return match status() {
                    ServiceStatus::NotRegistered | ServiceStatus::NotFound => register(),
                    _ => Err("the background service did not stop in time; use Repair background service again or set the service up again".to_owned()),
                };
            }
        }
        register()
    }

    pub fn job_state() -> JobState {
        let Ok(mut child) = Command::new("/bin/launchctl")
            .args(["print", &format!("system/{LABEL}")])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        else {
            return JobState::Unknown;
        };
        let Some(mut stdout) = child.stdout.take() else {
            return JobState::Unknown;
        };
        let reader = std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stdout.read_to_string(&mut text);
            text
        });
        let deadline = Instant::now() + LAUNCHCTL_TIMEOUT;
        let listed = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status.success(),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break false;
                }
            }
        };
        let text = reader.join().unwrap_or_default();
        parse_job_state(&text, listed)
    }

    pub fn open_login_items() {
        unsafe { SMAppService::openSystemSettingsLoginItems() };
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::{JobState, ServiceStatus};

    pub fn applicable() -> bool {
        false
    }

    pub fn status() -> ServiceStatus {
        ServiceStatus::Enabled
    }

    pub fn register() -> Result<(), String> {
        Err("service registration is not supported on this system".to_owned())
    }

    pub fn reregister() -> Result<(), String> {
        register()
    }

    pub fn job_state() -> JobState {
        JobState::Unknown
    }

    pub fn open_login_items() {}
}

#[cfg(target_os = "macos")]
pub use imp::unregister;
pub use imp::{applicable, job_state, open_login_items, status};

pub fn register() -> Result<Registration, String> {
    settle_registration(imp::register(), imp::status())
}

pub fn reregister() -> Result<Registration, String> {
    settle_registration(imp::reregister(), imp::status())
}

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

    const OLD: Option<&str> = Some("0.1.0");

    fn evidence(job: JobState, probe: Probe) -> Evidence {
        Evidence {
            job,
            probe,
            session_active: false,
        }
    }

    fn action(stored: Option<&str>, status: ServiceStatus, evidence: Evidence) -> LaunchAction {
        launch_action(stored, "0.2.0", status, evidence)
    }

    #[test]
    fn unchanged_version_never_touches_the_service() {
        for job in [JobState::Stale, JobState::Healthy, JobState::Unknown] {
            for probe in [Probe::Unreachable, Probe::Current, Probe::Outdated] {
                assert_eq!(
                    launch_action(OLD, "0.1.0", ServiceStatus::Enabled, evidence(job, probe)),
                    LaunchAction::Nothing
                );
            }
        }
    }

    #[test]
    fn healthy_current_daemon_only_records() {
        for stored in [OLD, None] {
            for job in [JobState::Healthy, JobState::Unknown] {
                assert_eq!(
                    action(
                        stored,
                        ServiceStatus::Enabled,
                        evidence(job, Probe::Current)
                    ),
                    LaunchAction::RecordVersion
                );
            }
        }
    }

    #[test]
    fn failed_registration_awaiting_approval_is_not_an_error() {
        let failed = || Err("Operation not permitted".to_owned());
        assert_eq!(
            settle_registration(failed(), ServiceStatus::RequiresApproval),
            Ok(Registration::NeedsApproval)
        );
        assert_eq!(
            settle_registration(Ok(()), ServiceStatus::RequiresApproval),
            Ok(Registration::NeedsApproval)
        );
        assert_eq!(
            settle_registration(Ok(()), ServiceStatus::Enabled),
            Ok(Registration::Done)
        );
        for status in [
            ServiceStatus::NotRegistered,
            ServiceStatus::NotFound,
            ServiceStatus::Enabled,
        ] {
            assert_eq!(
                settle_registration(failed(), status),
                Err("Operation not permitted".to_owned())
            );
        }
    }

    #[test]
    fn current_daemon_wins_over_a_stale_job() {
        assert_eq!(
            action(
                OLD,
                ServiceStatus::Enabled,
                evidence(JobState::Stale, Probe::Current)
            ),
            LaunchAction::RecordVersion
        );
    }

    #[test]
    fn unknown_statuses_on_a_reachable_daemon_count_as_a_session() {
        assert!(session_may_be_active(true, Probe::Unreachable, true));
        assert!(session_may_be_active(false, Probe::Outdated, false));
        assert!(session_may_be_active(false, Probe::Current, false));
        assert!(!session_may_be_active(false, Probe::Outdated, true));
        assert!(!session_may_be_active(false, Probe::Unreachable, false));
    }

    #[test]
    fn probe_available_but_actually_outdated_reregisters() {
        let old = Probe::from_version("0.1.0", "0.2.0");
        assert_eq!(old, Probe::Outdated);
        assert_eq!(
            action(
                OLD,
                ServiceStatus::Enabled,
                evidence(JobState::Healthy, old)
            ),
            LaunchAction::Reregister
        );
    }

    #[test]
    fn spawn_failed_reregisters_even_without_a_daemon() {
        for stored in [OLD, None] {
            assert_eq!(
                action(
                    stored,
                    ServiceStatus::Enabled,
                    evidence(JobState::Stale, Probe::Unreachable)
                ),
                LaunchAction::Reregister
            );
        }
    }

    #[test]
    fn slow_but_healthy_job_is_left_alone() {
        assert_eq!(
            action(
                OLD,
                ServiceStatus::Enabled,
                evidence(JobState::Healthy, Probe::Unreachable)
            ),
            LaunchAction::Nothing
        );
    }

    #[test]
    fn unreachable_with_no_job_information_reregisters() {
        assert_eq!(
            action(
                None,
                ServiceStatus::Enabled,
                evidence(JobState::Unknown, Probe::Unreachable)
            ),
            LaunchAction::Reregister
        );
    }

    #[test]
    fn active_session_defers_the_repair() {
        let busy = Evidence {
            session_active: true,
            ..evidence(JobState::Stale, Probe::Outdated)
        };
        assert_eq!(
            action(OLD, ServiceStatus::Enabled, busy),
            LaunchAction::Nothing
        );
    }

    #[test]
    fn only_an_enabled_service_is_ever_touched() {
        for status in [
            ServiceStatus::RequiresApproval,
            ServiceStatus::NotRegistered,
            ServiceStatus::NotFound,
        ] {
            for stored in [OLD, None] {
                assert_eq!(
                    action(stored, status, evidence(JobState::Stale, Probe::Outdated)),
                    LaunchAction::Nothing
                );
            }
        }
    }

    #[test]
    fn evidence_is_conclusive_once_something_answers() {
        assert!(!evidence(JobState::Healthy, Probe::Unreachable).conclusive());
        assert!(!evidence(JobState::Unknown, Probe::Unreachable).conclusive());
        assert!(evidence(JobState::Stale, Probe::Unreachable).conclusive());
        assert!(evidence(JobState::Healthy, Probe::Current).conclusive());
        assert!(evidence(JobState::Healthy, Probe::Outdated).conclusive());
    }

    const RUNNING: &str = "system/com.aprdth.wyvpn.daemon = {\n\tactive count = 1\n\tstate = running\n\tjob state = running\n\tlast exit code = (never exited)\n\tproperties = has LWCR | inferred program\n}\n";
    const SPAWN_FAILED: &str = "system/com.aprdth.wyvpn.daemon = {\n\tstate = not running\n\tjob state = spawn failed\n\tlast exit code = 78: EX_CONFIG\n\tproperties = needs LWCR update | has LWCR\n}\n";

    #[test]
    fn launchctl_output_is_classified() {
        assert_eq!(parse_job_state(RUNNING, true), JobState::Healthy);
        assert_eq!(parse_job_state(SPAWN_FAILED, true), JobState::Stale);
        assert_eq!(
            parse_job_state("\tjob state = waiting\n\tlast exit code = 1\n", true),
            JobState::Healthy
        );
        assert_eq!(
            parse_job_state("\tlast exit code = 78: EX_CONFIG\n", true),
            JobState::Stale
        );
        assert_eq!(
            parse_job_state("\tproperties = needs LWCR update\n", true),
            JobState::Stale
        );
        assert_eq!(
            parse_job_state("\tlast exit code = 780\n\tjob state = running\n", true),
            JobState::Healthy
        );
    }

    #[test]
    fn missing_or_unparseable_jobs_are_unknown() {
        assert_eq!(
            parse_job_state("Could not find service", false),
            JobState::Unknown
        );
        assert_eq!(parse_job_state("", true), JobState::Unknown);
        assert_eq!(parse_job_state("garbage\n", true), JobState::Unknown);
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
