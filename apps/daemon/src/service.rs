use std::ffi::OsString;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::Notify;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::Args;

const SERVICE_NAME: &str = "wyvpnd";
const START_HINT: Duration = Duration::from_secs(15);
const STOP_HINT: Duration = Duration::from_secs(30);

static ARGS: OnceLock<Mutex<Option<Args>>> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

pub fn run(args: Args) -> anyhow::Result<()> {
    let _ = ARGS.set(Mutex::new(Some(args)));
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(err) = run_service() {
        tracing::error!(%err, "service failed");
    }
}

fn status(
    state: ServiceState,
    accepted: ServiceControlAccept,
    exit: u32,
    checkpoint: u32,
    hint: Duration,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accepted,
        exit_code: if exit == 0 {
            ServiceExitCode::Win32(0)
        } else {
            ServiceExitCode::ServiceSpecific(exit)
        },
        checkpoint,
        wait_hint: hint,
        process_id: None,
    }
}

fn run_service() -> anyhow::Result<()> {
    let args = ARGS
        .get()
        .and_then(|slot| slot.lock().ok()?.take())
        .ok_or_else(|| anyhow::anyhow!("service arguments are missing"))?;

    let stop = Arc::new(Notify::new());
    let signal = stop.clone();
    let handle = service_control_handler::register(SERVICE_NAME, move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            signal.notify_one();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;

    handle.set_service_status(status(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        0,
        1,
        START_HINT,
    ))?;

    let running = || {
        let _ = handle.set_service_status(status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            0,
            0,
            Duration::ZERO,
        ));
    };
    let stopping = async {
        stop.notified().await;
        let _ = handle.set_service_status(status(
            ServiceState::StopPending,
            ServiceControlAccept::empty(),
            0,
            1,
            STOP_HINT,
        ));
    };

    let result = crate::run(args, stopping, running);
    if let Err(err) = &result {
        tracing::error!(%err, "wyvpnd failed");
    }
    handle.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        u32::from(result.is_err()),
        0,
        Duration::ZERO,
    ))?;
    result
}
