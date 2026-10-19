mod admin;
mod control;
mod dns;
mod egress;
#[cfg(any(target_os = "macos", all(test, unix)))]
mod exe_watch;
mod hook;
mod launcher;
mod listener;
mod log;
mod openvpn;
mod server;
#[cfg(windows)]
mod service;
mod session;
mod state;
mod storage;
#[cfg(test)]
mod testdata;
#[expect(dead_code, reason = "backend not yet called by the session loop")]
mod wireguard;

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "wyvpnd", version, about = "WyVPN privileged daemon")]
struct Args {
    /// Group granted access to the control socket
    #[arg(long, default_value = listener::default_socket_group())]
    socket_group: String,

    /// OpenVPN executable to use instead of the default locations
    #[arg(long, value_name = "PATH")]
    openvpn_path: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    #[command(hide = true)]
    Hook {
        #[arg(num_args = 0.., allow_hyphen_values = true, trailing_var_arg = true)]
        _args: Vec<String>,
    },
    #[command(hide = true)]
    Service,
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let Ok(mut term) = signal(SignalKind::terminate()) else {
            let _ = tokio::signal::ctrl_c().await;
            return;
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(target_os = "macos")]
async fn shutdown_or_replaced(state: Arc<state::State>, baseline: Option<exe_watch::Identity>) {
    let Ok(exe) = std::env::current_exe() else {
        return shutdown_signal().await;
    };
    let watch = exe_watch::replaced(
        exe,
        baseline,
        std::time::Duration::from_secs(5),
        openvpn::signature::verify_hook,
        move || {
            state
                .sessions
                .close_if_restartable(!openvpn::signature::signed_build())
        },
    );
    tokio::select! {
        () = shutdown_signal() => {}
        () = watch => tracing::info!("wyvpnd executable replaced; restarting"),
    }
}

fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    let baseline = std::env::current_exe()
        .ok()
        .and_then(|exe| exe_watch::Identity::read(&exe));
    let args = Args::parse();
    if let Some(Command::Hook { .. }) = args.command {
        hook::run();
        return Ok(());
    }
    init_logging();
    if let Some(Command::Service) = args.command {
        #[cfg(windows)]
        return service::run(args);
        #[cfg(not(windows))]
        anyhow::bail!("service mode is only available on Windows");
    }
    #[cfg(target_os = "macos")]
    return run(
        args,
        move |state| shutdown_or_replaced(state, baseline),
        || {},
    );
    #[cfg(not(target_os = "macos"))]
    run(args, |_| shutdown_signal(), || {})
}

fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(log_filter())
        .init();
}

async fn report_openvpn(path: Option<PathBuf>, data_dir: PathBuf) {
    let found =
        tokio::task::spawn_blocking(move || openvpn::binary::locate(path.as_deref(), &data_dir))
            .await;
    match found {
        Ok(Ok(binary)) => {
            tracing::info!(path = %binary.path.display(), version = %binary.version, "openvpn found");
        }
        Ok(Err(err)) => tracing::warn!(%err, "openvpn is not usable; connections will fail"),
        Err(_) => {}
    }
}

fn log_filter() -> EnvFilter {
    match std::env::var("RUST_LOG") {
        Ok(spec) if !spec.trim().is_empty() => {
            EnvFilter::try_new(spec).unwrap_or_else(|_| EnvFilter::new("wyvpnd=info"))
        }
        _ => EnvFilter::new("wyvpnd=info"),
    }
}

fn run<F: Future<Output = ()>>(
    args: Args,
    shutdown: impl FnOnce(Arc<state::State>) -> F,
    ready: impl FnOnce(),
) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?
        .block_on(serve_daemon(args, shutdown, ready))
}

async fn serve_daemon<F: Future<Output = ()>>(
    args: Args,
    shutdown: impl FnOnce(Arc<state::State>) -> F,
    ready: impl FnOnce(),
) -> anyhow::Result<()> {
    let path = wyvpn_ipc::socket_path();
    tracing::info!(socket = %path, "wyvpnd starting");

    let listener =
        listener::bind(&path, &args.socket_group).with_context(|| format!("cannot bind {path}"))?;
    let data_dir = storage::default_dir();
    let profiles = storage::FileProfiles::open(data_dir.clone())
        .with_context(|| format!("cannot prepare {}", data_dir.display()))?;
    tracing::info!(dir = %data_dir.display(), "profile storage ready");
    #[cfg(unix)]
    dns::recover(&data_dir);
    openvpn::runtime::sweep(&data_dir);
    report_openvpn(args.openvpn_path.clone(), data_dir.clone()).await;
    let launcher = launcher::TunnelLauncher::new(
        data_dir.clone(),
        args.openvpn_path,
        openvpn::process::HookCommand::current_trusted(&data_dir),
    );
    let state = Arc::new(state::State::with_launcher(profiles, Arc::new(launcher)));
    ready();
    listener::serve(
        listener,
        state.clone(),
        listener::Limits::default(),
        shutdown(state.clone()),
    )
    .await?;
    state.sessions.shutdown().await;

    tracing::info!("wyvpnd stopping");
    #[cfg(unix)]
    let _ = std::fs::remove_file(&path);
    Ok(())
}
