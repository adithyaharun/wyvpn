use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::Context;
use tokio::io::AsyncRead;
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use wyvpn_core::Secret;
use wyvpn_core::auth::OpenVpnCredentials;

use super::binary::{self, OpenVpnBinary, Trust};
use super::management::{self, LineReader, Setup, TunnelEvent};
use super::runtime::{CONFIG_FILE, RuntimeDir};
use super::stage::{bin_dir, stage};

pub const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(8);
const EVENT_CAPACITY: usize = 64;
const CHILD_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
const DRAIN_GRACE: Duration = Duration::from_secs(1);
const MANAGEMENT_DRAIN: Duration = Duration::from_millis(250);
const EXIT_GRACE: Duration = Duration::from_secs(2);
#[cfg(windows)]
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);

fn accept_staged(
    copy: PathBuf,
    verify: &dyn Fn(&Path) -> binary::Check,
    require_signature: bool,
) -> Result<PathBuf, String> {
    match verify(&copy) {
        binary::Check::Pass => Ok(copy),
        binary::Check::Skip(_) if !require_signature => Ok(copy),
        binary::Check::Skip(reason) | binary::Check::Fail(reason) => {
            Err(format!("staged wyvpnd is not verified: {reason}"))
        }
    }
}

#[derive(Debug, Clone)]
pub struct HookCommand {
    pub executable: PathBuf,
}

impl HookCommand {
    pub fn current() -> io::Result<Self> {
        Ok(Self {
            executable: std::env::current_exe()?,
        })
    }

    pub fn current_trusted(data_dir: &Path) -> Option<Self> {
        let current = match Self::current() {
            Ok(current) => current,
            Err(err) => {
                tracing::warn!(%err, "cannot locate the wyvpnd executable; DNS will not be configured");
                return None;
            }
        };
        match binary::resolve_trusted(&current.executable, &Trust::root()) {
            Ok(executable) => return Some(Self { executable }),
            Err(err) => {
                tracing::info!(path = %current.executable.display(), %err, "wyvpnd is not in a root-only location, staging a private copy for the DNS hook");
            }
        }
        let staged = stage(&current.executable, &bin_dir(data_dir), "wyvpnd")
            .map_err(|err| err.to_string())
            .and_then(|copy| {
                binary::resolve_trusted(&copy, &Trust::root()).map_err(|err| err.to_string())
            })
            .and_then(|copy| {
                accept_staged(
                    copy,
                    &super::signature::verify_hook,
                    super::signature::signed_build(),
                )
            });
        match staged {
            Ok(executable) => Some(Self { executable }),
            Err(err) => {
                tracing::warn!(%err, "no verified root-only copy of wyvpnd is available, so the DNS hook is disabled and tunnels will not set DNS");
                None
            }
        }
    }

    #[cfg_attr(windows, allow(dead_code))]
    pub fn command_line(&self) -> Option<String> {
        let path = self.executable.to_str()?;
        if path.chars().any(char::is_control) {
            return None;
        }
        Some(format!("{} hook", management::quote(path)))
    }
}

pub struct StartOptions {
    pub binary: OpenVpnBinary,
    pub credentials: Option<OpenVpnCredentials>,
    pub hook: Option<HookCommand>,
    pub stop_timeout: Duration,
}

pub struct Prepared {
    runtime: RuntimeDir,
    endpoint: Endpoint,
}

impl Prepared {
    #[cfg_attr(windows, allow(dead_code))]
    pub fn runtime_dir(&self) -> &Path {
        self.runtime.path()
    }
}

pub struct Tunnel {
    #[cfg(all(test, unix))]
    runtime_dir: PathBuf,
    stop: Option<oneshot::Sender<()>>,
    supervisor: JoinHandle<()>,
}

impl Tunnel {
    pub fn prepare(data_dir: &Path, config: &Secret) -> anyhow::Result<Prepared> {
        let runtime =
            RuntimeDir::create(data_dir, config).context("cannot create runtime directory")?;
        let endpoint = Endpoint::bind(&runtime).context("cannot prepare management endpoint")?;
        Ok(Prepared { runtime, endpoint })
    }

    pub fn start(
        prepared: Prepared,
        opts: StartOptions,
    ) -> anyhow::Result<(Self, mpsc::Receiver<TunnelEvent>)> {
        let Prepared { runtime, endpoint } = prepared;
        let command = build_command(
            &opts.binary.path,
            &runtime,
            &endpoint,
            opts.hook.as_ref(),
            opts.credentials.is_some(),
        )?;
        Self::launch(
            runtime,
            endpoint,
            command,
            opts.credentials,
            opts.stop_timeout,
        )
    }

    #[cfg(all(test, unix))]
    pub fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    pub async fn stop(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = (&mut self.supervisor).await;
    }

    pub(super) fn launch(
        runtime: RuntimeDir,
        endpoint: Endpoint,
        mut command: Command,
        credentials: Option<OpenVpnCredentials>,
        stop_timeout: Duration,
    ) -> anyhow::Result<(Self, mpsc::Receiver<TunnelEvent>)> {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().context("cannot start openvpn")?;
        let child_pid = child.id();

        let (events_tx, events_rx) = mpsc::channel(EVENT_CAPACITY);
        let (commands_tx, commands_rx) = mpsc::channel(4);
        let (stop_tx, stop_rx) = oneshot::channel();

        let mut logs = Vec::new();
        if let Some(stdout) = child.stdout.take() {
            logs.push(tokio::spawn(forward_output(stdout, events_tx.clone())));
        }
        if let Some(stderr) = child.stderr.take() {
            logs.push(tokio::spawn(forward_output(stderr, events_tx.clone())));
        }

        let management = tokio::spawn({
            let events = events_tx.clone();
            async move {
                endpoint
                    .serve(child_pid, credentials, events, commands_rx)
                    .await;
            }
        });

        #[cfg(all(test, unix))]
        let runtime_dir = runtime.path().to_path_buf();
        let supervisor = tokio::spawn(supervise(Supervised {
            child,
            runtime,
            management,
            logs,
            commands: commands_tx,
            stop: stop_rx,
            events: events_tx,
            stop_timeout,
        }));
        Ok((
            Self {
                #[cfg(all(test, unix))]
                runtime_dir,
                stop: Some(stop_tx),
                supervisor,
            },
            events_rx,
        ))
    }
}

struct Supervised {
    child: Child,
    runtime: RuntimeDir,
    management: JoinHandle<()>,
    logs: Vec<JoinHandle<()>>,
    commands: mpsc::Sender<management::Command>,
    stop: oneshot::Receiver<()>,
    events: mpsc::Sender<TunnelEvent>,
    stop_timeout: Duration,
}

async fn supervise(mut s: Supervised) {
    let status = tokio::select! {
        status = s.child.wait() => status.ok(),
        _ = &mut s.stop => terminate(&mut s).await,
        _ = &mut s.management => reap(&mut s.child).await,
    };

    if !s.management.is_finished() {
        let _ = tokio::time::timeout(MANAGEMENT_DRAIN, &mut s.management).await;
    }
    s.management.abort();
    for log in s.logs {
        let _ = tokio::time::timeout(DRAIN_GRACE, log).await;
    }
    s.runtime.remove();
    let code = status.and_then(|status| status.code());
    let _ = s.events.send(TunnelEvent::Exited(code)).await;
}

async fn reap(child: &mut Child) -> Option<std::process::ExitStatus> {
    if let Ok(status) = tokio::time::timeout(EXIT_GRACE, child.wait()).await {
        return status.ok();
    }
    let _ = child.kill().await;
    child.wait().await.ok()
}

async fn terminate(s: &mut Supervised) -> Option<std::process::ExitStatus> {
    let _ = s.commands.try_send(management::Command::Terminate);
    let exited = tokio::select! {
        status = s.child.wait() => Some(status.ok()),
        _ = &mut s.management => None,
        _ = tokio::time::sleep(s.stop_timeout) => None,
    };
    if let Some(status) = exited {
        return status;
    }
    if let Ok(Some(status)) = s.child.try_wait() {
        return Some(status);
    }
    if s.management.is_finished() {
        return reap(&mut s.child).await;
    }
    let _ = s.child.kill().await;
    s.child.wait().await.ok()
}

async fn forward_output<R: AsyncRead + Unpin>(stream: R, events: mpsc::Sender<TunnelEvent>) {
    let mut lines = LineReader::new(stream);
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim_end();
        tracing::debug!(target: "wyvpnd::openvpn", "{}", crate::log::redact(line));
        let _ = events.send(TunnelEvent::Log(line.to_owned())).await;
    }
}

pub(super) enum Endpoint {
    #[cfg(unix)]
    Unix {
        listener: tokio::net::UnixListener,
        socket: PathBuf,
    },
    #[cfg(windows)]
    Tcp {
        listener: tokio::net::TcpListener,
        port: u16,
    },
}

#[cfg(unix)]
impl Endpoint {
    pub(super) fn bind(runtime: &RuntimeDir) -> io::Result<Self> {
        let socket = runtime.management_socket();
        let listener = tokio::net::UnixListener::bind(&socket)?;
        Ok(Self::Unix { listener, socket })
    }

    fn args(&self) -> Vec<OsString> {
        let Self::Unix { socket, .. } = self;
        vec![
            "--management".into(),
            socket.clone().into_os_string(),
            "unix".into(),
            "--management-client".into(),
        ]
    }

    async fn serve(
        self,
        _child_pid: Option<u32>,
        credentials: Option<OpenVpnCredentials>,
        events: mpsc::Sender<TunnelEvent>,
        mut commands: mpsc::Receiver<management::Command>,
    ) {
        let Self::Unix { listener, .. } = self;
        let stream = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(err) => {
                    tracing::debug!(target: "wyvpnd::openvpn", %err, "management accept failed");
                    return;
                }
            },
            _ = commands.recv() => return,
        };
        drop(listener);
        let setup = Setup { credentials };
        if let Err(err) = management::drive(stream, setup, &events, &mut commands).await {
            tracing::debug!(target: "wyvpnd::openvpn", %err, "management session ended");
        }
    }
}

#[cfg(windows)]
impl Endpoint {
    pub(super) fn bind(_runtime: &RuntimeDir) -> io::Result<Self> {
        let std_listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        std_listener.set_nonblocking(true)?;
        let port = std_listener.local_addr()?.port();
        let listener = tokio::net::TcpListener::from_std(std_listener)?;
        Ok(Self::Tcp { listener, port })
    }

    fn args(&self) -> Vec<OsString> {
        let Self::Tcp { port, .. } = self;
        vec![
            "--management".into(),
            "127.0.0.1".into(),
            port.to_string().into(),
            "--management-client".into(),
        ]
    }

    async fn serve(
        self,
        child_pid: Option<u32>,
        credentials: Option<OpenVpnCredentials>,
        events: mpsc::Sender<TunnelEvent>,
        mut commands: mpsc::Receiver<management::Command>,
    ) {
        let Self::Tcp { listener, port } = self;
        let deadline = tokio::time::sleep(ACCEPT_TIMEOUT);
        tokio::pin!(deadline);
        let stream = loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, peer)) => {
                        if peer_is_child(peer, port, child_pid).await {
                            break stream;
                        }
                        tracing::warn!(target: "wyvpnd::openvpn", %peer, "rejected management connection from a foreign process");
                    }
                    Err(err) => {
                        tracing::debug!(target: "wyvpnd::openvpn", %err, "management accept failed");
                        return;
                    }
                },
                _ = commands.recv() => return,
                _ = &mut deadline => {
                    tracing::debug!(target: "wyvpnd::openvpn", "management connect timed out");
                    return;
                }
            }
        };
        drop(listener);
        let setup = Setup { credentials };
        if let Err(err) = management::drive(stream, setup, &events, &mut commands).await {
            tracing::debug!(target: "wyvpnd::openvpn", %err, "management session ended");
        }
    }
}

#[cfg(windows)]
async fn peer_is_child(
    peer: std::net::SocketAddr,
    listen_port: u16,
    child_pid: Option<u32>,
) -> bool {
    let (std::net::SocketAddr::V4(local), Some(child_pid)) = (peer, child_pid) else {
        return false;
    };
    let owner =
        tokio::task::spawn_blocking(move || super::peer::connection_owner(local, listen_port))
            .await;
    matches!(owner, Ok(Ok(Some(pid))) if pid == child_pid)
}

fn build_command(
    program: &Path,
    runtime: &RuntimeDir,
    endpoint: &Endpoint,
    hook: Option<&HookCommand>,
    with_credentials: bool,
) -> anyhow::Result<Command> {
    let mut command = Command::new(program);
    command.env_clear().env("PATH", CHILD_PATH);
    #[cfg(windows)]
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    command.current_dir(runtime.path());
    command.args([
        "--config",
        CONFIG_FILE,
        "--verb",
        "3",
        "--management-hold",
        "--management-query-passwords",
    ]);
    if with_credentials {
        command.arg("--auth-user-pass");
    }
    command.args(endpoint.args());

    #[cfg(unix)]
    if let Some(hook) = hook {
        let line = hook
            .command_line()
            .context("hook executable path is not usable in an openvpn command line")?;
        command.args(["--script-security", "2", "--up", &line, "--down", &line]);
        return Ok(command);
    }
    #[cfg(windows)]
    let _ = hook;
    command.args(["--script-security", "1"]);
    Ok(command)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::Instant;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    fn short_tempdir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("wy")
            .tempdir_in("/tmp")
            .unwrap()
    }

    fn args_of(command: &Command) -> Vec<String> {
        command
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    fn fixture(dir: &Path) -> (RuntimeDir, Endpoint) {
        let runtime = RuntimeDir::create(dir, &Secret::new("client\n")).unwrap();
        let endpoint = Endpoint::bind(&runtime).unwrap();
        (runtime, endpoint)
    }

    #[tokio::test]
    async fn command_line_without_hook() {
        let data = short_tempdir();
        let (runtime, endpoint) = fixture(data.path());
        let command = build_command(
            Path::new("/usr/sbin/openvpn"),
            &runtime,
            &endpoint,
            None,
            false,
        )
        .unwrap();
        let args = args_of(&command);
        let socket = runtime.management_socket().to_string_lossy().into_owned();
        let expected: Vec<String> = [
            "--config",
            "openvpn.conf",
            "--verb",
            "3",
            "--management-hold",
            "--management-query-passwords",
            "--management",
            &socket,
            "unix",
            "--management-client",
            "--script-security",
            "1",
        ]
        .map(String::from)
        .into();
        assert_eq!(args, expected);

        let std = command.as_std();
        assert_eq!(std.get_current_dir(), Some(runtime.path()));
        let envs: Vec<_> = std.get_envs().collect();
        assert_eq!(envs.len(), 1);
        assert_eq!(envs[0].0, "PATH");
        assert_eq!(envs[0].1.unwrap(), CHILD_PATH);
    }

    #[tokio::test]
    async fn command_line_with_hook_quotes_paths_with_spaces() {
        let data = short_tempdir();
        let (runtime, endpoint) = fixture(data.path());
        let hook = HookCommand {
            executable: PathBuf::from("/opt/my \"apps\"/wyvpnd"),
        };
        let command = build_command(
            Path::new("/usr/sbin/openvpn"),
            &runtime,
            &endpoint,
            Some(&hook),
            true,
        )
        .unwrap();
        let args = args_of(&command);
        let line = r#""/opt/my \"apps\"/wyvpnd" hook"#;
        let at = args.iter().position(|a| a == "--script-security").unwrap();
        assert_eq!(args[at + 1], "2");
        assert_eq!(args[at + 2], "--up");
        assert_eq!(args[at + 3], line);
        assert_eq!(args[at + 4], "--down");
        assert_eq!(args[at + 5], line);
        assert!(
            !args
                .iter()
                .any(|a| a.contains("auth-user-pass") && a != "--auth-user-pass")
        );
    }

    #[tokio::test]
    async fn auth_user_pass_only_with_credentials() {
        let data = short_tempdir();
        let (runtime, endpoint) = fixture(data.path());
        let program = Path::new("/usr/sbin/openvpn");
        let without = build_command(program, &runtime, &endpoint, None, false).unwrap();
        assert!(!args_of(&without).contains(&"--auth-user-pass".to_owned()));
        let with = build_command(program, &runtime, &endpoint, None, true).unwrap();
        assert!(args_of(&with).contains(&"--auth-user-pass".to_owned()));
    }

    #[test]
    fn staged_hook_needs_a_passing_signature_check() {
        use binary::Check;
        let copy = || PathBuf::from("/data/bin/wyvpnd");
        let run = |check: Check, strict| accept_staged(copy(), &|_| check.clone(), strict);
        assert!(run(Check::Pass, true).is_ok());
        assert!(run(Check::Fail("bad".into()), true).is_err());
        assert!(run(Check::Fail("bad".into()), false).is_err());
        assert!(run(Check::Skip("no team".into()), true).is_err());
        assert!(run(Check::Skip("unsigned".into()), false).is_ok());
        assert!(run(Check::Pass, false).is_ok());
    }

    #[test]
    fn hook_rejects_unusable_paths() {
        let hook = HookCommand {
            executable: PathBuf::from("/a\nb/wyvpnd"),
        };
        assert!(hook.command_line().is_none());
        let hook = HookCommand {
            executable: PathBuf::from("/usr/local/bin/wyvpnd"),
        };
        assert_eq!(
            hook.command_line().unwrap(),
            r#""/usr/local/bin/wyvpnd" hook"#
        );
    }

    #[tokio::test]
    async fn hung_process_is_killed_and_runtime_dir_removed() {
        let data = short_tempdir();
        let (runtime, endpoint) = fixture(data.path());
        let mut command = Command::new("/bin/sleep");
        command.arg("60");
        let timeout = Duration::from_millis(400);
        let (tunnel, mut events) =
            Tunnel::launch(runtime, endpoint, command, None, timeout).unwrap();
        let dir = tunnel.runtime_dir().to_path_buf();
        assert!(dir.join(CONFIG_FILE).exists());

        let stream = UnixStream::connect(dir.join(crate::openvpn::runtime::MGMT_SOCKET))
            .await
            .unwrap();
        let (read, mut write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();
        let (seen_tx, mut seen) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = seen_tx.send(line);
            }
        });
        write
            .write_all(b">HOLD:Waiting for hold release:0\n")
            .await
            .unwrap();
        let mut got = Vec::new();
        while got.last().map(String::as_str) != Some("hold release") {
            got.push(seen.recv().await.unwrap());
        }
        assert_eq!(got, ["state on", "bytecount 5", "hold release"]);

        let started = Instant::now();
        tunnel.stop().await;
        let elapsed = started.elapsed();
        assert_eq!(seen.recv().await.unwrap(), "signal SIGTERM");
        assert!(elapsed >= timeout, "killed too early: {elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
        assert!(!dir.exists());

        let mut last = None;
        while let Some(event) = events.recv().await {
            last = Some(event);
        }
        assert_eq!(last, Some(TunnelEvent::Exited(None)));
        drop(write);
    }

    #[tokio::test]
    async fn closed_management_connection_is_killed_after_the_grace_period() {
        let data = short_tempdir();
        let (runtime, endpoint) = fixture(data.path());
        let mut command = Command::new("/bin/sleep");
        command.arg("60");
        let (tunnel, mut events) =
            Tunnel::launch(runtime, endpoint, command, None, Duration::from_secs(30)).unwrap();
        let dir = tunnel.runtime_dir().to_path_buf();
        let stream = UnixStream::connect(dir.join(crate::openvpn::runtime::MGMT_SOCKET))
            .await
            .unwrap();
        drop(stream);

        let started = Instant::now();
        assert_eq!(events.recv().await, Some(TunnelEvent::Exited(None)));
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_secs(1),
            "killed too early: {elapsed:?}"
        );
        assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
        tunnel.stop().await;
        assert!(!dir.exists());
    }

    #[tokio::test]
    async fn unexpected_exit_reports_code_and_cleans_up() {
        let data = short_tempdir();
        let (runtime, endpoint) = fixture(data.path());
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "echo hi; exit 3"]);
        let (tunnel, mut events) =
            Tunnel::launch(runtime, endpoint, command, None, Duration::from_secs(1)).unwrap();
        let dir = tunnel.runtime_dir().to_path_buf();
        assert_eq!(events.recv().await, Some(TunnelEvent::Log("hi".into())));
        assert_eq!(events.recv().await, Some(TunnelEvent::Exited(Some(3))));
        assert!(!dir.exists());
        tunnel.stop().await;
    }
}
