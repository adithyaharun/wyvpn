use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use anyhow::Context;
use tokio::sync::mpsc;
use wyvpn_core::Secret;
use wyvpn_core::auth::OpenVpnCredentials;

use crate::openvpn::binary;
use crate::openvpn::management::TunnelEvent;
use crate::openvpn::process::{DEFAULT_STOP_TIMEOUT, HookCommand, StartOptions, Tunnel};
use crate::wireguard::launcher::{WireGuardLauncher, WireGuardRequest};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub struct OpenVpnRequest {
    pub config: Secret,
    pub credentials: Option<OpenVpnCredentials>,
}

pub enum LaunchRequest {
    OpenVpn(OpenVpnRequest),
    WireGuard(Box<WireGuardRequest>),
}

pub struct Launched {
    pub running: Box<dyn Running>,
    pub events: mpsc::Receiver<TunnelEvent>,
}

pub trait Running: Send {
    fn stop(self: Box<Self>) -> BoxFuture<'static, ()>;
}

pub trait Launcher: Send + Sync + 'static {
    fn launch(&self, request: LaunchRequest) -> BoxFuture<'_, anyhow::Result<Launched>>;
}

pub struct TunnelLauncher {
    data_dir: PathBuf,
    binary_path: Option<PathBuf>,
    hook: Option<HookCommand>,
    wireguard: WireGuardLauncher,
}

impl TunnelLauncher {
    pub fn new(data_dir: PathBuf, binary_path: Option<PathBuf>, hook: Option<HookCommand>) -> Self {
        Self {
            wireguard: WireGuardLauncher::system(data_dir.clone()),
            data_dir,
            binary_path,
            hook,
        }
    }

    async fn start(&self, request: OpenVpnRequest) -> anyhow::Result<Launched> {
        let path = self.binary_path.clone();
        let data_dir = self.data_dir.clone();
        let binary =
            tokio::task::spawn_blocking(move || binary::locate(path.as_deref(), &data_dir))
                .await
                .context("binary lookup was interrupted")??;
        let prepared = Tunnel::prepare(&self.data_dir, &request.config)?;
        #[cfg(unix)]
        let dns = dns_guard::DnsGuard::attach(prepared.runtime_dir(), &self.data_dir)
            .context("cannot listen for tunnel hooks")?;
        let started = Tunnel::start(
            prepared,
            StartOptions {
                binary,
                credentials: request.credentials,
                hook: self.hook.clone(),
                stop_timeout: DEFAULT_STOP_TIMEOUT,
            },
        );
        let (tunnel, events) = match started {
            Ok(started) => started,
            Err(err) => {
                #[cfg(unix)]
                dns.finish().await;
                return Err(err);
            }
        };
        Ok(Launched {
            running: Box::new(Active {
                tunnel,
                #[cfg(unix)]
                dns,
            }),
            events,
        })
    }
}

impl Launcher for TunnelLauncher {
    fn launch(&self, request: LaunchRequest) -> BoxFuture<'_, anyhow::Result<Launched>> {
        match request {
            LaunchRequest::OpenVpn(request) => Box::pin(self.start(request)),
            LaunchRequest::WireGuard(request) => self.wireguard.launch_request(*request),
        }
    }
}

struct Active {
    tunnel: Tunnel,
    #[cfg(unix)]
    dns: dns_guard::DnsGuard,
}

impl Running for Active {
    fn stop(self: Box<Self>) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            let Self {
                tunnel,
                #[cfg(unix)]
                dns,
            } = *self;
            tunnel.stop().await;
            #[cfg(unix)]
            dns.finish().await;
        })
    }
}

#[cfg(unix)]
mod dns_guard {
    use std::io;
    use std::path::Path;
    use std::sync::Arc;

    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;

    use crate::dns::{Dns, HookListener, HookPhase};

    pub struct DnsGuard {
        dns: Arc<Dns>,
        stop: Option<oneshot::Sender<()>>,
        task: Option<JoinHandle<()>>,
        restored: bool,
    }

    impl DnsGuard {
        pub fn attach(runtime_dir: &Path, data_dir: &Path) -> io::Result<Self> {
            let listener = HookListener::bind(runtime_dir)?;
            let dns = Arc::new(Dns::new(data_dir));
            let (stop, stopped) = oneshot::channel();
            let task = tokio::spawn(serve(listener, dns.clone(), stopped));
            Ok(Self {
                dns,
                stop: Some(stop),
                task: Some(task),
                restored: false,
            })
        }

        pub async fn finish(mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            if let Some(task) = self.task.take() {
                let _ = task.await;
            }
            self.restored = true;
            restore(self.dns.clone()).await;
        }
    }

    impl Drop for DnsGuard {
        fn drop(&mut self) {
            if self.restored {
                return;
            }
            if let Some(task) = self.task.take() {
                task.abort();
            }
            if let Err(err) = self.dns.restore() {
                tracing::warn!(%err, "cannot restore dns");
            }
        }
    }

    async fn restore(dns: Arc<Dns>) {
        let result = tokio::task::spawn_blocking(move || dns.restore()).await;
        if let Ok(Err(err)) = result {
            tracing::warn!(%err, "cannot restore dns");
        }
    }

    async fn serve(mut listener: HookListener, dns: Arc<Dns>, mut stopped: oneshot::Receiver<()>) {
        loop {
            let report = tokio::select! {
                report = listener.next() => match report {
                    Some(report) => report,
                    None => return,
                },
                _ = &mut stopped => return,
            };
            match report.phase {
                HookPhase::Up => {
                    let dns = dns.clone();
                    let applied =
                        tokio::task::spawn_blocking(move || dns.apply(&report.dev, &report.dns))
                            .await;
                    if let Ok(Err(err)) = applied {
                        tracing::warn!(%err, "cannot apply dns");
                    }
                }
                HookPhase::Down => restore(dns.clone()).await,
            }
        }
    }
}

#[cfg(test)]
pub struct Unavailable;

#[cfg(test)]
impl Launcher for Unavailable {
    fn launch(&self, _request: LaunchRequest) -> BoxFuture<'_, anyhow::Result<Launched>> {
        Box::pin(async { Err(anyhow::anyhow!("no launcher configured")) })
    }
}

#[cfg(test)]
pub mod fake {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    pub struct Process {
        pub credentials: Option<OpenVpnCredentials>,
        pub events: mpsc::Sender<TunnelEvent>,
        stopped: Arc<AtomicBool>,
    }

    impl Process {
        pub fn stopped(&self) -> bool {
            self.stopped.load(Ordering::SeqCst)
        }

        pub async fn send(&self, event: TunnelEvent) {
            self.events.send(event).await.unwrap();
        }

        pub fn password(&self) -> String {
            self.credentials
                .as_ref()
                .unwrap()
                .password
                .expose()
                .to_owned()
        }
    }

    pub struct Fake {
        launched: mpsc::UnboundedSender<Process>,
        fail: bool,
    }

    pub fn pair() -> (Arc<Fake>, mpsc::UnboundedReceiver<Process>) {
        let (launched, receiver) = mpsc::unbounded_channel();
        (
            Arc::new(Fake {
                launched,
                fail: false,
            }),
            receiver,
        )
    }

    pub fn failing() -> Arc<Fake> {
        let (launched, _) = mpsc::unbounded_channel();
        Arc::new(Fake {
            launched,
            fail: true,
        })
    }

    struct FakeRunning {
        events: mpsc::Sender<TunnelEvent>,
        stopped: Arc<AtomicBool>,
    }

    impl Running for FakeRunning {
        fn stop(self: Box<Self>) -> BoxFuture<'static, ()> {
            Box::pin(async move {
                self.stopped.store(true, Ordering::SeqCst);
                let _ = self.events.send(TunnelEvent::Exited(None)).await;
            })
        }
    }

    impl Launcher for Fake {
        fn launch(&self, request: LaunchRequest) -> BoxFuture<'_, anyhow::Result<Launched>> {
            Box::pin(async move {
                if self.fail {
                    anyhow::bail!("launch refused");
                }
                let (events, receiver) = mpsc::channel(64);
                let stopped = Arc::new(AtomicBool::new(false));
                let credentials = match request {
                    LaunchRequest::OpenVpn(request) => request.credentials,
                    LaunchRequest::WireGuard(_) => None,
                };
                let _ = self.launched.send(Process {
                    credentials,
                    events: events.clone(),
                    stopped: stopped.clone(),
                });
                Ok(Launched {
                    running: Box::new(FakeRunning { events, stopped }),
                    events: receiver,
                })
            })
        }
    }
}
