use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use tokio::sync::{Mutex, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval};
use wyvpn_core::http::ApiClient;
use wyvpn_core::tls::{Fingerprint, Pins, TlsPolicy, pin_key};
use wyvpn_core::wireguard::{
    DeviceInfo, Keepalive, KeepaliveInput, Platform, WireGuardSession, registration_hosts,
    send_keepalive,
};
use wyvpn_core::{Error as CoreError, Profile};
use zeroize::Zeroizing;

use super::backend::SharedBackend;
use super::handshake::wait_for_handshake;
use super::keepalive::{self, Pinger, Timing};
use super::preflight::{self, Unavailable};
use super::register::{self, RegisterError};
use super::tunnel::{Parts, Tunnel};
use crate::launcher::{BoxFuture, LaunchRequest, Launched, Launcher, Running};
use crate::openvpn::management::TunnelEvent;

const STATS_INTERVAL: Duration = Duration::from_secs(2);
const EVENT_BUFFER: usize = 64;

pub struct WireGuardRequest {
    pub profile: Profile,
    pub pins: Pins,
    pub pin: Option<Zeroizing<String>>,
    pub device: DeviceInfo,
}

pub struct Registered {
    pub session: Arc<WireGuardSession>,
    pub pinger: Arc<dyn Pinger>,
}

pub trait Server: Send + Sync {
    fn register<'a>(
        &'a self,
        request: &'a WireGuardRequest,
    ) -> BoxFuture<'a, Result<Registered, RegisterError>>;
}

type Preflight = Arc<dyn Fn() -> Result<(), Unavailable> + Send + Sync>;
type PartsFactory = Arc<dyn Fn() -> anyhow::Result<Parts> + Send + Sync>;

pub struct WireGuardLauncher {
    preflight: Preflight,
    server: Arc<dyn Server>,
    parts: PartsFactory,
    timing: Timing,
    stats_interval: Duration,
    bring_up_gate: Arc<Mutex<()>>,
}

struct CancelOnDrop(Option<Arc<AtomicBool>>);

impl CancelOnDrop {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(flag) = self.0.take() {
            flag.store(true, Ordering::SeqCst);
        }
    }
}

impl WireGuardLauncher {
    pub fn system(data_dir: PathBuf) -> Self {
        Self {
            preflight: Arc::new(preflight::check_system),
            server: Arc::new(HttpsServer),
            parts: Arc::new(move || Parts::system(tokio::runtime::Handle::current(), &data_dir)),
            timing: Timing::default(),
            stats_interval: STATS_INTERVAL,
            bring_up_gate: Arc::default(),
        }
    }

    pub fn launch_request(
        &self,
        request: WireGuardRequest,
    ) -> BoxFuture<'_, anyhow::Result<Launched>> {
        Box::pin(self.start(request))
    }

    async fn start(&self, request: WireGuardRequest) -> anyhow::Result<Launched> {
        let preflight = Arc::clone(&self.preflight);
        tokio::task::spawn_blocking(move || preflight())
            .await
            .context("the availability check was interrupted")??;

        let registered =
            tokio::time::timeout(register::TOTAL_DEADLINE, self.server.register(&request))
                .await
                .map_err(|_| RegisterError::Timeout)??;
        drop(request);
        let Registered { session, pinger } = registered;

        let cancelled = Arc::new(AtomicBool::new(false));
        let mut cancel_on_drop = CancelOnDrop(Some(Arc::clone(&cancelled)));
        let gate = Arc::clone(&self.bring_up_gate).lock_owned().await;
        let parts = (self.parts)()?;
        let for_bring_up = Arc::clone(&session);
        let tunnel = tokio::task::spawn_blocking(move || {
            if cancelled.load(Ordering::SeqCst) {
                bail!("the connection was cancelled");
            }
            let mut tunnel = Tunnel::bring_up(parts, &for_bring_up.config, &for_bring_up.keys)?;
            tunnel.keep(gate);
            Ok(tunnel)
        })
        .await
        .context("tunnel bring-up was interrupted")??;
        cancel_on_drop.disarm();

        let (events, receiver) = mpsc::channel(EVENT_BUFFER);
        let _ = events
            .send(TunnelEvent::Log(format!(
                "interface {} is up, waiting for the server",
                tunnel.interface()
            )))
            .await;
        let link = Link {
            tunnel_ip: session.config.address.addr.to_string(),
            remote: tunnel.endpoint().to_string(),
        };
        let keepalive_interval = session.config.keepalive_interval();
        drop(session);

        let (handshake_up, handshake) = watch::channel(false);
        let monitor = tokio::spawn(monitor(
            tunnel.backend(),
            events.clone(),
            link,
            self.stats_interval,
            handshake_up,
        ));
        let keepalive = tokio::spawn(keepalive::run(
            pinger,
            keepalive_interval,
            self.timing,
            wyvpn_core::rng::below,
            events,
            handshake,
        ));
        Ok(Launched {
            running: Box::new(Active {
                tasks: vec![monitor, keepalive],
                tunnel: Some(tunnel),
            }),
            events: receiver,
        })
    }
}

impl Launcher for WireGuardLauncher {
    fn launch(&self, request: LaunchRequest) -> BoxFuture<'_, anyhow::Result<Launched>> {
        match request {
            LaunchRequest::WireGuard(request) => self.launch_request(*request),
            LaunchRequest::OpenVpn(_) => {
                Box::pin(async { bail!("not a WireGuard launch request") })
            }
        }
    }
}

struct Link {
    tunnel_ip: String,
    remote: String,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

async fn monitor(
    backend: SharedBackend,
    events: mpsc::Sender<TunnelEvent>,
    link: Link,
    tick: Duration,
    handshake_up: watch::Sender<bool>,
) {
    let first = match wait_for_handshake(&backend).await {
        Ok(stats) => stats,
        Err(err) => {
            let _ = events.send(TunnelEvent::Fatal(err.to_string())).await;
            return;
        }
    };
    let _ = handshake_up.send(true);
    let mut last_handshake = None;
    let mut report = |stats: super::backend::PeerStats| {
        let at = stats
            .handshake_age
            .map(|age| unix_now().saturating_sub(age.as_secs()));
        let mut out = Vec::with_capacity(2);
        if at.is_some() && at != last_handshake {
            last_handshake = at;
            out.extend(at.map(TunnelEvent::Handshake));
        }
        out.push(TunnelEvent::Bytes {
            rx: stats.rx_bytes,
            tx: stats.tx_bytes,
        });
        out
    };
    let mut batch = report(first);
    let bytes = batch.pop();
    for event in batch {
        if events.send(event).await.is_err() {
            return;
        }
    }
    let connected = TunnelEvent::Connected {
        tunnel_ip: Some(link.tunnel_ip),
        remote: Some(link.remote),
    };
    for event in [Some(connected), bytes].into_iter().flatten() {
        if events.send(event).await.is_err() {
            return;
        }
    }
    let mut ticker = interval(tick);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        match backend.stats().await {
            Ok(stats) => {
                for event in report(stats) {
                    if events.send(event).await.is_err() {
                        return;
                    }
                }
            }
            Err(err) => {
                let _ = events
                    .send(TunnelEvent::Fatal(format!(
                        "tunnel interface lost: {err:#}"
                    )))
                    .await;
                return;
            }
        }
    }
}

struct Active {
    tasks: Vec<JoinHandle<()>>,
    tunnel: Option<Tunnel>,
}

impl Drop for Active {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Running for Active {
    fn stop(mut self: Box<Self>) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            let tasks = std::mem::take(&mut self.tasks);
            for task in &tasks {
                task.abort();
            }
            for task in tasks {
                let _ = task.await;
            }
            let Some(mut tunnel) = self.tunnel.take() else {
                return;
            };
            match tokio::task::spawn_blocking(move || tunnel.tear_down()).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    tracing::warn!(error = %format!("{err:#}"), "tunnel teardown failed")
                }
                Err(_) => tracing::warn!("tunnel teardown was interrupted"),
            }
        })
    }
}

pub fn keepalive_pins(
    base: &Pins,
    gateway: std::net::Ipv4Addr,
    web_port: u16,
    registration_cert: Option<Fingerprint>,
) -> Pins {
    let mut pins = base.clone();
    if let Some(fingerprint) = registration_cert {
        pins.entry(pin_key(&gateway.to_string(), web_port))
            .or_insert(fingerprint);
    }
    pins
}

fn registration_fingerprint(client: &ApiClient, profile: &Profile) -> Option<Fingerprint> {
    registration_hosts(profile)
        .iter()
        .rev()
        .filter_map(|host| url::Url::parse(host).ok())
        .find_map(|url| client.tls_observation(&url))
        .map(|observed| observed.fingerprint)
}

struct HttpsPinger {
    client: ApiClient,
    profile: Profile,
    session: Arc<WireGuardSession>,
    device: DeviceInfo,
}

impl Pinger for HttpsPinger {
    fn ping(&self) -> BoxFuture<'_, Result<Keepalive, CoreError>> {
        Box::pin(async move {
            send_keepalive(
                &self.client,
                &self.profile,
                &self.session,
                &KeepaliveInput {
                    device: &self.device,
                    auth_token: None,
                },
            )
            .await
        })
    }
}

pub struct HttpsServer;

impl Server for HttpsServer {
    fn register<'a>(
        &'a self,
        request: &'a WireGuardRequest,
    ) -> BoxFuture<'a, Result<Registered, RegisterError>> {
        Box::pin(async move {
            let client = register::https_client(&request.pins)?;
            let session = register::register(
                &client,
                &request.profile,
                &request.device,
                request.pin.as_ref().map(|pin| pin.as_str()),
            )
            .await?;
            let pins = keepalive_pins(
                &request.pins,
                session.config.gateway,
                session.config.web_port,
                registration_fingerprint(&client, &request.profile),
            );
            let session = Arc::new(session);
            let pinger = HttpsPinger {
                client: ApiClient::new(TlsPolicy::strict(pins))?,
                profile: request.profile.clone(),
                session: Arc::clone(&session),
                device: request.device.clone(),
            };
            Ok(Registered {
                session,
                pinger: Arc::new(pinger),
            })
        })
    }
}

pub fn device_info() -> DeviceInfo {
    DeviceInfo {
        hostname: hostname(),
        platform: Platform::current(),
        client_version: wyvpn_ipc::VERSION.to_owned(),
        mac_addr: String::new(),
        mac_addrs: Vec::new(),
        public_address: String::new(),
        public_address6: String::new(),
    }
}

#[cfg(unix)]
fn hostname() -> String {
    nix::unistd::gethostname()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(windows)]
fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_default()
}

#[cfg(test)]
pub mod testing {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, PoisonError, Weak};

    use wyvpn_core::wireguard::{WireGuardConfig, WireGuardKeys};

    use super::*;
    use crate::wireguard::backend::fake::{self, Handle};
    use crate::wireguard::dnsctl::fake::FakeDns;
    use crate::wireguard::netops::fake::FakeNet;
    use crate::wireguard::state::StateStore;
    use crate::wireguard::testutil::{config, route};

    #[derive(Default)]
    pub struct ScriptedPinger {
        replies: Mutex<VecDeque<Result<bool, u16>>>,
        pings: AtomicUsize,
    }

    impl ScriptedPinger {
        pub fn push(&self, reply: Result<bool, u16>) {
            self.replies
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push_back(reply);
        }

        pub fn pings(&self) -> usize {
            self.pings.load(Ordering::SeqCst)
        }
    }

    impl Pinger for ScriptedPinger {
        fn ping(&self) -> BoxFuture<'_, Result<Keepalive, CoreError>> {
            self.pings.fetch_add(1, Ordering::SeqCst);
            let next = self
                .replies
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front();
            Box::pin(async move {
                match next.unwrap_or(Ok(true)) {
                    Ok(status) => Ok(Keepalive {
                        status,
                        timestamp: 0,
                    }),
                    Err(code) => Err(CoreError::Status(code)),
                }
            })
        }
    }

    struct HoldsSession {
        script: Arc<ScriptedPinger>,
        _session: Arc<WireGuardSession>,
    }

    impl Pinger for HoldsSession {
        fn ping(&self) -> BoxFuture<'_, Result<Keepalive, CoreError>> {
            self.script.ping()
        }
    }

    pub struct Fakes {
        pub backends: Arc<Mutex<Vec<Handle>>>,
        pub net: FakeNet,
        pub dns: FakeDns,
        pub registrations: Arc<AtomicUsize>,
        pub sessions: Arc<Mutex<Vec<Weak<WireGuardSession>>>>,
        pub pinger: Arc<ScriptedPinger>,
        pub deny: Arc<AtomicBool>,
        pub unavailable: Arc<AtomicBool>,
        pub fail_up: Arc<Mutex<Option<String>>>,
        pub register_delay: Arc<Mutex<Duration>>,
        pub block_up: Arc<Mutex<Option<BlockUp>>>,
        pub config: WireGuardConfig,
        data: Arc<tempfile::TempDir>,
    }

    struct FakeServer {
        registrations: Arc<AtomicUsize>,
        sessions: Arc<Mutex<Vec<Weak<WireGuardSession>>>>,
        pinger: Arc<ScriptedPinger>,
        deny: Arc<AtomicBool>,
        delay: Arc<Mutex<Duration>>,
        config: WireGuardConfig,
    }

    pub struct BlockUp {
        pub entered: std::sync::mpsc::Sender<()>,
        pub release: std::sync::mpsc::Receiver<()>,
    }

    struct BlockingBackend {
        inner: fake::FakeBackend,
        block: BlockUp,
    }

    impl super::super::backend::WgBackend for BlockingBackend {
        fn up(
            &mut self,
            config: &super::super::backend::BackendConfig,
            keys: &WireGuardKeys,
        ) -> anyhow::Result<super::super::backend::Interface> {
            let _ = self.block.entered.send(());
            let _ = self.block.release.recv();
            self.inner.up(config, keys)
        }

        fn stats(&self) -> anyhow::Result<super::super::backend::PeerStats> {
            self.inner.stats()
        }

        fn down(&mut self) -> anyhow::Result<()> {
            self.inner.down()
        }
    }

    impl Server for FakeServer {
        fn register<'a>(
            &'a self,
            _request: &'a WireGuardRequest,
        ) -> BoxFuture<'a, Result<Registered, RegisterError>> {
            Box::pin(async move {
                self.registrations.fetch_add(1, Ordering::SeqCst);
                let delay = *self.delay.lock().unwrap_or_else(PoisonError::into_inner);
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                if self.deny.load(Ordering::SeqCst) {
                    return Err(RegisterError::Denied {
                        reason: Some("no access".into()),
                    });
                }
                let session = Arc::new(WireGuardSession {
                    keys: WireGuardKeys::generate(),
                    config: self.config.clone(),
                });
                self.sessions
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(Arc::downgrade(&session));
                let pinger = Arc::new(HoldsSession {
                    script: self.pinger.clone(),
                    _session: Arc::clone(&session),
                });
                Ok(Registered { session, pinger })
            })
        }
    }

    impl Fakes {
        pub fn new() -> Self {
            let mut config = config();
            config.routes = vec![route("10.0.0.0/8")];
            config.dns_servers = vec!["10.200.0.1".parse().unwrap()];
            Self {
                backends: Arc::default(),
                net: FakeNet::with_gateway("192.168.1.1", "en0"),
                dns: FakeDns::default(),
                registrations: Arc::default(),
                sessions: Arc::default(),
                pinger: Arc::default(),
                deny: Arc::default(),
                unavailable: Arc::default(),
                fail_up: Arc::default(),
                register_delay: Arc::default(),
                block_up: Arc::default(),
                config,
                data: Arc::new(tempfile::tempdir().unwrap()),
            }
        }

        pub fn backend(&self, index: usize) -> Handle {
            self.backends.lock().unwrap_or_else(PoisonError::into_inner)[index].clone()
        }

        pub fn backend_count(&self) -> usize {
            self.backends
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .len()
        }

        pub fn handshake(&self, index: usize, rx: u64, tx: u64) {
            self.backend(index).with(|record| {
                record.stats.handshake_age = Some(Duration::from_secs(1));
                record.stats.rx_bytes = rx;
                record.stats.tx_bytes = tx;
            });
        }

        pub fn state_record(&self) -> std::path::PathBuf {
            self.data.path().join("state/wg.json")
        }

        pub fn live_sessions(&self) -> usize {
            self.sessions
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .filter(|session| session.upgrade().is_some())
                .count()
        }

        pub fn launcher(&self) -> WireGuardLauncher {
            let unavailable = Arc::clone(&self.unavailable);
            let backends = Arc::clone(&self.backends);
            let net = self.net.clone();
            let dns = self.dns.clone();
            let data = Arc::clone(&self.data);
            let fail_up = Arc::clone(&self.fail_up);
            let block_up = Arc::clone(&self.block_up);
            WireGuardLauncher {
                preflight: Arc::new(move || {
                    if unavailable.load(Ordering::SeqCst) {
                        Err(Unavailable::NeedsRoot)
                    } else {
                        Ok(())
                    }
                }),
                server: Arc::new(FakeServer {
                    registrations: Arc::clone(&self.registrations),
                    sessions: Arc::clone(&self.sessions),
                    pinger: Arc::clone(&self.pinger),
                    deny: Arc::clone(&self.deny),
                    delay: Arc::clone(&self.register_delay),
                    config: self.config.clone(),
                }),
                parts: Arc::new(move || {
                    let (backend, handle) = fake::pair();
                    handle.with(|record| {
                        record.fail_up = fail_up
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .clone();
                    });
                    backends
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(handle);
                    let blocked = block_up
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .take();
                    let backend: Box<dyn super::super::backend::WgBackend> = match blocked {
                        Some(block) => Box::new(BlockingBackend {
                            inner: backend,
                            block,
                        }),
                        None => Box::new(backend),
                    };
                    Ok(Parts {
                        backend,
                        routes: Box::new(net.clone()),
                        dns: Box::new(dns.clone()),
                        store: StateStore::new(data.path()),
                        resolve: Box::new(crate::wireguard::backend::resolve_endpoint),
                    })
                }),
                timing: Timing::default(),
                stats_interval: STATS_INTERVAL,
                bring_up_gate: Arc::default(),
            }
        }
    }

    pub fn request() -> WireGuardRequest {
        WireGuardRequest {
            profile: Profile::parse(&crate::testdata::ovpn(&[])).unwrap(),
            pins: Pins::new(),
            pin: Some(Zeroizing::new("0000".to_owned())),
            device: device_info(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::testing::{Fakes, request};
    use super::*;

    async fn next(events: &mut mpsc::Receiver<TunnelEvent>) -> TunnelEvent {
        events.recv().await.expect("the event stream ended")
    }

    async fn next_non_log(events: &mut mpsc::Receiver<TunnelEvent>) -> TunnelEvent {
        loop {
            match next(events).await {
                TunnelEvent::Log(_) => {}
                other => return other,
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn bring_up_reports_the_handshake_connected_and_counters() {
        let fakes = Fakes::new();
        let launcher = fakes.launcher();
        let Launched {
            running,
            mut events,
        } = launcher.launch_request(request()).await.unwrap();
        assert!(
            matches!(next(&mut events).await, TunnelEvent::Log(line) if line.contains("fake0"))
        );
        fakes.handshake(0, 10, 20);

        let TunnelEvent::Handshake(at) = next(&mut events).await else {
            panic!("expected the handshake time first");
        };
        assert!(at <= unix_now() && unix_now() - at < 5);
        assert_eq!(
            next(&mut events).await,
            TunnelEvent::Connected {
                tunnel_ip: Some("10.200.0.5".into()),
                remote: Some("203.0.113.9:51820".into()),
            }
        );
        assert_eq!(
            next(&mut events).await,
            TunnelEvent::Bytes { rx: 10, tx: 20 }
        );

        fakes.handshake(0, 30, 40);
        assert_eq!(
            next(&mut events).await,
            TunnelEvent::Bytes { rx: 30, tx: 40 }
        );
        running.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn the_server_is_configured_before_bring_up_and_the_key_is_fresh_each_time() {
        let fakes = Fakes::new();
        let launcher = fakes.launcher();
        let mut keys = Vec::new();
        for index in 0..2 {
            let Launched { running, events } = launcher.launch_request(request()).await.unwrap();
            fakes.handshake(index, 0, 0);
            running.stop().await;
            drop(events);
            keys.push(
                fakes
                    .backend(index)
                    .with(|record| record.public_keys_seen[0].clone()),
            );
        }
        assert_ne!(keys[0], keys[1]);
        assert_eq!(fakes.registrations.load(Ordering::SeqCst), 2);
        assert_eq!(fakes.backend_count(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn stop_removes_routes_dns_interface_and_the_key() {
        let fakes = Fakes::new();
        let launcher = fakes.launcher();
        let Launched {
            running,
            mut events,
        } = launcher.launch_request(request()).await.unwrap();
        fakes.handshake(0, 1, 1);
        while !matches!(next(&mut events).await, TunnelEvent::Connected { .. }) {}
        assert!(
            fakes
                .net
                .log()
                .contains(&"add 10.0.0.0/8 dev fake0".to_owned())
        );
        assert_eq!(fakes.dns.log(), ["apply fake0 [10.200.0.1]"]);
        assert!(fakes.state_record().exists());
        assert_eq!(fakes.live_sessions(), 1);

        running.stop().await;
        assert!(
            fakes
                .net
                .log()
                .contains(&"del 10.0.0.0/8 dev fake0".to_owned())
        );
        assert_eq!(fakes.dns.log().last().unwrap(), "restore");
        fakes.backend(0).with(|record| {
            assert_eq!(record.downs, 1);
            assert!(!record.is_up);
        });
        assert!(!fakes.state_record().exists());
        assert_eq!(fakes.live_sessions(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn no_handshake_within_25_seconds_is_a_handshake_timeout() {
        let fakes = Fakes::new();
        let launcher = fakes.launcher();
        let Launched {
            running,
            mut events,
        } = launcher.launch_request(request()).await.unwrap();
        let started = tokio::time::Instant::now();
        let TunnelEvent::Fatal(reason) = next_non_log(&mut events).await else {
            panic!("expected a failure");
        };
        assert!(reason.contains("handshake timeout"), "{reason}");
        assert_eq!(started.elapsed(), Duration::from_secs(25));
        running.stop().await;
        fakes.backend(0).with(|record| assert_eq!(record.downs, 1));
        assert!(!fakes.state_record().exists());
    }

    #[tokio::test(start_paused = true)]
    async fn an_unavailable_backend_fails_before_registration() {
        let fakes = Fakes::new();
        fakes.unavailable.store(true, Ordering::SeqCst);
        let err = fakes
            .launcher()
            .launch_request(request())
            .await
            .err()
            .unwrap();
        assert!(err.downcast_ref::<Unavailable>().is_some());
        assert!(err.to_string().contains("root"));
        assert_eq!(fakes.registrations.load(Ordering::SeqCst), 0);
        assert_eq!(fakes.backend_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_denied_registration_touches_nothing() {
        let fakes = Fakes::new();
        fakes.deny.store(true, Ordering::SeqCst);
        let err = fakes
            .launcher()
            .launch_request(request())
            .await
            .err()
            .unwrap();
        let refusal = err.downcast_ref::<RegisterError>().unwrap();
        assert!(refusal.is_terminal());
        assert_eq!(fakes.backend_count(), 0);
        assert!(fakes.net.log().is_empty());
        assert_eq!(fakes.live_sessions(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn bring_up_failure_leaves_nothing_behind() {
        let fakes = Fakes::new();
        *fakes.fail_up.lock().unwrap() = Some("no tun device".into());
        let err = fakes
            .launcher()
            .launch_request(request())
            .await
            .err()
            .unwrap();
        assert!(format!("{err:#}").contains("no tun device"));
        assert!(fakes.net.log().is_empty());
        assert!(fakes.dns.log().is_empty());
        fakes.backend(0).with(|record| {
            assert!(record.configs.is_empty());
            assert!(!record.is_up);
        });
        assert!(!fakes.state_record().exists());
        assert_eq!(fakes.live_sessions(), 0);
        *fakes.fail_up.lock().unwrap() = None;
        assert!(fakes.launcher().launch_request(request()).await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_keepalive_after_connecting_is_reported_as_lost() {
        let fakes = Fakes::new();
        fakes.pinger.push(Ok(true));
        fakes.pinger.push(Ok(false));
        let launcher = fakes.launcher();
        let Launched {
            running,
            mut events,
        } = launcher.launch_request(request()).await.unwrap();
        fakes.handshake(0, 0, 0);
        assert!(matches!(
            next_non_log(&mut events).await,
            TunnelEvent::Handshake(_)
        ));
        assert!(matches!(
            next_non_log(&mut events).await,
            TunnelEvent::Connected { .. }
        ));
        let lost = loop {
            if let TunnelEvent::Fatal(reason) = next(&mut events).await {
                break reason;
            }
        };
        assert!(lost.starts_with("keepalive failed"), "{lost}");
        assert_eq!(fakes.pinger.pings(), 2);
        running.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_keepalive_fires_at_the_start_of_the_handshake_wait() {
        let fakes = Fakes::new();
        let launcher = fakes.launcher();
        let Launched { running, events } = launcher.launch_request(request()).await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(fakes.pinger.pings(), 1);
        drop(events);
        running.stop().await;
    }

    async fn settle_until(mut done: impl FnMut() -> bool) {
        for _ in 0..2000 {
            if done() {
                return;
            }
            tokio::task::yield_now().await;
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("the condition never became true");
    }

    #[tokio::test(start_paused = true)]
    async fn keepalive_failures_before_the_handshake_do_not_hide_the_timeout() {
        let fakes = Fakes::new();
        for _ in 0..64 {
            fakes.pinger.push(Err(503));
        }
        let Launched {
            running,
            mut events,
        } = fakes.launcher().launch_request(request()).await.unwrap();
        let TunnelEvent::Fatal(reason) = next_non_log(&mut events).await else {
            panic!("expected a failure");
        };
        assert!(reason.contains("handshake timeout"), "{reason}");
        running.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_late_handshake_survives_an_early_failed_keepalive_round() {
        let fakes = Fakes::new();
        for _ in 0..8 {
            fakes.pinger.push(Err(503));
        }
        let Launched {
            running,
            mut events,
        } = fakes.launcher().launch_request(request()).await.unwrap();
        tokio::time::sleep(Duration::from_secs(20)).await;
        fakes.handshake(0, 1, 1);
        loop {
            match next(&mut events).await {
                TunnelEvent::Connected { .. } => break,
                TunnelEvent::Fatal(reason) => panic!("unexpected failure: {reason}"),
                _ => {}
            }
        }
        running.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn slow_registration_is_cut_off_with_its_own_error() {
        let fakes = Fakes::new();
        *fakes.register_delay.lock().unwrap() = Duration::from_secs(3600);
        let started = tokio::time::Instant::now();
        let err = fakes
            .launcher()
            .launch_request(request())
            .await
            .err()
            .unwrap();
        assert!(matches!(
            err.downcast_ref::<RegisterError>(),
            Some(RegisterError::Timeout)
        ));
        assert_eq!(started.elapsed(), register::TOTAL_DEADLINE);
        assert_eq!(fakes.backend_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn stopping_during_registration_never_brings_the_tunnel_up() {
        let fakes = Fakes::new();
        *fakes.register_delay.lock().unwrap() = Duration::from_secs(10);
        let launcher = Arc::new(fakes.launcher());
        let pending = tokio::spawn({
            let launcher = Arc::clone(&launcher);
            async move { launcher.launch_request(request()).await.map(drop) }
        });
        tokio::time::sleep(Duration::from_secs(1)).await;
        pending.abort();
        let _ = pending.await;
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert_eq!(fakes.backend_count(), 0);
        assert!(fakes.net.log().is_empty());
        *fakes.register_delay.lock().unwrap() = Duration::ZERO;
        let Launched { running, .. } = launcher.launch_request(request()).await.unwrap();
        running.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn an_abandoned_bring_up_is_torn_down_before_the_next_one_starts() {
        let fakes = Fakes::new();
        let (entered_tx, entered) = std::sync::mpsc::channel();
        let (release_tx, release) = std::sync::mpsc::channel();
        *fakes.block_up.lock().unwrap() = Some(testing::BlockUp {
            entered: entered_tx,
            release,
        });
        let launcher = Arc::new(fakes.launcher());
        let first = tokio::spawn({
            let launcher = Arc::clone(&launcher);
            async move { launcher.launch_request(request()).await.map(drop) }
        });
        settle_until(|| entered.try_recv().is_ok()).await;
        first.abort();
        let _ = first.await;

        let second = tokio::spawn({
            let launcher = Arc::clone(&launcher);
            async move { launcher.launch_request(request()).await }
        });
        tokio::task::yield_now().await;
        assert_eq!(fakes.backend_count(), 1);
        release_tx.send(()).unwrap();
        let Launched { running, .. } = second.await.unwrap().unwrap();
        fakes.backend(0).with(|record| assert_eq!(record.downs, 1));
        assert_eq!(fakes.backend_count(), 2);
        assert!(fakes.state_record().exists());
        running.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_a_running_tunnel_still_cleans_up() {
        let fakes = Fakes::new();
        let Launched {
            running,
            mut events,
        } = fakes.launcher().launch_request(request()).await.unwrap();
        fakes.handshake(0, 1, 1);
        while !matches!(next(&mut events).await, TunnelEvent::Connected { .. }) {}
        drop(running);
        settle_until(|| fakes.backend(0).with(|record| record.downs) == 1).await;
        settle_until(|| !fakes.state_record().exists()).await;
        assert!(
            fakes
                .net
                .log()
                .contains(&"del 10.0.0.0/8 dev fake0".to_owned())
        );
        assert_eq!(fakes.dns.log().last().unwrap(), "restore");
        settle_until(|| fakes.live_sessions() == 0).await;
    }

    #[test]
    fn the_gateway_pin_follows_the_registration_certificate_unless_one_is_stored() {
        let gateway = "10.200.0.1".parse().unwrap();
        let fingerprint = wyvpn_core::tls::Fingerprint::of_certificate(b"cert");
        let other = wyvpn_core::tls::Fingerprint::of_certificate(b"other");
        let learned = keepalive_pins(&Pins::new(), gateway, 443, Some(fingerprint));
        assert_eq!(learned.get("10.200.0.1:443"), Some(&fingerprint));
        let stored = Pins::from([("10.200.0.1:443".to_owned(), other)]);
        let kept = keepalive_pins(&stored, gateway, 443, Some(fingerprint));
        assert_eq!(kept.get("10.200.0.1:443"), Some(&other));
        assert!(keepalive_pins(&Pins::new(), gateway, 443, None).is_empty());
    }
}
