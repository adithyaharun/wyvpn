use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{Instant, sleep};
use wyvpn_core::Error as CoreError;
use wyvpn_core::wireguard::Keepalive;

use crate::control::core_error;
use crate::launcher::BoxFuture;
use crate::openvpn::management::TunnelEvent;

pub trait Pinger: Send + Sync {
    fn ping(&self) -> BoxFuture<'_, Result<Keepalive, CoreError>>;
}

#[derive(Debug, Clone, Copy)]
pub struct Timing {
    pub attempts: u32,
    pub retry_delay: Duration,
    pub round_cap: Duration,
    pub max_jitter_ms: u32,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            attempts: 8,
            retry_delay: Duration::from_secs(1),
            round_cap: Duration::from_secs(15),
            max_jitter_ms: 2000,
        }
    }
}

fn is_final(err: &CoreError) -> bool {
    matches!(
        err,
        CoreError::Status(400..=499)
            | CoreError::CertificateChanged { .. }
            | CoreError::PinRequired(_)
            | CoreError::InsecureScheme
    )
}

pub async fn round(pinger: &dyn Pinger, timing: &Timing) -> Result<(), String> {
    let started = Instant::now();
    let mut last = String::new();
    for attempt in 1..=timing.attempts {
        match pinger.ping().await {
            Ok(reply) if reply.status => return Ok(()),
            Ok(_) => return Err("the server no longer has this client".to_owned()),
            Err(err) => {
                last = core_error(&err).message;
                if is_final(&err) {
                    return Err(last);
                }
            }
        }
        if attempt == timing.attempts || started.elapsed() >= timing.round_cap {
            break;
        }
        sleep(timing.retry_delay).await;
    }
    Err(last)
}

pub async fn run(
    pinger: Arc<dyn Pinger>,
    interval: Duration,
    timing: Timing,
    jitter: fn(u32) -> u32,
    events: mpsc::Sender<TunnelEvent>,
) {
    loop {
        if let Err(reason) = round(pinger.as_ref(), &timing).await {
            let _ = events
                .send(TunnelEvent::Fatal(format!("keepalive failed: {reason}")))
                .await;
            return;
        }
        let jitter = Duration::from_millis(u64::from(jitter(timing.max_jitter_ms + 1)));
        sleep(interval + jitter).await;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;

    struct Script {
        replies: Mutex<VecDeque<Result<bool, u16>>>,
        calls: Mutex<Vec<Instant>>,
    }

    impl Script {
        fn new(replies: &[Result<bool, u16>]) -> Arc<Self> {
            Arc::new(Self {
                replies: Mutex::new(replies.iter().copied().collect()),
                calls: Mutex::default(),
            })
        }

        fn count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl Pinger for Script {
        fn ping(&self) -> BoxFuture<'_, Result<Keepalive, CoreError>> {
            self.calls.lock().unwrap().push(Instant::now());
            let next = self.replies.lock().unwrap().pop_front();
            Box::pin(async move {
                match next {
                    Some(Ok(status)) => Ok(Keepalive {
                        status,
                        timestamp: 0,
                    }),
                    Some(Err(code)) => Err(CoreError::Status(code)),
                    None => Err(CoreError::Status(503)),
                }
            })
        }
    }

    fn no_jitter(_max: u32) -> u32 {
        0
    }

    #[tokio::test(start_paused = true)]
    async fn a_transient_failure_is_retried_within_the_round() {
        let pinger = Script::new(&[Err(503), Err(502), Ok(true)]);
        let start = Instant::now();
        round(pinger.as_ref(), &Timing::default()).await.unwrap();
        assert_eq!(pinger.count(), 3);
        assert_eq!(start.elapsed(), Duration::from_secs(2));
    }

    #[tokio::test(start_paused = true)]
    async fn a_round_gives_up_after_eight_attempts() {
        let pinger = Script::new(&[]);
        let start = Instant::now();
        let err = round(pinger.as_ref(), &Timing::default())
            .await
            .unwrap_err();
        assert_eq!(pinger.count(), 8);
        assert_eq!(start.elapsed(), Duration::from_secs(7));
        assert!(err.contains("503"), "{err}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_round_stops_at_the_time_cap() {
        let pinger = Script::new(&[]);
        let timing = Timing {
            attempts: 100,
            ..Timing::default()
        };
        let start = Instant::now();
        round(pinger.as_ref(), &timing).await.unwrap_err();
        assert_eq!(start.elapsed(), Duration::from_secs(15));
        assert_eq!(pinger.count(), 16);
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_error_stops_the_round_at_once() {
        let pinger = Script::new(&[Err(417), Ok(true)]);
        let err = round(pinger.as_ref(), &Timing::default())
            .await
            .unwrap_err();
        assert_eq!(pinger.count(), 1);
        assert!(err.contains("417"), "{err}");
    }

    #[tokio::test(start_paused = true)]
    async fn status_false_is_not_retried() {
        let pinger = Script::new(&[Ok(false), Ok(true)]);
        let err = round(pinger.as_ref(), &Timing::default())
            .await
            .unwrap_err();
        assert_eq!(pinger.count(), 1);
        assert!(err.contains("no longer has this client"));
    }

    struct Changed;

    impl Pinger for Changed {
        fn ping(&self) -> BoxFuture<'_, Result<Keepalive, CoreError>> {
            Box::pin(async {
                Err(CoreError::CertificateChanged {
                    expected: "aa".into(),
                    actual: "bb".into(),
                })
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_gateway_pin_mismatch_is_final() {
        let start = Instant::now();
        let err = round(&Changed, &Timing::default()).await.unwrap_err();
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert!(err.contains("certificate"), "{err}");
    }

    #[tokio::test(start_paused = true)]
    async fn the_loop_sends_at_start_then_each_interval_plus_jitter() {
        let pinger = Script::new(&[Ok(true), Ok(true), Ok(true), Ok(false)]);
        let (events, mut receiver) = mpsc::channel(4);
        let start = Instant::now();
        tokio::spawn(run(
            pinger.clone(),
            Duration::from_secs(30),
            Timing::default(),
            |max| max.min(1500),
            events,
        ));
        let event = receiver.recv().await.unwrap();
        let calls = pinger.calls.lock().unwrap().clone();
        assert_eq!(
            calls
                .iter()
                .map(|at| at.duration_since(start))
                .collect::<Vec<_>>(),
            [
                Duration::ZERO,
                Duration::from_millis(31_500),
                Duration::from_millis(63_000),
                Duration::from_millis(94_500),
            ]
        );
        let TunnelEvent::Fatal(reason) = event else {
            panic!("expected a lost event")
        };
        assert!(reason.starts_with("keepalive failed"));
    }

    #[tokio::test(start_paused = true)]
    async fn an_exhausted_round_emits_lost_once_and_ends_the_loop() {
        let pinger = Script::new(&[Ok(true)]);
        let (events, mut receiver) = mpsc::channel(4);
        let task = tokio::spawn(run(
            pinger.clone(),
            Duration::from_secs(5),
            Timing::default(),
            no_jitter,
            events,
        ));
        assert!(matches!(receiver.recv().await, Some(TunnelEvent::Fatal(_))));
        task.await.unwrap();
        assert!(receiver.recv().await.is_none());
        assert_eq!(pinger.count(), 9);
    }
}
