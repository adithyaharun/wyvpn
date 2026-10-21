use std::future::Future;
use std::time::Duration;

use tokio::time::{Instant, MissedTickBehavior, interval_at};

pub const FIRST_CHECK_DELAY: Duration = Duration::from_secs(30);
pub const CHECK_POLL: Duration = Duration::from_secs(60 * 60);
pub const CHECK_PERIOD: Duration = Duration::from_secs(24 * 60 * 60);

pub fn due(now: u64, last: Option<u64>, period: Duration) -> bool {
    last.is_none_or(|last| now.saturating_sub(last) >= period.as_secs())
}

pub async fn run<N, L, E, C, F>(
    first: Duration,
    poll: Duration,
    period: Duration,
    now: N,
    last_success: L,
    enabled: E,
    mut check: C,
) where
    N: Fn() -> u64,
    L: Fn() -> Option<u64>,
    E: Fn() -> bool,
    C: FnMut() -> F,
    F: Future<Output = ()>,
{
    let mut ticks = interval_at(Instant::now() + first, poll);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        if enabled() && due(now(), last_success(), period) {
            check().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use super::*;

    const START: u64 = 1_000_000;

    struct Harness {
        checks: Arc<AtomicU64>,
        enabled: Arc<AtomicBool>,
        jump: Arc<AtomicU64>,
        task: tokio::task::JoinHandle<()>,
    }

    async fn start(enabled: bool, records_success: bool) -> Harness {
        let checks = Arc::new(AtomicU64::new(0));
        let flag = Arc::new(AtomicBool::new(enabled));
        let jump = Arc::new(AtomicU64::new(0));
        let last = Arc::new(AtomicU64::new(0));
        let began = Instant::now();
        let clock = {
            let jump = jump.clone();
            move || START + began.elapsed().as_secs() + jump.load(Ordering::SeqCst)
        };
        let task = tokio::spawn(run(
            FIRST_CHECK_DELAY,
            CHECK_POLL,
            CHECK_PERIOD,
            clock.clone(),
            {
                let last = last.clone();
                move || Some(last.load(Ordering::SeqCst)).filter(|value| *value != 0)
            },
            {
                let flag = flag.clone();
                move || flag.load(Ordering::SeqCst)
            },
            {
                let checks = checks.clone();
                move || {
                    let checks = checks.clone();
                    let last = last.clone();
                    let now = clock();
                    async move {
                        checks.fetch_add(1, Ordering::SeqCst);
                        if records_success {
                            last.store(now, Ordering::SeqCst);
                        }
                    }
                }
            },
        ));
        tokio::task::yield_now().await;
        Harness {
            checks,
            enabled: flag,
            jump,
            task,
        }
    }

    async fn advance(by: Duration) {
        tokio::time::advance(by).await;
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
    }

    impl Harness {
        fn count(&self) -> u64 {
            self.checks.load(Ordering::SeqCst)
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[test]
    fn due_when_never_checked_or_a_period_has_passed() {
        let day = Duration::from_secs(86_400);
        assert!(due(10, None, day));
        assert!(!due(86_409, Some(10), day));
        assert!(due(86_410, Some(10), day));
        assert!(!due(5, Some(10), day));
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_check_runs_after_the_delay() {
        let harness = start(true, true).await;
        advance(FIRST_CHECK_DELAY - Duration::from_secs(1)).await;
        assert_eq!(harness.count(), 0);
        advance(Duration::from_secs(2)).await;
        assert_eq!(harness.count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_check_runs_after_a_day_not_every_poll() {
        let harness = start(true, true).await;
        advance(FIRST_CHECK_DELAY + Duration::from_secs(1)).await;
        assert_eq!(harness.count(), 1);
        for _ in 0..22 {
            advance(CHECK_POLL).await;
        }
        assert_eq!(harness.count(), 1);
        for _ in 0..3 {
            advance(CHECK_POLL).await;
        }
        assert_eq!(harness.count(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_wall_clock_jump_during_sleep_triggers_a_check_at_the_next_poll() {
        let harness = start(true, true).await;
        advance(FIRST_CHECK_DELAY + Duration::from_secs(1)).await;
        assert_eq!(harness.count(), 1);
        harness.jump.store(2 * 86_400, Ordering::SeqCst);
        advance(CHECK_POLL).await;
        assert_eq!(harness.count(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_check_that_did_not_succeed_is_retried_at_the_next_poll() {
        let harness = start(true, false).await;
        advance(FIRST_CHECK_DELAY + Duration::from_secs(1)).await;
        assert_eq!(harness.count(), 1);
        advance(CHECK_POLL).await;
        assert_eq!(harness.count(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_runs_while_the_setting_is_off() {
        let harness = start(false, true).await;
        advance(FIRST_CHECK_DELAY + CHECK_PERIOD * 2).await;
        assert_eq!(harness.count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn turning_the_setting_on_makes_the_next_poll_check() {
        let harness = start(false, true).await;
        advance(FIRST_CHECK_DELAY + Duration::from_secs(1)).await;
        assert_eq!(harness.count(), 0);
        harness.enabled.store(true, Ordering::SeqCst);
        advance(CHECK_POLL).await;
        assert_eq!(harness.count(), 1);
    }
}
