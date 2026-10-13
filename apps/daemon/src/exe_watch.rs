use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::openvpn::binary::Check;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
}

impl Identity {
    pub fn read(path: &Path) -> Option<Self> {
        let meta = std::fs::metadata(path).ok()?;
        Some(Self {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
        })
    }
}

pub struct Tracker {
    baseline: Identity,
    candidate: Option<Identity>,
}

impl Tracker {
    pub fn new(baseline: Identity) -> Self {
        Self {
            baseline,
            candidate: None,
        }
    }

    pub fn observe(&mut self, reading: Option<Identity>) -> Option<Identity> {
        let reading = reading?;
        if reading == self.baseline {
            self.candidate = None;
            return None;
        }
        if self.candidate.as_ref() == Some(&reading) {
            return Some(reading);
        }
        self.candidate = Some(reading);
        None
    }
}

pub async fn replaced(
    path: PathBuf,
    baseline: Option<Identity>,
    interval: Duration,
    verify: impl Fn(&Path) -> Check,
    restartable: impl Fn() -> bool,
) {
    let Some(baseline) = baseline else {
        return std::future::pending().await;
    };
    let mut tracker = Tracker::new(baseline);
    let mut changed = false;
    loop {
        tokio::time::sleep(interval).await;
        if !changed {
            if let Some(confirmed) = tracker.observe(Identity::read(&path)) {
                if let Check::Fail(reason) = verify(&path) {
                    tracing::warn!(%reason, "replaced wyvpnd executable failed verification; keeping the running daemon");
                    tracker = Tracker::new(confirmed);
                } else {
                    changed = true;
                }
            }
        }
        if changed && restartable() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;

    const INTERVAL: Duration = Duration::from_secs(5);

    fn id(ino: u64) -> Identity {
        Identity {
            dev: 1,
            ino,
            size: 10,
            mtime: 100,
            mtime_nsec: 0,
        }
    }

    #[test]
    fn unchanged_identity_never_reports_replaced() {
        let mut tracker = Tracker::new(id(1));
        for _ in 0..5 {
            assert_eq!(tracker.observe(Some(id(1))), None);
        }
    }

    #[test]
    fn changed_identity_reports_on_second_equal_reading() {
        let mut tracker = Tracker::new(id(1));
        assert_eq!(tracker.observe(Some(id(2))), None);
        assert_eq!(tracker.observe(Some(id(2))), Some(id(2)));
    }

    #[test]
    fn identity_changing_every_reading_never_reports() {
        let mut tracker = Tracker::new(id(1));
        for ino in 2..10 {
            assert_eq!(tracker.observe(Some(id(ino))), None);
        }
    }

    #[test]
    fn missing_reading_keeps_a_pending_change() {
        let mut tracker = Tracker::new(id(1));
        assert_eq!(tracker.observe(Some(id(2))), None);
        assert_eq!(tracker.observe(None), None);
        assert_eq!(tracker.observe(Some(id(2))), Some(id(2)));
    }

    #[test]
    fn reading_the_baseline_clears_a_pending_change() {
        let mut tracker = Tracker::new(id(1));
        assert_eq!(tracker.observe(Some(id(2))), None);
        assert_eq!(tracker.observe(Some(id(1))), None);
        assert_eq!(tracker.observe(Some(id(2))), None);
    }

    fn rewrite(path: &Path, content: &str) {
        std::fs::remove_file(path).unwrap();
        std::fs::write(path, content).unwrap();
    }

    fn temp_exe() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wyvpnd");
        std::fs::write(&path, "old").unwrap();
        (dir, path)
    }

    fn pass(_: &Path) -> Check {
        Check::Pass
    }

    fn watch(
        path: &Path,
        verify: impl Fn(&Path) -> Check + Send + 'static,
        restartable: impl Fn() -> bool + Send + 'static,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(replaced(
            path.to_path_buf(),
            Identity::read(path),
            INTERVAL,
            verify,
            restartable,
        ))
    }

    async fn tick(intervals: u32) {
        tokio::task::yield_now().await;
        for _ in 0..intervals {
            tokio::time::advance(INTERVAL).await;
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn rewritten_file_resolves_after_two_intervals_while_restartable() {
        let (_dir, path) = temp_exe();
        let task = watch(&path, pass, || true);
        rewrite(&path, "new content");

        tick(1).await;
        assert!(!task.is_finished());

        tick(1).await;
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn waits_until_restartable_before_resolving() {
        let (_dir, path) = temp_exe();
        let ready = Arc::new(AtomicBool::new(false));
        let flag = ready.clone();
        let task = watch(&path, pass, move || flag.load(Ordering::SeqCst));
        rewrite(&path, "new content");

        tick(4).await;
        assert!(!task.is_finished());

        ready.store(true, Ordering::SeqCst);
        tokio::time::advance(INTERVAL).await;
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn unreadable_baseline_never_resolves() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing");
        let task = watch(&path, pass, || true);
        std::fs::write(&path, "now present").unwrap();

        tick(6).await;
        assert!(!task.is_finished());
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn failing_verification_keeps_running_until_a_valid_replacement() {
        let (_dir, path) = temp_exe();
        let valid = Arc::new(AtomicBool::new(false));
        let flag = valid.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let task = watch(
            &path,
            move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                if flag.load(Ordering::SeqCst) {
                    Check::Pass
                } else {
                    Check::Fail("bad signature".into())
                }
            },
            || true,
        );
        rewrite(&path, "forged content");

        tick(5).await;
        assert!(!task.is_finished());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        valid.store(true, Ordering::SeqCst);
        rewrite(&path, "genuine replacement");
        tick(1).await;
        tokio::time::advance(INTERVAL).await;
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }
}
