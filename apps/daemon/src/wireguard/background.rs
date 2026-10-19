use std::sync::{Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

static THREADS: Mutex<Vec<JoinHandle<()>>> = Mutex::new(Vec::new());

pub fn spawn(work: impl FnOnce() + Send + 'static) {
    let mut threads = THREADS.lock().unwrap_or_else(PoisonError::into_inner);
    threads.retain(|handle| !handle.is_finished());
    threads.push(thread::spawn(work));
}

pub fn join_all(bound: Duration) -> bool {
    let deadline = Instant::now() + bound;
    loop {
        let mut threads = THREADS.lock().unwrap_or_else(PoisonError::into_inner);
        let (done, running): (Vec<_>, Vec<_>) = std::mem::take(&mut *threads)
            .into_iter()
            .partition(JoinHandle::is_finished);
        *threads = running;
        let idle = threads.is_empty();
        drop(threads);
        for handle in done {
            let _ = handle.join();
        }
        if idle {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[test]
    fn join_all_waits_for_tracked_work_within_the_bound() {
        let done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&done);
        spawn(move || {
            thread::sleep(Duration::from_millis(100));
            flag.store(true, Ordering::SeqCst);
        });
        assert!(join_all(Duration::from_secs(5)));
        assert!(done.load(Ordering::SeqCst));
    }

    #[test]
    fn join_all_gives_up_on_stuck_work() {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        spawn(move || {
            let _ = wait.recv();
        });
        assert!(!join_all(Duration::from_millis(100)));
        drop(release);
        assert!(join_all(Duration::from_secs(5)));
    }
}
