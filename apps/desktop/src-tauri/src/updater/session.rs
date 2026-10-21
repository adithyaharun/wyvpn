use std::collections::HashSet;
use std::future::Future;
use std::time::Duration;

use tokio::time::{Instant, sleep, timeout_at};

use crate::error::CmdError;

pub const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(20);
pub const DISCONNECT_POLL: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisconnectTimeout;

pub trait Session {
    fn reachable(&self) -> bool;
    fn active_profiles(&self) -> impl Future<Output = Vec<String>> + Send;
    fn mark_user_disconnect(&self, profile_id: &str);
    fn disconnect(&self, profile_id: String) -> impl Future<Output = Result<(), CmdError>> + Send;
}

pub async fn disconnect_all<S: Session>(
    session: &S,
    timeout: Duration,
    poll: Duration,
) -> Result<(), DisconnectTimeout> {
    if !session.reachable() {
        return Ok(());
    }
    let deadline = Instant::now() + timeout;
    let mut requested: HashSet<String> = HashSet::new();
    loop {
        let active = timeout_at(deadline, session.active_profiles())
            .await
            .map_err(|_| DisconnectTimeout)?;
        requested.retain(|id| active.contains(id));
        let fresh: Vec<&String> = active
            .iter()
            .filter(|id| !requested.contains(*id))
            .collect();
        for profile_id in fresh {
            session.mark_user_disconnect(profile_id);
            requested.insert(profile_id.clone());
            match timeout_at(deadline, session.disconnect(profile_id.clone())).await {
                Err(_) => return Err(DisconnectTimeout),
                Ok(Err(error)) => {
                    tracing::warn!("disconnect before update failed: {}", error.code);
                }
                Ok(Ok(())) => {}
            }
        }
        if active.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(DisconnectTimeout);
        }
        sleep(poll).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct Fake {
        reachable: bool,
        sessions: Mutex<Vec<String>>,
        stuck: bool,
        hang: bool,
        late: Mutex<Option<String>>,
        marks: Mutex<Vec<String>>,
        requests: Mutex<Vec<String>>,
    }

    impl Fake {
        fn with(sessions: &[&str]) -> Self {
            Self {
                reachable: true,
                sessions: Mutex::new(sessions.iter().map(|s| (*s).to_owned()).collect()),
                ..Self::default()
            }
        }
    }

    impl Session for Fake {
        fn reachable(&self) -> bool {
            self.reachable
        }

        async fn active_profiles(&self) -> Vec<String> {
            if let Some(late) = self
                .late
                .lock()
                .unwrap()
                .take_if(|_| !self.requests.lock().unwrap().is_empty())
            {
                self.sessions.lock().unwrap().push(late);
            }
            self.sessions.lock().unwrap().clone()
        }

        fn mark_user_disconnect(&self, profile_id: &str) {
            self.marks.lock().unwrap().push(profile_id.to_owned());
        }

        async fn disconnect(&self, profile_id: String) -> Result<(), CmdError> {
            self.requests.lock().unwrap().push(profile_id.clone());
            if self.hang {
                std::future::pending::<()>().await;
            }
            if !self.stuck {
                self.sessions.lock().unwrap().retain(|id| *id != profile_id);
            }
            Ok(())
        }
    }

    const POLL: Duration = Duration::from_millis(100);

    #[tokio::test(start_paused = true)]
    async fn no_session_goes_straight_through() {
        let fake = Fake::with(&[]);
        assert!(
            disconnect_all(&fake, DISCONNECT_TIMEOUT, POLL)
                .await
                .is_ok()
        );
        assert!(fake.requests.lock().unwrap().is_empty());
        assert!(fake.marks.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_connected_session_is_marked_then_disconnected() {
        let fake = Fake::with(&["a"]);
        assert!(
            disconnect_all(&fake, DISCONNECT_TIMEOUT, POLL)
                .await
                .is_ok()
        );
        assert_eq!(*fake.marks.lock().unwrap(), vec!["a".to_owned()]);
        assert_eq!(*fake.requests.lock().unwrap(), vec!["a".to_owned()]);
        assert!(fake.sessions.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn every_active_session_is_disconnected() {
        let fake = Fake::with(&["a", "waiting-for-pin"]);
        assert!(
            disconnect_all(&fake, DISCONNECT_TIMEOUT, POLL)
                .await
                .is_ok()
        );
        assert_eq!(fake.requests.lock().unwrap().len(), 2);
        assert_eq!(fake.marks.lock().unwrap().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_session_that_does_not_end_times_out() {
        let mut fake = Fake::with(&["a"]);
        fake.stuck = true;
        let started = Instant::now();
        let result = disconnect_all(&fake, DISCONNECT_TIMEOUT, POLL).await;
        assert_eq!(result, Err(DisconnectTimeout));
        assert!(started.elapsed() >= DISCONNECT_TIMEOUT);
        assert!(started.elapsed() < DISCONNECT_TIMEOUT + Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn an_unreachable_daemon_proceeds_without_a_disconnect() {
        let mut fake = Fake::with(&["a"]);
        fake.reachable = false;
        assert!(
            disconnect_all(&fake, DISCONNECT_TIMEOUT, POLL)
                .await
                .is_ok()
        );
        assert!(fake.requests.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_hanging_disconnect_request_still_times_out() {
        let mut fake = Fake::with(&["a"]);
        fake.hang = true;
        let started = Instant::now();
        let result = disconnect_all(&fake, DISCONNECT_TIMEOUT, POLL).await;
        assert_eq!(result, Err(DisconnectTimeout));
        assert!(started.elapsed() <= DISCONNECT_TIMEOUT + Duration::from_millis(1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_session_that_starts_late_is_disconnected_too() {
        let fake = Fake::with(&["a"]);
        *fake.late.lock().unwrap() = Some("b".to_owned());
        assert!(
            disconnect_all(&fake, DISCONNECT_TIMEOUT, POLL)
                .await
                .is_ok()
        );
        assert_eq!(
            *fake.requests.lock().unwrap(),
            vec!["a".to_owned(), "b".to_owned()]
        );
    }
}
