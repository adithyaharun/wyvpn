use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::files::ImportFile;

const TTL: Duration = Duration::from_secs(120);

struct Pending {
    token: String,
    file: ImportFile,
    expires: Instant,
}

pub struct RetryStore {
    ttl: Duration,
    slot: Mutex<Option<Pending>>,
}

impl Default for RetryStore {
    fn default() -> Self {
        Self::with_ttl(TTL)
    }
}

impl RetryStore {
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl,
            slot: Mutex::new(None),
        }
    }

    pub fn put(&self, file: ImportFile) -> String {
        self.put_at(file, Instant::now())
    }

    pub fn take(&self, token: &str) -> Option<ImportFile> {
        self.take_at(token, Instant::now())
    }

    fn put_at(&self, file: ImportFile, now: Instant) -> String {
        let token = random_token();
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(Pending {
            token: token.clone(),
            file,
            expires: now + self.ttl,
        });
        token
    }

    fn take_at(&self, token: &str, now: Instant) -> Option<ImportFile> {
        let mut slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.as_ref().is_none_or(|pending| pending.token != token) {
            return None;
        }
        slot.take()
            .filter(|pending| now < pending.expires)
            .map(|pending| pending.file)
    }
}

fn random_token() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("operating system randomness is unavailable");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn file(bytes: &[u8]) -> ImportFile {
        ImportFile {
            name: "office.ovpn".into(),
            bytes: Zeroizing::new(bytes.to_vec()),
        }
    }

    #[test]
    fn token_is_single_use() {
        let store = RetryStore::default();
        let token = store.put(file(b"one"));
        assert_eq!(token.len(), 32);
        let taken = store.take(&token).unwrap();
        assert_eq!(taken.bytes.as_slice(), b"one");
        assert!(store.take(&token).is_none());
    }

    #[test]
    fn unknown_token_is_rejected_and_keeps_the_pending_file() {
        let store = RetryStore::default();
        let token = store.put(file(b"one"));
        assert!(store.take("nope").is_none());
        assert!(store.take(&token).is_some());
    }

    #[test]
    fn only_the_latest_file_is_kept() {
        let store = RetryStore::default();
        let first = store.put(file(b"one"));
        let second = store.put(file(b"two"));
        assert_ne!(first, second);
        assert!(store.take(&first).is_none());
        assert_eq!(store.take(&second).unwrap().bytes.as_slice(), b"two");
    }

    #[test]
    fn token_expires() {
        let store = RetryStore::with_ttl(Duration::from_secs(120));
        let start = Instant::now();
        let token = store.put_at(file(b"one"), start);
        assert!(
            store
                .take_at(&token, start + Duration::from_secs(120))
                .is_none()
        );
        assert!(store.take_at(&token, start).is_none());

        let token = store.put_at(file(b"two"), start);
        assert!(
            store
                .take_at(&token, start + Duration::from_secs(119))
                .is_some()
        );
    }
}
