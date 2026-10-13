use crate::error::{Error, Result};
use crate::rng;
use crate::secret::Secret;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_NONCE_LEN: usize = 32;
const MAX_SIGNED_LEN: usize = 10_240;

#[derive(Clone)]
pub struct RequestAuth {
    pub token: String,
    pub timestamp: String,
    pub nonce: String,
    pub signature: String,
}

impl fmt::Debug for RequestAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestAuth")
            .field("timestamp", &self.timestamp)
            .field("nonce", &self.nonce)
            .finish_non_exhaustive()
    }
}

impl RequestAuth {
    pub fn headers(&self) -> [(&'static str, String); 4] {
        [
            ("Auth-Token", self.token.clone()),
            ("Auth-Timestamp", self.timestamp.clone()),
            ("Auth-Nonce", self.nonce.clone()),
            ("Auth-Signature", self.signature.clone()),
        ]
    }
}

pub fn generate_nonce() -> String {
    rng::alphanumeric(MAX_NONCE_LEN)
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub fn string_to_sign(
    token: &str,
    timestamp: &str,
    nonce: &str,
    method: &str,
    path: &str,
    extra: &[&str],
) -> String {
    let mut out = format!("{token}&{timestamp}&{nonce}&{method}&{path}");
    for field in extra {
        out.push('&');
        out.push_str(field);
    }
    out
}

pub fn hmac_base64(secret: &Secret, message: &[u8]) -> String {
    STANDARD.encode(mac(secret, message).finalize().into_bytes())
}

pub fn verify_hmac_base64(secret: &Secret, message: &[u8], signature: &str) -> bool {
    let Ok(expected) = STANDARD.decode(signature.trim()) else {
        return false;
    };
    mac(secret, message).verify_slice(&expected).is_ok()
}

fn mac(secret: &Secret, message: &[u8]) -> Hmac<Sha512> {
    let mut mac = Hmac::<Sha512>::new_from_slice(secret.expose().as_bytes())
        .unwrap_or_else(|_| unreachable!("HMAC accepts keys of any length"));
    mac.update(message);
    mac
}

pub fn sign_request(
    secret: &Secret,
    token: &str,
    timestamp: u64,
    nonce: &str,
    method: &str,
    path: &str,
    extra: &[&str],
) -> Result<RequestAuth> {
    if nonce.chars().count() > MAX_NONCE_LEN {
        return Err(Error::NonceTooLong);
    }
    let timestamp = timestamp.to_string();
    let message = string_to_sign(token, &timestamp, nonce, method, path, extra);
    if message.chars().count() > MAX_SIGNED_LEN {
        return Err(Error::RequestTooLong);
    }
    Ok(RequestAuth {
        token: token.to_owned(),
        timestamp,
        nonce: nonce.to_owned(),
        signature: hmac_base64(secret, message.as_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "Ns7d8KJmQw2xY4pZ0aB1cD3eF5gH6iJk";
    const SECRET: &str = "Xy9Pq2Lm7Nr4St6Uv8Wz0Ab3Cd5Ef1Gh";
    const NONCE: &str = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6";
    const PATH: &str = "/key/sync/5f3c1a2b4d6e8f0a1b2c3d4e/5f3c1a2b4d6e8f0a1b2c3d4f/5f3c1a2b4d6e8f0a1b2c3d50/0cc175b9c0f1b6a831c399e269772661";

    #[test]
    fn sync_request_matches_documented_vector() {
        let auth = sign_request(
            &Secret::new(SECRET),
            TOKEN,
            1_760_000_000,
            NONCE,
            "GET",
            PATH,
            &[],
        )
        .unwrap();
        assert_eq!(
            auth.signature,
            "Ub74S44oz+GzX796YXi1lHI9+XpwPkXE2sZHtMQqqGeUCeH0xL5HC+qweQN+muRQJNb0ioZZJC9SqdutVKfgqg=="
        );
        assert_eq!(
            string_to_sign(TOKEN, "1760000000", NONCE, "GET", PATH, &[]).len(),
            198
        );
    }

    #[test]
    fn response_signature_matches_documented_vector() {
        let signature = hmac_base64(&Secret::new(SECRET), b"client\ndev tun\n");
        assert_eq!(
            signature,
            "51JrpTosG79JmOCIEmsdCLGJGeAGIWRUuGFHUSWe11HeUMyUJkuN/AdUPb9BdgRHwHeRRshvbaLMGQ2uho6KxA=="
        );
        assert!(verify_hmac_base64(
            &Secret::new(SECRET),
            b"client\ndev tun\n",
            &signature
        ));
        assert!(!verify_hmac_base64(
            &Secret::new(SECRET),
            b"client\ndev tap\n",
            &signature
        ));
        assert!(!verify_hmac_base64(
            &Secret::new(SECRET),
            b"x",
            "not base64!"
        ));
    }

    #[test]
    fn extra_fields_are_appended_with_ampersands() {
        let text = string_to_sign("t", "1", "n", "POST", "/p", &["a", "b"]);
        assert_eq!(text, "t&1&n&POST&/p&a&b");
    }

    #[test]
    fn long_nonce_is_rejected() {
        let nonce = "x".repeat(33);
        let err =
            sign_request(&Secret::new(SECRET), TOKEN, 1, &nonce, "GET", "/p", &[]).unwrap_err();
        assert!(matches!(err, Error::NonceTooLong));
    }

    #[test]
    fn oversized_request_is_rejected() {
        let big = "x".repeat(10_300);
        let err =
            sign_request(&Secret::new(SECRET), TOKEN, 1, NONCE, "PUT", "/p", &[&big]).unwrap_err();
        assert!(matches!(err, Error::RequestTooLong));
    }

    #[test]
    fn generated_nonce_fits_the_server_limit() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 32);
        assert_ne!(nonce, generate_nonce());
    }
}
