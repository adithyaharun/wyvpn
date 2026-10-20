use crypto_box::aead::OsRng;
use crypto_box::aead::rand_core::RngCore;

const ALPHANUMERIC: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

pub(crate) fn fill(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    fill(&mut out);
    out
}

pub fn below(max_exclusive: u32) -> u32 {
    u32::from_le_bytes(random_bytes::<4>()) % max_exclusive.max(1)
}

pub fn alphanumeric(len: usize) -> String {
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 64];
    while out.len() < len {
        fill(&mut buf);
        for &byte in &buf {
            // rejection sampling keeps the distribution uniform
            if byte < 248 && out.len() < len {
                out.push(ALPHANUMERIC[usize::from(byte) % 62] as char);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_stays_in_range() {
        assert!((0..200).all(|_| below(3) < 3));
        assert_eq!(below(0), 0);
        assert_eq!(below(1), 0);
    }

    #[test]
    fn alphanumeric_has_requested_length_and_charset() {
        let value = alphanumeric(100);
        assert_eq!(value.len(), 100);
        assert!(value.bytes().all(|b| b.is_ascii_alphanumeric()));
    }
}
