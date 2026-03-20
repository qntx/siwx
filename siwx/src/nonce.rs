//! Cryptographically secure nonce generation for replay-attack prevention.

use rand::RngExt;

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Generates a random alphanumeric nonce of the given `len`.
///
/// CAIP-122 does not mandate a minimum length, but EIP-4361 requires ≥ 8
/// characters. A length of 17 (matching the siwe reference suite) is a
/// sensible default.
///
/// # Panics
///
/// Panics if `len == 0`.
#[must_use]
pub fn generate(len: usize) -> String {
    assert!(len > 0, "nonce length must be > 0");
    let mut rng = rand::rng();
    (0..len)
        .map(|_| ALPHABET[rng.random_range(..ALPHABET.len())] as char)
        .collect()
}

/// Default nonce length (17 characters, matching the siwe reference suite).
pub const DEFAULT_LEN: usize = 17;

/// Generates a random alphanumeric nonce with the [`DEFAULT_LEN`] of 17.
#[must_use]
pub fn generate_default() -> String {
    generate(DEFAULT_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_has_correct_length() {
        assert_eq!(generate(8).len(), 8);
        assert_eq!(generate(32).len(), 32);
    }

    #[test]
    fn nonce_is_alphanumeric() {
        let n = generate(100);
        assert!(n.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn default_nonce_is_17() {
        assert_eq!(generate_default().len(), 17);
    }

    #[test]
    #[should_panic(expected = "nonce length must be > 0")]
    fn zero_length_panics() {
        let _ = generate(0);
    }
}
