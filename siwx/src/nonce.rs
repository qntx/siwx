//! Cryptographically secure nonce generation for replay-attack prevention.

use rand::RngExt;

use crate::SiwxError;
use crate::message::MIN_NONCE_LEN;

/// Default nonce length (17 characters, matching the siwe reference suite).
pub const DEFAULT_LEN: usize = 17;

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Generates a random alphanumeric nonce of the given `len`.
///
/// EIP-4361 requires ≥ [`MIN_NONCE_LEN`] characters. A length of 17 (matching
/// the siwe reference suite) is a sensible default — see [`DEFAULT_LEN`].
///
/// # Errors
///
/// Returns [`SiwxError::InvalidNonce`] if `len < MIN_NONCE_LEN`.
///
/// # Examples
///
/// ```
/// let nonce = siwx::nonce::generate(17)?;
/// assert_eq!(nonce.len(), 17);
/// assert!(nonce.chars().all(|c| c.is_ascii_alphanumeric()));
/// # Ok::<(), siwx::SiwxError>(())
/// ```
pub fn generate(len: usize) -> Result<String, SiwxError> {
    if len < MIN_NONCE_LEN {
        return Err(SiwxError::InvalidNonce(format!(
            "length must be at least {MIN_NONCE_LEN}, got {len}"
        )));
    }
    let mut rng = rand::rng();
    Ok((0..len)
        .map(|_| {
            let idx = rng.random_range(..ALPHABET.len());
            ALPHABET.get(idx).copied().unwrap_or(b'A') as char
        })
        .collect())
}

/// Generates a random alphanumeric nonce with the [`DEFAULT_LEN`] of 17.
///
/// # Examples
///
/// ```
/// let nonce = siwx::nonce::generate_default();
/// assert_eq!(nonce.len(), siwx::nonce::DEFAULT_LEN);
/// ```
#[must_use]
pub fn generate_default() -> String {
    const {
        assert!(
            DEFAULT_LEN >= MIN_NONCE_LEN,
            "DEFAULT_LEN must be >= MIN_NONCE_LEN"
        );
    }
    let mut rng = rand::rng();
    (0..DEFAULT_LEN)
        .map(|_| {
            let idx = rng.random_range(..ALPHABET.len());
            ALPHABET.get(idx).copied().unwrap_or(b'A') as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_has_correct_length() {
        assert_eq!(generate(8).expect("ok").len(), 8);
        assert_eq!(generate(32).expect("ok").len(), 32);
    }

    #[test]
    fn nonce_is_alphanumeric() {
        let n = generate(100).expect("ok");
        assert!(n.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn default_nonce_is_17() {
        assert_eq!(generate_default().len(), 17);
    }

    #[test]
    fn short_length_errors() {
        assert!(matches!(
            generate(0).unwrap_err(),
            SiwxError::InvalidNonce(_)
        ));
        assert!(matches!(
            generate(7).unwrap_err(),
            SiwxError::InvalidNonce(_)
        ));
    }
}
