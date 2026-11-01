//! Cryptographically secure nonce generation for replay-attack prevention.

use rand::RngExt;

/// Generate a random nonce: 17 unbiased ASCII alphanumerics (OS-backed).
///
/// Exceeds the [`crate::MIN_NONCE_LEN`] of 8 required by EIP-4361.
///
/// # Examples
///
/// ```
/// let nonce = siwx::nonce::generate();
/// assert_eq!(nonce.len(), 17);
/// assert!(nonce.chars().all(|c| c.is_ascii_alphanumeric()));
/// ```
#[must_use]
pub fn generate() -> String {
    const LEN: usize = 17;
    const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..LEN)
        .map(|_| {
            #[allow(clippy::indexing_slicing, reason = "idx in 0..62")]
            let c = ALPHABET[rng.random_range(0..62)] as char;
            c
        })
        .collect()
}
