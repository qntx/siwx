//! # siwx-svm — Solana verification for Sign-In with X
//!
//! Implements CAIP-122 namespace profile for Solana:
//! - **Ed25519** signature verification (`solana:ed25519`)
//!
//! # Quick start
//!
//! ```rust,no_run
//! use siwx::SiwxMessage;
//! use siwx_svm::{Ed25519Verifier, CHAIN_NAME};
//! use siwx::Verifier;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let message = SiwxMessage::new(
//!     "example.com",
//!     "GwAF45zjfyGzUbd3i3hXxzGeuchzEZXwpRYHZM5912F1",
//!     "https://example.com/login",
//!     "1",
//!     "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
//! )?;
//! // let pubkey: [u8; 32] = ...; // Ed25519 public key
//! // let sig_bytes: [u8; 64] = ...; // Ed25519 signature
//! // Ed25519Verifier::new(pubkey).verify(&message, &sig_bytes).await?;
//! # Ok(())
//! # }
//! ```

mod ed25519;

pub use ed25519::Ed25519Verifier;
use siwx::{SiwxError, SiwxMessage};

/// Human-readable chain name for the Solana namespace, used in the CAIP-122
/// preamble line.
pub const CHAIN_NAME: &str = "Solana";

/// CAIP-122 signature type for Solana Ed25519.
pub const SIG_TYPE: &str = "solana:ed25519";

/// Convenience: format a [`SiwxMessage`] into the Solana CAIP-122 signing
/// string.
#[must_use]
pub fn format_message(message: &SiwxMessage) -> String {
    message.to_sign_string(CHAIN_NAME)
}

/// Validate that `address` is a valid base58-encoded Solana public key (32
/// bytes decoded).
///
/// # Errors
///
/// Returns [`SiwxError::InvalidAddress`] if the format is wrong.
pub fn validate_address(address: &str) -> Result<(), SiwxError> {
    let bytes = bs58::decode(address)
        .into_vec()
        .map_err(|e| SiwxError::InvalidAddress(format!("invalid base58: {e}")))?;
    if bytes.len() != 32 {
        return Err(SiwxError::InvalidAddress(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_address_valid() {
        assert!(validate_address("11111111111111111111111111111111").is_ok());
        assert!(validate_address("GwAF45zjfyGzUbd3i3hXxzGeuchzEZXwpRYHZM5912F1").is_ok());
    }

    #[test]
    fn validate_address_invalid() {
        assert!(validate_address("not-valid").is_err());
        assert!(validate_address("").is_err());
    }

    #[test]
    fn format_message_preamble() {
        let msg = SiwxMessage::new(
            "example.com",
            "GwAF45zjfyGzUbd3i3hXxzGeuchzEZXwpRYHZM5912F1",
            "https://example.com",
            "1",
            "1",
        )
        .unwrap();
        let text = format_message(&msg);
        assert!(text.starts_with("example.com wants you to sign in with your Solana account:"));
    }
}
