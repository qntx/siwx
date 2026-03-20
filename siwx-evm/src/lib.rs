//! # siwx-evm — Ethereum verification for Sign-In with X
//!
//! Implements CAIP-122 namespace profile for EIP-155 chains:
//! - **EIP-191** (`personal_sign`) — ECDSA recovery-based verification
//! - **EIP-1271** — smart-contract `isValidSignature` verification (requires RPC)
//!
//! # Quick start
//!
//! ```rust,no_run
//! use siwx::SiwxMessage;
//! use siwx_evm::{Eip191Verifier, CHAIN_NAME};
//! use siwx::Verifier;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let message = SiwxMessage::new(
//!     "example.com",
//!     "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
//!     "https://example.com/login",
//!     "1",
//!     "1",
//! )?;
//! let text = siwx_evm::format_message(&message);
//! // let signature_bytes: [u8; 65] = ...; // from wallet
//! // Eip191Verifier.verify(&message, &signature_bytes).await?;
//! # Ok(())
//! # }
//! ```

mod eip1271;
mod eip191;

use alloy::primitives::Address;
pub use eip191::Eip191Verifier;
pub use eip1271::Eip1271Verifier;
use siwx::{SiwxError, SiwxMessage};

/// Human-readable chain name for the EIP-155 namespace, used in the CAIP-122
/// preamble line.
pub const CHAIN_NAME: &str = "Ethereum";

/// CAIP-122 signature type for EIP-191 `personal_sign`.
pub const SIG_TYPE_EIP191: &str = "eip191";

/// CAIP-122 signature type for EIP-1271 contract signatures.
pub const SIG_TYPE_EIP1271: &str = "eip1271";

/// Convenience: format a [`SiwxMessage`] into the EIP-4361 signing string.
#[must_use]
pub fn format_message(message: &SiwxMessage) -> String {
    message.to_sign_string(CHAIN_NAME)
}

/// Validate that `address` is a well-formed 0x-prefixed, 40-hex-char Ethereum
/// address.
///
/// # Errors
///
/// Returns [`SiwxError::InvalidAddress`] if the format is wrong.
pub fn validate_address(address: &str) -> Result<(), SiwxError> {
    if address.len() != 42 {
        return Err(SiwxError::InvalidAddress(format!(
            "expected 42 chars (0x + 40 hex), got {}",
            address.len()
        )));
    }
    if !address.starts_with("0x") {
        return Err(SiwxError::InvalidAddress("must start with 0x".into()));
    }
    if !address[2..].chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SiwxError::InvalidAddress(
            "contains non-hex characters".into(),
        ));
    }
    Ok(())
}

/// Parse an Ethereum address string into an [`alloy::primitives::Address`].
///
/// # Errors
///
/// Returns [`SiwxError::InvalidAddress`] on invalid format.
pub(crate) fn parse_address(s: &str) -> Result<Address, SiwxError> {
    s.parse::<Address>()
        .map_err(|e| SiwxError::InvalidAddress(e.to_string()))
}

/// Auto-detecting verifier that tries EIP-191 first; if the recovered address
/// does not match `message.address`, falls back to EIP-1271.
///
/// Requires an RPC URL for the EIP-1271 fallback path.
#[derive(Debug)]
pub struct EvmVerifier {
    rpc_url: Option<String>,
}

impl EvmVerifier {
    /// Create a verifier without RPC (EIP-191 only).
    #[must_use]
    pub const fn new() -> Self {
        Self { rpc_url: None }
    }

    /// Create a verifier with RPC for EIP-1271 fallback.
    #[must_use]
    pub fn with_rpc(url: impl Into<String>) -> Self {
        Self {
            rpc_url: Some(url.into()),
        }
    }
}

impl Default for EvmVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl siwx::Verifier for EvmVerifier {
    async fn verify(&self, message: &SiwxMessage, signature: &[u8]) -> Result<(), SiwxError> {
        let eip191_err = match Eip191Verifier::verify_inner(message, signature) {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };

        let Some(rpc_url) = self.rpc_url.as_deref() else {
            return Err(eip191_err);
        };

        Eip1271Verifier::new(rpc_url)
            .verify_inner(message, signature)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_address_valid() {
        assert!(validate_address("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").is_ok());
        assert!(validate_address("0x0000000000000000000000000000000000000000").is_ok());
    }

    #[test]
    fn validate_address_invalid() {
        assert!(validate_address("not-an-address").is_err());
        assert!(validate_address("0x123").is_err());
        assert!(validate_address("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045").is_err());
    }

    #[test]
    fn format_message_preamble() {
        let msg = SiwxMessage::new(
            "example.com",
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            "https://example.com",
            "1",
            "1",
        )
        .unwrap();
        let text = format_message(&msg);
        assert!(text.starts_with("example.com wants you to sign in with your Ethereum account:"));
    }
}
