//! # siwx-evm — Ethereum verification for Sign-In with X
//!
//! Implements the CAIP-122 namespace profile for EIP-155 chains via a single
//! public type [`EvmVerifier`]:
//! - **EIP-191** (`personal_sign`) — always available
//! - **EIP-1271** — smart-contract `isValidSignature` (feature `eip1271` + RPC)
//!
//! # Quick start
//!
//! ```rust,no_run
//! use siwx::{SiwxMessage, Verifier};
//! use siwx_evm::EvmVerifier;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let message = SiwxMessage::new(
//!     "example.com",
//!     "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
//!     "https://example.com/login",
//!     "1",
//!     siwx::nonce::generate_default(),
//! )?;
//! let text = EvmVerifier::format_message(&message);
//! // let signature_bytes: [u8; 65] = ...; // from wallet
//! // EvmVerifier::new().verify(&message, &text, &signature_bytes).await?;
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "eip1271")]
mod eip1271;
mod eip191;

use alloy::primitives::Address;
use siwx::{SiwxError, SiwxMessage, Verifier};

/// Human-readable chain label embedded in the CAIP-122 preamble.
pub const CHAIN_NAME: &str = "Ethereum";

/// Validate that `address` is a well-formed 0x-prefixed, 40-hex-char Ethereum
/// address.
///
/// # Errors
///
/// Returns [`SiwxError::InvalidAddress`] if the format is wrong.
pub fn validate_address(address: &str) -> Result<(), SiwxError> {
    if !address.starts_with("0x") {
        return Err(SiwxError::InvalidAddress("must start with 0x".into()));
    }
    parse_address(address)?;
    Ok(())
}

/// Parse an Ethereum address string into an [`alloy::primitives::Address`].
pub(crate) fn parse_address(s: &str) -> Result<Address, SiwxError> {
    s.parse::<Address>()
        .map_err(|e| SiwxError::InvalidAddress(e.to_string()))
}

/// Ethereum CAIP-122 verifier.
///
/// Tries EIP-191 first. When built with the `eip1271` feature and constructed
/// via [`Self::with_rpc`], falls back to EIP-1271 on EIP-191 failure.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "eip1271"), derive(Copy))]
pub struct EvmVerifier {
    #[cfg(feature = "eip1271")]
    rpc_url: Option<String>,
}

impl EvmVerifier {
    /// Create a verifier that only performs EIP-191 recovery.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "eip1271")]
            rpc_url: None,
        }
    }

    /// Create a verifier with RPC for EIP-1271 fallback.
    ///
    /// Requires the `eip1271` feature.
    #[cfg(feature = "eip1271")]
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

impl Verifier for EvmVerifier {
    const CHAIN_NAME: &'static str = CHAIN_NAME;

    async fn verify(
        &self,
        message: &SiwxMessage,
        raw_message: &str,
        signature: &[u8],
    ) -> Result<(), SiwxError> {
        let eip191_err = match eip191::verify_sync(message, raw_message, signature) {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };

        #[cfg(feature = "eip1271")]
        if let Some(rpc_url) = self.rpc_url.as_deref() {
            return eip1271::Eip1271Verifier::new(rpc_url)
                .verify(message, raw_message, signature)
                .await;
        }

        Err(eip191_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_address_accepts_canonical_formats() {
        assert!(validate_address("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").is_ok());
        assert!(validate_address("0x0000000000000000000000000000000000000000").is_ok());
    }

    #[test]
    fn validate_address_rejects_bad_formats() {
        assert!(validate_address("not-an-address").is_err());
        assert!(validate_address("0x123").is_err());
        assert!(validate_address("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045").is_err());
    }

    #[test]
    fn format_message_uses_ethereum_preamble() {
        let msg = SiwxMessage::new(
            "example.com",
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            "https://example.com",
            "1",
            "testnonce12345678",
        )
        .expect("valid");
        let text = EvmVerifier::format_message(&msg);
        assert!(text.starts_with("example.com wants you to sign in with your Ethereum account:"));
    }
}
