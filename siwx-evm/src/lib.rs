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

#[cfg(not(feature = "eip1271"))]
use std::future::Future;

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

/// How to resolve an RPC endpoint for EIP-1271.
#[cfg(feature = "eip1271")]
#[derive(Debug, Clone)]
enum RpcConfig {
    /// Single endpoint used for every `chain_id`.
    Single(String),
    /// Endpoint chosen by message `chain_id` (exact string match).
    ByChain(std::collections::BTreeMap<String, String>),
}

/// Ethereum CAIP-122 verifier.
///
/// Tries EIP-191 first. When built with the `eip1271` feature and given RPC
/// configuration, falls back to EIP-1271 on EIP-191 failure.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "eip1271"), derive(Copy))]
pub struct EvmVerifier {
    #[cfg(feature = "eip1271")]
    rpc: Option<RpcConfig>,
}

impl EvmVerifier {
    /// Create a verifier that only performs EIP-191 recovery.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "eip1271")]
            rpc: None,
        }
    }

    /// Create a verifier with a single RPC URL for EIP-1271 fallback.
    ///
    /// Requires the `eip1271` feature. The same URL is used for every
    /// `message.chain_id` — caller must ensure it matches the message chain.
    #[cfg(feature = "eip1271")]
    #[must_use]
    pub fn with_rpc(url: impl Into<String>) -> Self {
        Self {
            rpc: Some(RpcConfig::Single(url.into())),
        }
    }

    /// Create a verifier that selects the RPC URL by `message.chain_id`.
    ///
    /// Requires the `eip1271` feature. If the message `chain_id` is missing
    /// from the map, verification fails with a clear error (no silent wrong-chain RPC).
    #[cfg(feature = "eip1271")]
    #[must_use]
    pub fn with_rpc_map(
        map: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        let map = map.into_iter().map(|(k, v)| (k.into(), v.into())).collect();
        Self {
            rpc: Some(RpcConfig::ByChain(map)),
        }
    }

    #[cfg(feature = "eip1271")]
    fn rpc_url_for(&self, chain_id: &str) -> Result<Option<&str>, SiwxError> {
        match self.rpc.as_ref() {
            None => Ok(None),
            Some(RpcConfig::Single(url)) => Ok(Some(url.as_str())),
            Some(RpcConfig::ByChain(map)) => map.get(chain_id).map_or_else(
                || {
                    Err(SiwxError::VerificationFailed(format!(
                        "no RPC configured for chain_id {chain_id}"
                    )))
                },
                |url| Ok(Some(url.as_str())),
            ),
        }
    }
}

impl Default for EvmVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "eip1271"))]
impl Verifier for EvmVerifier {
    const CHAIN_NAME: &'static str = CHAIN_NAME;

    fn validate_address(address: &str) -> Result<(), SiwxError> {
        validate_address(address)
    }

    fn verify(
        &self,
        message: &SiwxMessage,
        raw_message: &str,
        signature: &[u8],
    ) -> impl Future<Output = Result<(), SiwxError>> + Send {
        std::future::ready(eip191::verify_sync(message, raw_message, signature))
    }
}

#[cfg(feature = "eip1271")]
impl Verifier for EvmVerifier {
    const CHAIN_NAME: &'static str = CHAIN_NAME;

    fn validate_address(address: &str) -> Result<(), SiwxError> {
        validate_address(address)
    }

    async fn verify(
        &self,
        message: &SiwxMessage,
        raw_message: &str,
        signature: &[u8],
    ) -> Result<(), SiwxError> {
        match eip191::verify_sync(message, raw_message, signature) {
            Ok(()) => Ok(()),
            Err(eip191_err) => {
                let Some(rpc_url) = self.rpc_url_for(&message.chain_id)? else {
                    return Err(eip191_err);
                };
                eip1271::Eip1271Verifier::new(rpc_url)
                    .verify(message, raw_message, signature)
                    .await
            }
        }
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

    #[cfg(feature = "eip1271")]
    #[test]
    fn rpc_map_requires_matching_chain_id() {
        let v = EvmVerifier::with_rpc_map([("1", "https://eth.example")]);
        assert!(v.rpc_url_for("1").unwrap().is_some());
        let err = v.rpc_url_for("137").unwrap_err();
        assert!(matches!(err, SiwxError::VerificationFailed(_)));
        assert!(
            err.to_string()
                .contains("no RPC configured for chain_id 137"),
            "error must name missing chain: {err}"
        );
    }

    /// When EIP-191 fails, fallback uses the map; missing `chain_id` fails offline
    /// without contacting a real network.
    #[cfg(feature = "eip1271")]
    #[tokio::test]
    async fn verify_offline_fails_when_191_fails_and_chain_rpc_missing() {
        use alloy::signers::{Signer, local::PrivateKeySigner};
        use time::macros::datetime;

        let signer: PrivateKeySigner =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse()
                .expect("key");
        // Message claims a different address so EIP-191 recovery fails.
        let message = SiwxMessage::new(
            "example.com",
            "0x0000000000000000000000000000000000000001",
            "https://example.com",
            "137",
            "testnonce12345678",
        )
        .expect("valid")
        .with_issued_at(datetime!(2024-01-01 0:00 UTC));
        let text = EvmVerifier::format_message(&message);
        let sig = signer.sign_message(text.as_bytes()).await.expect("sign");

        let verifier = EvmVerifier::with_rpc_map([("1", "https://eth.example.invalid")]);
        let err = verifier
            .verify(&message, &text, &sig.as_bytes())
            .await
            .expect_err("must fail without RPC for chain 137");
        assert!(
            matches!(err, SiwxError::VerificationFailed(_)),
            "got {err:?}"
        );
        assert!(
            err.to_string()
                .contains("no RPC configured for chain_id 137"),
            "got: {err}"
        );
    }

    #[cfg(feature = "eip1271")]
    #[tokio::test]
    async fn verify_without_rpc_returns_eip191_error_when_sig_invalid() {
        use time::macros::datetime;

        let message = SiwxMessage::new(
            "example.com",
            "0x0000000000000000000000000000000000000001",
            "https://example.com",
            "1",
            "testnonce12345678",
        )
        .expect("valid")
        .with_issued_at(datetime!(2024-01-01 0:00 UTC));
        let text = EvmVerifier::format_message(&message);
        let err = EvmVerifier::new()
            .verify(&message, &text, &[0u8; 65])
            .await
            .expect_err("bad sig without rpc");
        // No RPC configured: surface the EIP-191 failure, not a map miss.
        assert!(
            matches!(
                err,
                SiwxError::InvalidSignature(_) | SiwxError::VerificationFailed(_)
            ),
            "got {err:?}"
        );
    }
}
