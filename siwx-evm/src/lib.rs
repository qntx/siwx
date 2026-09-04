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
#[cfg(feature = "eip1271")]
use std::sync::Arc;
#[cfg(feature = "eip1271")]
use std::time::Duration;

use alloy::primitives::Address;
use siwx::{ChainIdReason, SiwxError, SiwxMessage, Verifier};

/// Human-readable chain label embedded in the CAIP-122 preamble.
pub const CHAIN_NAME: &str = "Ethereum";

/// CAIP-2 namespace for EIP-155 chains.
pub const NAMESPACE: &str = "eip155";

#[cfg(feature = "eip1271")]
const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// Validate that `address` is EIP-55 checksummed (`0x` + 40 hex).
///
/// All-lowercase is accepted only when that string is the EIP-55 form of the
/// address.
///
/// # Errors
///
/// Returns [`SiwxError::InvalidAddress`] if the format or checksum is wrong.
pub fn validate_address(address: &str) -> Result<(), SiwxError> {
    parse_eip55(address).map(|_| ())
}

/// Parse an Ethereum address, requiring the EIP-55 checksum (no EIP-1191).
pub(crate) fn parse_eip55(s: &str) -> Result<Address, SiwxError> {
    Address::parse_checksummed(s, None).map_err(|e| SiwxError::InvalidAddress {
        reason: e.to_string(),
    })
}

/// EVM `chain-id`: `[0-9]+`, no leading zero unless the value is `"0"`, fits in `u64`.
pub(crate) fn parse_evm_chain_id(s: &str) -> Result<u64, SiwxError> {
    if s.is_empty() {
        return Err(SiwxError::InvalidChainId {
            reason: ChainIdReason::Empty,
        });
    }
    if !s.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(SiwxError::InvalidChainId {
            reason: ChainIdReason::NotDecimal,
        });
    }
    if s.len() > 1 && s.starts_with('0') {
        return Err(SiwxError::InvalidChainId {
            reason: ChainIdReason::LeadingZero,
        });
    }
    s.parse().map_err(|_| SiwxError::InvalidChainId {
        reason: ChainIdReason::Overflow,
    })
}

/// Per-chain RPC endpoint with a lazily connected provider.
#[cfg(feature = "eip1271")]
#[derive(Debug)]
struct RpcEndpoint {
    url: String,
    provider: tokio::sync::OnceCell<alloy::providers::DynProvider>,
}

/// Ethereum CAIP-122 verifier.
///
/// Tries EIP-191 first. When built with the `eip1271` feature and an RPC URL
/// is configured for the message chain, any EIP-191 error falls through to
/// EIP-1271 (`eth_chainId` then `isValidSignature`).
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "eip1271"), derive(Copy))]
pub struct EvmVerifier {
    #[cfg(feature = "eip1271")]
    rpc: Option<Arc<std::collections::BTreeMap<u64, RpcEndpoint>>>,
    #[cfg(feature = "eip1271")]
    timeout: Duration,
}

impl EvmVerifier {
    /// Create a verifier that only performs EIP-191 recovery.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "eip1271")]
            rpc: None,
            #[cfg(feature = "eip1271")]
            timeout: DEFAULT_RPC_TIMEOUT,
        }
    }

    /// Create a verifier that selects the RPC URL by EIP-155 chain id.
    ///
    /// Requires the `eip1271` feature. Chains missing from the map stay on
    /// EIP-191 (the 191 error is returned; no wrong-chain RPC).
    #[cfg(feature = "eip1271")]
    #[must_use]
    pub fn with_rpc_map(map: impl IntoIterator<Item = (u64, impl Into<String>)>) -> Self {
        let mut endpoints = std::collections::BTreeMap::new();
        for (id, url) in map {
            endpoints.insert(
                id,
                RpcEndpoint {
                    url: url.into(),
                    provider: tokio::sync::OnceCell::new(),
                },
            );
        }
        Self {
            rpc: Some(Arc::new(endpoints)),
            timeout: DEFAULT_RPC_TIMEOUT,
        }
    }

    /// Create a verifier with a single RPC URL bound to `chain_id`.
    #[cfg(feature = "eip1271")]
    #[must_use]
    pub fn with_rpc_for_chain(chain_id: u64, url: impl Into<String>) -> Self {
        Self::with_rpc_map([(chain_id, url)])
    }

    /// Override the RPC HTTP timeout (default 5 seconds).
    #[cfg(feature = "eip1271")]
    #[must_use]
    pub const fn with_rpc_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[cfg(feature = "eip1271")]
    fn endpoint_for(&self, chain_id: &str) -> Option<&RpcEndpoint> {
        let id = parse_evm_chain_id(chain_id).ok()?;
        self.rpc.as_ref()?.get(&id)
    }

    #[cfg(feature = "eip1271")]
    async fn provider_for<'a>(
        &self,
        endpoint: &'a RpcEndpoint,
    ) -> Result<&'a alloy::providers::DynProvider, SiwxError> {
        use alloy::network::Ethereum;
        use alloy::providers::{Provider, ProviderBuilder};

        let url = endpoint.url.clone();
        let timeout = self.timeout;
        endpoint
            .provider
            .get_or_try_init(|| async move {
                let connect = ProviderBuilder::new().connect(&url);
                let built = tokio::time::timeout(timeout, connect)
                    .await
                    .map_err(|_| SiwxError::VerificationFailed {
                        reason: "RPC timeout".into(),
                    })?
                    .map_err(|_| SiwxError::VerificationFailed {
                        reason: "RPC connect failed".into(),
                    })?;
                Ok(Provider::<Ethereum>::erased(built))
            })
            .await
    }

    #[cfg(feature = "eip1271")]
    async fn verify_eip1271(
        &self,
        message: &SiwxMessage,
        raw_message: &str,
        signature: &[u8],
        eip191_err: SiwxError,
    ) -> Result<(), SiwxError> {
        let Some(endpoint) = self.endpoint_for(&message.chain_id) else {
            return Err(eip191_err);
        };
        let provider = self.provider_for(endpoint).await?;
        eip1271::verify(provider, self.timeout, message, raw_message, signature).await
    }
}

impl Default for EvmVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Verifier for EvmVerifier {
    const CHAIN_NAME: &'static str = CHAIN_NAME;
    const NAMESPACE: &'static str = NAMESPACE;

    fn validate_address(address: &str) -> Result<(), SiwxError> {
        validate_address(address)
    }

    fn validate_chain_id(chain_id: &str) -> Result<(), SiwxError> {
        parse_evm_chain_id(chain_id).map(|_| ())
    }

    #[cfg(not(feature = "eip1271"))]
    fn verify(
        &self,
        message: &SiwxMessage,
        raw_message: &str,
        signature: &[u8],
    ) -> impl Future<Output = Result<(), SiwxError>> + Send {
        std::future::ready(eip191::verify_sync(message, raw_message, signature))
    }

    #[cfg(feature = "eip1271")]
    async fn verify(
        &self,
        message: &SiwxMessage,
        raw_message: &str,
        signature: &[u8],
    ) -> Result<(), SiwxError> {
        match eip191::verify_sync(message, raw_message, signature) {
            Ok(()) => Ok(()),
            Err(eip191_err) => {
                self.verify_eip1271(message, raw_message, signature, eip191_err)
                    .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json as _;

    use super::*;

    #[test]
    fn namespace_is_eip155() {
        assert_eq!(EvmVerifier::NAMESPACE, "eip155");
        assert_eq!(NAMESPACE, "eip155");
    }

    #[test]
    fn validate_address_accepts_canonical_formats() {
        assert!(validate_address("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").is_ok());
        assert!(validate_address("0x0000000000000000000000000000000000000000").is_ok());
        // All-lowercase is valid only when it is the EIP-55 form.
        assert!(validate_address("0xde709f2102306220921060314715629080e2fb77").is_ok());
    }

    #[test]
    fn validate_address_rejects_bad_formats() {
        assert!(validate_address("not-an-address").is_err());
        assert!(validate_address("0x123").is_err());
        assert!(validate_address("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045").is_err());
        assert!(validate_address("0xd8da6bf26964af9d7eed9e03e53415d37aa96045").is_err());
    }

    #[test]
    fn validate_chain_id_accepts_decimal() {
        assert!(EvmVerifier::validate_chain_id("0").is_ok());
        assert!(EvmVerifier::validate_chain_id("1").is_ok());
        assert!(EvmVerifier::validate_chain_id("137").is_ok());
    }

    #[test]
    fn validate_chain_id_rejects_empty_leading_zero_and_overflow() {
        assert!(matches!(
            EvmVerifier::validate_chain_id(""),
            Err(SiwxError::InvalidChainId {
                reason: ChainIdReason::Empty
            })
        ));
        assert!(matches!(
            EvmVerifier::validate_chain_id("01"),
            Err(SiwxError::InvalidChainId {
                reason: ChainIdReason::LeadingZero
            })
        ));
        assert!(matches!(
            EvmVerifier::validate_chain_id("00"),
            Err(SiwxError::InvalidChainId {
                reason: ChainIdReason::LeadingZero
            })
        ));
        assert!(matches!(
            EvmVerifier::validate_chain_id("1a"),
            Err(SiwxError::InvalidChainId {
                reason: ChainIdReason::NotDecimal
            })
        ));
        assert!(matches!(
            EvmVerifier::validate_chain_id("+1"),
            Err(SiwxError::InvalidChainId {
                reason: ChainIdReason::NotDecimal
            })
        ));
        assert!(matches!(
            EvmVerifier::validate_chain_id("18446744073709551616"),
            Err(SiwxError::InvalidChainId {
                reason: ChainIdReason::Overflow
            })
        ));
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
    fn rpc_map_missing_chain_has_no_endpoint() {
        let v = EvmVerifier::with_rpc_map([(1u64, "https://eth.example")]);
        assert!(v.endpoint_for("1").is_some());
        assert!(v.endpoint_for("137").is_none());
        assert!(v.endpoint_for("01").is_none());
    }

    /// When EIP-191 fails and the message chain has no RPC, return the 191 error.
    #[cfg(feature = "eip1271")]
    #[tokio::test]
    async fn verify_offline_returns_191_when_chain_rpc_missing() {
        use alloy::signers::{Signer, local::PrivateKeySigner};
        use time::macros::datetime;

        let signer: PrivateKeySigner =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse()
                .expect("key");
        let message = SiwxMessage::new(
            "example.com",
            "0x0000000000000000000000000000000000000001",
            "https://example.com",
            "137",
            "testnonce12345678",
        )
        .expect("valid")
        .with_issued_at(datetime!(2024-01-01 0:00 UTC))
        .expect("issued_at");
        let text = EvmVerifier::format_message(&message);
        let sig = signer.sign_message(text.as_bytes()).await.expect("sign");

        let verifier = EvmVerifier::with_rpc_map([(1u64, "https://eth.example.invalid")]);
        let err = verifier
            .verify(&message, &text, &sig.as_bytes())
            .await
            .expect_err("must fail without RPC for chain 137");
        assert!(
            matches!(err, SiwxError::VerificationFailed { .. }),
            "got {err:?}"
        );
        assert!(
            err.to_string().contains("recovered"),
            "missing-chain must surface the 191 error, got: {err}"
        );
        assert!(
            !err.to_string().contains("https://"),
            "error must not include RPC URL: {err}"
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
        .with_issued_at(datetime!(2024-01-01 0:00 UTC))
        .expect("issued_at");
        let text = EvmVerifier::format_message(&message);
        let err = EvmVerifier::new()
            .verify(&message, &text, &[0u8; 65])
            .await
            .expect_err("bad sig without rpc");
        assert!(
            matches!(
                err,
                SiwxError::InvalidSignature { .. } | SiwxError::VerificationFailed { .. }
            ),
            "got {err:?}"
        );
    }

    #[cfg(feature = "eip1271")]
    #[tokio::test]
    async fn high_s_falls_through_to_1271_when_rpc_configured() {
        use alloy::primitives::{Signature, U256};
        use alloy::signers::{Signer, local::PrivateKeySigner};
        use time::macros::datetime;

        let signer: PrivateKeySigner =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse()
                .expect("key");
        let addr = signer.address().to_string();
        let message = SiwxMessage::new(
            "example.com",
            &addr,
            "https://example.com",
            "1",
            "testnonce12345678",
        )
        .expect("valid")
        .with_issued_at(datetime!(2024-01-01 0:00 UTC))
        .expect("issued_at");
        let text = EvmVerifier::format_message(&message);
        let sig = signer.sign_message(text.as_bytes()).await.expect("sign");
        let low = Signature::try_from(sig.as_bytes().as_slice()).expect("sig");
        assert!(low.normalize_s().is_none(), "fixture must be low-s");
        let n: U256 = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
            .parse()
            .expect("n");
        let high = Signature::new(low.r(), n - low.s(), !low.v());

        let err = EvmVerifier::with_rpc_for_chain(1, "http://127.0.0.1:1")
            .verify(&message, &text, &high.as_bytes())
            .await
            .expect_err("1271 fallback after high-s");
        assert!(
            matches!(err, SiwxError::VerificationFailed { .. }),
            "high-s with RPC must not stay on InvalidSignature, got {err:?}"
        );
        assert!(
            !err.to_string().contains("http"),
            "connect-failure error must not include RPC URL: {err}"
        );
    }
}
