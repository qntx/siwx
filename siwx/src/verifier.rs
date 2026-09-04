use std::future::Future;

use crate::{ChainIdReason, SiwxError, SiwxMessage};

/// Chain-specific signature verifier.
///
/// Implementors live in companion crates (`siwx-evm`, `siwx-svm`, …).
/// Verification is async to accommodate on-chain checks (e.g. EIP-1271);
/// purely computational verifiers wrap synchronous work in
/// [`std::future::ready`].
///
/// # Contract
///
/// * Implement [`Self::validate_address`] for chain address shape checks.
/// * Override [`Self::validate_chain_id`] for namespace chain-id rules.
/// * Hash / verify over **`raw_message` bytes** (the exact string the wallet
///   signed), not a re-serialized form of `message`.
/// * Bind cryptographic identity to [`SiwxMessage::address`].
/// * Return `Ok(())` when the signature is **valid** for the given message.
/// * Return `Err(SiwxError::VerificationFailed { .. })` when the signature is
///   **cryptographically invalid**.
/// * Return other `Err` variants for malformed inputs.
///
/// Prefer [`crate::authenticate`] over calling [`Self::verify`] directly so
/// parse, field validation, chain-name binding, and address / chain-id checks
/// run first.
pub trait Verifier: Send + Sync {
    /// Ecosystem label embedded in the CAIP-122 preamble
    /// (`"{domain} wants you to sign in with your {CHAIN_NAME} account:"`).
    ///
    /// For example, `"Ethereum"` for EIP-155 chains, `"Solana"` for Solana.
    const CHAIN_NAME: &'static str;

    /// CAIP-2 namespace, e.g. `"eip155"` / `"solana"`.
    const NAMESPACE: &'static str;

    /// Validate that `address` matches this chain's expected format.
    ///
    /// Called by [`crate::authenticate`] before signature verification.
    /// Default accepts any non-empty address shape already enforced by the
    /// message model; chain crates override with real checks.
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError::InvalidAddress`] when the format is wrong.
    fn validate_address(address: &str) -> Result<(), SiwxError> {
        if address.is_empty() {
            return Err(SiwxError::InvalidAddress {
                reason: "empty".into(),
            });
        }
        Ok(())
    }

    /// Validate that `chain_id` matches this namespace's profile.
    ///
    /// Called by [`crate::authenticate`] after [`Self::validate_address`].
    /// Default rejects only the empty string; chain crates override (EVM
    /// decimal / SVM charset).
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError::InvalidChainId`] when the format is wrong.
    fn validate_chain_id(chain_id: &str) -> Result<(), SiwxError> {
        if chain_id.is_empty() {
            return Err(SiwxError::InvalidChainId {
                reason: ChainIdReason::Empty,
            });
        }
        Ok(())
    }

    /// Verify `signature` over `raw_message`, binding identity to `message`.
    ///
    /// `raw_message` must be the exact bytes the wallet signed.
    /// [`crate::authenticate`] verifies those original bytes; it does not
    /// re-serialize the parsed message before calling this method.
    fn verify(
        &self,
        message: &SiwxMessage,
        raw_message: &str,
        signature: &[u8],
    ) -> impl Future<Output = Result<(), SiwxError>> + Send;

    /// Render `message` into the chain's canonical signing string.
    ///
    /// Convenience default that calls
    /// [`SiwxMessage::to_sign_string`] with [`Self::CHAIN_NAME`].
    #[must_use]
    fn format_message(message: &SiwxMessage) -> String {
        message.to_sign_string(Self::CHAIN_NAME)
    }
}
