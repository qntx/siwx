use std::future::Future;

use crate::{SiwxError, SiwxMessage};

/// Chain-specific signature verifier.
///
/// Implementors live in companion crates (`siwx-evm`, `siwx-svm`, …).
/// Verification is async to accommodate on-chain checks (e.g. EIP-1271);
/// purely computational verifiers (EIP-191, Ed25519) simply wrap their
/// synchronous logic in `async {}`.
///
/// # Contract
///
/// * Hash / verify over **`raw_message` bytes** (the exact string the wallet
///   signed), not a re-serialized form of `message`.
/// * Bind cryptographic identity to `message.address`.
/// * Return `Ok(())` when the signature is **valid** for the given message.
/// * Return `Err(SiwxError::VerificationFailed(..))` when the signature is
///   **cryptographically invalid**.
/// * Return other `Err` variants for malformed inputs.
///
/// Prefer [`crate::authenticate`] over calling [`Self::verify`] directly so
/// parse, field validation, and canonical-form checks run first.
pub trait Verifier: Send + Sync {
    /// Ecosystem label embedded in the CAIP-122 preamble
    /// (`"{domain} wants you to sign in with your {CHAIN_NAME} account:"`).
    ///
    /// For example, `"Ethereum"` for EIP-155 chains, `"Solana"` for Solana.
    const CHAIN_NAME: &'static str;

    /// Verify `signature` over `raw_message`, binding identity to `message`.
    ///
    /// `raw_message` must be the exact bytes the wallet signed.
    /// [`crate::authenticate`] guarantees it matches
    /// [`Self::format_message`] before calling this method.
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
