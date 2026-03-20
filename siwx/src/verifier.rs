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
/// * Return `Ok(())` when the signature is **valid** for the given message.
/// * Return `Err(SiwxError::VerificationFailed(..))` when the signature is
///   **cryptographically invalid**.
/// * Return other `Err` variants for malformed inputs.
pub trait Verifier: Send + Sync {
    /// Verify `signature` over `message`.
    fn verify(
        &self,
        message: &SiwxMessage,
        signature: &[u8],
    ) -> impl Future<Output = Result<(), SiwxError>> + Send;
}
