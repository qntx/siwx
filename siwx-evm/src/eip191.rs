use alloy::primitives::{Signature, eip191_hash_message};
use siwx::{SiwxError, SiwxMessage, Verifier};

use crate::{CHAIN_NAME, parse_address};

/// EIP-191 `personal_sign` verifier.
///
/// Recovers the signer address from the 65-byte ECDSA signature (r‖s‖v) and
/// compares it against `message.address`. Fully synchronous — no RPC needed.
#[derive(Debug, Clone, Copy)]
pub struct Eip191Verifier;

impl Eip191Verifier {
    /// Synchronous verification path used by [`crate::EvmVerifier`] as its
    /// EIP-191 fast-path before falling back to EIP-1271.
    ///
    /// # Errors
    ///
    /// See [`Verifier::verify`].
    pub fn verify_sync(message: &SiwxMessage, signature: &[u8]) -> Result<(), SiwxError> {
        if signature.len() != 65 {
            return Err(SiwxError::InvalidSignature(format!(
                "EIP-191 signature must be 65 bytes, got {}",
                signature.len()
            )));
        }

        let alloy_sig = Signature::try_from(signature)
            .map_err(|e| SiwxError::InvalidSignature(format!("bad signature encoding: {e}")))?;

        let text = message.to_sign_string(CHAIN_NAME);
        let hash = eip191_hash_message(text.as_bytes());

        let recovered = alloy_sig
            .recover_address_from_prehash(&hash)
            .map_err(|e| SiwxError::VerificationFailed(format!("ECDSA recovery failed: {e}")))?;

        let expected = parse_address(&message.address)?;

        if recovered != expected {
            return Err(SiwxError::VerificationFailed(format!(
                "recovered {recovered} != expected {expected}"
            )));
        }

        Ok(())
    }
}

impl Verifier for Eip191Verifier {
    const CHAIN_NAME: &'static str = CHAIN_NAME;

    async fn verify(&self, message: &SiwxMessage, signature: &[u8]) -> Result<(), SiwxError> {
        Self::verify_sync(message, signature)
    }
}

#[cfg(test)]
mod tests {
    use alloy::signers::{Signer, local::PrivateKeySigner};
    use siwx::Verifier;

    use super::*;

    #[tokio::test]
    async fn eip191_roundtrip() {
        let signer: PrivateKeySigner =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse()
                .expect("valid key");
        let addr = format!("{:?}", signer.address());

        let message = SiwxMessage::new("example.com", &addr, "https://example.com/login", "1", "1")
            .expect("valid message")
            .with_nonce("testnonce12345678");

        let text = Eip191Verifier::format_message(&message);
        let sig = signer.sign_message(text.as_bytes()).await.expect("signing");
        let sig_bytes = sig.as_bytes();

        Eip191Verifier
            .verify(&message, &sig_bytes)
            .await
            .expect("verification should succeed");
    }

    #[tokio::test]
    async fn eip191_wrong_address() {
        let signer: PrivateKeySigner =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse()
                .expect("valid key");

        let message = SiwxMessage::new(
            "example.com",
            "0x0000000000000000000000000000000000000001",
            "https://example.com/login",
            "1",
            "1",
        )
        .expect("valid message")
        .with_nonce("testnonce12345678");

        let text = Eip191Verifier::format_message(&message);
        let sig = signer.sign_message(text.as_bytes()).await.expect("signing");
        let sig_bytes = sig.as_bytes();

        let err = Eip191Verifier
            .verify(&message, &sig_bytes)
            .await
            .unwrap_err();
        assert!(matches!(err, SiwxError::VerificationFailed(_)));
    }

    #[tokio::test]
    async fn eip191_bad_signature_length() {
        let message = SiwxMessage::new(
            "example.com",
            "0x0000000000000000000000000000000000000001",
            "https://example.com",
            "1",
            "1",
        )
        .unwrap();

        let err = Eip191Verifier
            .verify(&message, &[0u8; 32])
            .await
            .unwrap_err();
        assert!(matches!(err, SiwxError::InvalidSignature(_)));
    }
}
