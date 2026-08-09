use std::future::Future;

use ed25519_dalek::{Signature, Verifier as DalekVerifier, VerifyingKey};
use siwx::{SiwxError, SiwxMessage, Verifier};

use crate::CHAIN_NAME;

/// Ed25519 signature verifier for Solana.
///
/// Verifies a 64-byte Ed25519 signature over the raw message bytes using the
/// public key derived from `message.address` (base58). Fully synchronous —
/// no RPC needed.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ed25519Verifier;

impl Ed25519Verifier {
    /// Create a Solana Ed25519 verifier.
    ///
    /// The verifying key is always taken from `message.address` at verify
    /// time — callers cannot inject a separate public key.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn verifying_key_from_address(address: &str) -> Result<VerifyingKey, SiwxError> {
        let bytes = bs58::decode(address)
            .into_vec()
            .map_err(|e| SiwxError::InvalidAddress(format!("invalid base58 pubkey: {e}")))?;
        let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            SiwxError::InvalidAddress(format!("Ed25519 pubkey must be 32 bytes, got {}", v.len()))
        })?;
        VerifyingKey::from_bytes(&arr)
            .map_err(|e| SiwxError::InvalidAddress(format!("invalid Ed25519 pubkey: {e}")))
    }

    fn verify_sync(
        message: &SiwxMessage,
        raw_message: &str,
        signature: &[u8],
    ) -> Result<(), SiwxError> {
        let sig_arr: [u8; 64] = signature.try_into().map_err(|_| {
            SiwxError::InvalidSignature(format!(
                "Ed25519 signature must be 64 bytes, got {}",
                signature.len()
            ))
        })?;
        let sig = Signature::from_bytes(&sig_arr);

        let verifying_key = Self::verifying_key_from_address(&message.address)?;

        verifying_key
            .verify(raw_message.as_bytes(), &sig)
            .map_err(|e| SiwxError::VerificationFailed(format!("Ed25519 verify failed: {e}")))
    }
}

impl Verifier for Ed25519Verifier {
    const CHAIN_NAME: &'static str = CHAIN_NAME;

    fn verify(
        &self,
        message: &SiwxMessage,
        raw_message: &str,
        signature: &[u8],
    ) -> impl Future<Output = Result<(), SiwxError>> + Send {
        std::future::ready(Self::verify_sync(message, raw_message, signature))
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use time::macros::datetime;

    use super::*;

    fn make_keypair(seed: u8) -> SigningKey {
        let bytes: [u8; 32] =
            std::array::from_fn(|i| seed.wrapping_add(u8::try_from(i).unwrap_or(0)));
        SigningKey::from_bytes(&bytes)
    }

    fn sample_message(addr: &str) -> SiwxMessage {
        SiwxMessage::new(
            "example.com",
            addr,
            "https://example.com/login",
            "1",
            "testnonce12345678",
        )
        .expect("valid")
        .with_issued_at(datetime!(2024-01-01 0:00 UTC))
    }

    #[tokio::test]
    async fn ed25519_roundtrip() {
        let sk = make_keypair(1);
        let vk = sk.verifying_key();
        let addr = bs58::encode(vk.to_bytes()).into_string();

        let message = sample_message(&addr);
        let text = Ed25519Verifier::format_message(&message);
        let sig = sk.sign(text.as_bytes());

        Ed25519Verifier::new()
            .verify(&message, &text, &sig.to_bytes())
            .await
            .expect("should verify");
    }

    #[tokio::test]
    async fn ed25519_wrong_address_in_message() {
        let sk = make_keypair(1);
        let wrong_addr = bs58::encode(make_keypair(2).verifying_key().to_bytes()).into_string();

        let message = sample_message(&wrong_addr);
        let text = Ed25519Verifier::format_message(&message);
        let sig = sk.sign(text.as_bytes());

        let err = Ed25519Verifier::new()
            .verify(&message, &text, &sig.to_bytes())
            .await
            .unwrap_err();
        assert!(matches!(err, SiwxError::VerificationFailed(_)));
    }

    #[tokio::test]
    async fn ed25519_bad_sig_length() {
        let vk = make_keypair(1).verifying_key();
        let addr = bs58::encode(vk.to_bytes()).into_string();

        let message = sample_message(&addr);
        let text = Ed25519Verifier::format_message(&message);

        let err = Ed25519Verifier::new()
            .verify(&message, &text, &[0u8; 32])
            .await
            .unwrap_err();
        assert!(matches!(err, SiwxError::InvalidSignature(_)));
    }

    #[tokio::test]
    async fn ed25519_rejects_signature_over_different_bytes() {
        let sk = make_keypair(1);
        let addr = bs58::encode(sk.verifying_key().to_bytes()).into_string();

        let message = sample_message(&addr);
        let text = Ed25519Verifier::format_message(&message);
        let sig = sk.sign(text.as_bytes());

        let mut tampered = text.clone();
        tampered.push(' ');
        let err = Ed25519Verifier::new()
            .verify(&message, &tampered, &sig.to_bytes())
            .await
            .unwrap_err();
        assert!(matches!(err, SiwxError::VerificationFailed(_)));
    }

    #[test]
    fn verifying_key_from_address_rejects_invalid() {
        assert!(Ed25519Verifier::verifying_key_from_address("!!!").is_err());
    }
}
