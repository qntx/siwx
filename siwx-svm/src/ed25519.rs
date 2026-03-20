use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use siwx::{SiwxError, SiwxMessage};

use crate::format_message;

/// Ed25519 signature verifier for Solana.
///
/// Verifies a 64-byte Ed25519 signature against the message bytes using the
/// provided public key. Fully synchronous — no RPC needed.
#[derive(Debug, Clone, Copy)]
pub struct Ed25519Verifier {
    pubkey: [u8; 32],
}

impl Ed25519Verifier {
    /// Create a verifier for the given 32-byte Ed25519 public key.
    #[must_use]
    pub const fn new(pubkey: [u8; 32]) -> Self {
        Self { pubkey }
    }

    /// Create a verifier from a base58-encoded public key string.
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError::InvalidAddress`] if decoding fails or length != 32.
    pub fn from_base58(key: &str) -> Result<Self, SiwxError> {
        let bytes = bs58::decode(key)
            .into_vec()
            .map_err(|e| SiwxError::InvalidAddress(format!("invalid base58 pubkey: {e}")))?;
        let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            SiwxError::InvalidAddress(format!("Ed25519 pubkey must be 32 bytes, got {}", v.len()))
        })?;
        Ok(Self { pubkey: arr })
    }

    /// Core verification logic (synchronous).
    pub(crate) fn verify_inner(
        &self,
        message: &SiwxMessage,
        signature: &[u8],
    ) -> Result<(), SiwxError> {
        let sig_arr: [u8; 64] = signature.try_into().map_err(|_| {
            SiwxError::InvalidSignature(format!(
                "Ed25519 signature must be 64 bytes, got {}",
                signature.len()
            ))
        })?;
        let sig = Signature::from_bytes(&sig_arr);

        let verifying_key = VerifyingKey::from_bytes(&self.pubkey)
            .map_err(|e| SiwxError::InvalidAddress(format!("invalid Ed25519 pubkey: {e}")))?;

        let text = format_message(message);
        let msg_bytes = text.as_bytes();

        verifying_key
            .verify(msg_bytes, &sig)
            .map_err(|e| SiwxError::VerificationFailed(format!("Ed25519 verify failed: {e}")))
    }
}

impl siwx::Verifier for Ed25519Verifier {
    async fn verify(&self, message: &SiwxMessage, signature: &[u8]) -> Result<(), SiwxError> {
        self.verify_inner(message, signature)
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;
    use siwx::Verifier as _;

    use super::*;

    fn make_keypair(seed: u8) -> SigningKey {
        #[allow(clippy::cast_possible_truncation)]
        let bytes: [u8; 32] = std::array::from_fn(|i| seed.wrapping_add(i as u8));
        SigningKey::from_bytes(&bytes)
    }

    #[tokio::test]
    async fn ed25519_roundtrip() {
        let sk = make_keypair(1);
        let vk = sk.verifying_key();
        let addr = bs58::encode(vk.to_bytes()).into_string();

        let message = SiwxMessage::new("example.com", &addr, "https://example.com/login", "1", "1")
            .expect("valid")
            .with_nonce("testnonce12345678");

        let text = format_message(&message);
        let sig = sk.sign(text.as_bytes());

        Ed25519Verifier::new(vk.to_bytes())
            .verify(&message, &sig.to_bytes())
            .await
            .expect("should verify");
    }

    #[tokio::test]
    async fn ed25519_wrong_key() {
        let sk = make_keypair(1);
        let wrong_vk = make_keypair(2).verifying_key();
        let addr = bs58::encode(wrong_vk.to_bytes()).into_string();

        let message = SiwxMessage::new("example.com", &addr, "https://example.com/login", "1", "1")
            .expect("valid");

        let text = format_message(&message);
        let sig = sk.sign(text.as_bytes());

        let err = Ed25519Verifier::new(wrong_vk.to_bytes())
            .verify(&message, &sig.to_bytes())
            .await
            .unwrap_err();
        assert!(matches!(err, SiwxError::VerificationFailed(_)));
    }

    #[tokio::test]
    async fn ed25519_bad_sig_length() {
        let vk = make_keypair(1).verifying_key();
        let addr = bs58::encode(vk.to_bytes()).into_string();

        let message = SiwxMessage::new("d.com", &addr, "https://d.com", "1", "1").unwrap();

        let err = Ed25519Verifier::new(vk.to_bytes())
            .verify(&message, &[0u8; 32])
            .await
            .unwrap_err();
        assert!(matches!(err, SiwxError::InvalidSignature(_)));
    }

    #[test]
    fn from_base58_valid() {
        let vk = make_keypair(1).verifying_key();
        let b58 = bs58::encode(vk.to_bytes()).into_string();
        let verifier = Ed25519Verifier::from_base58(&b58).unwrap();
        assert_eq!(verifier.pubkey, vk.to_bytes());
    }

    #[test]
    fn from_base58_invalid() {
        assert!(Ed25519Verifier::from_base58("!!!").is_err());
    }
}
