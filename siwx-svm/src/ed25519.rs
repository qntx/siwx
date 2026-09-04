use std::future::Future;

use ed25519_dalek::{Signature, Verifier as DalekVerifier, VerifyingKey};
use siwx::{SiwxError, SiwxMessage, Verifier};

use crate::{CHAIN_NAME, NAMESPACE};

/// Ed25519 signature verifier for Solana.
///
/// Verifies a 64-byte Ed25519 signature over the raw message bytes using the
/// public key derived from [`SiwxMessage::address`] (base58). Fully synchronous —
/// no RPC needed.
///
/// Uses [`ed25519_dalek::Verifier::verify`] (RFC 8032 canonical `s`), not
/// [`ed25519_dalek::VerifyingKey::verify_strict`]. Address validation
/// special-cases only the 32-zero System Program identity; other torsion
/// points pass and are verified with `verify`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ed25519Verifier;

/// Decode `address` as a 32-byte Ed25519 verifying key.
///
/// Rejects the all-zero identity even though dalek 3 `from_bytes` accepts it.
pub(crate) fn verifying_key_from_address(address: &str) -> Result<VerifyingKey, SiwxError> {
    let bytes = bs58::decode(address)
        .into_vec()
        .map_err(|e| SiwxError::InvalidAddress {
            reason: format!("invalid base58: {e}"),
        })?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| SiwxError::InvalidAddress {
            reason: format!("expected 32 bytes, got {}", v.len()),
        })?;
    if arr == [0u8; 32] {
        return Err(SiwxError::InvalidAddress {
            reason: "identity pubkey (32 zero bytes)".into(),
        });
    }
    VerifyingKey::from_bytes(&arr).map_err(|e| SiwxError::InvalidAddress {
        reason: format!("invalid Ed25519 pubkey: {e}"),
    })
}

impl Ed25519Verifier {
    /// Create a Solana Ed25519 verifier.
    ///
    /// The verifying key is always taken from [`SiwxMessage::address`] at verify
    /// time — callers cannot inject a separate public key.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn verify_sync(
        message: &SiwxMessage,
        raw_message: &str,
        signature: &[u8],
    ) -> Result<(), SiwxError> {
        let sig_arr: [u8; 64] = signature
            .try_into()
            .map_err(|_| SiwxError::InvalidSignature {
                reason: format!(
                    "Ed25519 signature must be 64 bytes, got {}",
                    signature.len()
                ),
            })?;
        let sig = Signature::from_bytes(&sig_arr);

        let verifying_key = verifying_key_from_address(message.address())?;

        // RFC 8032 `verify`, not `verify_strict` (small-order A/R).
        verifying_key
            .verify(raw_message.as_bytes(), &sig)
            .map_err(|e| SiwxError::VerificationFailed {
                reason: format!("Ed25519 verify failed: {e}"),
            })
    }
}

impl Verifier for Ed25519Verifier {
    const CHAIN_NAME: &'static str = CHAIN_NAME;
    const NAMESPACE: &'static str = NAMESPACE;

    fn validate_address(address: &str) -> Result<(), SiwxError> {
        crate::validate_address(address)
    }

    fn validate_chain_id(chain_id: &str) -> Result<(), SiwxError> {
        crate::validate_chain_id(chain_id)
    }

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
        .expect("issued_at")
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
        assert!(
            matches!(err, SiwxError::VerificationFailed { .. }),
            "got {err:?}"
        );
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
        assert!(
            matches!(err, SiwxError::InvalidSignature { .. }),
            "got {err:?}"
        );
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
        assert!(
            matches!(err, SiwxError::VerificationFailed { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn verifying_key_from_address_rejects_invalid() {
        assert!(verifying_key_from_address("!!!").is_err(), "non-base58");
        assert!(
            verifying_key_from_address("11111111111111111111111111111111").is_err(),
            "identity"
        );
    }

    /// curve25519-dalek `EIGHT_TORSION[4]`: order-2 point. `from_bytes` succeeds
    /// (`is_weak`), `verify_strict` rejects, RFC 8032 `verify` accepts.
    const WEAK_PUBKEY: [u8; 32] = [
        236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ];

    #[tokio::test]
    async fn verify_accepts_weak_key_that_verify_strict_rejects() {
        let vk = VerifyingKey::from_bytes(&WEAK_PUBKEY).expect("on-curve torsion");
        assert!(vk.is_weak(), "fixture must be a small-order key");

        // R = Edwards identity (y = 1), s = 0. Probe: `verify` ok on 4 zero bytes.
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0] = 1;
        let sig = Signature::from_bytes(&sig_bytes);
        let raw = "\0\0\0\0";
        assert!(
            vk.verify(raw.as_bytes(), &sig).is_ok(),
            "RFC 8032 verify accepts this small-order key"
        );
        assert!(
            vk.verify_strict(raw.as_bytes(), &sig).is_err(),
            "verify_strict rejects small-order A; this crate must not switch to it"
        );

        let addr = bs58::encode(WEAK_PUBKEY).into_string();
        assert!(
            crate::validate_address(&addr).is_ok(),
            "weak keys other than 32-zero identity remain valid addresses"
        );
        let message = sample_message(&addr);
        Ed25519Verifier::new()
            .verify(&message, raw, &sig_bytes)
            .await
            .expect("Ed25519Verifier uses verify, not verify_strict");
    }
}
