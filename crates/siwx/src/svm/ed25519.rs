//! Ed25519 signature verification for Solana (internal).

use ed25519_dalek::{Signature, Verifier as DalekVerifier, VerifyingKey};

use crate::{Error, Message};

/// Decode `address` as a 32-byte Ed25519 verifying key.
///
/// Rejects [`VerifyingKey::is_weak`] keys after `from_bytes` (small-order,
/// including the 32-zero identity dalek 3 otherwise accepts).
pub(crate) fn verifying_key_from_address(address: &str) -> Result<VerifyingKey, Error> {
    let bytes = bs58::decode(address)
        .into_vec()
        .map_err(|_| Error::field(crate::Field::Address, "invalid base58"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::field(crate::Field::Address, "expected 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&arr)
        .map_err(|_| Error::field(crate::Field::Address, "invalid Ed25519 pubkey"))?;
    if vk.is_weak() {
        return Err(Error::field(
            crate::Field::Address,
            "weak/small-order pubkey",
        ));
    }
    Ok(vk)
}

/// Synchronous Ed25519 verification used by [`crate::svm::Svm`].
pub(crate) fn verify_sync(message: &Message, signed: &[u8], signature: &[u8]) -> Result<(), Error> {
    let sig_arr: [u8; 64] = signature.try_into().map_err(|_| Error::InvalidSignature {
        reason: "Ed25519 signature must be 64 bytes",
    })?;
    let sig = Signature::from_bytes(&sig_arr);

    let verifying_key = verifying_key_from_address(message.address())?;

    // RFC 8032 `verify`, not `verify_strict` (small-order A/R).
    verifying_key
        .verify(signed, &sig)
        .map_err(|_| Error::VerificationFailed)
}
