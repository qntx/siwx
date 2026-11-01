//! Ed25519 signature verification for Solana (internal).

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use ed25519_dalek::{Signature, VerifyingKey};

use super::{address_bytes, canonical_point};
use crate::{Error, Message};

/// Decode `address` as a canonical, on-curve, prime-order-subgroup Ed25519
/// verifying key.
pub(crate) fn verifying_key_from_address(address: &str) -> Result<VerifyingKey, Error> {
    let arr = address_bytes(address)?;
    canonical_point(&arr)?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|_| Error::field(crate::Field::Address, "invalid Ed25519 pubkey"))
}

/// Synchronous Ed25519 verification used by [`crate::svm::Svm`].
pub(crate) fn verify_sync(message: &Message, signed: &[u8], signature: &[u8]) -> Result<(), Error> {
    let sig_arr: [u8; 64] = signature.try_into().map_err(|_| Error::InvalidSignature {
        reason: "Ed25519 signature must be 64 bytes",
    })?;
    let (r_bytes, s_bytes) = sig_arr.split_at(32);
    let mut s_arr = [0u8; 32];
    s_arr.copy_from_slice(s_bytes);
    if Option::<Scalar>::from(Scalar::from_canonical_bytes(s_arr)).is_none() {
        return Err(Error::InvalidSignature {
            reason: "S must be a canonical scalar (S < L)",
        });
    }
    // Address key first: canonical, on-curve, prime-order subgroup.
    let verifying_key = verifying_key_from_address(message.address())?;

    // R must be a canonical, prime-order-subgroup, non-identity encoding.
    let mut r_arr = [0u8; 32];
    r_arr.copy_from_slice(r_bytes);
    let Some(r_point) = CompressedEdwardsY(r_arr).decompress() else {
        return Err(Error::VerificationFailed);
    };
    if !r_point.is_torsion_free() || r_point.is_identity() || r_point.compress().0 != r_arr {
        return Err(Error::VerificationFailed);
    }
    let sig = Signature::from_bytes(&sig_arr);

    // RFC 8032 cofactorless on torsion-free A/R: canonical encodings, S < L.
    verifying_key
        .verify_strict(signed, &sig)
        .map_err(|_| Error::VerificationFailed)
}
