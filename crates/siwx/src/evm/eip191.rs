//! EIP-191 `personal_sign` verification (internal).
//!
//! Signature decode order (cross-language contract, mirrored by TS):
//! length ≠ 65 → `v ∉ {0,1,27,28}` → `r`/`s` equal to 0 or ≥ n → `s > n/2`
//! (all [`Error::InvalidSignature`]) → recovery failure or address mismatch
//! → [`Error::VerificationFailed`].

use alloy::primitives::{Signature, U256, eip191_hash_message, uint};

use crate::{Error, Message};

use super::parse_eip55;

/// secp256k1 group order n.
const N: U256 =
    uint!(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFE_BAAE_DCE6_AF48_A03B_BFD2_5E8C_D036_4141_U256);

/// Synchronous EIP-191 verification used by [`crate::evm::Evm`].
pub(crate) fn verify_sync(message: &Message, signed: &[u8], signature: &[u8]) -> Result<(), Error> {
    let sig: &[u8; 65] = signature.try_into().map_err(|_| Error::InvalidSignature {
        reason: "EIP-191 signature must be 65 bytes",
    })?;
    let (rs, v) = sig.split_last_chunk::<1>().unwrap_or((&sig[..64], &[0]));
    let [v] = *v;
    if !matches!(v, 0 | 1 | 27 | 28) {
        return Err(Error::InvalidSignature {
            reason: "v must be 0, 1, 27 or 28",
        });
    }
    let (r_bytes, s_bytes) = rs.split_at(32);
    let r = U256::from_be_slice(r_bytes);
    let s = U256::from_be_slice(s_bytes);
    if r == U256::ZERO || r >= N || s == U256::ZERO || s >= N {
        return Err(Error::InvalidSignature {
            reason: "r/s out of range",
        });
    }
    // EIP-2 low-s.
    if s > N / U256::from(2u8) {
        return Err(Error::InvalidSignature {
            reason: "high-s (EIP-2)",
        });
    }

    let alloy_sig = Signature::try_from(signature).map_err(|_| Error::InvalidSignature {
        reason: "bad encoding",
    })?;

    let hash = eip191_hash_message(signed);

    let recovered = alloy_sig
        .recover_address_from_prehash(&hash)
        .map_err(|_| Error::VerificationFailed)?;

    let expected = parse_eip55(message.address())?;

    if recovered != expected {
        return Err(Error::VerificationFailed);
    }

    Ok(())
}
