//! EIP-191 `personal_sign` verification (internal).

use alloy::primitives::{Signature, eip191_hash_message};

use crate::{Error, Message};

use super::parse_eip55;

/// Synchronous EIP-191 verification used by [`crate::evm::Evm`].
pub(crate) fn verify_sync(message: &Message, signed: &[u8], signature: &[u8]) -> Result<(), Error> {
    if signature.len() != 65 {
        return Err(Error::InvalidSignature {
            reason: "EIP-191 signature must be 65 bytes",
        });
    }

    let alloy_sig = Signature::try_from(signature).map_err(|_| Error::InvalidSignature {
        reason: "bad encoding",
    })?;

    // recover_address_from_prehash accepts high-s; EIP-2 requires low-s.
    if alloy_sig.normalize_s().is_some() {
        return Err(Error::InvalidSignature {
            reason: "high-s (EIP-2)",
        });
    }

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
