//! EIP-1271 smart-contract signature verification (feature `eip1271`).

use std::future::Future;
use std::time::Duration;

use alloy::primitives::{FixedBytes, eip191_hash_message};
use alloy::providers::{DynProvider, Provider};
use alloy::sol;
use siwx::{SiwxError, SiwxMessage};

use crate::{parse_eip55, parse_evm_chain_id};

/// EIP-1271 magic value returned by `isValidSignature` on success.
pub(crate) const EIP1271_MAGIC: FixedBytes<4> = FixedBytes([0x16, 0x26, 0xBA, 0x7E]);

/// Returns true if `magic` is the EIP-1271 success value `0x1626ba7e`.
#[must_use]
pub(crate) fn is_success_magic(magic: FixedBytes<4>) -> bool {
    magic == EIP1271_MAGIC
}

sol! {
    #[sol(rpc)]
    contract IERC1271 {
        function isValidSignature(bytes32 hash, bytes signature) external view returns (bytes4 magicValue);
    }
}

/// Require `eth_chainId` to equal the message chain id (decimal `u64`).
pub(crate) fn assert_rpc_chain_id(
    message_chain_id: &str,
    rpc_chain_id: u64,
) -> Result<(), SiwxError> {
    let expected = parse_evm_chain_id(message_chain_id)?;
    if expected != rpc_chain_id {
        return Err(SiwxError::ChainIdMismatch {
            expected: expected.to_string(),
            actual: rpc_chain_id.to_string(),
        });
    }
    Ok(())
}

async fn timed<T, E>(
    timeout: Duration,
    fut: impl Future<Output = Result<T, E>> + Send,
    what: &'static str,
) -> Result<T, SiwxError> {
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| SiwxError::VerificationFailed {
            reason: format!("{what} timed out"),
        })?
        .map_err(|_| SiwxError::VerificationFailed {
            reason: format!("{what} failed"),
        })
}

pub(crate) async fn verify(
    provider: &DynProvider,
    timeout: Duration,
    message: &SiwxMessage,
    raw_message: &str,
    signature: &[u8],
) -> Result<(), SiwxError> {
    let contract_addr = parse_eip55(message.address())?;
    let rpc_chain = timed(
        timeout,
        async { provider.get_chain_id().await },
        "eth_chainId",
    )
    .await?;
    // Wrong-chain contracts must not see isValidSignature.
    assert_rpc_chain_id(message.chain_id(), rpc_chain)?;

    let hash = eip191_hash_message(raw_message.as_bytes());
    let contract = IERC1271::new(contract_addr, provider);
    let magic: FixedBytes<4> = timed(
        timeout,
        async {
            contract
                .isValidSignature(hash, signature.to_vec().into())
                .call()
                .await
        },
        "isValidSignature",
    )
    .await?;

    if !is_success_magic(magic) {
        return Err(SiwxError::VerificationFailed {
            reason: format!("EIP-1271 magic mismatch: expected {EIP1271_MAGIC}, got {magic}"),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use siwx::ChainIdReason;

    use super::*;

    #[test]
    fn eip1271_magic_is_is_valid_signature_selector() {
        // bytes4(keccak256("isValidSignature(bytes32,bytes)")) == 0x1626ba7e
        assert_eq!(EIP1271_MAGIC, FixedBytes([0x16, 0x26, 0xBA, 0x7E]));
        assert!(is_success_magic(EIP1271_MAGIC));
    }

    #[test]
    fn non_success_magic_is_rejected_by_helper() {
        let bad = FixedBytes([0x00, 0x00, 0x00, 0x00]);
        assert!(!is_success_magic(bad));
        let almost = FixedBytes([0x16, 0x26, 0xBA, 0x7F]);
        assert!(!is_success_magic(almost));
    }

    #[test]
    fn assert_rpc_chain_id_matches_message() {
        assert_rpc_chain_id("1", 1).expect("match");
        assert_rpc_chain_id("137", 137).expect("match");
        let mismatch = assert_rpc_chain_id("137", 1).expect_err("mismatch");
        assert!(
            matches!(
                mismatch,
                SiwxError::ChainIdMismatch {
                    ref expected,
                    ref actual
                } if expected == "137" && actual == "1"
            ),
            "got {mismatch:?}"
        );
        let leading = assert_rpc_chain_id("01", 1).expect_err("leading zero");
        assert!(
            matches!(
                leading,
                SiwxError::InvalidChainId {
                    reason: ChainIdReason::LeadingZero
                }
            ),
            "got {leading:?}"
        );
    }
}
