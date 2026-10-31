//! EIP-1271 smart-contract signature verification (feature `eip1271`).

use std::future::Future;
use std::time::Duration;

use alloy::primitives::{FixedBytes, eip191_hash_message};
use alloy::providers::{DynProvider, Provider};
use alloy::sol;

use crate::{Error, Field, Message};

use super::{parse_eip55, parse_evm_chain_id};

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
pub(crate) fn assert_rpc_chain_id(message_chain_id: &str, rpc_chain_id: u64) -> Result<(), Error> {
    let expected = parse_evm_chain_id(message_chain_id)?;
    if expected != rpc_chain_id {
        return Err(Error::Mismatch {
            field: Field::ChainId,
            expected: expected.to_string(),
            actual: Some(rpc_chain_id.to_string()),
        });
    }
    Ok(())
}

pub(crate) async fn timed<T, E>(
    timeout: Duration,
    fut: impl Future<Output = Result<T, E>> + Send,
    what: &'static str,
) -> Result<T, Error> {
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| Error::Backend {
            reason: format!("{what} timed out"),
        })?
        .map_err(|_| Error::VerificationFailed)
}

pub(crate) async fn verify(
    provider: &DynProvider,
    timeout: Duration,
    message: &Message,
    signed: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let contract_addr = parse_eip55(message.address())?;
    let rpc_chain = timed(
        timeout,
        async { provider.get_chain_id().await },
        "eth_chainId",
    )
    .await?;
    // Wrong-chain contracts must not see isValidSignature.
    assert_rpc_chain_id(message.chain_id(), rpc_chain)?;

    let hash = eip191_hash_message(signed);
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
        return Err(Error::VerificationFailed);
    }

    Ok(())
}
