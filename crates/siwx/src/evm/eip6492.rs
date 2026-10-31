//! ERC-6492 counterfactual signature verification.
//!
//! The 32-byte magic suffix is detected unconditionally. RPC verification is
//! compiled only with feature `eip6492`.

#[cfg(feature = "eip6492")]
use crate::Error;

/// ERC-6492 detection suffix: `0x6492` repeated 16 times.
pub(crate) const MAGIC: [u8; 32] = [
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
];

/// True when `signature` ends with [`MAGIC`].
#[must_use]
pub(crate) fn has_magic_suffix(signature: &[u8]) -> bool {
    signature.len() >= MAGIC.len() && signature.ends_with(&MAGIC)
}

#[cfg(feature = "eip6492")]
mod rpc {
    use std::time::Duration;

    use alloy::network::{Ethereum, Network};
    use alloy::primitives::{Address, B256, Bytes, eip191_hash_message};
    use alloy::providers::{DynProvider, Provider};
    use alloy::sol;
    use alloy::sol_types::SolConstructor;

    use crate::{Error, Message};

    use super::eth_call_bool;
    use crate::evm::eip1271;
    use crate::evm::parse_eip55;

    /// Byte length of vendored ox `universalSignatureValidatorBytecode`.
    const BYTECODE_LEN: usize = 1684;

    /// Deployless constructor initcode from wevm/ox (see `bytecode/SOURCE.txt`).
    const BYTECODE: [u8; BYTECODE_LEN] = match alloy::primitives::hex::const_decode_to_array(
        include_bytes!("bytecode/universalSignatureValidatorBytecode.hex"),
    ) {
        Ok(bytes) => bytes,
        Err(_) => panic!("invalid vendored ox universalSignatureValidatorBytecode hex"),
    };

    sol! {
        contract UniversalSignatureValidator {
            constructor(address _signer, bytes32 _hash, bytes _signature);
        }
    }

    fn deployless_calldata(signer: Address, hash: B256, signature: &[u8]) -> Vec<u8> {
        let encoded = UniversalSignatureValidator::constructorCall {
            _signer: signer,
            _hash: hash,
            _signature: Bytes::copy_from_slice(signature),
        }
        .abi_encode();
        let mut data = Vec::with_capacity(BYTECODE.len() + encoded.len());
        data.extend_from_slice(&BYTECODE);
        data.extend_from_slice(&encoded);
        data
    }

    /// Create-call request: `to` omitted, both `input` and `data` set (legacy RPC).
    fn deployless_tx(
        signer: Address,
        hash: B256,
        signature: &[u8],
    ) -> <Ethereum as Network>::TransactionRequest {
        let bytes = Bytes::from(deployless_calldata(signer, hash, signature));
        let mut tx = <Ethereum as Network>::TransactionRequest::default();
        tx.input.input = Some(bytes.clone());
        tx.input.data = Some(bytes);
        tx
    }

    pub(crate) async fn verify(
        provider: &DynProvider,
        timeout: Duration,
        message: &Message,
        signed: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        let signer = parse_eip55(message.address())?;
        let rpc_chain = eip1271::timed(
            timeout,
            async { provider.get_chain_id().await },
            "eth_chainId",
        )
        .await?;
        eip1271::assert_rpc_chain_id(message.chain_id(), rpc_chain)?;

        let hash = eip191_hash_message(signed);
        let tx = deployless_tx(signer, hash, signature);

        let result = eip1271::timed(timeout, async { provider.call(tx).await }, "eth_call").await?;
        if eth_call_bool(result.as_ref())? {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

#[cfg(feature = "eip6492")]
pub(crate) use rpc::verify;

/// Interpret a deployless validator `eth_call` result as a bool.
///
/// Nodes pad `return(31, 1)` to 32 bytes. Accept any length whose last byte is
/// `0x00`/`0x01` and whose prefix is all zeros.
#[cfg(feature = "eip6492")]
pub(crate) fn eth_call_bool(data: &[u8]) -> Result<bool, Error> {
    let Some((&last, prefix)) = data.split_last() else {
        return Err(Error::VerificationFailed);
    };
    match last {
        0x01 if prefix.iter().all(|b| *b == 0) => Ok(true),
        0x00 if prefix.iter().all(|b| *b == 0) => Ok(false),
        _ => Err(Error::VerificationFailed),
    }
}
