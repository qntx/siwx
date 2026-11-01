//! ERC-6492 universal validator via a deployless `eth_call`.
//!
//! The vendored wevm/ox `universalSignatureValidatorBytecode` (see
//! `bytecode/SOURCE.txt`) covers deployed ERC-1271 accounts, counterfactual
//! ERC-6492 accounts and EOAs — one verification path for all smart accounts.
//! Magic-suffix detection and result decoding are always compiled; the RPC
//! call itself requires the `rpc` feature.

#[cfg(feature = "rpc")]
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

/// Interpret a deployless validator `eth_call` result.
///
/// Valid is exactly `0x01` or a 32-byte word of zeros ending `01`; the same
/// shapes ending `00` are `false`; anything else is malformed.
///
/// # Errors
///
/// [`Error::Backend`] `malformed eth_call result`.
#[cfg(feature = "rpc")]
pub(crate) fn decode_result(data: &[u8]) -> Result<bool, Error> {
    let bad = || Error::Backend {
        reason: "malformed eth_call result".into(),
    };
    let zeros = |d: &[u8]| d.iter().all(|b| *b == 0);
    match data.split_last() {
        Some((&1, rest)) if (data.len() == 1 || data.len() == 32) && zeros(rest) => Ok(true),
        Some((&0, rest)) if (data.len() == 1 || data.len() == 32) && zeros(rest) => Ok(false),
        _ => Err(bad()),
    }
}

#[cfg(feature = "rpc")]
pub(crate) use rpc::verify;
#[cfg(all(test, feature = "rpc"))]
pub(crate) use rpc::{BYTECODE, deployless_calldata};

#[cfg(feature = "rpc")]
mod rpc {
    use alloy::network::{Ethereum, Network};
    use alloy::primitives::{Address, B256, Bytes, eip191_hash_message};
    use alloy::providers::{DynProvider, Provider};
    use alloy::sol;
    use alloy::sol_types::SolConstructor;

    use crate::{Error, Message};

    use super::decode_result;
    use crate::evm::parse_eip55;

    /// Byte length of vendored ox `universalSignatureValidatorBytecode`.
    const BYTECODE_LEN: usize = 1684;

    /// Deployless constructor initcode from wevm/ox (see `bytecode/SOURCE.txt`).
    pub(crate) const BYTECODE: [u8; BYTECODE_LEN] =
        match alloy::primitives::hex::const_decode_to_array(include_bytes!(
            "bytecode/universalSignatureValidatorBytecode.hex"
        )) {
            Ok(bytes) => bytes,
            Err(_) => panic!("invalid vendored ox universalSignatureValidatorBytecode hex"),
        };

    sol! {
        contract UniversalSignatureValidator {
            constructor(address _signer, bytes32 _hash, bytes _signature);
        }
    }

    /// `data = bytecode ‖ abi.encode(signer, hash, signature)`.
    #[must_use]
    pub(crate) fn deployless_calldata(signer: Address, hash: B256, signature: &[u8]) -> Vec<u8> {
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

    /// Create-call request: `to` omitted, both `input` and `data` set.
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

    /// JSON-RPC code 3 (EIP-1474 execution reverted) ⇒ signature rejected.
    fn is_revert(err: &alloy::transports::TransportError) -> bool {
        err.as_error_resp().is_some_and(|p| p.code == 3)
    }

    fn backend() -> Error {
        Error::Backend {
            reason: "RPC request failed".into(),
        }
    }

    /// Deployless `eth_call` against the vendored universal validator at
    /// `"latest"`. The caller has already bound `eth_chainId` to the message
    /// chain. Transport errors, malformed results and every JSON-RPC code
    /// other than 3 are [`Error::Backend`]; code 3 and a `0` result are
    /// [`Error::VerificationFailed`]. Reasons never contain provider details.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidField`], [`Error::Backend`],
    /// [`Error::VerificationFailed`].
    pub(crate) async fn verify(
        provider: &DynProvider,
        message: &Message,
        signed: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        // The caller already bound `eth_chainId` to the message chain.
        let signer = parse_eip55(message.address())?;
        let hash = eip191_hash_message(signed);
        let tx = deployless_tx(signer, hash, signature);
        let result = provider.call(tx).await.map_err(|e| {
            if is_revert(&e) {
                Error::VerificationFailed
            } else {
                backend()
            }
        })?;
        if decode_result(result.as_ref())? {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

/// Cross-language vector runner for the calldata/result-decode tables
/// (`vectors/evm/universal-validator.json`).
#[cfg(all(test, feature = "rpc"))]
#[expect(
    clippy::tests_outside_test_module,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::shadow_unrelated,
    reason = "vector runner test module"
)]
mod tests {
    use super::{BYTECODE, decode_result, deployless_calldata, has_magic_suffix};
    use crate::Error;
    use serde_json::Value;

    fn vector() -> Value {
        serde_json::from_str(include_str!(
            "../../../../vectors/evm/universal-validator.json"
        ))
        .expect("json")
    }

    fn hex(s: &str) -> Vec<u8> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn calldata_matches_vector() {
        let v = vector();
        for case in v["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let signer = case["signer"].as_str().unwrap().parse().unwrap();
            let hash: alloy::primitives::B256 = case["hashHex"].as_str().unwrap().parse().unwrap();
            let sig = hex(case["signatureHex"].as_str().unwrap());
            let want = hex(case["calldataHex"].as_str().unwrap());
            let got = deployless_calldata(signer, hash, &sig);
            assert_eq!(got, want, "{name}");
            assert!(got.starts_with(&BYTECODE), "{name}: bytecode prefix");
        }
    }

    #[test]
    fn decode_table() {
        let v = vector();
        for case in v["decode"].as_array().unwrap() {
            let data = hex(case["resultHex"].as_str().unwrap());
            let verdict = case["verdict"].as_str().unwrap();
            match (verdict, decode_result(&data)) {
                ("valid", Ok(true))
                | ("invalid", Ok(false))
                | ("backend", Err(Error::Backend { .. })) => {}
                (v, r) => panic!("{}: {v} got {r:?}", case["resultHex"].as_str().unwrap()),
            }
        }
    }

    #[test]
    fn magic_suffix_detection() {
        let mut sig = [0u8; 65].to_vec();
        assert!(!has_magic_suffix(&sig));
        sig.extend_from_slice(&super::MAGIC);
        assert!(has_magic_suffix(&sig));
        assert!(!has_magic_suffix(&super::MAGIC[..31]));
    }
}
