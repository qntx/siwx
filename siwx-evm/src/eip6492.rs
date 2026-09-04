//! ERC-6492 counterfactual signature verification.
//!
//! The 32-byte magic suffix is detected unconditionally. RPC verification is
//! compiled only with feature `eip6492`.

use siwx::SiwxError;

/// ERC-6492 detection suffix: `0x6492` repeated 16 times.
pub(crate) const MAGIC: [u8; 32] = [
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
];

/// `InvalidSignature` when the crate is built without `eip6492`.
#[cfg(not(feature = "eip6492"))]
pub(crate) fn not_enabled() -> SiwxError {
    SiwxError::InvalidSignature {
        reason: "EIP-6492 not enabled".into(),
    }
}

/// `InvalidSignature` when the message chain has no RPC endpoint.
#[cfg(feature = "eip6492")]
pub(crate) fn requires_rpc() -> SiwxError {
    SiwxError::InvalidSignature {
        reason: "EIP-6492 requires RPC".into(),
    }
}

/// True when `signature` ends with [`MAGIC`].
#[must_use]
pub(crate) fn has_magic_suffix(signature: &[u8]) -> bool {
    signature.len() >= MAGIC.len() && signature.ends_with(&MAGIC)
}

#[cfg(feature = "eip6492")]
mod rpc {
    use std::time::Duration;

    use alloy::network::{Ethereum, Network, TransactionBuilder};
    use alloy::primitives::{Address, B256, Bytes, eip191_hash_message};
    use alloy::providers::{DynProvider, Provider};
    use alloy::sol;
    use alloy::sol_types::SolConstructor;
    use siwx::{SiwxError, SiwxMessage};

    use super::eth_call_bool;
    use crate::eip1271;
    use crate::parse_eip55;

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

    pub(crate) async fn verify(
        provider: &DynProvider,
        timeout: Duration,
        message: &SiwxMessage,
        raw_message: &str,
        signature: &[u8],
    ) -> Result<(), SiwxError> {
        let signer = parse_eip55(&message.address)?;
        let rpc_chain = eip1271::timed(
            timeout,
            async { provider.get_chain_id().await },
            "eth_chainId",
        )
        .await?;
        eip1271::assert_rpc_chain_id(&message.chain_id, rpc_chain)?;

        let hash = eip191_hash_message(raw_message.as_bytes());
        let data = deployless_calldata(signer, hash, signature);
        let tx = <Ethereum as Network>::TransactionRequest::default().with_input(data);

        let result = eip1271::timed(timeout, async { provider.call(tx).await }, "eth_call").await?;
        if eth_call_bool(result.as_ref())? {
            Ok(())
        } else {
            Err(SiwxError::VerificationFailed {
                reason: "EIP-6492 invalid".into(),
            })
        }
    }

    #[cfg(test)]
    mod rpc_unit_tests {
        use alloy::primitives::{Address, B256};

        use super::{BYTECODE, BYTECODE_LEN, deployless_calldata};

        #[test]
        fn vendored_bytecode_is_solc_initcode() {
            assert_eq!(BYTECODE.len(), BYTECODE_LEN, "bytecode length");
            assert!(
                BYTECODE.starts_with(&[0x60, 0x80]),
                "solc initcode prefix 0x6080"
            );
        }

        #[test]
        fn deployless_calldata_is_bytecode_then_args() {
            let data = deployless_calldata(Address::ZERO, B256::ZERO, &[0u8; 65]);
            assert!(
                data.starts_with(&BYTECODE),
                "calldata must start with ox bytecode"
            );
            assert!(
                data.len() > BYTECODE.len(),
                "constructor args must be appended"
            );
        }
    }
}

#[cfg(feature = "eip6492")]
pub(crate) use rpc::verify;

/// Interpret a deployless validator `eth_call` result as a bool.
///
/// Nodes pad `return(31, 1)` to 32 bytes. Accept any length whose last byte is
/// `0x00`/`0x01` and whose prefix is all zeros.
#[cfg(any(test, feature = "eip6492"))]
pub(crate) fn eth_call_bool(data: &[u8]) -> Result<bool, SiwxError> {
    let Some((last, rest)) = data.split_last() else {
        return Err(SiwxError::VerificationFailed {
            reason: "empty eth_call result".into(),
        });
    };
    if rest.iter().any(|&b| b != 0) {
        return Err(SiwxError::VerificationFailed {
            reason: "malformed 6492 eth_call result".into(),
        });
    }
    match last {
        1 => Ok(true),
        0 => Ok(false),
        _ => Err(SiwxError::VerificationFailed {
            reason: "malformed 6492 eth_call result".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use siwx::{SiwxError, SiwxMessage, Verifier};
    use time::macros::datetime;

    use super::{MAGIC, eth_call_bool, has_magic_suffix};
    use crate::EvmVerifier;

    fn sample_message() -> SiwxMessage {
        SiwxMessage::new(
            "example.com",
            "0x0000000000000000000000000000000000000001",
            "https://example.com",
            "1",
            "testnonce12345678",
        )
        .expect("valid")
        .with_issued_at(datetime!(2024-01-01 0:00 UTC))
        .expect("issued_at")
    }

    fn magic_signature() -> Vec<u8> {
        let mut sig = vec![0u8; 65];
        sig.extend_from_slice(&MAGIC);
        sig
    }

    #[test]
    fn magic_is_6492_repeated_sixteen_times() {
        assert_eq!(MAGIC.as_slice(), [0x64, 0x92].repeat(16));
    }

    #[test]
    fn has_magic_suffix_detects_exact_and_wrapped() {
        assert!(has_magic_suffix(&MAGIC));
        assert!(has_magic_suffix(&magic_signature()));
        assert!(!has_magic_suffix(&[0u8; 65]));
        assert!(!has_magic_suffix(&[]));
        let short = MAGIC
            .split_last()
            .map(|(_, rest)| rest)
            .expect("32-byte magic");
        assert!(!has_magic_suffix(short));
    }

    #[test]
    fn eth_call_bool_accepts_padded_and_short() {
        assert!(eth_call_bool(&[1]).expect("1"));
        assert!(!eth_call_bool(&[0]).expect("0"));
        let mut padded_true = [0u8; 32];
        *padded_true.last_mut().expect("32") = 1;
        assert!(eth_call_bool(&padded_true).expect("pad 1"));
        assert!(!eth_call_bool(&[0u8; 32]).expect("pad 0"));
    }

    #[test]
    fn eth_call_bool_rejects_empty_and_malformed() {
        assert!(matches!(
            eth_call_bool(&[]),
            Err(SiwxError::VerificationFailed { ref reason }) if reason == "empty eth_call result"
        ));
        assert!(matches!(
            eth_call_bool(&[2]),
            Err(SiwxError::VerificationFailed { ref reason }) if reason == "malformed 6492 eth_call result"
        ));
        assert!(matches!(
            eth_call_bool(&[1, 0]),
            Err(SiwxError::VerificationFailed { ref reason }) if reason == "malformed 6492 eth_call result"
        ));
        let mut bad = [0u8; 32];
        if let Some(first) = bad.first_mut() {
            *first = 1;
        }
        if let Some(last) = bad.last_mut() {
            *last = 1;
        }
        assert!(matches!(
            eth_call_bool(&bad),
            Err(SiwxError::VerificationFailed { ref reason }) if reason == "malformed 6492 eth_call result"
        ));
    }

    #[cfg(not(feature = "eip6492"))]
    #[tokio::test]
    async fn magic_suffix_without_feature_is_not_enabled() {
        let message = sample_message();
        let text = EvmVerifier::format_message(&message);
        let err = EvmVerifier::new()
            .verify(&message, &text, &magic_signature())
            .await
            .expect_err("6492 without feature");
        assert!(
            matches!(
                err,
                SiwxError::InvalidSignature { ref reason } if reason == "EIP-6492 not enabled"
            ),
            "got {err:?}"
        );
        assert!(
            !err.to_string().contains("65 bytes"),
            "must not fall through to EIP-191, got: {err}"
        );
    }

    #[cfg(feature = "eip6492")]
    #[tokio::test]
    async fn magic_suffix_with_new_requires_rpc() {
        let message = sample_message();
        let text = EvmVerifier::format_message(&message);
        let err = EvmVerifier::new()
            .verify(&message, &text, &magic_signature())
            .await
            .expect_err("6492 with new()");
        assert!(
            matches!(
                err,
                SiwxError::InvalidSignature { ref reason } if reason == "EIP-6492 requires RPC"
            ),
            "got {err:?}"
        );
        assert!(
            !err.to_string().contains("65 bytes"),
            "must not fall through to EIP-191, got: {err}"
        );
    }

    #[cfg(feature = "eip6492")]
    #[tokio::test]
    async fn magic_suffix_missing_chain_rpc_requires_rpc() {
        let message = sample_message();
        let text = EvmVerifier::format_message(&message);
        let err = EvmVerifier::with_rpc_map([(137u64, "https://polygon.example.invalid")])
            .verify(&message, &text, &magic_signature())
            .await
            .expect_err("6492 without RPC for chain 1");
        assert!(
            matches!(
                err,
                SiwxError::InvalidSignature { ref reason } if reason == "EIP-6492 requires RPC"
            ),
            "got {err:?}"
        );
    }

    #[cfg(feature = "eip6492")]
    #[tokio::test]
    async fn magic_suffix_rpc_connect_fail_hides_url() {
        let message = sample_message();
        let text = EvmVerifier::format_message(&message);
        let err = EvmVerifier::with_rpc_for_chain(1, "http://127.0.0.1:1")
            .verify(&message, &text, &magic_signature())
            .await
            .expect_err("connect fail");
        assert!(
            matches!(err, SiwxError::VerificationFailed { .. }),
            "got {err:?}"
        );
        assert!(
            !err.to_string().contains("http"),
            "error must not include RPC URL: {err}"
        );
        assert!(
            !err.to_string().contains("127.0.0.1"),
            "error must not include RPC host: {err}"
        );
    }
}
