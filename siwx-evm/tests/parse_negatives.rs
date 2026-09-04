//! EVM-only official parse negatives.
//!
//! Core `FromStr` is chain-agnostic and must accept `0x`+40 hex that is not
//! EIP-55. `EvmVerifier::validate_address` / `authenticate` reject it.
//! Non-decimal `chain-id` is accepted by parse and rejected by
//! `EvmVerifier::validate_chain_id`.

#![allow(
    unused_crate_dependencies,
    reason = "integration test crate links lib deps it does not use"
)]

#[cfg(test)]
mod tests {
    use siwx::{AuthOpts, ChainIdReason, SiwxError, SiwxMessage, Verifier, authenticate};
    use siwx_evm::{EvmVerifier, validate_address};
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    /// Official spruceid/siwe `parsing_negative.json` `"address not EIP-55"`.
    const ADDRESS_NOT_EIP55: &str = "\
service.org wants you to sign in with your Ethereum account:
0xe5a12547fe4e872d192e3ececb76f2ce1aea4946

I accept the ServiceOrg Terms of Service: https://service.org/tos

URI: https://service.org/login
Version: 1
Chain ID: 1
Nonce: 12341234
Issued At: 2022-03-17T12:45:13.610Z
Expiration Time: 2023-03-17T12:45:13.610Z
Not Before: 2022-03-17T12:45:13.610Z
Request ID: some_id
Resources:
- https://service.org/login";

    /// Official spruceid/siwe `parsing_negative.json` `"not a valid chainId"`.
    const CHAIN_ID_NOT_DECIMAL: &str = "\
service.org wants you to sign in with your Ethereum account:
0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946

I accept the ServiceOrg Terms of Service: https://service.org/tos

URI: https://service.org/login
Version: 1
Chain ID: ?
Nonce: 12341234
Issued At: 2022-03-17T12:45:13.610Z
Expiration Time: 2023-03-17T12:45:13.610Z
Not Before: 2022-03-17T12:45:13.610Z
Request ID: some_id
Resources:
- https://service.org/login";

    fn injected_opts() -> AuthOpts {
        let now = OffsetDateTime::parse("2022-03-17T12:45:13.610Z", &Rfc3339).unwrap();
        AuthOpts::new("service.org", "12341234")
            .with_clock_skew(time::Duration::ZERO)
            .with_timestamp(now)
    }

    #[test]
    fn core_parse_accepts_non_checksum_address() {
        let parsed: SiwxMessage = ADDRESS_NOT_EIP55.parse().unwrap();
        assert_eq!(parsed.address, "0xe5a12547fe4e872d192e3ececb76f2ce1aea4946");
    }

    #[test]
    fn validate_address_rejects_non_eip55() {
        let err = validate_address("0xe5a12547fe4e872d192e3ececb76f2ce1aea4946").unwrap_err();
        assert!(
            matches!(err, SiwxError::InvalidAddress { .. }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn authenticate_rejects_address_not_eip55() {
        let err = authenticate(
            &EvmVerifier::new(),
            ADDRESS_NOT_EIP55,
            &[],
            &injected_opts(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, SiwxError::InvalidAddress { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn core_parse_accepts_non_decimal_chain_id() {
        let parsed: SiwxMessage = CHAIN_ID_NOT_DECIMAL.parse().unwrap();
        assert_eq!(parsed.chain_id, "?");
    }

    #[test]
    fn validate_chain_id_rejects_non_decimal() {
        let err = EvmVerifier::validate_chain_id("?").unwrap_err();
        assert!(
            matches!(
                err,
                SiwxError::InvalidChainId {
                    reason: ChainIdReason::NotDecimal
                }
            ),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn authenticate_rejects_non_decimal_chain_id() {
        let err = authenticate(
            &EvmVerifier::new(),
            CHAIN_ID_NOT_DECIMAL,
            &[],
            &injected_opts(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                SiwxError::InvalidChainId {
                    reason: ChainIdReason::NotDecimal
                }
            ),
            "got {err:?}"
        );
    }
}
