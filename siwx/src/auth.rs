//! End-to-end authentication: parse → validate → chain-name bind → verify.

use crate::message::MAX_MESSAGE_BYTES;
use crate::validate::AuthOpts;
use crate::verifier::Verifier;
use crate::{SiwxError, SiwxMessage};

/// Successful authentication result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    /// Parsed and verified CAIP-122 message.
    pub message: SiwxMessage,
}

/// Parse `raw_message`, validate fields, bind preamble chain name, then verify
/// `signature` over the original `raw_message` bytes.
///
/// This is the recommended entry point for backend login flows.
///
/// Steps:
/// 1. Reject oversize input ([`MAX_MESSAGE_BYTES`]).
/// 2. Parse `raw_message` into [`SiwxMessage`].
/// 3. [`SiwxMessage::validate`] with `opts` (domain, nonce, optional chain id).
/// 4. Require [`SiwxMessage::chain_name`] == [`Verifier::CHAIN_NAME`].
/// 5. [`Verifier::validate_address`] for chain-specific address shape.
/// 6. [`Verifier::verify`] over the original `raw_message` bytes.
///
/// # Errors
///
/// Returns parse, validation, chain-name, address, or verification errors.
pub async fn authenticate<V: Verifier>(
    verifier: &V,
    raw_message: &str,
    signature: &[u8],
    opts: &AuthOpts,
) -> Result<Authenticated, SiwxError> {
    if raw_message.len() > MAX_MESSAGE_BYTES {
        return Err(SiwxError::InvalidFormat(format!(
            "message exceeds maximum size of {MAX_MESSAGE_BYTES} bytes"
        )));
    }

    let message: SiwxMessage = raw_message.parse()?;
    message.validate(opts)?;
    if message.chain_name() != Some(V::CHAIN_NAME) {
        return Err(SiwxError::ChainNameMismatch {
            expected: V::CHAIN_NAME.to_owned(),
            actual: message.chain_name().map(str::to_owned),
        });
    }
    V::validate_address(&message.address)?;

    verifier.verify(&message, raw_message, signature).await?;

    Ok(Authenticated { message })
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use time::format_description::well_known::Rfc3339;
    use time::macros::datetime;

    use super::*;
    use crate::SiwxError;

    struct AcceptingVerifier;

    impl Verifier for AcceptingVerifier {
        const CHAIN_NAME: &'static str = "Ethereum";

        fn verify(
            &self,
            _message: &SiwxMessage,
            _raw_message: &str,
            _signature: &[u8],
        ) -> impl Future<Output = Result<(), SiwxError>> + Send {
            std::future::ready(Ok(()))
        }
    }

    #[derive(Default)]
    struct CountingVerifier {
        verify_calls: AtomicUsize,
    }

    impl Verifier for CountingVerifier {
        const CHAIN_NAME: &'static str = "Ethereum";

        fn verify(
            &self,
            _message: &SiwxMessage,
            _raw_message: &str,
            _signature: &[u8],
        ) -> impl Future<Output = Result<(), SiwxError>> + Send {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(()))
        }
    }

    fn sample_msg() -> SiwxMessage {
        SiwxMessage::new(
            "example.com",
            "addr1",
            "https://example.com",
            "1",
            "testnonce12345678",
        )
        .expect("valid")
        .with_issued_at(datetime!(2024-01-01 0:00 UTC))
        .expect("issued_at")
    }

    #[tokio::test]
    async fn authenticate_accepts_self_generated_message() {
        let msg = sample_msg();
        let raw = AcceptingVerifier::format_message(&msg);
        let opts = AuthOpts::new(&msg.domain, &msg.nonce);
        let auth = authenticate(&AcceptingVerifier, &raw, &[], &opts)
            .await
            .expect("should authenticate");
        assert_eq!(auth.message.domain, "example.com");
        assert_eq!(auth.message.chain_name(), Some("Ethereum"));
    }

    #[tokio::test]
    async fn authenticate_rejects_trailing_newline() {
        let msg = sample_msg();
        let mut raw = AcceptingVerifier::format_message(&msg);
        raw.push('\n');
        let opts = AuthOpts::new(&msg.domain, &msg.nonce);
        let err = authenticate(&AcceptingVerifier, &raw, &[], &opts)
            .await
            .expect_err("trailing newline must fail parse");
        assert!(matches!(err, SiwxError::InvalidFormat(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn authenticate_rejects_domain_mismatch() {
        let msg = sample_msg();
        let raw = AcceptingVerifier::format_message(&msg);
        let opts = AuthOpts::new("other.com", &msg.nonce);
        let err = authenticate(&AcceptingVerifier, &raw, &[], &opts)
            .await
            .expect_err("domain binding");
        assert!(matches!(err, SiwxError::InvalidDomain(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn authenticate_rejects_oversize_message() {
        let padding = "x".repeat(MAX_MESSAGE_BYTES + 1);
        let err = authenticate(
            &AcceptingVerifier,
            &padding,
            &[],
            &AuthOpts::new("d.com", "n12345678"),
        )
        .await
        .expect_err("oversize");
        assert!(matches!(err, SiwxError::InvalidFormat(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn authenticate_rejects_solana_preamble_for_ethereum_verifier() {
        let msg = sample_msg();
        let raw = msg.to_sign_string("Solana");
        let opts = AuthOpts::new(&msg.domain, &msg.nonce);
        let verifier = CountingVerifier::default();
        let err = authenticate(&verifier, &raw, &[], &opts)
            .await
            .expect_err("chain name mismatch");
        assert!(
            matches!(
                err,
                SiwxError::ChainNameMismatch {
                    ref expected,
                    actual: Some(ref actual),
                } if expected == "Ethereum" && actual == "Solana"
            ),
            "got {err:?}"
        );
        assert_eq!(
            verifier.verify_calls.load(Ordering::SeqCst),
            0,
            "verify must not run on chain name mismatch"
        );
    }

    #[tokio::test]
    async fn authenticate_rejects_missing_preamble_chain_name() {
        let msg = sample_msg();
        let raw = msg.to_sign_string("");
        let opts = AuthOpts::new(&msg.domain, &msg.nonce);
        let verifier = CountingVerifier::default();
        let err = authenticate(&verifier, &raw, &[], &opts)
            .await
            .expect_err("missing chain name");
        assert!(
            matches!(
                err,
                SiwxError::ChainNameMismatch {
                    ref expected,
                    actual: None,
                } if expected == "Ethereum"
            ),
            "got {err:?}"
        );
        assert_eq!(
            verifier.verify_calls.load(Ordering::SeqCst),
            0,
            "verify must not run on missing chain name"
        );
    }

    #[test]
    fn parsed_to_sign_string_equals_self_generated_raw() {
        let msg = sample_msg();
        let raw = msg.to_sign_string("Ethereum");
        let parsed: SiwxMessage = raw.parse().expect("parse");
        assert_eq!(
            parsed.to_sign_string("Ethereum"),
            raw,
            "self-generated signing string must round-trip"
        );
        assert_eq!(parsed.chain_name(), Some("Ethereum"));
        assert!(
            msg.chain_name().is_none(),
            "builder leaves chain_name unset"
        );
    }

    #[tokio::test]
    async fn authenticate_accepts_timestamp_original_not_rfc3339_reformat() {
        let raw_ts = "2024-01-01T00:00:00.000Z";
        let msg = sample_msg().with_issued_at_raw(raw_ts).expect("issued_at");
        let raw = AcceptingVerifier::format_message(&msg);
        let reformatted = msg.issued_at.datetime().format(&Rfc3339).expect("rfc3339");
        assert_ne!(
            reformatted, raw_ts,
            "Rfc3339 reformat must differ from the .000Z original"
        );
        assert!(
            raw.contains(raw_ts),
            "raw must keep subsecond original, got {raw}"
        );

        let verifier = CountingVerifier::default();
        let opts = AuthOpts::new(&msg.domain, &msg.nonce);
        authenticate(&verifier, &raw, &[], &opts)
            .await
            .expect("original timestamp form must reach verify");
        assert_eq!(
            verifier.verify_calls.load(Ordering::SeqCst),
            1,
            "verify must run; authenticate must not reject format != raw"
        );
    }
}
