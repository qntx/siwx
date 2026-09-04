//! End-to-end authentication: size → CR → parse → validate → `chain_name` → address → `chain_id` → verify original bytes.

use crate::message::MAX_MESSAGE_BYTES;
use crate::validate::AuthOpts;
use crate::verifier::Verifier;
use crate::{SiwxError, SiwxMessage};

/// Successful authentication result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    message: SiwxMessage,
}

impl Authenticated {
    /// Parsed and verified CAIP-122 message.
    #[must_use]
    pub const fn message(&self) -> &SiwxMessage {
        &self.message
    }

    /// Signer address from the verified message.
    #[must_use]
    pub fn address(&self) -> &str {
        self.message.address()
    }

    /// CAIP-10 account id `{namespace}:{chain_id}:{address}`.
    ///
    /// Pass the CAIP-2 namespace explicitly (e.g. `"eip155"`, `"solana"`).
    /// See [`SiwxMessage::caip10`] for charset rules and the CAIP-2
    /// `{1,32}` reference-length mismatch with Solana genesis hashes.
    ///
    /// # Errors
    ///
    /// Returns an error if `namespace` or `address` fail CAIP-10 charset
    /// checks.
    pub fn caip10(&self, namespace: &str) -> Result<String, SiwxError> {
        self.message.caip10(namespace)
    }
}

/// Parse `raw_message`, validate fields, bind preamble chain name, then verify
/// `signature` over the original `raw_message` bytes.
///
/// This is the recommended entry point for backend login flows.
/// There is no canonical re-serialize check: the wallet-signed bytes are
/// verified as-is. [`AuthOpts::new`] requires `domain` and `nonce`. Default
/// clock skew is 60 seconds (expiration / not-before / max issued-at age).
///
/// Steps (fail-fast):
/// 1. Reject oversize input ([`MAX_MESSAGE_BYTES`]).
/// 2. Reject CR (`InvalidFormat { CrLf }`) during parse.
/// 3. Parse `raw_message` into [`SiwxMessage`] (ABNF; trailing LF rejected).
/// 4. [`SiwxMessage::validate`] with `opts` (domain, nonce, optional scheme /
///    uri / chain id / request id, temporal window).
/// 5. Require [`SiwxMessage::chain_name`] == [`Verifier::CHAIN_NAME`].
/// 6. [`Verifier::validate_address`] for chain-specific address shape.
/// 7. [`Verifier::validate_chain_id`] for namespace chain-id shape.
/// 8. [`Verifier::verify`] over the original `raw_message` bytes.
///
/// Relying parties that must accept a leftover LF from `join("\n")` clients
/// should `trim_end_matches('\n')` before calling this function. The library
/// does not trim.
///
/// # Errors
///
/// Returns parse, validation, chain-name, address, chain-id, or verification
/// errors.
pub async fn authenticate<V: Verifier>(
    verifier: &V,
    raw_message: &str,
    signature: &[u8],
    opts: &AuthOpts,
) -> Result<Authenticated, SiwxError> {
    if raw_message.len() > MAX_MESSAGE_BYTES {
        return Err(SiwxError::MessageTooLarge {
            len: raw_message.len(),
            max: MAX_MESSAGE_BYTES,
        });
    }

    let message: SiwxMessage = raw_message.parse()?;
    message.validate(opts)?;
    if message.chain_name() != Some(V::CHAIN_NAME) {
        return Err(SiwxError::ChainNameMismatch {
            expected: V::CHAIN_NAME.to_owned(),
            actual: message.chain_name().map(str::to_owned),
        });
    }
    V::validate_address(message.address())?;
    V::validate_chain_id(message.chain_id())?;

    verifier.verify(&message, raw_message, signature).await?;

    Ok(Authenticated { message })
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use time::macros::datetime;

    use super::*;
    use crate::{ChainIdReason, FormatReason, SiwxError};

    struct AcceptingVerifier;

    impl Verifier for AcceptingVerifier {
        const CHAIN_NAME: &'static str = "Ethereum";
        const NAMESPACE: &'static str = "eip155";

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
    struct RecordingVerifier {
        verify_calls: AtomicUsize,
        last_raw: Mutex<Option<String>>,
    }

    impl Verifier for RecordingVerifier {
        const CHAIN_NAME: &'static str = "Ethereum";
        const NAMESPACE: &'static str = "eip155";

        fn verify(
            &self,
            _message: &SiwxMessage,
            raw_message: &str,
            _signature: &[u8],
        ) -> impl Future<Output = Result<(), SiwxError>> + Send {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
            *self.last_raw.lock().expect("last_raw mutex") = Some(raw_message.to_owned());
            std::future::ready(Ok(()))
        }
    }

    struct RejectingChainId {
        verify_calls: AtomicUsize,
    }

    impl Verifier for RejectingChainId {
        const CHAIN_NAME: &'static str = "Ethereum";
        const NAMESPACE: &'static str = "eip155";

        fn validate_chain_id(_chain_id: &str) -> Result<(), SiwxError> {
            Err(SiwxError::InvalidChainId {
                reason: ChainIdReason::NotDecimal,
            })
        }

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
        let opts = AuthOpts::new(msg.domain(), msg.nonce());
        let auth = authenticate(&AcceptingVerifier, &raw, &[], &opts)
            .await
            .expect("should authenticate");
        assert_eq!(auth.message().domain(), "example.com");
        assert_eq!(auth.address(), "addr1");
        assert_eq!(auth.message().chain_name(), Some("Ethereum"));
        assert_eq!(auth.caip10("eip155").expect("caip10"), "eip155:1:addr1");
    }

    #[tokio::test]
    async fn authenticate_rejects_trailing_newline() {
        let msg = sample_msg();
        let mut raw = AcceptingVerifier::format_message(&msg);
        raw.push('\n');
        let opts = AuthOpts::new(msg.domain(), msg.nonce());
        let err = authenticate(&AcceptingVerifier, &raw, &[], &opts)
            .await
            .expect_err("trailing newline must fail parse");
        assert!(
            matches!(
                err,
                SiwxError::InvalidFormat {
                    reason: FormatReason::UnexpectedTrailing
                }
            ),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn authenticate_rejects_domain_mismatch() {
        let msg = sample_msg();
        let raw = AcceptingVerifier::format_message(&msg);
        let opts = AuthOpts::new("other.com", msg.nonce());
        let err = authenticate(&AcceptingVerifier, &raw, &[], &opts)
            .await
            .expect_err("domain binding");
        assert!(
            matches!(err, SiwxError::DomainMismatch { .. }),
            "got {err:?}"
        );
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
        assert!(
            matches!(
                err,
                SiwxError::MessageTooLarge {
                    len,
                    max: MAX_MESSAGE_BYTES,
                } if len == MAX_MESSAGE_BYTES + 1
            ),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn authenticate_rejects_solana_preamble_for_ethereum_verifier() {
        let msg = sample_msg();
        let raw = msg.to_sign_string("Solana");
        let opts = AuthOpts::new(msg.domain(), msg.nonce());
        let verifier = RecordingVerifier::default();
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
        let opts = AuthOpts::new(msg.domain(), msg.nonce());
        let verifier = RecordingVerifier::default();
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
    fn default_validate_chain_id_rejects_empty() {
        let err = AcceptingVerifier::validate_chain_id("").expect_err("empty");
        assert!(
            matches!(
                err,
                SiwxError::InvalidChainId {
                    reason: ChainIdReason::Empty
                }
            ),
            "got {err:?}"
        );
        AcceptingVerifier::validate_chain_id("1").expect("non-empty default ok");
    }

    #[tokio::test]
    async fn authenticate_rejects_invalid_chain_id_before_verify() {
        let msg = sample_msg();
        let raw = msg.to_sign_string("Ethereum");
        let opts = AuthOpts::new(msg.domain(), msg.nonce());
        let verifier = RejectingChainId {
            verify_calls: AtomicUsize::new(0),
        };
        let err = authenticate(&verifier, &raw, &[], &opts)
            .await
            .expect_err("chain id rejected");
        assert!(
            matches!(
                err,
                SiwxError::InvalidChainId {
                    reason: ChainIdReason::NotDecimal
                }
            ),
            "got {err:?}"
        );
        assert_eq!(
            verifier.verify_calls.load(Ordering::SeqCst),
            0,
            "verify must not run on invalid chain id"
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
    async fn authenticate_verifies_original_bytes_not_reformatted() {
        let msg = sample_msg();
        let mut raw = msg.to_sign_string("Ethereum");
        raw.push_str("\nResources:");

        let parsed: SiwxMessage = raw.parse().expect("empty Resources: footer parses");
        let reformatted = RecordingVerifier::format_message(&parsed);
        assert_ne!(reformatted, raw, "formatter omits empty Resources: footer");
        assert!(
            parsed.resources().is_empty(),
            "empty Resources: must parse as no resources, got {:?}",
            parsed.resources()
        );

        let verifier = RecordingVerifier::default();
        let opts = AuthOpts::new(msg.domain(), msg.nonce());
        authenticate(&verifier, &raw, &[], &opts)
            .await
            .expect("original bytes must authenticate when format differs");
        assert_eq!(
            verifier.verify_calls.load(Ordering::SeqCst),
            1,
            "verify must run"
        );
        let captured = verifier.last_raw.lock().expect("last_raw mutex");
        assert_eq!(
            captured.as_deref(),
            Some(raw.as_str()),
            "verify must receive the original raw_message"
        );
        assert_ne!(
            captured.as_deref(),
            Some(reformatted.as_str()),
            "verify must not receive the reformatted message"
        );
    }
}
