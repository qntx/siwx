//! End-to-end authentication: parse → validate → canonical check → verify.

use crate::validate::AuthOpts;
use crate::verifier::Verifier;
use crate::{SiwxError, SiwxMessage};

/// Successful authentication result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    /// Parsed and verified CAIP-122 message.
    pub message: SiwxMessage,
}

/// Parse `raw_message`, validate fields, require canonical form, then verify
/// `signature` with `verifier`.
///
/// This is the recommended entry point for backend login flows.
///
/// Steps:
/// 1. Parse `raw_message` into [`SiwxMessage`].
/// 2. [`SiwxMessage::validate`] with `opts` (domain, nonce, optional chain id).
/// 3. Reject if `raw_message` is not bit-identical to
///    [`Verifier::format_message`] (also binds preamble chain name).
/// 4. [`Verifier::verify`] over the original `raw_message` bytes.
///
/// # Errors
///
/// Returns parse, validation, canonical-form, or verification errors.
pub async fn authenticate<V: Verifier>(
    verifier: &V,
    raw_message: &str,
    signature: &[u8],
    opts: &AuthOpts,
) -> Result<Authenticated, SiwxError> {
    let message: SiwxMessage = raw_message.parse()?;
    message.validate(opts)?;

    let canonical = V::format_message(&message);
    if canonical != raw_message {
        return Err(SiwxError::InvalidFormat(
            "message is not in canonical form".into(),
        ));
    }

    verifier
        .verify(&message, raw_message, signature)
        .await?;

    Ok(Authenticated { message })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SiwxError;
    use time::macros::datetime;

    struct AcceptingVerifier;

    impl Verifier for AcceptingVerifier {
        const CHAIN_NAME: &'static str = "Ethereum";

        async fn verify(
            &self,
            _message: &SiwxMessage,
            _raw_message: &str,
            _signature: &[u8],
        ) -> Result<(), SiwxError> {
            Ok(())
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
    }

    #[tokio::test]
    async fn authenticate_accepts_canonical_message() {
        let msg = sample_msg();
        let raw = AcceptingVerifier::format_message(&msg);
        let opts = AuthOpts::new(&msg.domain, &msg.nonce);
        let auth = authenticate(&AcceptingVerifier, &raw, &[], &opts)
            .await
            .expect("should authenticate");
        assert_eq!(auth.message.domain, "example.com");
    }

    #[tokio::test]
    async fn authenticate_rejects_non_canonical_raw() {
        let msg = sample_msg();
        let mut raw = AcceptingVerifier::format_message(&msg);
        raw.push('\n');
        let opts = AuthOpts::new(&msg.domain, &msg.nonce);
        let err = authenticate(&AcceptingVerifier, &raw, &[], &opts)
            .await
            .expect_err("trailing newline must fail canonical check");
        assert!(matches!(err, SiwxError::InvalidFormat(_)));
    }

    #[tokio::test]
    async fn authenticate_rejects_domain_mismatch() {
        let msg = sample_msg();
        let raw = AcceptingVerifier::format_message(&msg);
        let opts = AuthOpts::new("other.com", &msg.nonce);
        let err = authenticate(&AcceptingVerifier, &raw, &[], &opts)
            .await
            .expect_err("domain binding");
        assert!(matches!(err, SiwxError::InvalidDomain(_)));
    }
}
