//! EIP-191 `personal_sign` verification (internal).

use alloy::primitives::{Signature, eip191_hash_message};
use siwx::{SiwxError, SiwxMessage};

use crate::parse_address;

/// Synchronous EIP-191 verification used by [`crate::EvmVerifier`].
pub(crate) fn verify_sync(
    message: &SiwxMessage,
    raw_message: &str,
    signature: &[u8],
) -> Result<(), SiwxError> {
    if signature.len() != 65 {
        return Err(SiwxError::InvalidSignature(format!(
            "EIP-191 signature must be 65 bytes, got {}",
            signature.len()
        )));
    }

    let alloy_sig = Signature::try_from(signature)
        .map_err(|e| SiwxError::InvalidSignature(format!("bad signature encoding: {e}")))?;

    let hash = eip191_hash_message(raw_message.as_bytes());

    let recovered = alloy_sig
        .recover_address_from_prehash(&hash)
        .map_err(|e| SiwxError::VerificationFailed(format!("ECDSA recovery failed: {e}")))?;

    let expected = parse_address(&message.address)?;

    if recovered != expected {
        return Err(SiwxError::VerificationFailed(format!(
            "recovered {recovered} != expected {expected}"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy::signers::{Signer, local::PrivateKeySigner};
    use siwx::{AuthOpts, SiwxError, SiwxMessage, Verifier, authenticate};
    use time::macros::datetime;

    use crate::EvmVerifier;

    /// Well-known Anvil/Hardhat account #0 private key (public test fixture only).
    const FIXTURE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    const FIXTURE_DOMAIN: &str = "login.example.com";
    const FIXTURE_NONCE: &str = "fixtureNonce12345";
    const FIXTURE_CHAIN: &str = "1";
    const FIXTURE_URI: &str = "https://login.example.com/siwx";

    fn sample_message(addr: &str) -> SiwxMessage {
        SiwxMessage::new(
            "example.com",
            addr,
            "https://example.com/login",
            "1",
            "testnonce12345678",
        )
        .expect("valid message")
        .with_issued_at(datetime!(2024-01-01 0:00 UTC))
    }

    fn fixture_signer() -> PrivateKeySigner {
        FIXTURE_KEY.parse().expect("valid fixture key")
    }

    /// End-to-end EOA fixture: build → format → sign → `authenticate` with bound opts.
    #[tokio::test]
    async fn authenticate_eoa_fixture_end_to_end() {
        let signer = fixture_signer();
        let addr = format!("{:?}", signer.address());

        let message = SiwxMessage::new(
            FIXTURE_DOMAIN,
            &addr,
            FIXTURE_URI,
            FIXTURE_CHAIN,
            FIXTURE_NONCE,
        )
        .expect("valid message")
        .with_statement("Sign in to Example")
        .expect("statement")
        .with_issued_at(datetime!(2024-06-01 12:00 UTC));

        let raw = EvmVerifier::format_message(&message);
        assert!(
            raw.starts_with("login.example.com wants you to sign in with your Ethereum account:"),
            "fixture uses shipped formatter"
        );

        let sig = signer
            .sign_message(raw.as_bytes())
            .await
            .expect("signing over canonical raw");
        let sig_bytes = sig.as_bytes();

        let opts = AuthOpts::new(FIXTURE_DOMAIN, FIXTURE_NONCE)
            .with_chain_id(FIXTURE_CHAIN)
            .with_timestamp(datetime!(2024-06-01 12:00 UTC));

        let auth = authenticate(&EvmVerifier::new(), &raw, &sig_bytes, &opts)
            .await
            .expect("authenticate must succeed on real EOA fixture");

        assert_eq!(auth.message.domain, FIXTURE_DOMAIN);
        assert_eq!(auth.message.nonce, FIXTURE_NONCE);
        assert_eq!(auth.message.chain_id, FIXTURE_CHAIN);
        assert_eq!(auth.message.address, addr);
    }

    #[tokio::test]
    async fn authenticate_eoa_rejects_wrong_bound_nonce() {
        let signer = fixture_signer();
        let addr = format!("{:?}", signer.address());
        let message = SiwxMessage::new(
            FIXTURE_DOMAIN,
            &addr,
            FIXTURE_URI,
            FIXTURE_CHAIN,
            FIXTURE_NONCE,
        )
        .expect("valid")
        .with_issued_at(datetime!(2024-06-01 12:00 UTC));
        let raw = EvmVerifier::format_message(&message);
        let sig = signer.sign_message(raw.as_bytes()).await.expect("sign");

        let opts = AuthOpts::new(FIXTURE_DOMAIN, "wrongNonce99999")
            .with_chain_id(FIXTURE_CHAIN)
            .with_timestamp(datetime!(2024-06-01 12:00 UTC));

        let err = authenticate(&EvmVerifier::new(), &raw, &sig.as_bytes(), &opts)
            .await
            .expect_err("nonce binding must fail");
        assert!(matches!(err, SiwxError::InvalidNonce(_)));
    }

    #[tokio::test]
    async fn eip191_roundtrip() {
        let signer: PrivateKeySigner =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse()
                .expect("valid key");
        let addr = format!("{:?}", signer.address());

        let message = sample_message(&addr);
        let text = EvmVerifier::format_message(&message);
        let sig = signer.sign_message(text.as_bytes()).await.expect("signing");
        let sig_bytes = sig.as_bytes();

        EvmVerifier::new()
            .verify(&message, &text, &sig_bytes)
            .await
            .expect("verification should succeed");
    }

    #[tokio::test]
    async fn eip191_wrong_address() {
        let signer: PrivateKeySigner =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse()
                .expect("valid key");

        let message = sample_message("0x0000000000000000000000000000000000000001");
        let text = EvmVerifier::format_message(&message);
        let sig = signer.sign_message(text.as_bytes()).await.expect("signing");
        let sig_bytes = sig.as_bytes();

        let err = EvmVerifier::new()
            .verify(&message, &text, &sig_bytes)
            .await
            .unwrap_err();
        assert!(matches!(err, SiwxError::VerificationFailed(_)));
    }

    #[tokio::test]
    async fn eip191_bad_signature_length() {
        let message = sample_message("0x0000000000000000000000000000000000000001");
        let text = EvmVerifier::format_message(&message);
        let err = EvmVerifier::new()
            .verify(&message, &text, &[0u8; 32])
            .await
            .unwrap_err();
        assert!(matches!(err, SiwxError::InvalidSignature(_)));
    }

    #[tokio::test]
    async fn eip191_rejects_signature_over_different_bytes() {
        let signer: PrivateKeySigner =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse()
                .expect("valid key");
        let addr = format!("{:?}", signer.address());

        let message = sample_message(&addr);
        let text = EvmVerifier::format_message(&message);
        let sig = signer.sign_message(text.as_bytes()).await.expect("signing");

        let mut tampered = text.clone();
        tampered.push(' ');
        let err = EvmVerifier::new()
            .verify(&message, &tampered, &sig.as_bytes())
            .await
            .unwrap_err();
        assert!(matches!(err, SiwxError::VerificationFailed(_)));
    }
}
