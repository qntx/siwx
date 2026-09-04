//! # siwx-svm — Solana verification for Sign-In with X
//!
//! Implements the CAIP-122 namespace profile for Solana:
//! - **Ed25519** signature verification ([`ed25519_dalek::Verifier::verify`],
//!   not `verify_strict`)
//!
//! # Quick start
//!
//! ```rust,no_run
//! use siwx::{SiwxMessage, Verifier};
//! use siwx_svm::Ed25519Verifier;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let message = SiwxMessage::new(
//!     "example.com",
//!     "GwAF45zjfyGzUbd3i3hXxzGeuchzEZXwpRYHZM5912F1",
//!     "https://example.com/login",
//!     "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
//!     siwx::nonce::generate_default(),
//! )?;
//! let text = Ed25519Verifier::format_message(&message);
//! // let sig_bytes: [u8; 64] = ...; // Ed25519 signature from wallet
//! // Ed25519Verifier::new().verify(&message, &text, &sig_bytes).await?;
//! # Ok(())
//! # }
//! ```

mod ed25519;

pub use ed25519::Ed25519Verifier;
use siwx::{ChainIdReason, SiwxError};

/// Human-readable chain label embedded in the CAIP-122 preamble.
pub const CHAIN_NAME: &str = "Solana";

/// CAIP-2 namespace for Solana.
pub const NAMESPACE: &str = "solana";

/// Maximum `chain-id` length accepted by [`validate_chain_id`].
///
/// CAIP-2 `{1,32}` is too short for Solana genesis hashes (base58 of 32
/// bytes). 44 is the maximum base58 length of 32 bytes.
const MAX_CHAIN_ID_LEN: usize = 44;

/// Validate that `address` is a base58 Ed25519 verifying key.
///
/// Requires a successful 32-byte decode **and**
/// [`ed25519_dalek::VerifyingKey::from_bytes`]. Off-curve encodings (Solana
/// PDAs) fail `from_bytes`.
///
/// Among weak / small-order keys, **only** the 32-zero System Program identity
/// (`11111111111111111111111111111111`) is special-cased. Other torsion points
/// (including Edwards identity `[1, 0, ...]`) pass. Signature checks use RFC 8032
/// [`ed25519_dalek::Verifier::verify`], not
/// [`ed25519_dalek::VerifyingKey::verify_strict`].
///
/// # Errors
///
/// Returns [`SiwxError::InvalidAddress`] if the format is wrong.
pub fn validate_address(address: &str) -> Result<(), SiwxError> {
    ed25519::verifying_key_from_address(address).map(|_| ())
}

/// Validate a Solana `chain-id` (CAIP-2 *reference* only).
///
/// Charset is `[-_a-zA-Z0-9]`. Length is `1..=44`, **not** CAIP-2 `{1,32}`:
/// this product stores Solana genesis hashes such as
/// `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d` (~43 characters). Phantom
/// aliases like `"mainnet"` are charset-valid and are **not** rewritten to a
/// genesis hash.
///
/// # Errors
///
/// Returns [`SiwxError::InvalidChainId`] with [`ChainIdReason::Empty`] or
/// [`ChainIdReason::BadCharset`].
pub fn validate_chain_id(chain_id: &str) -> Result<(), SiwxError> {
    if chain_id.is_empty() {
        return Err(SiwxError::InvalidChainId {
            reason: ChainIdReason::Empty,
        });
    }
    let valid_charset = chain_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !valid_charset || chain_id.len() > MAX_CHAIN_ID_LEN {
        return Err(SiwxError::InvalidChainId {
            reason: ChainIdReason::BadCharset,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use siwx::{AuthOpts, ChainIdReason, SiwxError, SiwxMessage, Verifier, authenticate};

    use super::*;

    /// Solana mainnet genesis hash used as `chain-id` (not a Phantom alias).
    const MAINNET_GENESIS_HASH: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
    const ON_CURVE_ADDR: &str = "GwAF45zjfyGzUbd3i3hXxzGeuchzEZXwpRYHZM5912F1";

    #[test]
    fn validate_address_accepts_on_curve_pubkey() {
        assert!(
            validate_address(ON_CURVE_ADDR).is_ok(),
            "canonical on-curve address"
        );
    }

    #[test]
    fn validate_address_rejects_identity() {
        let identity = bs58::encode([0u8; 32]).into_string();
        assert_eq!(
            identity, "11111111111111111111111111111111",
            "Solana system-program encoding of 32 zero bytes"
        );
        let err = validate_address(&identity).expect_err("32-zero identity");
        assert!(
            matches!(err, SiwxError::InvalidAddress { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_address_rejects_off_curve() {
        let addr = bs58::encode([2u8; 32]).into_string();
        let err = validate_address(&addr).expect_err("off-curve PDA encoding");
        assert!(
            matches!(err, SiwxError::InvalidAddress { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_address_rejects_bad_formats() {
        assert!(
            matches!(
                validate_address("not-valid"),
                Err(SiwxError::InvalidAddress { .. })
            ),
            "non-base58"
        );
        assert!(
            matches!(validate_address(""), Err(SiwxError::InvalidAddress { .. })),
            "empty"
        );
    }

    #[test]
    fn validate_chain_id_accepts_genesis_hash() {
        assert!(
            validate_chain_id(MAINNET_GENESIS_HASH).is_ok(),
            "mainnet genesis hash is {n} chars",
            n = MAINNET_GENESIS_HASH.len()
        );
        assert!(
            MAINNET_GENESIS_HASH.len() > 32,
            "this is the CAIP-2 {{1,32}} mismatch"
        );
    }

    #[test]
    fn validate_chain_id_accepts_length_1_to_44() {
        assert!(validate_chain_id("1").is_ok(), "length 1");
        assert!(validate_chain_id(&"a".repeat(32)).is_ok(), "CAIP-2 max 32");
        assert!(
            validate_chain_id(&"a".repeat(33)).is_ok(),
            "past CAIP-2 32, still ok"
        );
        assert!(
            validate_chain_id(&"a".repeat(44)).is_ok(),
            "base58 32-byte max"
        );
    }

    #[test]
    fn validate_chain_id_mainnet_is_not_rewritten() {
        assert!(
            validate_chain_id("mainnet").is_ok(),
            "Phantom 'mainnet' is charset-valid"
        );
        let msg = SiwxMessage::new(
            "example.com",
            ON_CURVE_ADDR,
            "https://example.com",
            "mainnet",
            "testnonce12345678",
        )
        .expect("valid");
        assert_eq!(msg.chain_id(), "mainnet", "must not map mainnet → genesis");
        let text = Ed25519Verifier::format_message(&msg);
        assert!(
            text.contains("Chain ID: mainnet"),
            "rendered chain-id stays mainnet: {text}"
        );
        assert!(
            !text.contains(MAINNET_GENESIS_HASH),
            "must not alias mainnet to genesis: {text}"
        );
    }

    #[test]
    fn validate_chain_id_rejects_empty_and_bad_charset() {
        assert!(
            matches!(
                validate_chain_id(""),
                Err(SiwxError::InvalidChainId {
                    reason: ChainIdReason::Empty
                })
            ),
            "empty"
        );
        assert!(
            matches!(
                validate_chain_id(&"a".repeat(45)),
                Err(SiwxError::InvalidChainId {
                    reason: ChainIdReason::BadCharset
                })
            ),
            "length 45"
        );
        assert!(
            matches!(
                validate_chain_id("solana:mainnet"),
                Err(SiwxError::InvalidChainId {
                    reason: ChainIdReason::BadCharset
                })
            ),
            "colon"
        );
        for id in ["mainnet.1", "main net", "solana/mainnet"] {
            assert!(
                matches!(
                    validate_chain_id(id),
                    Err(SiwxError::InvalidChainId {
                        reason: ChainIdReason::BadCharset
                    })
                ),
                "{id}"
            );
        }
    }

    #[test]
    fn genesis_hash_format_is_unchanged() {
        let msg = SiwxMessage::new(
            "example.com",
            ON_CURVE_ADDR,
            "https://example.com",
            MAINNET_GENESIS_HASH,
            "testnonce12345678",
        )
        .expect("valid");
        assert_eq!(msg.chain_id(), MAINNET_GENESIS_HASH);
        let text = Ed25519Verifier::format_message(&msg);
        assert!(
            text.contains(&format!("Chain ID: {MAINNET_GENESIS_HASH}")),
            "{text}"
        );
    }

    #[test]
    fn namespace_is_solana() {
        assert_eq!(Ed25519Verifier::NAMESPACE, "solana", "trait NAMESPACE");
        assert_eq!(NAMESPACE, "solana", "crate NAMESPACE");
    }

    #[test]
    fn format_message_uses_solana_preamble() {
        let msg = SiwxMessage::new(
            "example.com",
            ON_CURVE_ADDR,
            "https://example.com",
            "1",
            "testnonce12345678",
        )
        .expect("valid");
        let text = Ed25519Verifier::format_message(&msg);
        assert!(
            text.starts_with("example.com wants you to sign in with your Solana account:"),
            "{text}"
        );
    }

    fn solana_raw(address: &str, chain_id: &str) -> (String, AuthOpts) {
        let msg = SiwxMessage::new(
            "example.com",
            address,
            "https://example.com",
            chain_id,
            "testnonce12345678",
        )
        .expect("valid");
        let opts = AuthOpts::new(msg.domain(), msg.nonce());
        (Ed25519Verifier::format_message(&msg), opts)
    }

    #[tokio::test]
    async fn authenticate_rejects_identity_address_before_verify() {
        let identity = bs58::encode([0u8; 32]).into_string();
        let (raw, opts) = solana_raw(&identity, MAINNET_GENESIS_HASH);
        let err = authenticate(&Ed25519Verifier::new(), &raw, &[], &opts)
            .await
            .expect_err("identity");
        assert!(
            matches!(err, SiwxError::InvalidAddress { .. }),
            "empty sig must not reach verify, got {err:?}"
        );
    }

    #[tokio::test]
    async fn authenticate_rejects_off_curve_address_before_verify() {
        let addr = bs58::encode([2u8; 32]).into_string();
        let (raw, opts) = solana_raw(&addr, MAINNET_GENESIS_HASH);
        let err = authenticate(&Ed25519Verifier::new(), &raw, &[], &opts)
            .await
            .expect_err("off-curve");
        assert!(
            matches!(err, SiwxError::InvalidAddress { .. }),
            "empty sig must not reach verify, got {err:?}"
        );
    }

    #[tokio::test]
    async fn authenticate_rejects_colon_chain_id_before_verify() {
        let (raw, opts) = solana_raw(ON_CURVE_ADDR, "solana:mainnet");
        let err = authenticate(&Ed25519Verifier::new(), &raw, &[], &opts)
            .await
            .expect_err("solana:mainnet");
        assert!(
            matches!(
                err,
                SiwxError::InvalidChainId {
                    reason: ChainIdReason::BadCharset
                }
            ),
            "empty sig must not reach verify, got {err:?}"
        );
    }

    #[tokio::test]
    async fn authenticate_wrong_chain_name_is_mismatch() {
        let msg = SiwxMessage::new(
            "example.com",
            ON_CURVE_ADDR,
            "https://example.com",
            MAINNET_GENESIS_HASH,
            "testnonce12345678",
        )
        .expect("valid");
        let raw = msg.to_sign_string("Ethereum");
        let opts = AuthOpts::new(msg.domain(), msg.nonce());
        let err = authenticate(&Ed25519Verifier::new(), &raw, &[], &opts)
            .await
            .expect_err("Ethereum preamble");
        assert!(
            matches!(
                err,
                SiwxError::ChainNameMismatch {
                    ref expected,
                    actual: Some(ref actual),
                } if expected == "Solana" && actual == "Ethereum"
            ),
            "got {err:?}"
        );
    }
}
