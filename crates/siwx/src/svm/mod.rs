//! `siwx::svm` — Solana (`solana`) namespace profile (Ed25519).

mod ed25519;

use crate::{AccountId, BoxFuture, Error, Field, Message, Namespace, eip4361};

/// Human-readable preamble label.
pub const CHAIN_NAME: &str = "Solana";

/// CAIP-2 namespace for Solana.
pub const NAMESPACE: &str = "solana";

/// Validate that `address` is a base58 Ed25519 verifying key (non-weak).
///
/// # Errors
///
/// [`Error::InvalidField`] [`Field::Address`].
pub fn validate_address(address: &str) -> Result<(), Error> {
    ed25519::verifying_key_from_address(address).map(|_| ())
}

/// CAIP-2 reference for a Solana `chain-id` alias.
///
/// Accepts `mainnet|testnet|devnet|localnet` and the `solana:`-prefixed
/// forms. Aliases map to the cluster genesis hash (truncated to CAIP-2's
/// 32-char reference limit); `localnet` maps to `localnet`.
fn chain_reference(chain_id: &str) -> Result<&'static str, Error> {
    match chain_id.strip_prefix("solana:").unwrap_or(chain_id) {
        "mainnet" => Ok("5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"),
        "testnet" => Ok("4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z"),
        "devnet" => Ok("EtWTRABZaYq6iMfeYKouRu166VU2xqa1"),
        "localnet" => Ok("localnet"),
        _ => Err(Error::field(Field::ChainId, "unknown Solana cluster")),
    }
}

/// Solana (`solana`) namespace verifier.
///
/// Signature verification is RFC 8032 [`ed25519_dalek::Verifier::verify`]
/// (canonical `s`), not `verify_strict`. Address validation rejects
/// [`ed25519_dalek::VerifyingKey::is_weak`] keys (small-order, including the
/// 32-zero identity).
#[derive(Debug, Clone, Copy, Default)]
pub struct Svm;

impl Svm {
    /// Create a Solana Ed25519 verifier.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Namespace for Svm {
    fn namespace(&self) -> &'static str {
        NAMESPACE
    }

    fn label(&self) -> &'static str {
        CHAIN_NAME
    }

    fn account(&self, message: &Message) -> Result<AccountId, Error> {
        validate_address(message.address())?;
        let reference = chain_reference(message.chain_id())?;
        AccountId::new(NAMESPACE, reference, message.address())
    }

    fn format(&self, message: &Message) -> Result<String, Error> {
        self.account(message)?;
        Ok(eip4361::format(CHAIN_NAME, message))
    }

    fn parse(&self, signed: &[u8]) -> Result<Message, Error> {
        eip4361::parse_labeled(CHAIN_NAME, signed)
    }

    fn verify<'a>(
        &'a self,
        message: &'a Message,
        signed: &'a [u8],
        signature: &'a [u8],
    ) -> BoxFuture<'a, Result<(), Error>> {
        let result = ed25519::verify_sync(message, signed, signature);
        Box::pin(std::future::ready(result))
    }
}
