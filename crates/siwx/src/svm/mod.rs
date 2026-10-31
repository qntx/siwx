//! `siwx::svm` — Solana (`solana`) namespace profile.
//!
//! Layout: the SIWS (Sign-In-With-Solana) text layout in [`siws`]; `Svm`
//! additionally accepts signed bytes wrapped in the Solana off-chain
//! message v1 envelope (sRFC 38): `\xffsolana offchain` (16) ‖ version u8
//! ‖ signer count u8 ‖ signers (32 × count, strictly ascending) ‖ content
//! (UTF-8, non-empty).

mod ed25519;
pub mod siws;

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::traits::IsIdentity;

use crate::{AccountId, BoxFuture, Error, Field, MAX_MESSAGE_BYTES, Message, Namespace, Syntax};

/// Human-readable preamble label.
pub const CHAIN_NAME: &str = "Solana";

/// CAIP-2 namespace for Solana.
pub const NAMESPACE: &str = "solana";

/// Off-chain message v1 signing domain (sRFC 38).
const OFFCHAIN_DOMAIN: &[u8; 16] = b"\xffsolana offchain";

const fn syntax(kind: Syntax) -> Error {
    Error::Syntax(kind)
}

/// Decode `address` as a base58 (Bitcoin alphabet) string of 32–44 chars
/// that decodes to exactly 32 bytes.
fn address_bytes(address: &str) -> Result<[u8; 32], Error> {
    if !(32..=44).contains(&address.len()) {
        return Err(Error::field(Field::Address, "expected 32–44 base58 chars"));
    }
    let bytes = bs58::decode(address)
        .into_vec()
        .map_err(|_| Error::field(Field::Address, "invalid base58"))?;
    bytes
        .try_into()
        .map_err(|_| Error::field(Field::Address, "expected 32 bytes"))
}

/// The canonical, on-curve, torsion-free Ed25519 point for `bytes`
/// (decompress → recompress byte equality proves canonicity).
fn canonical_point(bytes: &[u8; 32]) -> Result<(), Error> {
    let point = CompressedEdwardsY(*bytes)
        .decompress()
        .ok_or_else(|| Error::field(Field::Address, "invalid Ed25519 pubkey"))?;
    if point.is_identity() {
        return Err(Error::field(Field::Address, "identity pubkey"));
    }
    if !point.is_torsion_free() {
        return Err(Error::field(
            Field::Address,
            "not in the prime-order subgroup",
        ));
    }
    if point.compress().0 != *bytes {
        return Err(Error::field(Field::Address, "non-canonical pubkey"));
    }
    Ok(())
}

/// Validate that `address` is a canonical, on-curve, non-small-order
/// Ed25519 verifying key in base58 form.
///
/// # Errors
///
/// [`Error::InvalidField`] [`Field::Address`].
pub fn validate_address(address: &str) -> Result<(), Error> {
    canonical_point(&address_bytes(address)?)
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

/// Base58 encoding of `bytes` for error messages.
fn b58(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

/// A decoded off-chain message v1 envelope.
struct Envelope<'a> {
    signer: &'a [u8],
    content: &'a [u8],
}

/// Decode the v1 envelope at the start of `signed` — `signed` must already
/// be known to start with [`OFFCHAIN_DOMAIN`].
fn decode_envelope(signed: &[u8]) -> Result<Envelope<'_>, Error> {
    let invalid = || syntax(Syntax::InvalidEnvelope);
    let (version, rest) = signed
        .get(16..)
        .and_then(<[u8]>::split_first)
        .ok_or_else(invalid)?;
    if *version != 1 {
        return Err(Error::Unsupported {
            reason: "off-chain message version",
        });
    }
    let (count, rest) = rest.split_first().ok_or_else(invalid)?;
    // SIWS 1.1 requires exactly one signer.
    if *count != 1 {
        return Err(invalid());
    }
    let n = 32usize * usize::from(*count);
    let signers = rest.get(..n).ok_or_else(invalid)?;
    // Strictly ascending signers.
    let mut prev: Option<&[u8; 32]> = None;
    for s in signers.as_chunks::<32>().0 {
        if prev.is_some_and(|p| s <= p) {
            return Err(invalid());
        }
        prev = Some(s);
    }
    let content = rest.get(n..).ok_or_else(invalid)?;
    if content.is_empty() {
        return Err(invalid());
    }
    Ok(Envelope {
        signer: signers,
        content,
    })
}

/// Wrap `text` in the off-chain message v1 envelope for `signer`
/// (validated as an SIWS address).
///
/// # Errors
///
/// [`Error::InvalidField`] [`Field::Address`] for a bad signer, or for a
/// `text` containing CR.
pub fn offchain_message(text: &str, signer: &str) -> Result<Vec<u8>, Error> {
    let signer_bytes = address_bytes(signer)?;
    canonical_point(&signer_bytes)?;
    let mut out = Vec::with_capacity(18 + 32 + text.len());
    out.extend_from_slice(OFFCHAIN_DOMAIN);
    out.push(1u8);
    out.push(1u8);
    out.extend_from_slice(&signer_bytes);
    out.extend_from_slice(text.as_bytes());
    Ok(out)
}

/// Solana (`solana`) namespace verifier.
///
/// Signature verification requires `A` (address key) and `R` to be canonical
/// encodings of prime-order-subgroup points (torsion-free — this excludes
/// identity, small-order and mixed points), `S < L`, then RFC 8032
/// verification via `ed25519_dalek::VerifyingKey::verify_strict`. For
/// torsion-free `A`/`R` the cofactored and cofactorless equations coincide.
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
        siws::format(message)
    }

    fn parse(&self, signed: &[u8]) -> Result<Message, Error> {
        if signed.len() > MAX_MESSAGE_BYTES {
            return Err(Error::MessageTooLarge {
                len: signed.len(),
                max: MAX_MESSAGE_BYTES,
            });
        }
        if signed.starts_with(OFFCHAIN_DOMAIN) {
            let env = decode_envelope(signed)?;
            let message = siws::parse_bytes(env.content)?;
            let expected = address_bytes(message.address())?;
            if env.signer != expected {
                return Err(Error::Mismatch {
                    field: Field::Address,
                    expected: message.address().to_owned(),
                    actual: Some(b58(env.signer)),
                });
            }
            return Ok(message);
        }
        siws::parse_bytes(signed)
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
