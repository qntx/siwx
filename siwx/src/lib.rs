//! # siwx — Sign-In with X (CAIP-122)
//!
//! Chain-agnostic core library implementing the [CAIP-122] Sign-In with X
//! abstract data model. This crate provides message construction, parsing,
//! validation, and a [`Verifier`] trait for chain-specific signature
//! verification.
//!
//! Prefer [`authenticate`] for backend login: size and CR checks, ABNF parse,
//! domain/nonce validation (default clock skew 60s), preamble chain-name bind,
//! then signature verification over the original bytes. Trailing LF is
//! rejected; trim before [`authenticate`] if a client leaves one.
//!
//! Chain-specific implementations live in companion crates:
//! - `siwx-evm` — Ethereum (EIP-191 / EIP-1271 / EIP-6492)
//! - `siwx-svm` — Solana (Ed25519)
//!
//! # Examples
//!
//! ```
//! use siwx::{AuthOpts, SiwxMessage};
//! use time::macros::datetime;
//!
//! let msg = SiwxMessage::new(
//!     "example.com",
//!     "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
//!     "https://example.com/login",
//!     "1",
//!     siwx::nonce::generate_default(),
//! )?
//! .with_statement("I accept the Terms of Service")?
//! .with_issued_at(datetime!(2024-01-01 0:00 UTC))?;
//!
//! msg.validate(&AuthOpts::new("example.com", msg.nonce()))?;
//!
//! let signing_text = msg.to_sign_string("Ethereum");
//! assert!(signing_text.contains("Ethereum"));
//! # Ok::<(), siwx::SiwxError>(())
//! ```
//!
//! [CAIP-122]: https://chainagnostic.org/CAIPs/caip-122

mod auth;
mod error;
mod formatter;
mod message;
pub mod nonce;
mod parser;
mod validate;
mod verifier;

pub use auth::{Authenticated, authenticate};
pub use error::{ChainIdReason, FormatReason, SiwxError};
pub use message::{
    MAX_MESSAGE_BYTES, MAX_REQUEST_ID_BYTES, MAX_RESOURCES, MAX_STATEMENT_BYTES, MAX_URI_BYTES,
    MIN_NONCE_LEN, SiwxMessage, Timestamp, VERSION,
};
#[cfg(test)]
use proptest as _;
#[cfg(test)]
use serde_json as _;
pub use validate::AuthOpts;
pub use verifier::Verifier;
