//! # siwx — Sign-In with X (CAIP-122)
//!
//! Chain-agnostic core implementing the [CAIP-122] Sign-In with X abstract
//! data model: [`Message`]/[`MessageFields`], the [`eip4361`] text layout,
//! [`Expect`] binding + time policy, [`AccountId`], and the [`Namespace`]
//! trait for chain-specific verification via [`authenticate`].
//!
//! Chain profiles live in feature-gated modules:
//! - [`evm`] — Ethereum (EIP-191 / EIP-1271 / EIP-6492), feature `evm`
//! - [`svm`] — Solana (Ed25519), feature `svm`
//!
//! [CAIP-122]: https://chainagnostic.org/CAIPs/caip-122

mod account;
pub mod eip4361;
mod error;
#[cfg(feature = "evm")]
pub mod evm;
mod expect;
mod message;
mod namespace;
pub mod nonce;
#[cfg(feature = "svm")]
pub mod svm;

pub use account::AccountId;
pub use eip4361::Parsed;
pub use error::{Error, Field, Syntax};
pub use expect::Expect;
pub use message::{
    MAX_MESSAGE_BYTES, MAX_REQUEST_ID_BYTES, MAX_RESOURCES, MAX_STATEMENT_BYTES, MAX_URI_BYTES,
    MIN_NONCE_LEN, Message, MessageFields, Timestamp,
};
pub use namespace::{Authenticated, BoxFuture, Namespace, authenticate};
