//! # siwx — Sign-In with X (CAIP-122)
//!
//! Chain-agnostic core implementing the [CAIP-122] Sign-In with X abstract
//! data model: [`Message`]/[`MessageFields`], the [`eip4361`] text layout,
//! [`Expect`] binding + time policy, [`AccountId`], and the [`Namespace`]
//! trait for chain-specific verification via [`authenticate`].
//!
//! Chain profiles live in feature-gated modules:
//! - [`evm`] — Ethereum: EIP-4361 layout + EIP-191 offline verification
//!   (feature `evm`); on-chain smart-account verification through the
//!   ERC-6492 universal validator with injected providers (feature `rpc`).
//! - [`svm`] — Solana: SIWS layout + strict Ed25519, incl. the off-chain
//!   message v1 envelope (feature `svm`).
//!
//! [CAIP-122]: https://chainagnostic.org/CAIPs/caip-122

mod account;
pub mod eip4361;
mod error;
#[cfg(feature = "evm")]
pub mod evm;
mod expect;
mod layout;
mod message;
mod namespace;
pub mod nonce;
mod origin;
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
pub use origin::{OriginFinding, OriginFindingCode, OriginPolicy, Severity, check_origin};
