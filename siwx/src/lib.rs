//! # siwx — Sign-In with X (CAIP-122)
//!
//! Chain-agnostic core library implementing the [CAIP-122] Sign-In with X
//! abstract data model. This crate provides message construction, parsing,
//! validation, and a [`Verifier`] trait for chain-specific signature
//! verification.
//!
//! Chain-specific implementations live in companion crates:
//! - `siwx-evm` — Ethereum (EIP-191 / EIP-1271)
//! - `siwx-svm` — Solana (Ed25519)
//!
//! [CAIP-122]: https://chainagnostic.org/CAIPs/caip-122

mod error;
mod message;
pub mod nonce;
mod verifier;

pub use error::SiwxError;
pub use message::{SiwxMessage, ValidateOpts};
pub use verifier::Verifier;
