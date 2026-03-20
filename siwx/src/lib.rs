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
//! # Examples
//!
//! ```
//! use siwx::{SiwxMessage, ValidateOpts};
//!
//! let msg = SiwxMessage::new(
//!     "example.com",
//!     "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
//!     "https://example.com/login",
//!     "1",
//!     "1",
//! )?
//! .with_statement("I accept the Terms of Service")
//! .with_nonce(siwx::nonce::generate_default());
//!
//! msg.validate(&ValidateOpts::default())?;
//!
//! let signing_text = msg.to_sign_string("Ethereum");
//! assert!(signing_text.contains("Ethereum"));
//! # Ok::<(), siwx::SiwxError>(())
//! ```
//!
//! [CAIP-122]: https://chainagnostic.org/CAIPs/caip-122

mod error;
mod message;
pub mod nonce;
mod verifier;

pub use error::SiwxError;
pub use message::{SiwxMessage, ValidateOpts};
pub use verifier::Verifier;
