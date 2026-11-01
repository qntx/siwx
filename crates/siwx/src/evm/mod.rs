//! `siwx::evm` — EIP-155 (`eip155`) namespace profile.
//!
//! - **EIP-191** (`personal_sign`) — always available, fully offline
//! - **Smart accounts** — deployed ERC-1271, counterfactual ERC-6492 and EOA
//!   signatures via the ERC-6492 universal validator (deployless `eth_call`,
//!   feature `rpc`)
//!
//! [`Namespace::account`] emits the canonical EIP-55 checksum spelling of the
//! address, so lowercase / uppercase / checksummed spellings of the same
//! address map to the same [`AccountId`].
//!
//! Providers are injected per chain id; the library builds no transports and
//! applies no timeouts — transport policy belongs to the provider owner.
//! `eth_chainId` is bound to the message chain id before any `eth_call` and
//! cached per provider on success only.

mod eip191;
pub(crate) mod validator;

#[cfg(feature = "rpc")]
use std::collections::BTreeMap;
#[cfg(feature = "rpc")]
use std::sync::Arc;
#[cfg(feature = "rpc")]
use std::sync::OnceLock;

use alloy::primitives::Address;
#[cfg(feature = "rpc")]
use alloy::providers::Provider as _;

use crate::{AccountId, BoxFuture, Error, Field, Message, Namespace, eip4361};

/// Human-readable preamble label.
pub const CHAIN_NAME: &str = "Ethereum";

/// CAIP-2 namespace for EIP-155 chains.
pub const NAMESPACE: &str = "eip155";

/// Validate that `address` is `0x` + 40 hex; all-lowercase or all-uppercase
/// is accepted, mixed case must be a valid EIP-55 checksum.
///
/// # Errors
///
/// [`Error::InvalidField`] [`Field::Address`].
pub fn validate_address(address: &str) -> Result<(), Error> {
    parse_eip55(address).map(|_| ())
}

/// Parse an Ethereum address: `0x` + 40 hex, uniform case or EIP-55.
pub(crate) fn parse_eip55(s: &str) -> Result<Address, Error> {
    let bad = || Error::field(Field::Address, "expected 0x + 40 hex");
    let hex = s.strip_prefix("0x").ok_or_else(bad)?;
    if hex.len() != 40 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad());
    }
    let has_lower = hex.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = hex.bytes().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper {
        Address::parse_checksummed(s, None)
            .map_err(|_| Error::field(Field::Address, "bad EIP-55 checksum"))
    } else {
        s.parse::<Address>().map_err(|_| bad())
    }
}

/// EVM `chain-id`: `[0-9]+`, no leading zero unless `"0"`, fits in `u64`.
pub(crate) fn parse_evm_chain_id(s: &str) -> Result<u64, Error> {
    if s.is_empty() {
        return Err(Error::field(Field::ChainId, "empty"));
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::field(Field::ChainId, "not decimal"));
    }
    if s.len() > 1 && s.starts_with('0') {
        return Err(Error::field(Field::ChainId, "leading zero"));
    }
    s.parse()
        .map_err(|_| Error::field(Field::ChainId, "overflow"))
}

/// An injected provider plus its one-time `eth_chainId` binding cache.
#[cfg(feature = "rpc")]
struct ProviderEntry {
    provider: alloy::providers::DynProvider,
    /// Set once the provider's `eth_chainId` matched a message chain id.
    verified: OnceLock<()>,
}

#[cfg(feature = "rpc")]
impl std::fmt::Debug for ProviderEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderEntry").finish_non_exhaustive()
    }
}

/// Ethereum (`eip155`) namespace verifier.
///
/// If the signature carries the ERC-6492 magic suffix the on-chain path is
/// required (provider for the message chain, else
/// [`Error::Unsupported`]). Otherwise EIP-191 runs offline; on failure the
/// on-chain universal-validator path is taken only when a provider is
/// configured for the message chain — otherwise the EIP-191 error returns
/// unchanged.
#[derive(Debug)]
#[cfg_attr(not(feature = "rpc"), derive(Copy))]
#[derive(Clone)]
pub struct Evm {
    #[cfg(feature = "rpc")]
    providers: BTreeMap<u64, Arc<ProviderEntry>>,
}

impl Default for Evm {
    fn default() -> Self {
        Self::new()
    }
}

impl Evm {
    /// Create a verifier that only performs EIP-191 recovery.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "rpc")]
            providers: BTreeMap::new(),
        }
    }

    /// Register `provider` for `chain_id` and return `self` (repeatable).
    ///
    /// Requires the `rpc` feature. Chains without a provider never make RPC
    /// calls.
    #[cfg(feature = "rpc")]
    #[must_use]
    pub fn with_provider(mut self, chain_id: u64, provider: alloy::providers::DynProvider) -> Self {
        let _ = self.providers.insert(
            chain_id,
            Arc::new(ProviderEntry {
                provider,
                verified: OnceLock::new(),
            }),
        );
        self
    }

    /// The provider for `chain_id` after the `eth_chainId` binding holds.
    ///
    /// The binding is verified once per provider and cached on success only.
    #[cfg(feature = "rpc")]
    async fn checked_provider<'a>(
        &'a self,
        entry: &'a ProviderEntry,
        chain_id: u64,
    ) -> Result<&'a alloy::providers::DynProvider, Error> {
        if entry.verified.get().is_some() {
            return Ok(&entry.provider);
        }
        let rpc_chain = entry
            .provider
            .get_chain_id()
            .await
            .map_err(|_| Error::Backend {
                reason: "RPC request failed".into(),
            })?;
        if rpc_chain != chain_id {
            return Err(Error::Mismatch {
                field: Field::ChainId,
                expected: chain_id.to_string(),
                actual: Some(rpc_chain.to_string()),
            });
        }
        let _set = entry.verified.set(());
        Ok(&entry.provider)
    }

    #[cfg(feature = "rpc")]
    fn provider_for(&self, chain_id: &str) -> Option<(u64, &ProviderEntry)> {
        let id = parse_evm_chain_id(chain_id).ok()?;
        Some((id, self.providers.get(&id)?))
    }

    #[cfg(feature = "rpc")]
    async fn on_chain(
        &self,
        message: &Message,
        signed: &[u8],
        signature: &[u8],
        eip191_err: Option<Error>,
    ) -> Result<(), Error> {
        let Some((id, entry)) = self.provider_for(message.chain_id()) else {
            return eip191_err.map_or_else(
                || {
                    Err(Error::Unsupported {
                        reason: "EIP-6492 requires RPC",
                    })
                },
                Err,
            );
        };
        let provider = self.checked_provider(entry, id).await?;
        validator::verify(provider, message, signed, signature).await
    }
}

impl Namespace for Evm {
    fn namespace(&self) -> &'static str {
        NAMESPACE
    }

    fn label(&self) -> &'static str {
        CHAIN_NAME
    }

    fn account(&self, message: &Message) -> Result<AccountId, Error> {
        let address = parse_eip55(message.address())?;
        let _ = parse_evm_chain_id(message.chain_id())?;
        AccountId::new(NAMESPACE, message.chain_id(), address.to_checksum(None))
    }

    fn format(&self, message: &Message) -> Result<String, Error> {
        self.account(message)?;
        Ok(eip4361::format(CHAIN_NAME, message))
    }

    fn parse(&self, signed: &[u8]) -> Result<Message, Error> {
        eip4361::parse_labeled(CHAIN_NAME, signed)
    }

    #[cfg(not(feature = "rpc"))]
    fn verify<'a>(
        &'a self,
        message: &'a Message,
        signed: &'a [u8],
        signature: &'a [u8],
    ) -> BoxFuture<'a, Result<(), Error>> {
        let result = if validator::has_magic_suffix(signature) {
            Err(Error::Unsupported {
                reason: "EIP-6492 requires RPC",
            })
        } else {
            eip191::verify_sync(message, signed, signature)
        };
        Box::pin(std::future::ready(result))
    }

    #[cfg(feature = "rpc")]
    fn verify<'a>(
        &'a self,
        message: &'a Message,
        signed: &'a [u8],
        signature: &'a [u8],
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            if validator::has_magic_suffix(signature) {
                return self.on_chain(message, signed, signature, None).await;
            }
            match eip191::verify_sync(message, signed, signature) {
                Ok(()) => Ok(()),
                Err(e) => self.on_chain(message, signed, signature, Some(e)).await,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "rpc"))]
    fn message() -> Message {
        Message::new(crate::MessageFields {
            domain: "service.org".into(),
            address: "0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946".into(),
            uri: "https://service.org".into(),
            version: "1".into(),
            chain_id: "1".into(),
            nonce: "12341234".into(),
            issued_at: "2022-03-17T12:45:13.610Z".into(),
            ..Default::default()
        })
        .expect("valid")
    }

    #[test]
    fn validate_address_accepts_canonical_formats() {
        assert!(validate_address("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").is_ok());
        assert!(validate_address("0x0000000000000000000000000000000000000000").is_ok());
    }

    #[test]
    fn eip6492_magic_suffix_detection() {
        let mut sig = [0u8; 65].to_vec();
        assert!(!validator::has_magic_suffix(&sig));
        sig.extend_from_slice(&validator::MAGIC);
        assert!(validator::has_magic_suffix(&sig));
        assert!(!validator::has_magic_suffix(&validator::MAGIC[..31]));
    }

    #[cfg(not(feature = "rpc"))]
    #[tokio::test]
    async fn eip6492_magic_suffix_without_rpc_is_unsupported() {
        let msg = message();
        let mut sig = [0u8; 65].to_vec();
        sig.extend_from_slice(&validator::MAGIC);
        let err = Evm::new()
            .verify(&msg, b"text", &sig)
            .await
            .expect_err("unsupported");
        assert!(matches!(err, Error::Unsupported { .. }), "got {err:?}");
    }

    #[test]
    fn account_uses_eip55_checksum() {
        let checksummed = "eip155:1:0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946";
        for spelling in [
            "0xe5a12547fe4e872d192e3ececb76f2ce1aea4946",
            "0xE5A12547FE4E872D192E3ECECB76F2CE1AEA4946",
            "0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946",
        ] {
            let msg = Message::new(crate::MessageFields {
                domain: "service.org".into(),
                address: spelling.into(),
                uri: "https://service.org".into(),
                version: "1".into(),
                chain_id: "1".into(),
                nonce: "12341234".into(),
                issued_at: "2022-03-17T12:45:13.610Z".into(),
                ..Default::default()
            })
            .expect("valid");
            assert_eq!(
                Evm::new().account(&msg).unwrap().to_string(),
                checksummed,
                "{spelling}"
            );
        }
    }
}
