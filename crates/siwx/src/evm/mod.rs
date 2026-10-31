//! `siwx::evm` — EIP-155 (`eip155`) namespace profile.
//!
//! - **EIP-191** (`personal_sign`) — always available
//! - **EIP-1271** — smart-contract `isValidSignature` (feature `eip1271` + RPC)
//! - **EIP-6492** — counterfactual signatures (feature `eip6492` + RPC)
//!
//! [`Namespace::account`] emits the canonical EIP-55 checksum spelling of the
//! address, so lowercase / uppercase / checksummed spellings of the same
//! address map to the same [`AccountId`].

#[cfg(feature = "eip1271")]
mod eip1271;
mod eip191;
mod eip6492;

#[cfg(feature = "eip1271")]
use std::sync::Arc;
#[cfg(feature = "eip1271")]
use std::time::Duration;

use alloy::primitives::Address;

use crate::{AccountId, BoxFuture, Error, Field, Message, Namespace, eip4361};

/// Human-readable preamble label.
pub const CHAIN_NAME: &str = "Ethereum";

/// CAIP-2 namespace for EIP-155 chains.
pub const NAMESPACE: &str = "eip155";

#[cfg(feature = "eip1271")]
const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(5);

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

/// Per-chain RPC endpoint with a lazily connected provider.
#[cfg(feature = "eip1271")]
#[derive(Debug)]
struct RpcEndpoint {
    url: String,
    provider: tokio::sync::OnceCell<alloy::providers::DynProvider>,
}

/// Ethereum (`eip155`) namespace verifier.
///
/// ERC-6492 magic suffix is checked first. When built with `eip6492` and an
/// RPC URL is configured for the message chain, verification is a deployless
/// `eth_call`. Otherwise EIP-191 runs; with `eip1271` and a per-chain RPC,
/// any EIP-191 error falls through to EIP-1271 (`eth_chainId` then
/// `isValidSignature`).
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "eip1271"), derive(Copy))]
pub struct Evm {
    #[cfg(feature = "eip1271")]
    rpc: Option<Arc<std::collections::BTreeMap<u64, RpcEndpoint>>>,
    #[cfg(feature = "eip1271")]
    timeout: Duration,
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
            #[cfg(feature = "eip1271")]
            rpc: None,
            #[cfg(feature = "eip1271")]
            timeout: DEFAULT_RPC_TIMEOUT,
        }
    }

    /// Create a verifier that selects the RPC URL by EIP-155 chain id.
    ///
    /// Requires the `eip1271` feature. Chains missing from the map stay on
    /// EIP-191 (the 191 error is returned; no wrong-chain RPC).
    #[cfg(feature = "eip1271")]
    #[must_use]
    pub fn with_rpc_map(map: impl IntoIterator<Item = (u64, impl Into<String>)>) -> Self {
        let mut endpoints = std::collections::BTreeMap::new();
        for (id, url) in map {
            endpoints.insert(
                id,
                RpcEndpoint {
                    url: url.into(),
                    provider: tokio::sync::OnceCell::new(),
                },
            );
        }
        Self {
            rpc: Some(Arc::new(endpoints)),
            timeout: DEFAULT_RPC_TIMEOUT,
        }
    }

    /// Create a verifier with a single RPC URL bound to `chain_id`.
    #[cfg(feature = "eip1271")]
    #[must_use]
    pub fn with_rpc_for_chain(chain_id: u64, url: impl Into<String>) -> Self {
        Self::with_rpc_map([(chain_id, url)])
    }

    /// Override the RPC HTTP timeout (default 5 seconds).
    #[cfg(feature = "eip1271")]
    #[must_use]
    pub const fn with_rpc_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[cfg(feature = "eip1271")]
    fn endpoint_for(&self, chain_id: &str) -> Option<&RpcEndpoint> {
        let id = parse_evm_chain_id(chain_id).ok()?;
        self.rpc.as_ref()?.get(&id)
    }

    #[cfg(feature = "eip1271")]
    async fn provider_for<'a>(
        &self,
        endpoint: &'a RpcEndpoint,
    ) -> Result<&'a alloy::providers::DynProvider, Error> {
        use alloy::network::Ethereum;
        use alloy::providers::{Provider, ProviderBuilder};

        let url = endpoint.url.clone();
        let timeout = self.timeout;
        endpoint
            .provider
            .get_or_try_init(|| async move {
                let connect = ProviderBuilder::new().connect(&url);
                let built = tokio::time::timeout(timeout, connect)
                    .await
                    .map_err(|_| Error::Backend {
                        reason: "RPC timeout".into(),
                    })?
                    .map_err(|_| Error::Backend {
                        reason: "RPC connect failed".into(),
                    })?;
                Ok(Provider::<Ethereum>::erased(built))
            })
            .await
    }

    #[cfg(feature = "eip1271")]
    async fn verify_eip1271(
        &self,
        message: &Message,
        signed: &[u8],
        signature: &[u8],
        eip191_err: Error,
    ) -> Result<(), Error> {
        let Some(endpoint) = self.endpoint_for(message.chain_id()) else {
            return Err(eip191_err);
        };
        let provider = self.provider_for(endpoint).await?;
        eip1271::verify(provider, self.timeout, message, signed, signature).await
    }

    #[cfg(feature = "eip6492")]
    async fn verify_eip6492(
        &self,
        message: &Message,
        signed: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        let Some(endpoint) = self.endpoint_for(message.chain_id()) else {
            return Err(Error::Unsupported {
                reason: "EIP-6492 requires RPC",
            });
        };
        let provider = self.provider_for(endpoint).await?;
        eip6492::verify(provider, self.timeout, message, signed, signature).await
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

    #[cfg(not(feature = "eip1271"))]
    fn verify<'a>(
        &'a self,
        message: &'a Message,
        signed: &'a [u8],
        signature: &'a [u8],
    ) -> BoxFuture<'a, Result<(), Error>> {
        let result = if eip6492::has_magic_suffix(signature) {
            Err(Error::Unsupported {
                reason: "EIP-6492 not enabled",
            })
        } else {
            eip191::verify_sync(message, signed, signature)
        };
        Box::pin(std::future::ready(result))
    }

    #[cfg(feature = "eip1271")]
    fn verify<'a>(
        &'a self,
        message: &'a Message,
        signed: &'a [u8],
        signature: &'a [u8],
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move { self.verify_inner(message, signed, signature).await })
    }
}

#[cfg(feature = "eip1271")]
impl Evm {
    async fn verify_inner(
        &self,
        message: &Message,
        signed: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        if eip6492::has_magic_suffix(signature) {
            #[cfg(feature = "eip6492")]
            {
                return self.verify_eip6492(message, signed, signature).await;
            }
            #[cfg(not(feature = "eip6492"))]
            {
                return Err(Error::Unsupported {
                    reason: "EIP-6492 not enabled",
                });
            }
        }
        match eip191::verify_sync(message, signed, signature) {
            Ok(()) => Ok(()),
            Err(eip191_err) => {
                self.verify_eip1271(message, signed, signature, eip191_err)
                    .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "eip6492"))]
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
        assert!(!eip6492::has_magic_suffix(&sig));
        sig.extend_from_slice(&eip6492::MAGIC);
        assert!(eip6492::has_magic_suffix(&sig));
        assert!(!eip6492::has_magic_suffix(&eip6492::MAGIC[..31]));
    }

    #[cfg(all(feature = "eip1271", not(feature = "eip6492")))]
    #[tokio::test]
    async fn eip6492_magic_suffix_under_eip1271_is_not_enabled() {
        let msg = message();
        let mut sig = [0u8; 65].to_vec();
        sig.extend_from_slice(&eip6492::MAGIC);
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

    #[cfg(feature = "eip1271")]
    #[test]
    fn default_uses_rpc_timeout() {
        assert_eq!(Evm::default().timeout, DEFAULT_RPC_TIMEOUT);
    }

    #[cfg(not(feature = "eip1271"))]
    #[tokio::test]
    async fn eip6492_magic_suffix_without_feature_is_not_enabled() {
        let msg = message();
        let mut sig = [0u8; 65].to_vec();
        sig.extend_from_slice(&eip6492::MAGIC);
        let err = Evm::new()
            .verify(&msg, b"text", &sig)
            .await
            .expect_err("unsupported");
        assert!(matches!(err, Error::Unsupported { .. }), "got {err:?}");
    }
}
