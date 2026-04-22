use alloy::network::Ethereum;
use alloy::primitives::{Address, FixedBytes, eip191_hash_message};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::sol;
use siwx::{SiwxError, SiwxMessage, Verifier};
use tokio::sync::OnceCell;

use crate::{CHAIN_NAME, parse_address};

/// EIP-1271 magic value returned by `isValidSignature` on success.
const EIP1271_MAGIC: FixedBytes<4> = FixedBytes([0x16, 0x26, 0xBA, 0x7E]);

sol! {
    #[sol(rpc)]
    contract IERC1271 {
        function isValidSignature(bytes32 hash, bytes signature) external view returns (bytes4 magicValue);
    }
}

/// EIP-1271 smart-contract signature verifier.
///
/// Calls `isValidSignature(hash, signature)` on the contract at
/// `message.address` and checks the returned magic value. The underlying
/// RPC provider is connected lazily on first use and cached for subsequent
/// calls.
///
/// Requires an Ethereum JSON-RPC endpoint.
#[derive(Debug)]
pub struct Eip1271Verifier {
    rpc_url: String,
    provider: OnceCell<DynProvider>,
}

impl Eip1271Verifier {
    /// Create a new verifier targeting the given RPC URL.
    #[must_use]
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            provider: OnceCell::new(),
        }
    }

    async fn provider(&self) -> Result<&DynProvider, SiwxError> {
        self.provider
            .get_or_try_init(|| async {
                let built = ProviderBuilder::new()
                    .connect(&self.rpc_url)
                    .await
                    .map_err(|e| {
                        SiwxError::VerificationFailed(format!("RPC connect failed: {e}"))
                    })?;
                Ok::<_, SiwxError>(Provider::<Ethereum>::erased(built))
            })
            .await
    }
}

impl Verifier for Eip1271Verifier {
    const CHAIN_NAME: &'static str = CHAIN_NAME;

    async fn verify(&self, message: &SiwxMessage, signature: &[u8]) -> Result<(), SiwxError> {
        let contract_addr: Address = parse_address(&message.address)?;

        let text = message.to_sign_string(CHAIN_NAME);
        let hash = eip191_hash_message(text.as_bytes());

        let provider = self.provider().await?;
        let contract = IERC1271::new(contract_addr, provider);

        let magic: FixedBytes<4> = contract
            .isValidSignature(hash, signature.to_vec().into())
            .call()
            .await
            .map_err(|e| {
                SiwxError::VerificationFailed(format!("isValidSignature call failed: {e}"))
            })?;

        if magic != EIP1271_MAGIC {
            return Err(SiwxError::VerificationFailed(format!(
                "EIP-1271 magic mismatch: expected {EIP1271_MAGIC}, got {magic}"
            )));
        }

        Ok(())
    }
}
