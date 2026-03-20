use alloy::primitives::{Address, FixedBytes};
use alloy::providers::ProviderBuilder;
use alloy::sol;
use siwx::{SiwxError, SiwxMessage};

use crate::{eip191_hash, format_message, parse_address};

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
/// `message.address` and checks the returned magic value.
///
/// Requires an Ethereum JSON-RPC endpoint.
#[derive(Debug)]
pub struct Eip1271Verifier {
    rpc_url: String,
}

impl Eip1271Verifier {
    /// Create a new verifier targeting the given RPC URL.
    #[must_use]
    pub fn new(rpc_url: &str) -> Self {
        Self {
            rpc_url: rpc_url.to_owned(),
        }
    }

    /// Core verification logic (async — makes an RPC call).
    pub(crate) async fn verify_inner(
        &self,
        message: &SiwxMessage,
        signature: &[u8],
    ) -> Result<(), SiwxError> {
        let contract_addr: Address = parse_address(&message.address)?;

        let text = format_message(message);
        let hash = eip191_hash(&text);

        let provider = ProviderBuilder::new()
            .connect(&self.rpc_url)
            .await
            .map_err(|e| SiwxError::VerificationFailed(format!("RPC connect failed: {e}")))?;

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

impl siwx::Verifier for Eip1271Verifier {
    async fn verify(&self, message: &SiwxMessage, signature: &[u8]) -> Result<(), SiwxError> {
        self.verify_inner(message, signature).await
    }
}
