//! EIP-1271 smart-contract signature verification (feature `eip1271`).

use alloy::network::Ethereum;
use alloy::primitives::{Address, FixedBytes, eip191_hash_message};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::sol;
use siwx::{SiwxError, SiwxMessage};
use tokio::sync::OnceCell;

use crate::parse_address;

/// EIP-1271 magic value returned by `isValidSignature` on success.
pub(crate) const EIP1271_MAGIC: FixedBytes<4> = FixedBytes([0x16, 0x26, 0xBA, 0x7E]);

/// Returns true if `magic` is the EIP-1271 success value `0x1626ba7e`.
#[must_use]
pub(crate) fn is_success_magic(magic: FixedBytes<4>) -> bool {
    magic == EIP1271_MAGIC
}

sol! {
    #[sol(rpc)]
    contract IERC1271 {
        function isValidSignature(bytes32 hash, bytes signature) external view returns (bytes4 magicValue);
    }
}

/// EIP-1271 smart-contract signature verifier (internal).
#[derive(Debug)]
pub(crate) struct Eip1271Verifier {
    rpc_url: String,
    provider: OnceCell<DynProvider>,
}

impl Eip1271Verifier {
    pub(crate) fn new(rpc_url: impl Into<String>) -> Self {
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

    pub(crate) async fn verify(
        &self,
        message: &SiwxMessage,
        raw_message: &str,
        signature: &[u8],
    ) -> Result<(), SiwxError> {
        let contract_addr: Address = parse_address(&message.address)?;

        let hash = eip191_hash_message(raw_message.as_bytes());

        let provider = self.provider().await?;
        let contract = IERC1271::new(contract_addr, provider);

        let magic: FixedBytes<4> = contract
            .isValidSignature(hash, signature.to_vec().into())
            .call()
            .await
            .map_err(|e| {
                SiwxError::VerificationFailed(format!("isValidSignature call failed: {e}"))
            })?;

        if !is_success_magic(magic) {
            return Err(SiwxError::VerificationFailed(format!(
                "EIP-1271 magic mismatch: expected {EIP1271_MAGIC}, got {magic}"
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip1271_magic_is_is_valid_signature_selector() {
        // bytes4(keccak256("isValidSignature(bytes32,bytes)")) == 0x1626ba7e
        assert_eq!(EIP1271_MAGIC, FixedBytes([0x16, 0x26, 0xBA, 0x7E]));
        assert!(is_success_magic(EIP1271_MAGIC));
    }

    #[test]
    fn non_success_magic_is_rejected_by_helper() {
        let bad = FixedBytes([0x00, 0x00, 0x00, 0x00]);
        assert!(!is_success_magic(bad));
        let almost = FixedBytes([0x16, 0x26, 0xBA, 0x7F]);
        assert!(!is_success_magic(almost));
    }

    #[test]
    fn eip1271_verifier_holds_rpc_url() {
        let v = Eip1271Verifier::new("https://eth.example");
        assert_eq!(v.rpc_url, "https://eth.example");
    }
}
