//! Ethereum (EIP-155) CLI commands.

use clap::{Args, Subcommand};
use siwx_evm::EvmVerifier;

use super::{CmdResult, MessageArgs, VerifyArgs, run_message, run_verify};

const CHAIN_LABEL: &str = "ethereum";

/// Ethereum (EIP-155) operations.
#[derive(Args)]
pub(crate) struct EvmCommand {
    #[command(subcommand)]
    pub action: EvmAction,
}

#[derive(Subcommand)]
pub(crate) enum EvmAction {
    /// Generate a CAIP-122 signing message for Ethereum.
    Message(Box<MessageArgs>),
    /// Verify an EIP-191 signature (EIP-1271 / EIP-6492 when built with those features + RPC).
    Verify(Box<EvmVerifyArgs>),
}

/// EVM-specific verify arguments.
#[derive(Args)]
pub(crate) struct EvmVerifyArgs {
    #[command(flatten)]
    pub common: VerifyArgs,

    /// JSON-RPC URL for EIP-1271 / EIP-6492. Repeatable; must pair with `--rpc-chain-id` in the same order.
    #[cfg(feature = "eip1271")]
    #[arg(long, requires = "rpc_chain_id", action = clap::ArgAction::Append)]
    pub rpc: Vec<String>,

    /// EIP-155 chain id for the corresponding `--rpc`. Repeatable; must pair with `--rpc`.
    #[cfg(feature = "eip1271")]
    #[arg(long = "rpc-chain-id", requires = "rpc", action = clap::ArgAction::Append)]
    pub rpc_chain_id: Vec<u64>,
}

impl EvmCommand {
    pub(crate) async fn execute(&self, json: bool) -> CmdResult {
        match &self.action {
            EvmAction::Message(args) => run_message::<EvmVerifier>(CHAIN_LABEL, args, json),
            EvmAction::Verify(args) => {
                let verifier = make_evm_verifier(args)?;
                run_verify(CHAIN_LABEL, &args.common, json, verifier).await
            }
        }
    }
}

fn make_evm_verifier(args: &EvmVerifyArgs) -> Result<EvmVerifier, super::BoxedError> {
    #[cfg(feature = "eip1271")]
    {
        if args.rpc.is_empty() && args.rpc_chain_id.is_empty() {
            Ok(EvmVerifier::new())
        } else if args.rpc.len() != args.rpc_chain_id.len() {
            Err("`--rpc` and `--rpc-chain-id` must be given in pairs".into())
        } else {
            let map = args
                .rpc_chain_id
                .iter()
                .copied()
                .zip(args.rpc.iter().cloned());
            Ok(EvmVerifier::with_rpc_map(map))
        }
    }
    #[cfg(not(feature = "eip1271"))]
    {
        let _ = args;
        Ok(EvmVerifier::new())
    }
}
