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
    /// Verify an EIP-191 signature (and EIP-1271 when built with `eip1271` + `--rpc`).
    Verify(EvmVerifyArgs),
}

/// EVM-specific verify arguments.
#[derive(Args)]
pub(crate) struct EvmVerifyArgs {
    #[command(flatten)]
    pub common: VerifyArgs,

    /// JSON-RPC URL for EIP-1271 fallback (requires the `eip1271` feature).
    #[cfg(feature = "eip1271")]
    #[arg(long)]
    pub rpc: Option<String>,
}

impl EvmCommand {
    pub(crate) async fn execute(&self, json: bool) -> CmdResult {
        match &self.action {
            EvmAction::Message(args) => run_message::<EvmVerifier>(CHAIN_LABEL, args, json),
            EvmAction::Verify(args) => {
                let verifier = make_evm_verifier(args);
                run_verify(CHAIN_LABEL, &args.common, json, verifier).await
            }
        }
    }
}

fn make_evm_verifier(args: &EvmVerifyArgs) -> EvmVerifier {
    #[cfg(feature = "eip1271")]
    if let Some(ref url) = args.rpc {
        return EvmVerifier::with_rpc(url);
    }
    #[cfg(not(feature = "eip1271"))]
    let _ = args;
    EvmVerifier::new()
}
