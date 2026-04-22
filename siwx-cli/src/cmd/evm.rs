//! Ethereum (EIP-155) CLI commands.

use clap::{Args, Subcommand};
use siwx_evm::Eip191Verifier;

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
    /// Verify an EIP-191 signature over a CAIP-122 message.
    Verify(EvmVerifyArgs),
}

/// EVM-specific verify arguments.
#[derive(Args)]
pub(crate) struct EvmVerifyArgs {
    #[command(flatten)]
    pub common: VerifyArgs,
}

impl EvmCommand {
    pub(crate) async fn execute(&self, json: bool) -> CmdResult {
        match &self.action {
            EvmAction::Message(args) => run_message::<Eip191Verifier>(CHAIN_LABEL, args, json),
            EvmAction::Verify(args) => {
                run_verify(CHAIN_LABEL, &args.common, json, |_msg| Ok(Eip191Verifier)).await
            }
        }
    }
}
