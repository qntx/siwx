//! Solana CLI commands.

use clap::{Args, Subcommand};
use siwx_svm::Ed25519Verifier;

use super::{CmdResult, MessageArgs, VerifyArgs, run_message, run_verify};

const CHAIN_LABEL: &str = "solana";

/// Solana operations.
#[derive(Args)]
pub(crate) struct SvmCommand {
    #[command(subcommand)]
    pub action: SvmAction,
}

#[derive(Subcommand)]
pub(crate) enum SvmAction {
    /// Generate a CAIP-122 signing message for Solana.
    Message(Box<MessageArgs>),
    /// Verify an Ed25519 signature over a CAIP-122 message.
    Verify(SvmVerifyArgs),
}

/// SVM-specific verify arguments.
#[derive(Args)]
pub(crate) struct SvmVerifyArgs {
    #[command(flatten)]
    pub common: VerifyArgs,
}

impl SvmCommand {
    pub(crate) async fn execute(&self, json: bool) -> CmdResult {
        match &self.action {
            SvmAction::Message(args) => run_message::<Ed25519Verifier>(CHAIN_LABEL, args, json),
            SvmAction::Verify(args) => {
                run_verify(CHAIN_LABEL, &args.common, json, |msg| {
                    Ok(Ed25519Verifier::from_base58(&msg.address)?)
                })
                .await
            }
        }
    }
}
