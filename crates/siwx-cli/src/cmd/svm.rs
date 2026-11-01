//! Solana CLI commands.

use clap::{Args, Subcommand};
use siwx::svm::Svm;

use super::{
    CmdResult, MessageArgs, ParseArgs, VerifyArgs, decode_svm_signature, run_message, run_parse,
    run_verify,
};

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
    Message(Box<SvmMessageArgs>),
    /// Verify an Ed25519 signature over a SIWS message or off-chain envelope.
    Verify(Box<VerifyArgs>),
    /// Parse a signing message into structured fields.
    Parse(ParseArgs),
}

/// svm message args — no `--scheme` (the SIWS layout rejects it).
#[derive(Args)]
pub(crate) struct SvmMessageArgs {
    #[command(flatten)]
    pub common: MessageArgs,
}

impl SvmCommand {
    pub(crate) async fn execute(&self, json: bool) -> CmdResult {
        match &self.action {
            SvmAction::Message(args) => run_message(CHAIN_LABEL, &args.common, json, &Svm::new()),
            SvmAction::Parse(args) => run_parse(CHAIN_LABEL, args, json, &Svm::new()),
            SvmAction::Verify(args) => {
                let sig = decode_svm_signature(&args.signature)?;
                run_verify(CHAIN_LABEL, args, sig, json, &Svm::new()).await
            }
        }
    }
}
