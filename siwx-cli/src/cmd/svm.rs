//! Solana CLI commands.

use clap::{Args, Subcommand};
use siwx::Verifier as _;

use super::{MessageArgs, VerifyArgs, decode_hex_signature, fmt_ts};
use crate::output;

/// Solana operations.
#[derive(Args)]
pub struct SvmCommand {
    #[command(subcommand)]
    pub action: SvmAction,
}

#[derive(Subcommand)]
pub enum SvmAction {
    /// Generate a CAIP-122 signing message for Solana.
    Message(Box<MessageArgs>),
    /// Verify an Ed25519 signature over a CAIP-122 message.
    Verify(SvmVerifyArgs),
}

/// SVM-specific verify arguments.
#[derive(Args)]
pub struct SvmVerifyArgs {
    #[command(flatten)]
    pub common: VerifyArgs,
}

impl SvmCommand {
    pub fn execute(&self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match &self.action {
            SvmAction::Message(args) => message(args, json),
            SvmAction::Verify(args) => verify(args, json),
        }
    }
}

fn message(args: &MessageArgs, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let msg = args.build()?;
    let text = siwx_svm::format_message(&msg);
    let out = output::MessageOutput {
        chain: "solana".into(),
        message: text,
        domain: msg.domain.clone(),
        address: msg.address.clone(),
        uri: msg.uri.clone(),
        version: msg.version.clone(),
        chain_id: msg.chain_id.clone(),
        nonce: msg.nonce.clone(),
        issued_at: msg.issued_at.map(fmt_ts),
        expiration_time: msg.expiration_time.map(fmt_ts),
        not_before: msg.not_before.map(fmt_ts),
    };
    output::render_message(&out, json)
}

fn verify(args: &SvmVerifyArgs, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let msg: siwx::SiwxMessage = args.common.message.parse()?;
    let sig = decode_hex_signature(&args.common.signature)?;

    let verifier = siwx_svm::Ed25519Verifier::from_base58(&msg.address)?;

    let rt = tokio::runtime::Builder::new_current_thread().build()?;

    let result = rt.block_on(verifier.verify(&msg, &sig));

    let out = output::VerifyOutput {
        valid: result.is_ok(),
        chain: "solana".into(),
        domain: msg.domain,
        address: msg.address,
    };

    if json {
        output::print_json(&out)?;
    } else {
        output::render_verify(&out, false)?;
        if let Err(e) = result {
            eprintln!("  Detail: {e}");
        }
    }
    Ok(())
}
