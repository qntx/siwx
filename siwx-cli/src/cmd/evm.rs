//! Ethereum (EIP-155) CLI commands.

use clap::{Args, Subcommand};
use siwx::Verifier as _;

use super::{MessageArgs, VerifyArgs, decode_hex_signature, fmt_ts};
use crate::output;

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
    pub(crate) fn execute(&self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match &self.action {
            EvmAction::Message(args) => message(args, json),
            EvmAction::Verify(args) => verify(args, json),
        }
    }
}

fn message(args: &MessageArgs, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let msg = args.build()?;
    let text = siwx_evm::format_message(&msg);
    let out = output::MessageOutput {
        chain: "ethereum".into(),
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

fn verify(args: &EvmVerifyArgs, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let msg: siwx::SiwxMessage = args.common.message.parse()?;
    let sig = decode_hex_signature(&args.common.signature)?;

    let rt = tokio::runtime::Builder::new_current_thread().build()?;

    let result = rt.block_on(siwx_evm::Eip191Verifier.verify(&msg, &sig));

    let out = output::VerifyOutput {
        valid: result.is_ok(),
        chain: "ethereum".into(),
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
