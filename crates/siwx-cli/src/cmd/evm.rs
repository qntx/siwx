//! Ethereum (EIP-155) CLI commands.

use clap::{Args, Subcommand};
use siwx::evm::Evm;

use super::{
    CmdResult, MessageArgs, ParseArgs, VerifyArgs, decode_hex_signature, run_message, run_parse,
    run_verify,
};

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
    /// Verify a signature (on-chain smart accounts via `--rpc`).
    Verify(Box<EvmVerifyArgs>),
    /// Parse a signing message into structured fields.
    Parse(ParseArgs),
}

/// EVM-specific verify arguments.
#[derive(Args)]
pub(crate) struct EvmVerifyArgs {
    #[command(flatten)]
    pub common: VerifyArgs,

    /// JSON-RPC endpoint as `CHAIN_ID=URL` for on-chain smart-account
    /// verification (universal validator). Repeatable.
    #[cfg(feature = "rpc")]
    #[arg(long, value_name = "CHAIN_ID=URL", action = clap::ArgAction::Append)]
    pub rpc: Vec<String>,
}

impl EvmCommand {
    pub(crate) async fn execute(&self, json: bool) -> CmdResult {
        match &self.action {
            EvmAction::Message(args) => run_message(CHAIN_LABEL, args, json, &Evm::new()),
            EvmAction::Parse(args) => run_parse(CHAIN_LABEL, args, json, &Evm::new()),
            EvmAction::Verify(args) => {
                let sig = decode_hex_signature(&args.common.signature)?;
                #[cfg(feature = "rpc")]
                let verifier = make_evm(args)?;
                #[cfg(not(feature = "rpc"))]
                let verifier = Evm::new();
                run_verify(CHAIN_LABEL, &args.common, sig, json, &verifier).await
            }
        }
    }
}

#[cfg(feature = "rpc")]
fn make_evm(args: &EvmVerifyArgs) -> Result<Evm, super::BoxedError> {
    use alloy::providers::{Provider, ProviderBuilder};
    use alloy::transports::http::reqwest;

    let mut evm = Evm::new();
    for spec in &args.rpc {
        let (id, url) = spec.split_once('=').ok_or("`--rpc` expects CHAIN_ID=URL")?;
        let chain_id: u64 = id
            .parse()
            .map_err(|_| "`--rpc` chain id must be a decimal u64")?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;
        let url = url.parse().map_err(|_| "`--rpc` URL is invalid")?;
        let provider: alloy::providers::DynProvider =
            Provider::erased(ProviderBuilder::new().connect_reqwest(client, url));
        evm = evm.with_provider(chain_id, provider);
    }
    Ok(evm)
}
