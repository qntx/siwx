//! CLI command definitions and dispatch.

mod evm;
mod svm;

use clap::{Args, Parser, Subcommand};
pub(crate) use evm::EvmCommand;
pub(crate) use svm::SvmCommand;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::output;

/// siwx — CAIP-122 Sign-In with X CLI tool.
#[derive(Parser)]
#[command(name = "siwx")]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub(crate) struct Cli {
    /// Output in JSON format for programmatic/agent consumption.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

/// Available commands.
#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Ethereum (EIP-155) operations.
    #[command(name = "evm", alias = "eth")]
    Evm(EvmCommand),

    /// Solana operations.
    #[command(name = "svm", alias = "sol")]
    Svm(SvmCommand),

    /// Generate a cryptographic nonce.
    #[command(name = "nonce")]
    Nonce(NonceArgs),

    /// Parse a CAIP-122 message string into structured fields.
    #[command(name = "parse")]
    Parse(ParseArgs),
}

/// Shared message-generation arguments.
#[derive(Args)]
pub(crate) struct MessageArgs {
    /// RFC 4501 domain requesting the signing.
    #[arg(long)]
    pub domain: String,

    /// Blockchain address performing the signing.
    #[arg(long)]
    pub address: String,

    /// RFC 3986 URI subject of the signing.
    #[arg(long)]
    pub uri: String,

    /// CAIP-2 chain identifier.
    #[arg(long)]
    pub chain_id: String,

    /// Human-readable statement.
    #[arg(long)]
    pub statement: Option<String>,

    /// Nonce (auto-generated if omitted).
    #[arg(long)]
    pub nonce: Option<String>,

    /// Expiration time (RFC 3339 timestamp, or seconds from now).
    #[arg(long)]
    pub expiration: Option<String>,

    /// Not-before time (RFC 3339 timestamp, or seconds from now).
    #[arg(long)]
    pub not_before: Option<String>,

    /// System-specific request ID.
    #[arg(long)]
    pub request_id: Option<String>,

    /// Resource URIs (repeatable).
    #[arg(long = "resource")]
    pub resources: Vec<String>,

    /// Message version (default: "1").
    #[arg(long = "msg-version", id = "msg_version", default_value = "1")]
    pub msg_version: String,
}

/// Shared verify arguments.
#[derive(Args)]
pub(crate) struct VerifyArgs {
    /// The raw CAIP-122 signing message text.
    #[arg(long)]
    pub message: String,

    /// Hex-encoded signature bytes (0x prefix optional).
    #[arg(long)]
    pub signature: String,
}

#[derive(Args)]
pub(crate) struct NonceArgs {
    /// Nonce length in characters.
    #[arg(short, long, default_value_t = siwx::nonce::DEFAULT_LEN)]
    pub len: usize,
}

#[derive(Args)]
pub(crate) struct ParseArgs {
    /// Raw CAIP-122 message text to parse.
    #[arg(long)]
    pub message: String,
}

impl MessageArgs {
    pub(crate) fn build(&self) -> Result<siwx::SiwxMessage, Box<dyn std::error::Error>> {
        let nonce = self
            .nonce
            .clone()
            .unwrap_or_else(siwx::nonce::generate_default);

        let mut msg = siwx::SiwxMessage::new(
            &self.domain,
            &self.address,
            &self.uri,
            &self.msg_version,
            &self.chain_id,
        )?
        .with_nonce(nonce)
        .with_issued_at(OffsetDateTime::now_utc());

        if let Some(ref s) = self.statement {
            msg = msg.with_statement(s);
        }
        if let Some(ref exp) = self.expiration {
            msg = msg.with_expiration_time(parse_time_or_duration(exp)?);
        }
        if let Some(ref nbf) = self.not_before {
            msg = msg.with_not_before(parse_time_or_duration(nbf)?);
        }
        if let Some(ref rid) = self.request_id {
            msg = msg.with_request_id(rid);
        }
        if !self.resources.is_empty() {
            msg = msg.with_resources(self.resources.clone());
        }
        Ok(msg)
    }
}

impl NonceArgs {
    pub(crate) fn execute(&self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        let nonce = siwx::nonce::generate(self.len);
        if json {
            output::print_json(&output::NonceOutput {
                nonce,
                len: self.len,
            })?;
        } else {
            println!("{nonce}");
        }
        Ok(())
    }
}

impl ParseArgs {
    pub(crate) fn execute(&self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        let msg: siwx::SiwxMessage = self.message.parse()?;
        let out = output::ParseOutput::from_message(&msg);
        output::render_parse(&out, json)
    }
}

pub(crate) fn decode_hex_signature(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(hex::decode(s)?)
}

pub(crate) fn fmt_ts(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_else(|_| t.to_string())
}

fn parse_time_or_duration(s: &str) -> Result<OffsetDateTime, Box<dyn std::error::Error>> {
    if let Ok(secs) = s.parse::<i64>() {
        return Ok(OffsetDateTime::now_utc() + time::Duration::seconds(secs));
    }
    Ok(OffsetDateTime::parse(s, &Rfc3339)?)
}
