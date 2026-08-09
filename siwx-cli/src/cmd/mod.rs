//! CLI command definitions and dispatch.

mod evm;
mod svm;

use clap::{Args, Parser, Subcommand};
pub(crate) use evm::EvmCommand;
use siwx::{AuthOpts, SiwxMessage, Verifier, authenticate};
pub(crate) use svm::SvmCommand;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::output::{
    MessageOutput, NonceOutput, ParseOutput, VerifyOutput, print_json, render_message,
    render_parse, render_verify,
};

type BoxedError = Box<dyn std::error::Error>;
pub(crate) type CmdResult = Result<(), BoxedError>;

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

    /// Expected domain binding (required unless `--trust-message-bindings`).
    #[arg(long)]
    pub domain: Option<String>,

    /// Expected nonce binding (required unless `--trust-message-bindings`).
    #[arg(long)]
    pub nonce: Option<String>,

    /// Expected chain id binding (optional; recommended for multi-chain).
    #[arg(long)]
    pub chain_id: Option<String>,

    /// Use domain/nonce (and chain id if present) from the message itself.
    ///
    /// Debug-only: does not prove the server issued the challenge.
    #[arg(long)]
    pub trust_message_bindings: bool,
}

#[derive(Args)]
pub(crate) struct NonceArgs {
    /// Nonce length in characters (≥ 8).
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
    pub(crate) fn build(&self) -> Result<SiwxMessage, BoxedError> {
        let nonce = self
            .nonce
            .clone()
            .unwrap_or_else(siwx::nonce::generate_default);

        let mut msg = SiwxMessage::new(
            &self.domain,
            &self.address,
            &self.uri,
            &self.chain_id,
            nonce,
        )?;

        if let Some(ref s) = self.statement {
            msg = msg.with_statement(s)?;
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
    pub(crate) fn execute(&self, json: bool) -> CmdResult {
        let nonce = siwx::nonce::generate(self.len)?;
        if json {
            print_json(&NonceOutput {
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
    pub(crate) fn execute(&self, json: bool) -> CmdResult {
        let msg: SiwxMessage = self.message.parse()?;
        let out = ParseOutput::from_message(&msg);
        render_parse(&out, json)
    }
}

/// Build a message for chain `V` and render it.
pub(crate) fn run_message<V: Verifier>(
    chain_label: &'static str,
    args: &MessageArgs,
    json: bool,
) -> CmdResult {
    V::validate_address(&args.address)?;
    let msg = args.build()?;
    let text = V::format_message(&msg);
    let out = MessageOutput::new(chain_label, text, &msg);
    render_message(&out, json)
}

/// Parse + authenticate a signature and render the outcome.
///
/// On cryptographic or validation failure, returns `Err` so the process exits
/// non-zero. Success always reports `valid: true`.
pub(crate) async fn run_verify<V: Verifier>(
    chain_label: &'static str,
    args: &VerifyArgs,
    json: bool,
    verifier: V,
) -> CmdResult {
    let sig = decode_hex_signature(&args.signature)?;
    let provisional: SiwxMessage = args.message.parse()?;

    let opts = build_auth_opts(args, &provisional)?;

    let auth = authenticate(&verifier, &args.message, &sig, &opts).await?;

    let out = VerifyOutput {
        valid: true,
        chain: chain_label.to_owned(),
        domain: auth.message.domain,
        address: auth.message.address,
    };

    if json {
        print_json(&out)?;
    } else {
        render_verify(&out, false)?;
    }
    Ok(())
}

fn build_auth_opts(args: &VerifyArgs, message: &SiwxMessage) -> Result<AuthOpts, BoxedError> {
    let (domain, nonce) = if args.trust_message_bindings {
        (
            args.domain
                .clone()
                .unwrap_or_else(|| message.domain.clone()),
            args.nonce.clone().unwrap_or_else(|| message.nonce.clone()),
        )
    } else {
        let domain = args.domain.clone().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "missing --domain (or pass --trust-message-bindings for debug)",
            )
        })?;
        let nonce = args.nonce.clone().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "missing --nonce (or pass --trust-message-bindings for debug)",
            )
        })?;
        (domain, nonce)
    };

    let mut opts = AuthOpts::new(domain, nonce);
    if let Some(ref chain_id) = args.chain_id {
        opts = opts.with_chain_id(chain_id);
    } else if args.trust_message_bindings {
        opts = opts.with_chain_id(&message.chain_id);
    }
    Ok(opts)
}

pub(crate) fn decode_hex_signature(s: &str) -> Result<Vec<u8>, BoxedError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(hex::decode(s)?)
}

pub(crate) fn fmt_ts(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_else(|_| t.to_string())
}

fn parse_time_or_duration(s: &str) -> Result<OffsetDateTime, BoxedError> {
    if let Ok(secs) = s.parse::<i64>() {
        return Ok(OffsetDateTime::now_utc() + time::Duration::seconds(secs));
    }
    Ok(OffsetDateTime::parse(s, &Rfc3339)?)
}
