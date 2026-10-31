//! CLI command definitions and dispatch.

mod evm;
mod svm;

use clap::{Args, Parser, Subcommand};
pub(crate) use evm::EvmCommand;
use siwx::{Expect, Message, MessageFields, Namespace, Timestamp, authenticate};
pub(crate) use svm::SvmCommand;
use time::OffsetDateTime;

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
    /// RFC 3986 authority requesting the signing.
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

    /// Expected domain binding (server-issued; required).
    #[arg(long)]
    pub domain: String,

    /// Expected nonce binding (server-issued; required).
    #[arg(long)]
    pub nonce: String,

    /// Expected URI binding (optional).
    #[arg(long)]
    pub uri: Option<String>,

    /// Expected preamble scheme binding (optional).
    #[arg(long)]
    pub scheme: Option<String>,

    /// Expected chain id binding (optional; recommended for multi-chain).
    #[arg(long)]
    pub chain_id: Option<String>,
}

#[derive(Args)]
pub(crate) struct NonceArgs {}

#[derive(Args)]
pub(crate) struct ParseArgs {
    /// Raw CAIP-122 message text to parse.
    #[arg(long)]
    pub message: String,
}

impl MessageArgs {
    pub(crate) fn build(&self) -> Result<Message, BoxedError> {
        let nonce = self.nonce.clone().unwrap_or_else(siwx::nonce::generate);
        Ok(Message::new(MessageFields {
            scheme: None,
            domain: self.domain.clone(),
            address: self.address.clone(),
            statement: self.statement.clone(),
            uri: self.uri.clone(),
            version: "1".to_owned(),
            chain_id: self.chain_id.clone(),
            nonce,
            issued_at: Timestamp::from_instant(OffsetDateTime::now_utc())
                .map(|t| t.as_str().to_owned())
                .ok_or("issued-at out of range")?,
            expiration_time: self
                .expiration
                .as_deref()
                .map(parse_time_or_duration)
                .transpose()?
                .map(|t| t.as_str().to_owned()),
            not_before: self
                .not_before
                .as_deref()
                .map(parse_time_or_duration)
                .transpose()?
                .map(|t| t.as_str().to_owned()),
            request_id: self.request_id.clone(),
            resources: if self.resources.is_empty() {
                None
            } else {
                Some(self.resources.clone())
            },
        })?)
    }
}

impl NonceArgs {
    pub(crate) fn execute(json: bool) -> CmdResult {
        let nonce = siwx::nonce::generate();
        if json {
            print_json(&NonceOutput {
                len: nonce.len(),
                nonce,
            })?;
        } else {
            println!("{nonce}");
        }
        Ok(())
    }
}

impl ParseArgs {
    pub(crate) fn execute(&self, json: bool) -> CmdResult {
        let parsed = siwx::eip4361::parse(&self.message)?;
        let out = ParseOutput::from_message(&parsed.label, &parsed.message);
        render_parse(&out, json)
    }
}

/// Build a message for chain `V` and render it.
pub(crate) fn run_message(
    chain_label: &'static str,
    args: &MessageArgs,
    json: bool,
    namespace: &dyn Namespace,
) -> CmdResult {
    let msg = args.build()?;
    let text = namespace.format(&msg)?;
    let out = MessageOutput::new(chain_label, text, &msg);
    render_message(&out, json)
}

/// Parse + authenticate a signature and render the outcome.
///
/// On cryptographic or validation failure, returns `Err` so the process exits
/// non-zero. Success always reports `valid: true`.
pub(crate) async fn run_verify(
    chain_label: &'static str,
    args: &VerifyArgs,
    json: bool,
    namespace: &dyn Namespace,
) -> CmdResult {
    let sig = decode_hex_signature(&args.signature)?;
    let expect = build_expect(args);

    let auth = authenticate(namespace, args.message.as_bytes(), &sig, &expect).await?;

    let out = VerifyOutput {
        valid: true,
        chain: chain_label.to_owned(),
        domain: auth.message().domain().to_owned(),
        address: auth.account().address().to_owned(),
    };

    if json {
        print_json(&out)?;
    } else {
        render_verify(&out, false)?;
    }
    Ok(())
}

fn build_expect(args: &VerifyArgs) -> Expect {
    let mut expect = Expect::new(args.domain.as_str(), args.nonce.as_str());
    if let Some(ref scheme) = args.scheme {
        expect = expect.with_scheme(scheme);
    }
    if let Some(ref uri) = args.uri {
        expect = expect.with_uri(uri);
    }
    if let Some(ref chain_id) = args.chain_id {
        expect = expect.with_chain_id(chain_id);
    }
    expect
}

pub(crate) fn decode_hex_signature(s: &str) -> Result<Vec<u8>, BoxedError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(hex::decode(s)?)
}

fn parse_time_or_duration(s: &str) -> Result<Timestamp, BoxedError> {
    if let Ok(secs) = s.parse::<i64>() {
        return Timestamp::from_instant(OffsetDateTime::now_utc() + time::Duration::seconds(secs))
            .ok_or_else(|| "timestamp out of range".into());
    }
    Timestamp::parse(s).ok_or_else(|| format!("invalid RFC 3339 timestamp: {s}").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(fields: &MessageFields) -> Message {
        Message::new(fields.clone()).expect("valid")
    }

    fn base_fields() -> MessageFields {
        MessageFields {
            scheme: None,
            domain: "example.com".into(),
            address: "addr1".into(),
            statement: None,
            uri: "https://example.com".into(),
            version: "1".into(),
            chain_id: "1".into(),
            nonce: "n12345678".into(),
            issued_at: "2022-03-17T12:45:13.610Z".into(),
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: None,
        }
    }

    fn verify_args() -> VerifyArgs {
        VerifyArgs {
            message: String::new(),
            signature: String::new(),
            domain: "example.com".into(),
            nonce: "n12345678".into(),
            uri: None,
            scheme: None,
            chain_id: None,
        }
    }

    #[test]
    fn expect_binds_required_domain_and_nonce() {
        build_expect(&verify_args())
            .check(&message(&base_fields()))
            .expect("domain/nonce bind");
    }

    #[test]
    fn expect_forwards_optional_uri_scheme_chain_id() {
        let args = VerifyArgs {
            uri: Some("https://example.com/login".into()),
            scheme: Some("https".into()),
            chain_id: Some("1".into()),
            ..verify_args()
        };
        let mut f = base_fields();
        f.scheme = Some("https".into());
        f.uri = "https://example.com/login".into();
        build_expect(&args)
            .check(&message(&f))
            .expect("optional bindings");
    }

    #[test]
    fn expect_uri_mismatch_is_rejected() {
        let args = VerifyArgs {
            uri: Some("https://other.example/login".into()),
            ..verify_args()
        };
        let err = build_expect(&args)
            .check(&message(&base_fields()))
            .expect_err("uri");
        assert!(
            matches!(
                err,
                siwx::Error::Mismatch {
                    field: siwx::Field::Uri,
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    fn try_parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    fn parse_err(args: &[&str]) -> clap::Error {
        try_parse(args)
            .map(|_cli| ())
            .expect_err("expected clap error")
    }

    #[cfg(feature = "eip1271")]
    fn parse_ok(args: &[&str]) -> Cli {
        try_parse(args)
            .map_err(|err| err.to_string())
            .expect("expected clap parse to succeed")
    }

    #[test]
    fn verify_requires_domain() {
        let err = parse_err(&[
            "siwx",
            "evm",
            "verify",
            "--message",
            "m",
            "--signature",
            "00",
            "--nonce",
            "n12345678",
        ]);
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        let rendered = err.to_string();
        assert!(rendered.contains("--domain"), "{rendered}");
    }

    #[test]
    fn verify_requires_nonce() {
        let err = parse_err(&[
            "siwx",
            "svm",
            "verify",
            "--message",
            "m",
            "--signature",
            "00",
            "--domain",
            "example.com",
        ]);
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        let rendered = err.to_string();
        assert!(rendered.contains("--nonce"), "{rendered}");
    }

    #[test]
    fn verify_rejects_trust_message_bindings() {
        let err = parse_err(&[
            "siwx",
            "evm",
            "verify",
            "--message",
            "m",
            "--signature",
            "00",
            "--domain",
            "example.com",
            "--nonce",
            "n12345678",
            "--trust-message-bindings",
        ]);
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
        let rendered = err.to_string();
        assert!(rendered.contains("trust-message-bindings"), "{rendered}");
    }

    #[cfg(feature = "eip1271")]
    #[test]
    fn verify_rpc_requires_rpc_chain_id() {
        let err = parse_err(&[
            "siwx",
            "evm",
            "verify",
            "--message",
            "m",
            "--signature",
            "00",
            "--domain",
            "example.com",
            "--nonce",
            "n12345678",
            "--rpc",
            "https://eth.example",
        ]);
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        let rendered = err.to_string();
        assert!(rendered.contains("--rpc-chain-id"), "{rendered}");
    }

    #[cfg(feature = "eip1271")]
    #[test]
    fn verify_rpc_chain_id_requires_rpc() {
        let err = parse_err(&[
            "siwx",
            "evm",
            "verify",
            "--message",
            "m",
            "--signature",
            "00",
            "--domain",
            "example.com",
            "--nonce",
            "n12345678",
            "--rpc-chain-id",
            "1",
        ]);
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        let rendered = err.to_string();
        assert!(rendered.contains("--rpc"), "{rendered}");
    }

    #[cfg(feature = "eip1271")]
    #[test]
    fn verify_rpc_pair_count_mismatch() {
        let cli = parse_ok(&[
            "siwx",
            "evm",
            "verify",
            "--message",
            "m",
            "--signature",
            "00",
            "--domain",
            "example.com",
            "--nonce",
            "n12345678",
            "--rpc-chain-id",
            "1",
            "--rpc",
            "https://eth.example",
            "--rpc-chain-id",
            "137",
        ]);
        let Commands::Evm(cmd) = cli.command else {
            unreachable!("expected evm");
        };
        let evm::EvmAction::Verify(args) = cmd.action else {
            unreachable!("expected verify");
        };
        let err = evm::make_evm(&args).expect_err("unequal counts");
        assert!(err.to_string().contains("pairs"), "{err}");
    }
}
