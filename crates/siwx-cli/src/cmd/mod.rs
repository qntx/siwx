//! CLI command definitions and dispatch.

mod evm;
mod svm;

use clap::{Args, Parser, Subcommand};
pub(crate) use evm::EvmCommand;
use siwx::{Expect, Message, MessageFields, Namespace, Timestamp, authenticate};
pub(crate) use svm::SvmCommand;
use time::OffsetDateTime;

use crate::output::{
    FieldsOutput, MessageOutput, NonceOutput, ParseOutput, VerifyOutput, print_json,
    render_message, render_parse, render_verify,
};

type BoxedError = Box<dyn std::error::Error + Send + Sync>;
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

    /// Preamble scheme (evm only — the SIWS layout rejects a scheme with
    /// `InvalidField { scheme }`).
    #[arg(long)]
    pub scheme: Option<String>,

    /// Nonce (auto-generated if omitted).
    #[arg(long)]
    pub nonce: Option<String>,

    /// Issued-at time (RFC 3339; defaults to now).
    #[arg(long)]
    pub issued_at: Option<String>,

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

/// Signed-bytes input: exactly one of the three forms.
#[derive(Args, Clone)]
#[group(required = true, multiple = false)]
pub(crate) struct MessageInput {
    /// The raw signing message text.
    #[arg(long)]
    pub message: Option<String>,

    /// Read the signing message from a file (raw bytes).
    #[arg(long, value_name = "PATH")]
    pub message_file: Option<std::path::PathBuf>,

    /// Hex-encoded signed bytes (`0x` optional) — needed for SIWS off-chain
    /// envelopes and other non-UTF-8 inputs.
    #[arg(long, value_name = "HEX")]
    pub message_hex: Option<String>,
}

impl MessageInput {
    pub(crate) fn bytes(&self) -> Result<Vec<u8>, BoxedError> {
        if let Some(ref m) = self.message {
            return Ok(m.clone().into_bytes());
        }
        if let Some(ref p) = self.message_file {
            return Ok(std::fs::read(p)?);
        }
        let h = self
            .message_hex
            .as_ref()
            .ok_or("one of --message/--message-file/--message-hex is required")?;
        Ok(hex::decode(h.strip_prefix("0x").unwrap_or(h))?)
    }
}

/// Shared verify arguments.
#[derive(Args)]
pub(crate) struct VerifyArgs {
    #[command(flatten)]
    pub input: MessageInput,

    /// Signature encoding: evm = hex (`0x` optional); svm = base58
    /// (`0x`-prefixed switches to hex).
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

    /// Expected request-id binding (optional).
    #[arg(long)]
    pub request_id: Option<String>,

    /// Clock-skew tolerance in seconds (default 60).
    #[arg(long, value_name = "SECS")]
    pub skew: Option<u64>,

    /// Maximum age of issued-at in seconds (no cap when omitted).
    #[arg(long, value_name = "SECS")]
    pub max_age: Option<u64>,
}

/// Parse arguments (per namespace).
#[derive(Args)]
pub(crate) struct ParseArgs {
    #[command(flatten)]
    pub input: MessageInput,
}

#[derive(Args)]
pub(crate) struct NonceArgs {}

impl MessageArgs {
    pub(crate) fn build(&self) -> Result<Message, BoxedError> {
        let nonce = self.nonce.clone().unwrap_or_else(siwx::nonce::generate);
        let issued_at = match self.issued_at.as_deref() {
            Some(s) => {
                Timestamp::parse(s).ok_or_else(|| format!("invalid RFC 3339 timestamp: {s}"))?
            }
            None => Timestamp::from_instant(OffsetDateTime::now_utc())
                .ok_or("issued-at out of range")?,
        };
        Ok(Message::new(MessageFields {
            scheme: self.scheme.clone(),
            domain: self.domain.clone(),
            address: self.address.clone(),
            statement: self.statement.clone(),
            uri: self.uri.clone(),
            version: "1".to_owned(),
            chain_id: self.chain_id.clone(),
            nonce,
            issued_at: issued_at.as_str().to_owned(),
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
            print_json(&NonceOutput { nonce })?;
        } else {
            println!("{nonce}");
        }
        Ok(())
    }
}

/// Build a message for chain `ns` and render `{chain, message, fields, account}`.
pub(crate) fn run_message(
    chain_label: &'static str,
    args: &MessageArgs,
    json: bool,
    namespace: &dyn Namespace,
) -> CmdResult {
    let msg = args.build()?;
    let text = namespace.format(&msg)?;
    let account = namespace.account(&msg)?.to_string();
    let out = MessageOutput {
        chain: chain_label.to_owned(),
        message: text,
        fields: FieldsOutput::from_message(&msg),
        account,
    };
    render_message(&out, json)
}

/// Parse signed bytes for chain `ns` and render `{chain, fields}`.
pub(crate) fn run_parse(
    chain_label: &'static str,
    args: &ParseArgs,
    json: bool,
    namespace: &dyn Namespace,
) -> CmdResult {
    let parsed = namespace.parse(&args.input.bytes()?)?;
    render_parse(
        &ParseOutput {
            chain: chain_label.to_owned(),
            fields: FieldsOutput::from_message(&parsed),
        },
        json,
    )
}

/// Parse + authenticate and render `{valid, chain, account, fields}`.
pub(crate) async fn run_verify(
    chain_label: &'static str,
    args: &VerifyArgs,
    sig: Vec<u8>,
    json: bool,
    namespace: &dyn Namespace,
) -> CmdResult {
    let expect = build_expect(args);
    let auth = authenticate(namespace, &args.input.bytes()?, &sig, &expect).await?;
    let out = VerifyOutput {
        valid: true,
        chain: chain_label.to_owned(),
        account: auth.account().to_string(),
        fields: FieldsOutput::from_message(auth.message()),
    };
    render_verify(&out, json)
}

pub(crate) fn decode_hex_signature(s: &str) -> Result<Vec<u8>, BoxedError> {
    Ok(hex::decode(s.strip_prefix("0x").unwrap_or(s))?)
}

/// svm signature: base58 by default, hex when `0x`-prefixed.
pub(crate) fn decode_svm_signature(s: &str) -> Result<Vec<u8>, BoxedError> {
    if s.starts_with("0x") {
        return decode_hex_signature(s);
    }
    Ok(bs58::decode(s).into_vec()?)
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
    if let Some(ref request_id) = args.request_id {
        expect = expect.with_request_id(request_id);
    }
    if let Some(skew) = args.skew {
        expect = expect.with_skew(std::time::Duration::from_secs(skew));
    }
    if let Some(max_age) = args.max_age {
        expect = expect.with_max_age(std::time::Duration::from_secs(max_age));
    }
    expect
}

fn parse_time_or_duration(s: &str) -> Result<Timestamp, BoxedError> {
    if let Ok(secs) = s.parse::<i64>() {
        return Timestamp::from_instant(OffsetDateTime::now_utc() + time::Duration::seconds(secs))
            .ok_or_else(|| "timestamp out of range".into());
    }
    Timestamp::parse(s).ok_or_else(|| format!("invalid RFC 3339 timestamp: {s}").into())
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::unwrap_in_result,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::needless_pass_by_value,
    reason = "test module"
)]
mod tests {
    use super::*;

    fn vector(path: &str) -> serde_json::Value {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vectors")
            .join(path);
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    fn cli(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    fn cli_err(args: &[&str]) -> clap::Error {
        Cli::try_parse_from(args)
            .err()
            .expect("expected clap error")
    }

    // clap-level shape tests

    #[test]
    fn verify_requires_domain_and_nonce() {
        let e = cli_err(&[
            "siwx",
            "evm",
            "verify",
            "--message",
            "m",
            "--signature",
            "00",
        ]);
        assert_eq!(e.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        for flag in ["--domain", "--nonce"] {
            let err = cli_err(&[
                "siwx",
                "evm",
                "verify",
                "--message",
                "m",
                "--signature",
                "00",
                flag,
                "x",
            ]);
            assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        }
    }

    #[test]
    fn message_inputs_are_mutually_exclusive() {
        let e = cli_err(&[
            "siwx",
            "svm",
            "parse",
            "--message",
            "a",
            "--message-hex",
            "00",
        ]);
        assert_eq!(e.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn top_level_parse_is_gone() {
        let e = cli_err(&["siwx", "parse", "--message", "a"]);
        assert_eq!(e.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn svm_scheme_fails_at_format_not_clap() {
        // --scheme parses (shared args) but the SIWS layout rejects it.
        let c = cli(&[
            "siwx",
            "svm",
            "message",
            "--domain",
            "d.example",
            "--address",
            "9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj",
            "--uri",
            "https://d.example",
            "--chain-id",
            "mainnet",
            "--scheme",
            "https",
        ])
        .expect("clap accepts");
        let Commands::Svm(cmd) = c.command else {
            panic!("svm")
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let err = rt
            .block_on(async { cmd.execute(false).await })
            .expect_err("SIWS rejects scheme");
        assert!(
            err.downcast_ref::<siwx::Error>().is_some_and(|e| matches!(
                e,
                siwx::Error::InvalidField {
                    field: siwx::Field::Scheme,
                    ..
                }
            )),
            "got {err:?}"
        );
    }

    // in-process end-to-end against fixed vectors

    fn fields_msg() -> Message {
        Message::new(MessageFields {
            scheme: None,
            domain: "siwe.xyz".into(),
            address: "0xAE9aA90F1a627c7a20783AF9e8747fCFEDEFAd03".into(),
            statement: Some("Sign In with Ethereum Example Statement".into()),
            uri: "https://siwe.xyz".into(),
            version: "1".into(),
            chain_id: "1".into(),
            nonce: "bTyXgcQxn2htgkjJn".into(),
            issued_at: "2022-01-27T17:09:38.578Z".into(),
            expiration_time: Some("2100-01-07T14:31:43.952Z".into()),
            not_before: None,
            request_id: None,
            resources: None,
        })
        .unwrap()
    }

    #[test]
    fn evm_e2e_message_parse_verify() {
        let v = vector("siwe/verification/verification_positive.json");
        let case = &v["example message"];
        let evm = siwx::evm::Evm::new();
        let text = evm.format(&fields_msg()).unwrap();
        // parse path
        run_parse(
            "ethereum",
            &ParseArgs {
                input: MessageInput {
                    message: Some(text.clone()),
                    message_file: None,
                    message_hex: None,
                },
            },
            false,
            &evm,
        )
        .unwrap();
        // verify path (max-age off; issued-at is in the past)
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            run_verify(
                "ethereum",
                &VerifyArgs {
                    input: MessageInput {
                        message: Some(text),
                        message_file: None,
                        message_hex: None,
                    },
                    signature: case["signature"].as_str().unwrap().to_owned(),
                    domain: "siwe.xyz".into(),
                    nonce: "bTyXgcQxn2htgkjJn".into(),
                    uri: None,
                    scheme: None,
                    chain_id: None,
                    request_id: None,
                    skew: None,
                    max_age: None,
                },
                decode_hex_signature(case["signature"].as_str().unwrap()).unwrap(),
                true,
                &evm,
            )
            .await
        })
        .unwrap();
    }

    fn run_svm(signed: Vec<u8>, sig: &str) -> Result<(), BoxedError> {
        let svm = siwx::svm::Svm::new();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            run_verify(
                "solana",
                &VerifyArgs {
                    input: MessageInput {
                        message: None,
                        message_file: None,
                        message_hex: Some(hex::encode(&signed)),
                    },
                    signature: sig.to_owned(),
                    domain: "service.org".into(),
                    nonce: "12341234".into(),
                    uri: None,
                    scheme: None,
                    chain_id: None,
                    request_id: None,
                    skew: None,
                    max_age: None,
                },
                decode_svm_signature(sig).unwrap(),
                true,
                &svm,
            )
            .await
        })
    }

    #[test]
    fn svm_e2e_raw_and_envelope() {
        let v = vector("svm/ed25519.json");
        for name in ["valid raw SIWS", "valid envelope"] {
            let case = v["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"] == name)
                .unwrap();
            let signed = match &case["signedHex"] {
                serde_json::Value::String(h) => hex::decode(h.strip_prefix("0x").unwrap()).unwrap(),
                _ => case["text"].as_str().unwrap().as_bytes().to_vec(),
            };
            let sig_hex = case["signatureHex"].as_str().unwrap();
            run_svm(signed, sig_hex).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }
}
