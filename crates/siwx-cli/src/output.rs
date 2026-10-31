//! Structured output types and unified rendering.

use std::fmt::Display;

use colored::{ColoredString, Colorize};
use serde::Serialize;
use siwx::{Error, Message, Syntax};

const LABEL_WIDTH: usize = 10;

/// All message fields, mirroring the TS `fields` output.
#[derive(Serialize)]
pub(crate) struct FieldsOutput {
    pub domain: String,
    pub address: String,
    pub uri: String,
    pub version: String,
    #[serde(rename = "chainId")]
    pub chain_id: String,
    pub nonce: String,
    #[serde(rename = "issuedAt")]
    pub issued_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    #[serde(rename = "expirationTime", skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<String>,
    #[serde(rename = "notBefore", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(rename = "requestId", skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<String>>,
}

impl FieldsOutput {
    pub(crate) fn from_message(msg: &Message) -> Self {
        Self {
            domain: msg.domain().to_owned(),
            address: msg.address().to_owned(),
            uri: msg.uri().to_owned(),
            version: msg.version().to_owned(),
            chain_id: msg.chain_id().to_owned(),
            nonce: msg.nonce().to_owned(),
            issued_at: msg.issued_at().as_str().to_owned(),
            scheme: msg.scheme().map(str::to_owned),
            statement: msg.statement().map(str::to_owned),
            expiration_time: msg.expiration_time().map(|t| t.as_str().to_owned()),
            not_before: msg.not_before().map(|t| t.as_str().to_owned()),
            request_id: msg.request_id().map(str::to_owned),
            resources: msg.resources().map(<[String]>::to_vec),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct MessageOutput {
    pub chain: String,
    pub message: String,
    pub fields: FieldsOutput,
    pub account: String,
}

#[derive(Serialize)]
pub(crate) struct VerifyOutput {
    pub valid: bool,
    pub chain: String,
    pub account: String,
    pub fields: FieldsOutput,
}

#[derive(Serialize)]
pub(crate) struct NonceOutput {
    pub nonce: String,
}

#[derive(Serialize)]
pub(crate) struct ParseOutput {
    pub chain: String,
    pub fields: FieldsOutput,
}

/// `{error: {code, message, field?, syntax?}}` — stable JSON contract.
#[derive(Serialize)]
pub(crate) struct ErrorJson {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syntax: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct ErrorOutput {
    pub error: ErrorJson,
}

impl ErrorOutput {
    pub(crate) fn from_error(error: &Error) -> Self {
        let (field, syntax) = match error {
            Error::Syntax(s) => (
                match s {
                    Syntax::MissingField(f) => Some(f.as_str().to_owned()),
                    _ => None,
                },
                Some(s.code().to_owned()),
            ),
            Error::InvalidField { field, .. } | Error::Mismatch { field, .. } => {
                (Some(field.as_str().to_owned()), None)
            }
            _ => (None, None),
        };
        Self {
            error: ErrorJson {
                code: error.code().to_owned(),
                message: error.to_string(),
                field,
                syntax,
            },
        }
    }

    /// Fallback for non-siwx errors (bad flags, I/O).
    pub(crate) fn plain(message: String) -> Self {
        Self {
            error: ErrorJson {
                code: "Error".to_owned(),
                message,
                field: None,
                syntax: None,
            },
        }
    }
}

pub(crate) fn print_json<T: Serialize>(value: &T) -> Result<(), serde_json::Error> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn fields(out: &FieldsOutput) {
    field("Domain", &out.domain);
    field("Address", &out.address.as_str().green());
    field("URI", &out.uri);
    field("Version", &out.version);
    field("Chain ID", &out.chain_id);
    field("Nonce", &out.nonce);
    field("Issued At", &out.issued_at);
    if let Some(ref s) = out.scheme {
        field("Scheme", s);
    }
    if let Some(ref t) = out.expiration_time {
        field("Expires", t);
    }
    if let Some(ref t) = out.not_before {
        field("Not Before", t);
    }
    if let Some(ref r) = out.request_id {
        field("Request ID", r);
    }
    if let Some(ref rs) = out.resources {
        println!("  {}", pad_label("Resources"));
        for r in rs {
            println!("    - {r}");
        }
    }
}

pub(crate) fn render_message(
    out: &MessageOutput,
    json: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if json {
        return Ok(print_json(out)?);
    }
    println!();
    field("Chain", &out.chain);
    field("Account", &out.account.as_str().yellow());
    fields(&out.fields);
    println!();
    println!("{}", "--- Signing Message ---".dimmed());
    println!("{}", out.message);
    println!();
    Ok(())
}

pub(crate) fn render_verify(
    out: &VerifyOutput,
    json: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if json {
        return Ok(print_json(out)?);
    }
    let verdict: ColoredString = "✓ Valid".green().bold();
    println!();
    field("Result", &verdict);
    field("Chain", &out.chain);
    field("Account", &out.account.as_str().yellow());
    fields(&out.fields);
    println!();
    Ok(())
}

pub(crate) fn render_parse(
    out: &ParseOutput,
    json: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if json {
        return Ok(print_json(out)?);
    }
    println!();
    field("Chain", &out.chain);
    fields(&out.fields);
    println!();
    Ok(())
}

fn field(label: &str, value: &impl Display) {
    println!("  {}  {}", pad_label(label), value);
}

fn pad_label(label: &str) -> ColoredString {
    format!("{label:<LABEL_WIDTH$}").cyan().bold()
}
