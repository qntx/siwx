//! Structured output types and unified rendering.

use std::fmt::Display;

use colored::{ColoredString, Colorize};
use serde::Serialize;
use siwx::SiwxMessage;

/// Width reserved for field labels in the human-readable renderer.
const LABEL_WIDTH: usize = 10;

#[derive(Serialize)]
pub(crate) struct MessageOutput {
    pub chain: String,
    pub message: String,
    pub domain: String,
    pub address: String,
    pub uri: String,
    pub version: String,
    pub chain_id: String,
    pub nonce: String,
    pub issued_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
}

impl MessageOutput {
    pub(crate) fn new(chain: impl Into<String>, message: String, msg: &SiwxMessage) -> Self {
        Self {
            chain: chain.into(),
            message,
            domain: msg.domain().to_owned(),
            address: msg.address().to_owned(),
            uri: msg.uri().to_owned(),
            version: msg.version().to_owned(),
            chain_id: msg.chain_id().to_owned(),
            nonce: msg.nonce().to_owned(),
            issued_at: msg.issued_at_raw().to_owned(),
            expiration_time: msg.expiration_time_raw().map(str::to_owned),
            not_before: msg.not_before_raw().map(str::to_owned),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct VerifyOutput {
    pub valid: bool,
    pub chain: String,
    pub domain: String,
    pub address: String,
}

#[derive(Serialize)]
pub(crate) struct NonceOutput {
    pub nonce: String,
    pub len: usize,
}

#[derive(Serialize)]
pub(crate) struct ParseOutput {
    pub domain: String,
    pub address: String,
    pub uri: String,
    pub version: String,
    pub chain_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
}

impl ParseOutput {
    pub(crate) fn from_message(msg: &SiwxMessage) -> Self {
        Self {
            domain: msg.domain().to_owned(),
            address: msg.address().to_owned(),
            uri: msg.uri().to_owned(),
            version: msg.version().to_owned(),
            chain_id: msg.chain_id().to_owned(),
            statement: msg.statement().map(str::to_owned),
            nonce: Some(msg.nonce().to_owned()),
            issued_at: Some(msg.issued_at_raw().to_owned()),
            expiration_time: msg.expiration_time_raw().map(str::to_owned),
            not_before: msg.not_before_raw().map(str::to_owned),
            request_id: msg.request_id().map(str::to_owned),
            resources: msg.resources().to_vec(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct ErrorOutput {
    pub error: String,
}

pub(crate) fn print_json<T: Serialize>(value: &T) -> Result<(), serde_json::Error> {
    let json = serde_json::to_string_pretty(value)?;
    println!("{json}");
    Ok(())
}

pub(crate) fn render_message(
    out: &MessageOutput,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if json {
        return Ok(print_json(out)?);
    }

    println!();
    field("Chain", &out.chain);
    field("Domain", &out.domain);
    field("Address", &out.address.as_str().green());
    field("URI", &out.uri);
    field("Version", &out.version);
    field("Chain ID", &out.chain_id);
    field("Nonce", &out.nonce);
    field("Issued At", &out.issued_at);
    if let Some(ref t) = out.expiration_time {
        field("Expires", t);
    }

    println!();
    println!("{}", "--- Signing Message ---".dimmed());
    println!("{}", out.message);
    println!();
    Ok(())
}

pub(crate) fn render_verify(
    out: &VerifyOutput,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if json {
        return Ok(print_json(out)?);
    }

    let verdict: ColoredString = if out.valid {
        "✓ Valid".green().bold()
    } else {
        "✗ Invalid".red().bold()
    };

    println!();
    field("Result", &verdict);
    field("Chain", &out.chain);
    field("Domain", &out.domain);
    field("Address", &out.address.as_str().green());
    println!();
    Ok(())
}

pub(crate) fn render_parse(
    out: &ParseOutput,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if json {
        return Ok(print_json(out)?);
    }

    println!();
    field("Domain", &out.domain);
    field("Address", &out.address.as_str().green());
    field("URI", &out.uri);
    field("Version", &out.version);
    field("Chain ID", &out.chain_id);
    if let Some(ref s) = out.statement {
        field("Statement", s);
    }
    if let Some(ref n) = out.nonce {
        field("Nonce", n);
    }
    if let Some(ref t) = out.issued_at {
        field("Issued At", t);
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
    if !out.resources.is_empty() {
        println!("  {}", pad_label("Resources"));
        for r in &out.resources {
            println!("    - {r}");
        }
    }
    println!();
    Ok(())
}

fn field(label: &str, value: &impl Display) {
    println!("  {}  {}", pad_label(label), value);
}

fn pad_label(label: &str) -> ColoredString {
    format!("{label:<LABEL_WIDTH$}").cyan().bold()
}
