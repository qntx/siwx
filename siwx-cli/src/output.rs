//! Structured output types and unified rendering.

use std::fmt::Display;

use colored::{ColoredString, Colorize};
use serde::Serialize;
use siwx::SiwxMessage;

use crate::cmd::fmt_ts;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
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
            domain: msg.domain.clone(),
            address: msg.address.clone(),
            uri: msg.uri.clone(),
            version: msg.version.clone(),
            chain_id: msg.chain_id.clone(),
            nonce: msg.nonce.clone(),
            issued_at: msg.issued_at.map(fmt_ts),
            expiration_time: msg.expiration_time.map(fmt_ts),
            not_before: msg.not_before.map(fmt_ts),
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
            domain: msg.domain.clone(),
            address: msg.address.clone(),
            uri: msg.uri.clone(),
            version: msg.version.clone(),
            chain_id: msg.chain_id.clone(),
            statement: msg.statement.clone(),
            nonce: msg.nonce.clone(),
            issued_at: msg.issued_at.map(fmt_ts),
            expiration_time: msg.expiration_time.map(fmt_ts),
            not_before: msg.not_before.map(fmt_ts),
            request_id: msg.request_id.clone(),
            resources: msg.resources.clone(),
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
    if let Some(ref n) = out.nonce {
        field("Nonce", n);
    }
    if let Some(ref t) = out.issued_at {
        field("Issued At", t);
    }
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
