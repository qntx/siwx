//! Structured output types and unified rendering.

use colored::Colorize;
use serde::Serialize;

#[derive(Serialize)]
pub struct MessageOutput {
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

#[derive(Serialize)]
pub struct VerifyOutput {
    pub valid: bool,
    pub chain: String,
    pub domain: String,
    pub address: String,
}

#[derive(Serialize)]
pub struct NonceOutput {
    pub nonce: String,
    pub len: usize,
}

#[derive(Serialize)]
pub struct ParseOutput {
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
    pub fn from_message(msg: &siwx::SiwxMessage) -> Self {
        use time::format_description::well_known::Rfc3339;
        Self {
            domain: msg.domain.clone(),
            address: msg.address.clone(),
            uri: msg.uri.clone(),
            version: msg.version.clone(),
            chain_id: msg.chain_id.clone(),
            statement: msg.statement.clone(),
            nonce: msg.nonce.clone(),
            issued_at: msg.issued_at.map(|t| t.format(&Rfc3339).expect("RFC 3339")),
            expiration_time: msg
                .expiration_time
                .map(|t| t.format(&Rfc3339).expect("RFC 3339")),
            not_before: msg
                .not_before
                .map(|t| t.format(&Rfc3339).expect("RFC 3339")),
            request_id: msg.request_id.clone(),
            resources: msg.resources.clone(),
        }
    }
}

#[derive(Serialize)]
pub struct ErrorOutput {
    pub error: String,
}

pub fn print_json<T: Serialize>(value: &T) -> Result<(), serde_json::Error> {
    let json = serde_json::to_string_pretty(value)?;
    println!("{json}");
    Ok(())
}

#[rustfmt::skip]
pub fn render_message(out: &MessageOutput, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    if json { return Ok(print_json(out)?); }

    println!();
    println!("    {}    {}", "Chain".cyan().bold(), out.chain);
    println!("   {}   {}", "Domain".cyan().bold(), out.domain);
    println!("  {}  {}", "Address".cyan().bold(), out.address.green());
    println!("      {}      {}", "URI".cyan().bold(), out.uri);
    println!("  {}  {}", "Version".cyan().bold(), out.version);
    println!(" {} {}", "Chain ID".cyan().bold(), out.chain_id);
    if let Some(ref n) = out.nonce {
        println!("    {}    {}", "Nonce".cyan().bold(), n);
    }
    if let Some(ref t) = out.issued_at {
        println!("{} {}", "Issued At".cyan().bold(), t);
    }
    if let Some(ref t) = out.expiration_time {
        println!("  {}  {}", "Expires".cyan().bold(), t);
    }
    println!();
    println!("{}", "--- Signing Message ---".dimmed());
    println!("{}", out.message);
    println!();
    Ok(())
}

#[rustfmt::skip]
pub fn render_verify(out: &VerifyOutput, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    if json { return Ok(print_json(out)?); }

    println!();
    if out.valid {
        println!("   {}   {}", "Result".cyan().bold(), "✓ Valid".green().bold());
    } else {
        println!("   {}   {}", "Result".cyan().bold(), "✗ Invalid".red().bold());
    }
    println!("    {}    {}", "Chain".cyan().bold(), out.chain);
    println!("   {}   {}", "Domain".cyan().bold(), out.domain);
    println!("  {}  {}", "Address".cyan().bold(), out.address.green());
    println!();
    Ok(())
}

#[rustfmt::skip]
pub fn render_parse(out: &ParseOutput, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    if json { return Ok(print_json(out)?); }

    println!();
    println!("   {}   {}", "Domain".cyan().bold(), out.domain);
    println!("  {}  {}", "Address".cyan().bold(), out.address.green());
    println!("      {}      {}", "URI".cyan().bold(), out.uri);
    println!("  {}  {}", "Version".cyan().bold(), out.version);
    println!(" {} {}", "Chain ID".cyan().bold(), out.chain_id);
    if let Some(ref s) = out.statement {
        println!("{} {}", "Statement".cyan().bold(), s);
    }
    if let Some(ref n) = out.nonce {
        println!("    {}    {}", "Nonce".cyan().bold(), n);
    }
    if let Some(ref t) = out.issued_at {
        println!("{} {}", "Issued At".cyan().bold(), t);
    }
    if let Some(ref t) = out.expiration_time {
        println!("  {}  {}", "Expires".cyan().bold(), t);
    }
    if let Some(ref t) = out.not_before {
        println!("  {} {}", "Not Before".cyan().bold(), t);
    }
    if !out.resources.is_empty() {
        println!("{}", "Resources".cyan().bold());
        for r in &out.resources {
            println!("  - {r}");
        }
    }
    println!();
    Ok(())
}
