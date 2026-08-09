//! CAIP-122 signing-string parser ([`FromStr`] impl for [`SiwxMessage`]).
//!
//! The grammar is the one specified by EIP-4361 / CAIP-122:
//!
//! ```text
//! {domain} wants you to sign in with your {chain} account:
//! {address}
//!
//! [{statement}]
//!
//! URI: {uri}
//! Version: {version}
//! Chain ID: {chain_id}
//! Nonce: {nonce}
//! Issued At: {rfc3339}
//! [Expiration Time: {rfc3339}]
//! [Not Before: {rfc3339}]
//! [Request ID: {request_id}]
//! [Resources:
//! - {uri}
//! - ...]
//! ```

use std::iter::Peekable;
use std::str::{FromStr, Split};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::SiwxError;
use crate::message::{
    MAX_MESSAGE_BYTES, MAX_RESOURCES, SiwxMessage, VERSION, check_domain, check_nonce_shape,
    check_statement,
};

pub(crate) const PREAMBLE_MID: &str = " wants you to sign in with your ";
pub(crate) const PREAMBLE_TAIL: &str = " account:";
pub(crate) const URI_TAG: &str = "URI: ";
pub(crate) const VERSION_TAG: &str = "Version: ";
pub(crate) const CHAIN_TAG: &str = "Chain ID: ";
pub(crate) const NONCE_TAG: &str = "Nonce: ";
pub(crate) const IAT_TAG: &str = "Issued At: ";
pub(crate) const EXP_TAG: &str = "Expiration Time: ";
pub(crate) const NBF_TAG: &str = "Not Before: ";
pub(crate) const RID_TAG: &str = "Request ID: ";
pub(crate) const RES_TAG: &str = "Resources:";

const TAGGED_FIELDS: &[&str] = &[
    URI_TAG,
    VERSION_TAG,
    CHAIN_TAG,
    NONCE_TAG,
    IAT_TAG,
    EXP_TAG,
    NBF_TAG,
    RID_TAG,
];

type Lines<'a> = Peekable<Split<'a, char>>;

impl FromStr for SiwxMessage {
    type Err = SiwxError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.len() > MAX_MESSAGE_BYTES {
            return Err(SiwxError::InvalidFormat(format!(
                "message exceeds maximum size of {MAX_MESSAGE_BYTES} bytes"
            )));
        }

        let mut lines = input.split('\n').peekable();

        let (domain, _chain_name) = parse_preamble(next(&mut lines, "preamble")?)?;
        let domain = check_domain(&domain)?;
        let address = next(&mut lines, "address")?.to_owned();
        if address.is_empty() {
            return Err(SiwxError::InvalidAddress("empty".into()));
        }

        expect_blank(&mut lines, "blank line after address")?;

        let statement = take_optional_statement(&mut lines)?;

        let uri = take_required_tag(&mut lines, URI_TAG)?;
        let version = take_required_tag(&mut lines, VERSION_TAG)?;
        if version != VERSION {
            return Err(SiwxError::InvalidFormat(format!(
                "version must be {VERSION}, got {version}"
            )));
        }
        let chain_id = take_required_tag(&mut lines, CHAIN_TAG)?;
        if chain_id.is_empty() {
            return Err(SiwxError::InvalidFormat("empty chain_id".into()));
        }

        let nonce = check_nonce_shape(&take_required_tag(&mut lines, NONCE_TAG)?)?;
        let issued_at = take_required_ts(&mut lines, IAT_TAG)?;
        let expiration_time = take_optional_ts(&mut lines, EXP_TAG)?;
        let not_before = take_optional_ts(&mut lines, NBF_TAG)?;
        let request_id = take_optional_tag(&mut lines, RID_TAG);

        let resources = take_resources(&mut lines)?;
        reject_trailing(&mut lines)?;

        Ok(Self {
            domain,
            address,
            statement,
            uri,
            version,
            chain_id,
            nonce,
            issued_at,
            expiration_time,
            not_before,
            request_id,
            resources,
        })
    }
}

fn parse_preamble(header: &str) -> Result<(String, &str), SiwxError> {
    let mid = header
        .find(PREAMBLE_MID)
        .ok_or_else(|| SiwxError::invalid_format("missing preamble marker"))?;
    let domain = header[..mid].to_owned();
    let after_mid = &header[mid + PREAMBLE_MID.len()..];
    let chain_name = after_mid
        .strip_suffix(PREAMBLE_TAIL)
        .ok_or_else(|| SiwxError::invalid_format("missing 'account:' suffix"))?;
    if chain_name.is_empty() {
        return Err(SiwxError::invalid_format("empty chain name in preamble"));
    }
    Ok((domain, chain_name))
}

fn expect_blank(lines: &mut Lines<'_>, ctx: &str) -> Result<(), SiwxError> {
    let line = next(lines, ctx)?;
    if !line.is_empty() {
        return Err(SiwxError::invalid_format(format!("expected {ctx}")));
    }
    Ok(())
}

fn take_optional_statement(lines: &mut Lines<'_>) -> Result<Option<String>, SiwxError> {
    let is_statement_line = lines
        .peek()
        .is_some_and(|line| !line.is_empty() && !is_tagged(line));
    if !is_statement_line {
        return Ok(None);
    }
    let stmt = lines
        .next()
        .ok_or_else(|| SiwxError::invalid_format("unexpected end of input (statement)"))?
        .to_owned();
    check_statement(&stmt)?;
    if lines.peek().is_some_and(|line| line.is_empty()) {
        lines.next();
    }
    Ok(Some(stmt))
}

fn take_required_tag(lines: &mut Lines<'_>, tag: &str) -> Result<String, SiwxError> {
    let line = lines
        .peek()
        .ok_or_else(|| SiwxError::invalid_format(format!("missing {tag}")))?;
    let value = line
        .strip_prefix(tag)
        .ok_or_else(|| SiwxError::invalid_format(format!("expected {tag}")))?
        .to_owned();
    lines.next();
    Ok(value)
}

fn take_optional_tag(lines: &mut Lines<'_>, tag: &str) -> Option<String> {
    let value = lines.peek().and_then(|l| l.strip_prefix(tag))?.to_owned();
    lines.next();
    Some(value)
}

fn take_required_ts(lines: &mut Lines<'_>, tag: &str) -> Result<OffsetDateTime, SiwxError> {
    let s = take_required_tag(lines, tag)?;
    parse_ts(&s)
}

fn take_optional_ts(lines: &mut Lines<'_>, tag: &str) -> Result<Option<OffsetDateTime>, SiwxError> {
    take_optional_tag(lines, tag)
        .map(|s| parse_ts(&s))
        .transpose()
}

fn take_resources(lines: &mut Lines<'_>) -> Result<Vec<String>, SiwxError> {
    if lines.peek().is_none_or(|l| *l != RES_TAG) {
        return Ok(Vec::new());
    }
    lines.next();
    let mut resources = Vec::new();
    while lines.peek().is_some_and(|l| !l.is_empty() && *l != RES_TAG) {
        if resources.len() >= MAX_RESOURCES {
            return Err(SiwxError::invalid_format(format!(
                "too many resources (max {MAX_RESOURCES})"
            )));
        }
        let line = next(lines, "resource item")?;
        let item = line
            .strip_prefix("- ")
            .ok_or_else(|| SiwxError::invalid_format("resource line must start with '- '"))?;
        resources.push(item.to_owned());
    }
    Ok(resources)
}

fn reject_trailing(lines: &mut Lines<'_>) -> Result<(), SiwxError> {
    for line in lines {
        if !line.is_empty() {
            return Err(SiwxError::invalid_format(format!(
                "unexpected trailing content: {line}"
            )));
        }
    }
    Ok(())
}

fn parse_ts(s: &str) -> Result<OffsetDateTime, SiwxError> {
    OffsetDateTime::parse(s, &Rfc3339).map_err(|e| SiwxError::InvalidTimestamp(e.to_string()))
}

fn next<'a>(lines: &mut impl Iterator<Item = &'a str>, ctx: &str) -> Result<&'a str, SiwxError> {
    lines
        .next()
        .ok_or_else(|| SiwxError::invalid_format(format!("unexpected end of input ({ctx})")))
}

pub(crate) fn is_tagged(line: &str) -> bool {
    TAGGED_FIELDS.iter().any(|tag| line.starts_with(tag)) || line == RES_TAG
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    fn sample() -> SiwxMessage {
        SiwxMessage::new(
            "service.org",
            "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
            "https://service.org/login",
            "1",
            "32891756",
        )
        .expect("valid")
        .with_statement("I accept the ServiceOrg Terms of Service: https://service.org/tos")
        .expect("statement")
        .with_issued_at(datetime!(2021-09-30 16:25:24 UTC))
        .with_resources([
            "ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/",
            "https://example.com/my-web2-claim.json",
        ])
    }

    #[test]
    fn roundtrip() {
        let msg = sample();
        let text = msg.to_sign_string("Ethereum");
        let parsed: SiwxMessage = text.parse().expect("parse");
        assert_eq!(parsed, msg);
    }

    #[test]
    fn trailing_empty_line_ok() {
        // split produces a final "" for a single trailing newline after last field;
        // reject_trailing allows empty lines only.
        let msg = sample();
        let mut text = msg.to_sign_string("Ethereum");
        text.push('\n');
        let parsed: SiwxMessage = text.parse().expect("empty trailing line ok for parse");
        assert_eq!(parsed.domain, msg.domain);
        // Note: authenticate still rejects non-canonical (with trailing \n).
    }

    #[test]
    fn trailing_garbage_fails() {
        let msg = sample();
        let text = format!("{}\nGARBAGE", msg.to_sign_string("Ethereum"));
        let err: SiwxError = text.parse::<SiwxMessage>().expect_err("garbage");
        assert!(matches!(err, SiwxError::InvalidFormat(_)));
    }

    #[test]
    fn missing_nonce_fails() {
        let text = "\
example.com wants you to sign in with your Ethereum account:
addr1

URI: https://example.com
Version: 1
Chain ID: 1
Issued At: 2021-09-30T16:25:24Z";
        let err: SiwxError = text.parse::<SiwxMessage>().expect_err("missing nonce");
        assert!(matches!(err, SiwxError::InvalidFormat(_)));
    }

    #[test]
    fn minimal_with_required_fields() {
        let msg = SiwxMessage::new(
            "example.com",
            "addr1",
            "https://example.com",
            "1",
            "testnonce12345678",
        )
        .expect("valid")
        .with_issued_at(datetime!(2021-09-30 16:25:24 UTC));
        let text = msg.to_sign_string("Ethereum");
        let parsed: SiwxMessage = text.parse().expect("parse");
        assert_eq!(parsed.domain, "example.com");
        assert!(parsed.statement.is_none());
        assert_eq!(parsed.nonce, "testnonce12345678");
        assert_eq!(parsed.issued_at, datetime!(2021-09-30 16:25:24 UTC));
    }

    #[test]
    fn missing_preamble_fails() {
        let err: SiwxError = "not a siwx message"
            .parse::<SiwxMessage>()
            .expect_err("should fail");
        assert!(matches!(err, SiwxError::InvalidFormat(_)));
    }
}
