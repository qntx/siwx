//! `siwx::svm::siws` — the Sign-In-With-Solana (SIWS) text layout.
//!
//! Phantom ABNF (LF only):
//!
//! ```text
//! domain " wants you to sign in with your Solana account:" LF address
//! [ LF LF statement ] [ LF advanced-fields ]
//!
//! advanced-fields = [ LF "URI: " uri ] [ LF "Version: " version ]
//!   [ LF "Chain ID: " chain-id ] [ LF "Nonce: " nonce ]
//!   [ LF "Issued At: " date-time ] [ LF "Expiration Time: " date-time ]
//!   [ LF "Not Before: " date-time ] [ LF "Request ID: " *pchar ]
//!   [ LF "Resources:" *( LF "- " uri ) ]
//! ```
//!
//! The relying-party profile pins `URI`, `Version`, `Chain ID`, `Nonce`
//! and `Issued At` as required; a text missing any of them fails with
//! [`Syntax::MissingField`]. Scheme prefixes are not part of SIWS.

use crate::layout::{MID, SUFFIX, decode, optional_tags, syntax};
use crate::{Error, Field, MAX_MESSAGE_BYTES, Message, MessageFields, Syntax};

const LABEL: &str = "Solana";

/// Format `message` as a SIWS signing text.
///
/// # Errors
///
/// [`Error::InvalidField`] [`Field::Scheme`] when `message` carries a scheme
/// (SIWS has none) and [`Field::Statement`] when the statement is empty.
pub fn format(message: &Message) -> Result<String, Error> {
    if message.scheme().is_some() {
        return Err(Error::field(Field::Scheme, "not supported by SIWS"));
    }
    if let Some(s) = message.statement() {
        if s.is_empty() {
            return Err(Error::field(Field::Statement, "empty"));
        }
        if s.starts_with("URI: ") {
            return Err(Error::field(
                Field::Statement,
                "ambiguous with the URI: tag",
            ));
        }
    }
    let mut out = String::with_capacity(512);
    out.push_str(message.domain());
    out.push_str(MID);
    out.push_str(LABEL);
    out.push_str(SUFFIX);
    out.push('\n');
    out.push_str(message.address());
    if let Some(s) = message.statement() {
        out.push_str("\n\n");
        out.push_str(s);
    }
    out.push_str("\n\nURI: ");
    out.push_str(message.uri());
    out.push_str("\nVersion: ");
    out.push_str(message.version());
    out.push_str("\nChain ID: ");
    out.push_str(message.chain_id());
    out.push_str("\nNonce: ");
    out.push_str(message.nonce());
    out.push_str("\nIssued At: ");
    out.push_str(message.issued_at().as_str());
    if let Some(v) = message.expiration_time() {
        out.push_str("\nExpiration Time: ");
        out.push_str(v.as_str());
    }
    if let Some(v) = message.not_before() {
        out.push_str("\nNot Before: ");
        out.push_str(v.as_str());
    }
    if let Some(v) = message.request_id() {
        out.push_str("\nRequest ID: ");
        out.push_str(v);
    }
    if let Some(rs) = message.resources() {
        out.push_str("\nResources:");
        for r in rs {
            out.push_str("\n- ");
            out.push_str(r);
        }
    }
    Ok(out)
}

/// Parse `text` into a validated [`Message`]; the preamble label must be
/// exactly `"Solana"`.
///
/// # Errors
///
/// [`Error::MessageTooLarge`] over [`MAX_MESSAGE_BYTES`]; [`Error::Syntax`]
/// for layout violations (a missing required field is
/// [`Syntax::MissingField`]); [`Error::Mismatch`] [`Field::Label`] for a
/// non-`"Solana"` label; [`Error::InvalidField`] for malformed values.
pub fn parse(text: &str) -> Result<Message, Error> {
    if text.len() > MAX_MESSAGE_BYTES {
        return Err(Error::MessageTooLarge {
            len: text.len(),
            max: MAX_MESSAGE_BYTES,
        });
    }
    if text.contains('\r') {
        return Err(syntax(Syntax::CarriageReturn));
    }
    if text.ends_with('\n') {
        return Err(syntax(Syntax::UnexpectedTrailing));
    }
    let lines: Vec<&str> = text.split('\n').collect();
    let mut i = 0usize;
    let next = |idx: &mut usize| -> Result<&str, Error> {
        let l = lines
            .get(*idx)
            .copied()
            .ok_or_else(|| syntax(Syntax::UnexpectedEof))?;
        *idx += 1;
        Ok(l)
    };

    // Preamble: `domain MID "Solana" SUFFIX`.
    let preamble = next(&mut i)?;
    let mid = preamble
        .find(MID)
        .ok_or_else(|| syntax(Syntax::MissingPreamble))?;
    let domain = preamble[..mid].to_owned();
    let label = preamble[mid + MID.len()..]
        .strip_suffix(SUFFIX)
        .ok_or_else(|| syntax(Syntax::MissingAccountSuffix))?;
    if label != LABEL {
        return Err(Error::Mismatch {
            field: Field::Label,
            expected: LABEL.to_owned(),
            actual: Some(label.to_owned()),
        });
    }

    let address = next(&mut i)?.to_owned();

    let statement = statement_then_fields(&lines, &mut i)?;

    let take = |idx: &mut usize, tag: &'static str, field: Field| -> Result<String, Error> {
        let v = lines
            .get(*idx)
            .and_then(|l| l.strip_prefix(tag))
            .map(str::to_owned)
            .ok_or_else(|| syntax(Syntax::MissingField(field)))?;
        *idx += 1;
        Ok(v)
    };
    let uri = take(&mut i, "URI: ", Field::Uri)?;
    let version = take(&mut i, "Version: ", Field::Version)?;
    let chain_id = take(&mut i, "Chain ID: ", Field::ChainId)?;
    let nonce = take(&mut i, "Nonce: ", Field::Nonce)?;
    let issued_at = take(&mut i, "Issued At: ", Field::IssuedAt)?;

    let (expiration_time, not_before, request_id, resources) = optional_tags(&lines, i)?;

    Message::new(MessageFields {
        scheme: None,
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

/// The optional statement and the gap up to the required `URI: ` line.
///
/// After the address, one blank line precedes either a single-line
/// statement or the advanced-fields block (which always starts `URI: `);
/// a second blank or an unseparated line is a layout error.
fn statement_then_fields(lines: &[&str], i: &mut usize) -> Result<Option<String>, Error> {
    let missing_uri = || syntax(Syntax::MissingField(Field::Uri));
    match lines.get(*i) {
        None => return Err(missing_uri()),
        Some(&"") => *i += 1,
        Some(_) => return Err(syntax(Syntax::ExpectedBlankLine)),
    }
    match lines.get(*i) {
        None => Err(missing_uri()),
        Some(&"") => Err(syntax(Syntax::ExpectedBlankLine)),
        Some(l) if l.starts_with("URI: ") => Ok(None),
        Some(l) => {
            let statement = (*l).to_owned();
            *i += 1;
            match lines.get(*i) {
                None => Err(missing_uri()),
                Some(&"") => {
                    *i += 1;
                    Ok(Some(statement))
                }
                Some(_) => Err(syntax(Syntax::ExpectedBlankLine)),
            }
        }
    }
}

/// [`parse`] over raw bytes: size check, strict UTF-8
/// ([`Syntax::InvalidUtf8`]), then [`parse`].
///
/// # Errors
///
/// Same as [`parse`].
pub fn parse_bytes(bytes: &[u8]) -> Result<Message, Error> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(Error::MessageTooLarge {
            len: bytes.len(),
            max: MAX_MESSAGE_BYTES,
        });
    }
    parse(decode(bytes)?)
}
