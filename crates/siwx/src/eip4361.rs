//! ERC-4361 signing-text layout (CAIP-122 text profile).
//!
//! [`format()`] emits the exact ABNF text for a [`Message`] under a
//! caller-supplied preamble `label` (`"Ethereum"`, `"Solana"`, …).
//! [`parse`] is its strict inverse: for every accepted text `t`,
//! `format(label, parse(t).message) == t` byte-for-byte.

use crate::message::MAX_MESSAGE_BYTES;
use crate::{Error, Field, Message, MessageFields, Syntax};

const MID: &str = " wants you to sign in with your ";
const SUFFIX: &str = " account:";

/// Result of [`parse`]: the preamble label plus the validated message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// Text between ` wants you to sign in with your ` and ` account:`.
    pub label: String,
    /// The parsed message.
    pub message: Message,
}

/// Render `message` as an ERC-4361 signing text under `label`.
///
/// The `label` is embedded verbatim between ` wants you to sign in with your `
/// and ` account:`; callers use their chain's human-readable name.
#[must_use]
pub fn format(label: &str, message: &Message) -> String {
    let mut out = String::new();
    if let Some(scheme) = message.scheme() {
        out.push_str(scheme);
        out.push_str("://");
    }
    out.push_str(message.domain());
    out.push_str(MID);
    out.push_str(label);
    out.push_str(SUFFIX);
    out.push('\n');
    out.push_str(message.address());
    out.push_str("\n\n");
    if let Some(statement) = message.statement() {
        out.push_str(statement);
        out.push('\n');
    }
    out.push('\n');
    out.push_str("URI: ");
    out.push_str(message.uri());
    out.push('\n');
    out.push_str("Version: ");
    out.push_str(message.version());
    out.push('\n');
    out.push_str("Chain ID: ");
    out.push_str(message.chain_id());
    out.push('\n');
    out.push_str("Nonce: ");
    out.push_str(message.nonce());
    out.push('\n');
    out.push_str("Issued At: ");
    out.push_str(message.issued_at().as_str());
    if let Some(exp) = message.expiration_time() {
        out.push('\n');
        out.push_str("Expiration Time: ");
        out.push_str(exp.as_str());
    }
    if let Some(nbf) = message.not_before() {
        out.push('\n');
        out.push_str("Not Before: ");
        out.push_str(nbf.as_str());
    }
    if let Some(request_id) = message.request_id() {
        out.push('\n');
        out.push_str("Request ID: ");
        out.push_str(request_id);
    }
    if let Some(resources) = message.resources() {
        out.push_str("\nResources:");
        for uri in resources {
            out.push_str("\n- ");
            out.push_str(uri);
        }
    }
    out
}

const fn syntax(kind: Syntax) -> Error {
    Error::Syntax(kind)
}

/// Parse `text` into a label + validated [`Message`].
///
/// # Errors
///
/// [`Error::MessageTooLarge`] when `text` exceeds
/// [`MAX_MESSAGE_BYTES`]; [`Error::Syntax`] for layout violations;
/// [`Error::InvalidField`] for malformed field values.
pub fn parse(text: &str) -> Result<Parsed, Error> {
    if text.len() > MAX_MESSAGE_BYTES {
        return Err(Error::MessageTooLarge {
            len: text.len(),
            max: MAX_MESSAGE_BYTES,
        });
    }
    if text.contains('\r') {
        return Err(syntax(Syntax::CarriageReturn));
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

    // Preamble: `[scheme "://"] domain MID label SUFFIX`.
    let preamble = next(&mut i)?;
    let mid = preamble
        .find(MID)
        .ok_or_else(|| syntax(Syntax::MissingPreamble))?;
    let head = &preamble[..mid];
    let tail = &preamble[mid + MID.len()..];
    let label = tail
        .strip_suffix(SUFFIX)
        .ok_or_else(|| syntax(Syntax::MissingAccountSuffix))?;
    if label.is_empty() {
        return Err(Error::field(Field::Label, "empty"));
    }
    let (scheme, domain) = match head.split_once("://") {
        Some((s, d)) => (Some(s.to_owned()), d.to_owned()),
        None => (None, head.to_owned()),
    };

    let address = next(&mut i)?.to_owned();

    // `address LF LF [statement LF] LF`: one blank then a line = statement;
    // two blanks = absent; three = empty statement; anything else malformed.
    let mut blanks = 0usize;
    while lines.get(i + blanks) == Some(&"") {
        blanks += 1;
    }
    let statement = match blanks {
        1 => {
            i += 1; // consume the blank
            let s = next(&mut i)?.to_owned();
            if !next(&mut i)?.is_empty() {
                return Err(syntax(Syntax::ExpectedBlankLine));
            }
            Some(s)
        }
        2 => {
            i += 2;
            None
        }
        3 => {
            i += 3;
            Some(String::new())
        }
        _ => return Err(syntax(Syntax::ExpectedBlankLine)),
    };

    // Required tags in order.
    let take_tag = |line: &str, tag: &str, field: Field| -> Result<String, Error> {
        line.strip_prefix(tag)
            .map(str::to_owned)
            .ok_or_else(|| syntax(Syntax::MissingField(field)))
    };

    let uri = take_tag(next(&mut i)?, "URI: ", Field::Uri)?;
    let version = take_tag(next(&mut i)?, "Version: ", Field::Version)?;
    let chain_id = take_tag(next(&mut i)?, "Chain ID: ", Field::ChainId)?;
    let nonce = take_tag(next(&mut i)?, "Nonce: ", Field::Nonce)?;
    let issued_at = take_tag(next(&mut i)?, "Issued At: ", Field::IssuedAt)?;

    let (expiration_time, not_before, request_id, resources) = optional_tags(&lines, i)?;

    let fields = MessageFields {
        scheme,
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
    };
    let message = Message::new(fields)?;
    Ok(Parsed {
        label: label.to_owned(),
        message,
    })
}

type OptionalTail = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Vec<String>>,
);

/// Parse the optional trailing tags in fixed ABNF order:
/// `Expiration Time`, `Not Before`, `Request ID`, `Resources` (with `- `
/// items). Each may appear at most once and only in this order.
fn optional_tags(lines: &[&str], mut i: usize) -> Result<OptionalTail, Error> {
    let mut expiration_time = None;
    let mut not_before = None;
    let mut request_id = None;
    let mut resources = None;

    if let Some(v) = lines
        .get(i)
        .and_then(|l| l.strip_prefix("Expiration Time: "))
    {
        expiration_time = Some(v.to_owned());
        i += 1;
    }
    if let Some(v) = lines.get(i).and_then(|l| l.strip_prefix("Not Before: ")) {
        not_before = Some(v.to_owned());
        i += 1;
    }
    if let Some(v) = lines.get(i).and_then(|l| l.strip_prefix("Request ID: ")) {
        request_id = Some(v.to_owned());
        i += 1;
    }
    if lines.get(i) == Some(&"Resources:") {
        i += 1;
        let mut list = Vec::new();
        while let Some(&r) = lines.get(i) {
            if let Some(v) = r.strip_prefix("- ") {
                list.push(v.to_owned());
                i += 1;
            } else if r.starts_with('-') {
                return Err(syntax(Syntax::ResourceSyntax));
            } else {
                return Err(syntax(Syntax::UnexpectedTrailing));
            }
        }
        resources = Some(list);
    }
    if i != lines.len() {
        return Err(syntax(Syntax::UnexpectedTrailing));
    }
    Ok((expiration_time, not_before, request_id, resources))
}

/// [`parse_bytes`] plus a required preamble `label`.
///
/// # Errors
///
/// [`Error::Mismatch`] [`Field::Label`] when the parsed label differs,
/// plus [`parse_bytes`] errors.
pub fn parse_labeled(label: &str, signed: &[u8]) -> Result<Message, Error> {
    let parsed = parse_bytes(signed)?;
    if parsed.label != label {
        return Err(Error::Mismatch {
            field: Field::Label,
            expected: label.to_owned(),
            actual: Some(parsed.label),
        });
    }
    Ok(parsed.message)
}

/// Parse `bytes`: size check, UTF-8 ([`Syntax::InvalidUtf8`]), then [`parse`].
///
/// # Errors
///
/// Same as [`parse`].
pub fn parse_bytes(bytes: &[u8]) -> Result<Parsed, Error> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(Error::MessageTooLarge {
            len: bytes.len(),
            max: MAX_MESSAGE_BYTES,
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| syntax(Syntax::InvalidUtf8))?;
    parse(text)
}
