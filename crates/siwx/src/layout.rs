//! Shared pieces of the CAIP-122 text layouts (eip4361 and SIWS):
//! the preamble infix/suffix, the `Syntax` error shorthand, the
//! size + UTF-8 pre-decode, and the optional trailing tags.

use crate::message::MAX_MESSAGE_BYTES;
use crate::{Error, Syntax};

pub(crate) const MID: &str = " wants you to sign in with your ";
pub(crate) const SUFFIX: &str = " account:";

pub(crate) const fn syntax(kind: Syntax) -> Error {
    Error::Syntax(kind)
}

/// Decode `bytes`: [`Error::MessageTooLarge`] over [`MAX_MESSAGE_BYTES`],
/// [`Syntax::InvalidUtf8`] on ill-formed UTF-8.
pub(crate) fn decode(bytes: &[u8]) -> Result<&str, Error> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(Error::MessageTooLarge {
            len: bytes.len(),
            max: MAX_MESSAGE_BYTES,
        });
    }
    std::str::from_utf8(bytes).map_err(|_| syntax(Syntax::InvalidUtf8))
}

pub(crate) type OptionalTail = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Vec<String>>,
);

/// Parse the optional trailing tags in fixed ABNF order:
/// `Expiration Time`, `Not Before`, `Request ID`, `Resources` (with `- `
/// items). Each may appear at most once and only in this order.
pub(crate) fn optional_tags(lines: &[&str], mut i: usize) -> Result<OptionalTail, Error> {
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
