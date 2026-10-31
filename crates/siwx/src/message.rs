//! CAIP-122 abstract data model.
//!
//! [`MessageFields`] is the plain lexical form (all strings); [`Message::new`]
//! is the single validation path producing a checked [`Message`]. Text layout
//! lives in [`crate::eip4361`], binding checks in [`crate::Expect`].

use std::fmt;

use iri_string::spec::UriSpec;
use iri_string::types::UriString;
use iri_string::validate::authority;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{Error, Field};

/// Minimum EIP-4361 nonce length.
pub const MIN_NONCE_LEN: usize = 8;

/// Maximum accepted signing-text size in bytes.
pub const MAX_MESSAGE_BYTES: usize = 16_384;

/// Maximum number of entries in the `Resources` list.
pub const MAX_RESOURCES: usize = 32;

/// Maximum accepted `statement` size in bytes.
pub const MAX_STATEMENT_BYTES: usize = 4_096;

/// Maximum accepted `request_id` size in bytes.
pub const MAX_REQUEST_ID_BYTES: usize = 128;

/// Maximum accepted URI size in bytes (`uri` and each resource).
pub const MAX_URI_BYTES: usize = 2_048;

/// RFC 3339 `date-time` preserving the original lexical form.
///
/// [`Eq`] requires the same instant **and** the same lexeme:
/// `2021-09-30T16:25:24Z` is not equal to `2021-09-30T16:25:24.000Z`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timestamp {
    instant: OffsetDateTime,
    lexeme: String,
}

impl Timestamp {
    /// Parse an RFC 3339 `date-time`, keeping `s` verbatim as the lexeme.
    ///
    /// Returns `None` when `s` lacks a `T`/`t` separator or `Z`/`z`/`±HH:MM`
    /// zone, is not RFC 3339, or names a nonexistent calendar instant.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        if !s.contains('T') && !s.contains('t') {
            return None;
        }
        if !has_rfc3339_timezone(s) {
            return None;
        }
        let instant = OffsetDateTime::parse(s, &Rfc3339).ok()?;
        Some(Self {
            instant,
            lexeme: s.to_owned(),
        })
    }

    /// Build from an instant as JavaScript `Date.prototype.toISOString()`:
    /// UTC, truncated to milliseconds, `YYYY-MM-DDTHH:MM:SS.sssZ`.
    ///
    /// Returns `None` when the year is outside `0000..=9999`.
    #[must_use]
    pub fn from_instant(instant: OffsetDateTime) -> Option<Self> {
        let utc = instant.to_offset(time::UtcOffset::UTC);
        let millis = utc
            .replace_nanosecond(utc.nanosecond() / 1_000_000 * 1_000_000)
            .ok()?;
        let (year, month, day) = (utc.year(), u8::from(utc.month()), utc.day());
        if !(0..=9999).contains(&year) {
            return None;
        }
        let lexeme = format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
            utc.hour(),
            utc.minute(),
            utc.second(),
            millis.millisecond(),
        );
        Some(Self {
            instant: millis,
            lexeme,
        })
    }

    /// Original RFC 3339 lexical form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.lexeme
    }

    /// Instant represented by this timestamp.
    #[must_use]
    pub const fn instant(&self) -> OffsetDateTime {
        self.instant
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.lexeme)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Timestamp {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.lexeme)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Timestamp {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::custom("invalid RFC 3339 date-time"))
    }
}

/// Plain lexical form of a CAIP-122 message (all strings, `Option` = absent).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct MessageFields {
    /// Optional RFC 3986 scheme prefixing the domain.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub scheme: Option<String>,
    /// RFC 3986 `authority` requesting the signing.
    pub domain: String,
    /// Blockchain address performing the signing.
    pub address: String,
    /// Human-readable assertion (may be empty when present).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub statement: Option<String>,
    /// RFC 3986 URI the message refers to.
    pub uri: String,
    /// Message version — must be `"1"`.
    pub version: String,
    /// CAIP-2 `chain-id` string.
    pub chain_id: String,
    /// Replay-prevention token.
    pub nonce: String,
    /// RFC 3339 `issued-at` date-time.
    pub issued_at: String,
    /// RFC 3339 `expiration-time` date-time.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub expiration_time: Option<String>,
    /// RFC 3339 `not-before` date-time.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub not_before: Option<String>,
    /// Opaque `request-id` (`*pchar`).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub request_id: Option<String>,
    /// `Resources:` URI list (may be empty when present).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub resources: Option<Vec<String>>,
}

/// Validated CAIP-122 Sign-In with X message.
///
/// Constructed only via [`Message::new`], which is the single validation
/// path — the [`crate::eip4361`] parser goes through it as well.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "MessageFields"))]
pub struct Message {
    /// Lexical fields as supplied (preserved byte-for-byte by `into_fields`).
    fields: MessageFields,
    /// Parsed `issued-at`.
    issued_at: Timestamp,
    /// Parsed `expiration-time`.
    expiration_time: Option<Timestamp>,
    /// Parsed `not-before`.
    not_before: Option<Timestamp>,
}

impl TryFrom<MessageFields> for Message {
    type Error = Error;

    fn try_from(fields: MessageFields) -> Result<Self, Self::Error> {
        Self::new(fields)
    }
}

impl Message {
    /// Validate `fields` and build a message. Field order of checks:
    /// scheme, domain, address, statement, uri, version, chain-id, nonce,
    /// issued-at, expiration-time, not-before, request-id, resources.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidField`] naming the first invalid field.
    pub fn new(fields: MessageFields) -> Result<Self, Error> {
        if let Some(scheme) = &fields.scheme {
            check_scheme(scheme)?;
        }
        check_domain(&fields.domain)?;
        check_address(&fields.address)?;
        if let Some(statement) = &fields.statement {
            check_statement(statement)?;
        }
        check_uri(&fields.uri, Field::Uri)?;
        if fields.version != "1" {
            return Err(Error::field(Field::Version, "must be \"1\""));
        }
        check_chain_id(&fields.chain_id)?;
        check_nonce(&fields.nonce)?;
        let issued_at = Timestamp::parse(&fields.issued_at)
            .ok_or_else(|| Error::field(Field::IssuedAt, "not an RFC 3339 date-time"))?;
        let expiration_time = fields
            .expiration_time
            .as_deref()
            .map(|s| {
                Timestamp::parse(s)
                    .ok_or_else(|| Error::field(Field::ExpirationTime, "not an RFC 3339 date-time"))
            })
            .transpose()?;
        let not_before = fields
            .not_before
            .as_deref()
            .map(|s| {
                Timestamp::parse(s)
                    .ok_or_else(|| Error::field(Field::NotBefore, "not an RFC 3339 date-time"))
            })
            .transpose()?;
        if let Some(request_id) = &fields.request_id {
            check_request_id(request_id)?;
        }
        if let Some(resources) = &fields.resources {
            check_resources(resources)?;
        }
        Ok(Self {
            fields,
            issued_at,
            expiration_time,
            not_before,
        })
    }

    /// Optional RFC 3986 scheme.
    #[must_use]
    pub fn scheme(&self) -> Option<&str> {
        self.fields.scheme.as_deref()
    }

    /// RFC 3986 `authority` requesting the signing.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.fields.domain
    }

    /// Signing address.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.fields.address
    }

    /// Optional statement (may be empty when present).
    #[must_use]
    pub fn statement(&self) -> Option<&str> {
        self.fields.statement.as_deref()
    }

    /// `URI` field.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.fields.uri
    }

    /// Message version (`"1"`).
    #[must_use]
    pub fn version(&self) -> &str {
        &self.fields.version
    }

    /// `chain-id` string.
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.fields.chain_id
    }

    /// Nonce.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.fields.nonce
    }

    /// `issued-at` timestamp.
    #[must_use]
    pub const fn issued_at(&self) -> &Timestamp {
        &self.issued_at
    }

    /// `expiration-time` timestamp.
    #[must_use]
    pub const fn expiration_time(&self) -> Option<&Timestamp> {
        self.expiration_time.as_ref()
    }

    /// `not-before` timestamp.
    #[must_use]
    pub const fn not_before(&self) -> Option<&Timestamp> {
        self.not_before.as_ref()
    }

    /// `request-id` (may be empty when present).
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.fields.request_id.as_deref()
    }

    /// `Resources` list (may be empty when present).
    #[must_use]
    pub fn resources(&self) -> Option<&[String]> {
        self.fields.resources.as_deref()
    }

    /// Consume the message into its lexical fields.
    #[must_use]
    pub fn into_fields(self) -> MessageFields {
        self.fields
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Message {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.fields.serialize(serializer)
    }
}

fn check_scheme(scheme: &str) -> Result<(), Error> {
    let bad = || Error::field(Field::Scheme, "not an RFC 3986 scheme");
    if scheme.is_empty()
        || !scheme
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return Err(bad());
    }
    Ok(())
}

fn check_domain(domain: &str) -> Result<(), Error> {
    if domain.is_empty() {
        return Err(Error::field(Field::Domain, "empty"));
    }
    if domain.contains('@') {
        // ERC-4361 erratum signinwithethereum/ERCs#1: userinfo rejected.
        return Err(Error::field(Field::Domain, "userinfo not allowed"));
    }
    if domain.starts_with(':') {
        // `@` is rejected above, so a leading `:` means `userinfo@` is
        // absent and the host is empty (`":8080"`); IP-literals start `[`.
        return Err(Error::field(Field::Domain, "empty host"));
    }
    authority::<UriSpec>(domain)
        .map_err(|_| Error::field(Field::Domain, "not an RFC 3986 authority"))?;
    Ok(())
}

fn check_address(address: &str) -> Result<(), Error> {
    if !(1..=128).contains(&address.len()) {
        return Err(Error::field(Field::Address, "expected 1..=128 characters"));
    }
    if !address
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'%'))
    {
        return Err(Error::field(Field::Address, "bad CAIP-10 charset"));
    }
    Ok(())
}

fn check_statement(statement: &str) -> Result<(), Error> {
    if statement.len() > MAX_STATEMENT_BYTES {
        return Err(Error::field(Field::Statement, "exceeds maximum size"));
    }
    if !statement.chars().all(is_statement_char) {
        return Err(Error::field(
            Field::Statement,
            "must be RFC 3986 reserved / unreserved / SP",
        ));
    }
    Ok(())
}

fn check_uri(uri: &str, field: Field) -> Result<(), Error> {
    if uri.is_empty() {
        return Err(Error::field(field, "empty"));
    }
    if uri.len() > MAX_URI_BYTES {
        return Err(Error::field(field, "exceeds maximum size"));
    }
    UriString::try_from(uri).map_err(|_| Error::field(field, "not an RFC 3986 URI"))?;
    Ok(())
}

fn check_chain_id(chain_id: &str) -> Result<(), Error> {
    if chain_id.is_empty() {
        return Err(Error::field(Field::ChainId, "empty"));
    }
    if chain_id.len() > 64 {
        return Err(Error::field(Field::ChainId, "exceeds 64 characters"));
    }
    if !chain_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':'))
    {
        return Err(Error::field(Field::ChainId, "bad charset"));
    }
    Ok(())
}

fn check_nonce(nonce: &str) -> Result<(), Error> {
    if nonce.len() < MIN_NONCE_LEN {
        return Err(Error::field(Field::Nonce, "too short"));
    }
    if !nonce.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(Error::field(Field::Nonce, "not ASCII alphanumeric"));
    }
    Ok(())
}

fn check_request_id(request_id: &str) -> Result<(), Error> {
    if request_id.len() > MAX_REQUEST_ID_BYTES {
        return Err(Error::field(Field::RequestId, "exceeds maximum size"));
    }
    if !is_pchar_string(request_id) {
        return Err(Error::field(Field::RequestId, "must be RFC 3986 *pchar"));
    }
    Ok(())
}

fn check_resources(resources: &[String]) -> Result<(), Error> {
    if resources.len() > MAX_RESOURCES {
        return Err(Error::field(Field::Resources, "too many"));
    }
    for uri in resources {
        check_uri(uri, Field::Resources)?;
    }
    Ok(())
}

const fn has_rfc3339_timezone(s: &str) -> bool {
    match s.as_bytes() {
        [.., b'Z' | b'z'] => true,
        [.., b'+' | b'-', h1, h2, b':', m1, m2]
            if h1.is_ascii_digit()
                && h2.is_ascii_digit()
                && m1.is_ascii_digit()
                && m2.is_ascii_digit() =>
        {
            true
        }
        _ => false,
    }
}

const fn is_statement_char(c: char) -> bool {
    matches!(
        c,
        'A'..='Z'
            | 'a'..='z'
            | '0'..='9'
            | '-'
            | '.'
            | '_'
            | '~'
            | ':'
            | '/'
            | '?'
            | '#'
            | '['
            | ']'
            | '@'
            | '!'
            | '$'
            | '&'
            | '\''
            | '('
            | ')'
            | '*'
            | '+'
            | ','
            | ';'
            | '='
            | ' '
    )
}

const fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

const fn is_sub_delim(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}

fn is_pchar_string(s: &str) -> bool {
    let mut bytes = s.as_bytes().iter().copied();
    while let Some(c) = bytes.next() {
        if is_unreserved(c) || is_sub_delim(c) || c == b':' || c == b'@' {
            continue;
        }
        if c == b'%' {
            let h1 = bytes.next();
            let h2 = bytes.next();
            if h1.is_some_and(|h| h.is_ascii_hexdigit())
                && h2.is_some_and(|h| h.is_ascii_hexdigit())
            {
                continue;
            }
        }
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_empty_host_is_rejected() {
        let fields = MessageFields {
            domain: ":8080".into(),
            address: "0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946".into(),
            uri: "https://x".into(),
            version: "1".into(),
            chain_id: "1".into(),
            nonce: "12341234".into(),
            issued_at: "2022-03-17T12:45:13.610Z".into(),
            ..Default::default()
        };
        let err = Message::new(fields).expect_err("must fail");
        assert!(
            matches!(
                err,
                Error::InvalidField {
                    field: Field::Domain,
                    reason: "empty host"
                }
            ),
            "got {err:?}"
        );
    }
}
