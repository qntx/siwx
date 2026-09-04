//! CAIP-122 abstract data model.
//!
//! Defines [`SiwxMessage`] — the chain-agnostic struct mirroring the CAIP-122
//! data model. Parsing lives in [`crate::parser`], formatting in
//! [`crate::formatter`], validation in [`crate::validate`].

use iri_string::spec::UriSpec;
use iri_string::types::UriString;
use iri_string::validate::authority;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::SiwxError;
use crate::parser::PREAMBLE_MID;

/// CAIP-122 message version (EIP-4361 / CAIP-122 mandate `"1"`).
pub const VERSION: &str = "1";

/// Minimum EIP-4361 nonce length.
pub const MIN_NONCE_LEN: usize = 8;

/// Maximum accepted signing-message size in bytes (denial-of-service bound).
pub const MAX_MESSAGE_BYTES: usize = 16_384;

/// Maximum number of entries in the `Resources` list.
pub const MAX_RESOURCES: usize = 32;

/// Maximum accepted `statement` size in bytes.
pub const MAX_STATEMENT_BYTES: usize = 4_096;

/// Maximum accepted `request_id` size in bytes.
pub const MAX_REQUEST_ID_BYTES: usize = 128;

/// Maximum accepted URI size in bytes (`uri` and each resource).
pub const MAX_URI_BYTES: usize = 2_048;

/// RFC 3339 `date-time` that preserves the original lexical form.
///
/// [`Eq`] requires the same original string **and** the same instant. A builder
/// `2021-09-30T16:25:24Z` is not equal to a parsed `2021-09-30T16:25:24.000Z`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timestamp {
    parsed: OffsetDateTime,
    original: String,
}

impl Timestamp {
    /// Parse an RFC 3339 date-time, keeping `s` verbatim as the original.
    ///
    /// The value must contain `T`/`t` (space separators are rejected) and a
    /// timezone `Z`/`z`/`±HH:MM`. Fractional seconds are allowed and not
    /// normalized.
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError::InvalidTimestamp`] when `s` is not RFC 3339
    /// `date-time`.
    pub fn parse(s: &str) -> Result<Self, SiwxError> {
        if !s.contains('T') && !s.contains('t') {
            return Err(SiwxError::InvalidTimestamp(
                "must contain T date-time separator".into(),
            ));
        }
        if !has_rfc3339_timezone(s) {
            return Err(SiwxError::InvalidTimestamp(
                "must have timezone Z or ±HH:MM".into(),
            ));
        }
        let parsed = OffsetDateTime::parse(s, &Rfc3339)
            .map_err(|e| SiwxError::InvalidTimestamp(e.to_string()))?;
        Ok(Self {
            parsed,
            original: s.to_owned(),
        })
    }

    /// Build from an instant. `original` is `t` formatted as RFC 3339.
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError::InvalidTimestamp`] if `t` cannot be formatted as
    /// RFC 3339.
    pub fn from_datetime(t: OffsetDateTime) -> Result<Self, SiwxError> {
        let original = t
            .format(&Rfc3339)
            .map_err(|e| SiwxError::InvalidTimestamp(e.to_string()))?;
        Ok(Self {
            parsed: t,
            original,
        })
    }

    /// Instant represented by this timestamp.
    #[must_use]
    pub const fn datetime(&self) -> OffsetDateTime {
        self.parsed
    }

    /// Original RFC 3339 lexical form (formatter input).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.original
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Timestamp {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.original)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Timestamp {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// CAIP-122 Sign-In with X message.
///
/// Chain-agnostic; chain-specific formatting and verification live in the
/// `siwx-evm` / `siwx-svm` companion crates.
///
/// See [CAIP-122] for the abstract data model.
///
/// [CAIP-122]: https://chainagnostic.org/CAIPs/caip-122
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SiwxMessage {
    /// Optional RFC 3986 scheme for the EIP-4361 preamble
    /// (`"{scheme}://{domain} wants you…"`).
    pub scheme: Option<String>,

    /// RFC 4501 `dnsauthority` requesting the signing.
    pub domain: String,

    /// Blockchain address performing the signing (CAIP-10 `account_address`
    /// segment — does **not** include the CAIP-2 chain id prefix).
    pub address: String,

    /// Human-readable assertion. When present, non-empty RFC 3986 `reserved` /
    /// `unreserved` / SP (no HT, CR, LF, other CTL, or non-ASCII).
    pub statement: Option<String>,

    /// RFC 3986 URI referring to the resource that is the subject of the signing.
    pub uri: String,

    /// Current version of the message (always [`VERSION`]).
    pub version: String,

    /// Chain identifier — the `reference` segment of a CAIP-2 chain id.
    ///
    /// For EIP-155 chains this is the decimal chain id (e.g. `"1"`).
    /// For Solana this is the genesis hash (e.g.
    /// `"5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"`).
    pub chain_id: String,

    /// Randomised token to prevent replay attacks (≥ [`MIN_NONCE_LEN`] alphanumerics).
    pub nonce: String,

    /// ISO 8601 / RFC 3339 issuance time (original lexical form preserved).
    pub issued_at: Timestamp,

    /// ISO 8601 / RFC 3339 expiration time.
    #[cfg_attr(feature = "serde", serde(default))]
    pub expiration_time: Option<Timestamp>,

    /// ISO 8601 / RFC 3339 earliest valid time.
    #[cfg_attr(feature = "serde", serde(default))]
    pub not_before: Option<Timestamp>,

    /// System-specific request identifier.
    pub request_id: Option<String>,

    /// List of RFC 3986 URI resources.
    #[cfg_attr(feature = "serde", serde(default))]
    pub resources: Vec<String>,
}

impl SiwxMessage {
    /// Create a message with the mandatory CAIP-122 / EIP-4361 fields.
    ///
    /// `version` is fixed to [`VERSION`]. `issued_at` defaults to
    /// [`OffsetDateTime::now_utc`]; override with [`Self::with_issued_at`].
    ///
    /// # Errors
    ///
    /// Returns an error if any mandatory field is empty, domain is malformed,
    /// `uri` is not an RFC 3986 URI, or `nonce` fails [`check_nonce_shape`].
    ///
    /// # Examples
    ///
    /// ```
    /// use siwx::SiwxMessage;
    ///
    /// let msg = SiwxMessage::new(
    ///     "example.com",
    ///     "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
    ///     "https://example.com/login",
    ///     "1",
    ///     "testnonce12345678",
    /// )?;
    /// assert_eq!(msg.version, "1");
    /// # Ok::<(), siwx::SiwxError>(())
    /// ```
    pub fn new(
        domain: impl Into<String>,
        address: impl Into<String>,
        uri: impl Into<String>,
        chain_id: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Result<Self, SiwxError> {
        let domain = check_domain(&domain.into())?;
        let address = non_empty(address.into(), "address")?;
        let uri = check_uri(&uri.into())?;
        let chain_id = non_empty(chain_id.into(), "chain_id")?;
        let nonce = check_nonce_shape(&nonce.into())?;

        Ok(Self {
            scheme: None,
            domain,
            address,
            uri,
            version: VERSION.to_owned(),
            chain_id,
            nonce,
            statement: None,
            issued_at: Timestamp::from_datetime(OffsetDateTime::now_utc())?,
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: Vec::new(),
        })
    }

    /// Set the optional preamble scheme (e.g. `"https"`).
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError::InvalidFormat`] if the scheme is empty, does not
    /// start with ALPHA, or contains characters outside `ALPHA / DIGIT / "+" /
    /// "-" / "."`.
    pub fn with_scheme(mut self, scheme: impl Into<String>) -> Result<Self, SiwxError> {
        self.scheme = Some(check_scheme(&scheme.into())?);
        Ok(self)
    }

    /// Set the human-readable statement.
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError::InvalidStatement`] if the value is empty, exceeds
    /// [`MAX_STATEMENT_BYTES`], or contains characters outside RFC 3986
    /// `reserved` / `unreserved` / SP.
    pub fn with_statement(mut self, statement: impl Into<String>) -> Result<Self, SiwxError> {
        let statement = statement.into();
        check_statement(&statement)?;
        self.statement = Some(statement);
        Ok(self)
    }

    /// Replace the nonce.
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError::InvalidNonce`] if the shape is invalid.
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Result<Self, SiwxError> {
        self.nonce = check_nonce_shape(&nonce.into())?;
        Ok(self)
    }

    /// Set the issuance time from an instant (RFC 3339 original is formatted).
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError::InvalidTimestamp`] if `t` cannot be formatted as
    /// RFC 3339.
    pub fn with_issued_at(mut self, t: OffsetDateTime) -> Result<Self, SiwxError> {
        self.issued_at = Timestamp::from_datetime(t)?;
        Ok(self)
    }

    /// Set the expiration time from an instant.
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError::InvalidTimestamp`] if `t` cannot be formatted as
    /// RFC 3339.
    pub fn with_expiration_time(mut self, t: OffsetDateTime) -> Result<Self, SiwxError> {
        self.expiration_time = Some(Timestamp::from_datetime(t)?);
        Ok(self)
    }

    /// Set the not-before time from an instant.
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError::InvalidTimestamp`] if `t` cannot be formatted as
    /// RFC 3339.
    pub fn with_not_before(mut self, t: OffsetDateTime) -> Result<Self, SiwxError> {
        self.not_before = Some(Timestamp::from_datetime(t)?);
        Ok(self)
    }

    /// Set the issuance time from an RFC 3339 string, preserving `s` verbatim.
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError::InvalidTimestamp`] if `s` is not RFC 3339
    /// `date-time`.
    pub fn with_issued_at_raw(mut self, s: &str) -> Result<Self, SiwxError> {
        self.issued_at = Timestamp::parse(s)?;
        Ok(self)
    }

    /// Set the expiration time from an RFC 3339 string, preserving `s` verbatim.
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError::InvalidTimestamp`] if `s` is not RFC 3339
    /// `date-time`.
    pub fn with_expiration_time_raw(mut self, s: &str) -> Result<Self, SiwxError> {
        self.expiration_time = Some(Timestamp::parse(s)?);
        Ok(self)
    }

    /// Set the not-before time from an RFC 3339 string, preserving `s` verbatim.
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError::InvalidTimestamp`] if `s` is not RFC 3339
    /// `date-time`.
    pub fn with_not_before_raw(mut self, s: &str) -> Result<Self, SiwxError> {
        self.not_before = Some(Timestamp::parse(s)?);
        Ok(self)
    }

    /// Set the request id (`*pchar`, max [`MAX_REQUEST_ID_BYTES`]).
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError::InvalidFormat`] if the value is not RFC 3986 `pchar`
    /// or exceeds the size limit.
    pub fn with_request_id(mut self, rid: impl Into<String>) -> Result<Self, SiwxError> {
        self.request_id = Some(check_request_id(&rid.into())?);
        Ok(self)
    }

    /// Set the resources list (≤ [`MAX_RESOURCES`] RFC 3986 URIs).
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError::InvalidFormat`] if there are too many entries, or
    /// [`SiwxError::InvalidUri`] if any entry is not an RFC 3986 URI.
    pub fn with_resources<I, S>(mut self, resources: I) -> Result<Self, SiwxError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.resources = check_resources(resources.into_iter().map(Into::into))?;
        Ok(self)
    }
}

pub(crate) fn non_empty(s: String, field: &str) -> Result<String, SiwxError> {
    if s.is_empty() {
        return Err(SiwxError::InvalidFormat(format!(
            "{field} must not be empty"
        )));
    }
    Ok(s)
}

pub(crate) fn check_scheme(scheme: &str) -> Result<String, SiwxError> {
    if scheme.is_empty() {
        return Err(SiwxError::InvalidFormat("empty scheme".into()));
    }
    if !scheme
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
    {
        return Err(SiwxError::InvalidFormat(
            "scheme must start with ASCII letter".into(),
        ));
    }
    if !scheme
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
    {
        return Err(SiwxError::InvalidFormat(
            "scheme must be ASCII alphanumeric, '+', '-', or '.'".into(),
        ));
    }
    Ok(scheme.to_owned())
}

pub(crate) fn check_domain(domain: &str) -> Result<String, SiwxError> {
    if domain.is_empty() {
        return Err(SiwxError::InvalidDomain("empty".into()));
    }
    if domain.contains(PREAMBLE_MID) {
        return Err(SiwxError::InvalidDomain(
            "must not contain preamble marker".into(),
        ));
    }
    // Empty authority is valid in iri-string (`file:///`); rejected above.
    authority::<UriSpec>(domain)
        .map_err(|_| SiwxError::InvalidDomain("not RFC 3986 authority".into()))?;
    Ok(domain.to_owned())
}

pub(crate) fn check_statement(statement: &str) -> Result<(), SiwxError> {
    if statement.is_empty() {
        return Err(SiwxError::InvalidStatement("empty".into()));
    }
    if statement.len() > MAX_STATEMENT_BYTES {
        return Err(SiwxError::InvalidStatement(format!(
            "exceeds maximum size of {MAX_STATEMENT_BYTES} bytes, got {}",
            statement.len()
        )));
    }
    if !statement.chars().all(is_statement_char) {
        return Err(SiwxError::InvalidStatement(
            "must be RFC 3986 reserved / unreserved / SP".into(),
        ));
    }
    Ok(())
}

pub(crate) fn check_uri(uri: &str) -> Result<String, SiwxError> {
    if uri.len() > MAX_URI_BYTES {
        return Err(SiwxError::InvalidUri(format!(
            "exceeds maximum size of {MAX_URI_BYTES} bytes, got {}",
            uri.len()
        )));
    }
    UriString::try_from(uri).map_err(|e| SiwxError::InvalidUri(e.to_string()))?;
    Ok(uri.to_owned())
}

pub(crate) fn check_request_id(rid: &str) -> Result<String, SiwxError> {
    if rid.len() > MAX_REQUEST_ID_BYTES {
        return Err(SiwxError::InvalidFormat(format!(
            "request_id exceeds maximum size of {MAX_REQUEST_ID_BYTES} bytes, got {}",
            rid.len()
        )));
    }
    if !is_pchar_string(rid) {
        return Err(SiwxError::InvalidFormat(
            "request_id must be RFC 3986 pchar".into(),
        ));
    }
    Ok(rid.to_owned())
}

pub(crate) fn check_resources(
    resources: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<Vec<String>, SiwxError> {
    let resources: Vec<String> = resources
        .into_iter()
        .map(|uri| uri.as_ref().to_owned())
        .collect();
    if resources.len() > MAX_RESOURCES {
        return Err(SiwxError::invalid_format(format!(
            "too many resources (max {MAX_RESOURCES})"
        )));
    }
    for uri in &resources {
        check_uri(uri)?;
    }
    Ok(resources)
}

/// Validate nonce length and charset (EIP-4361: ≥ 8 alphanumeric).
pub(crate) fn check_nonce_shape(nonce: &str) -> Result<String, SiwxError> {
    if nonce.len() < MIN_NONCE_LEN {
        return Err(SiwxError::InvalidNonce(format!(
            "must be at least {MIN_NONCE_LEN} characters, got {}",
            nonce.len()
        )));
    }
    if !nonce.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(SiwxError::InvalidNonce("must be ASCII alphanumeric".into()));
    }
    Ok(nonce.to_owned())
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
    use time::macros::datetime;

    use super::*;

    #[test]
    fn new_rejects_empty_mandatory_fields() {
        assert!(matches!(
            SiwxMessage::new("", "a", "https://d.com", "1", "testnonce12345678").unwrap_err(),
            SiwxError::InvalidDomain(_)
        ));
        assert!(matches!(
            SiwxMessage::new("d.com", "", "https://d.com", "1", "testnonce12345678").unwrap_err(),
            SiwxError::InvalidFormat(_)
        ));
    }

    #[test]
    fn new_rejects_short_nonce() {
        assert!(matches!(
            SiwxMessage::new("d.com", "a", "https://d.com", "1", "short").unwrap_err(),
            SiwxError::InvalidNonce(_)
        ));
    }

    #[test]
    fn new_sets_version_one() {
        let msg = SiwxMessage::new("d.com", "a", "https://d.com", "1", "testnonce12345678")
            .expect("valid");
        assert_eq!(msg.version, VERSION);
    }

    #[test]
    fn new_rejects_invalid_uri() {
        assert!(matches!(
            SiwxMessage::new(
                "d.com",
                "a",
                "not a valid uri ::: bad",
                "1",
                "testnonce12345678"
            )
            .unwrap_err(),
            SiwxError::InvalidUri(_)
        ));
    }

    #[test]
    fn builder_chains_all_setters() {
        let msg = SiwxMessage::new("d.com", "a", "https://d.com", "1", "testnonce12345678")
            .expect("valid")
            .with_statement("hi")
            .expect("statement")
            .with_request_id("rid")
            .expect("request_id")
            .with_resources(["https://r.com"])
            .expect("resources");
        assert_eq!(msg.statement.as_deref(), Some("hi"));
        assert_eq!(msg.nonce, "testnonce12345678");
        assert_eq!(msg.request_id.as_deref(), Some("rid"));
        assert_eq!(msg.resources, ["https://r.com"]);
    }

    #[test]
    fn with_statement_rejects_newline() {
        let err = SiwxMessage::new("d.com", "a", "https://d.com", "1", "testnonce12345678")
            .expect("valid")
            .with_statement("bad\nline")
            .unwrap_err();
        assert!(matches!(err, SiwxError::InvalidStatement(_)));
    }

    #[test]
    fn with_statement_rejects_empty() {
        let err = SiwxMessage::new("d.com", "a", "https://d.com", "1", "testnonce12345678")
            .expect("valid")
            .with_statement("")
            .unwrap_err();
        assert!(matches!(err, SiwxError::InvalidStatement(_)));
    }

    #[test]
    fn domain_rejects_preamble_injection() {
        let evil = format!("evil.com{PREAMBLE_MID}Ethereum account:\n0x");
        assert!(matches!(
            SiwxMessage::new(&evil, "a", "https://d.com", "1", "testnonce12345678").unwrap_err(),
            SiwxError::InvalidDomain(_)
        ));
    }

    #[test]
    fn domain_accepts_rfc3986_authority() {
        for domain in [
            "example.com",
            "example.com:3388",
            "localhost:8080",
            "127.0.0.1",
            "127.0.0.1:8080",
            "test@127.0.0.1",
            "[::cafe]",
        ] {
            let result = SiwxMessage::new(domain, "a", "https://d.com", "1", "testnonce12345678");
            assert!(
                result.is_ok(),
                "{domain} should be a valid authority: {result:?}"
            );
        }
    }

    #[test]
    fn domain_rejects_empty_and_non_authority() {
        assert!(matches!(
            SiwxMessage::new("", "a", "https://d.com", "1", "testnonce12345678").unwrap_err(),
            SiwxError::InvalidDomain(_)
        ));
        assert!(matches!(
            SiwxMessage::new(
                "#notrfc4501",
                "a",
                "https://d.com",
                "1",
                "testnonce12345678"
            )
            .unwrap_err(),
            SiwxError::InvalidDomain(_)
        ));
    }

    #[test]
    fn scheme_must_start_with_alpha() {
        let base = SiwxMessage::new("d.com", "a", "https://d.com", "1", "testnonce12345678")
            .expect("valid");
        let err = base.clone().with_scheme("1http").unwrap_err();
        assert!(matches!(err, SiwxError::InvalidFormat(_)));
        let https = base.with_scheme("https").expect("alpha scheme");
        assert_eq!(https.scheme.as_deref(), Some("https"));
    }

    #[test]
    fn timestamp_parse_preserves_original() {
        let raw = "2021-09-30T16:25:24.000Z";
        let ts = Timestamp::parse(raw).expect("parse");
        assert_eq!(ts.as_str(), raw);
        assert_eq!(ts.datetime(), datetime!(2021-09-30 16:25:24 UTC));
    }

    #[test]
    fn timestamp_parse_rejects_space_separator_and_missing_tz() {
        assert!(Timestamp::parse("2021-09-30 16:25:24Z").is_err());
        assert!(Timestamp::parse("2021-09-30T16:25:24").is_err());
    }

    #[test]
    fn timestamp_eq_requires_original_and_instant() {
        let parsed = Timestamp::parse("2021-09-30T16:25:24.000Z").expect("parse");
        let built = Timestamp::from_datetime(parsed.datetime()).expect("format");
        assert_ne!(parsed, built);
        assert_eq!(parsed.datetime(), built.datetime());
    }

    #[test]
    fn format_parse_preserves_raw_timestamp() {
        let raw_ts = "2021-09-30T16:25:24.000Z";
        let msg = SiwxMessage::new("d.com", "a", "https://d.com", "1", "testnonce12345678")
            .expect("valid")
            .with_issued_at_raw(raw_ts)
            .expect("issued_at");
        let formatted = msg.to_sign_string("Ethereum");
        let reparsed: SiwxMessage = formatted.parse().expect("parse");
        assert_eq!(reparsed.to_sign_string("Ethereum"), formatted);
        assert_eq!(reparsed.issued_at.as_str(), raw_ts);
    }
}
