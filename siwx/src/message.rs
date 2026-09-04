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

#[cfg(feature = "serde")]
use crate::error::FormatReason;
use crate::error::{ChainIdReason, SiwxError};
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
            return Err(SiwxError::InvalidTimestamp {
                reason: "must contain T date-time separator".into(),
            });
        }
        if !has_rfc3339_timezone(s) {
            return Err(SiwxError::InvalidTimestamp {
                reason: "must have timezone Z or ±HH:MM".into(),
            });
        }
        let parsed =
            OffsetDateTime::parse(s, &Rfc3339).map_err(|e| SiwxError::InvalidTimestamp {
                reason: e.to_string(),
            })?;
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
            .map_err(|e| SiwxError::InvalidTimestamp {
                reason: e.to_string(),
            })?;
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

/// Application-JSON DTO. [`TryFrom`] runs the same `check_*` path as `new` / `FromStr`.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct SiwxMessageDto {
    #[serde(default)]
    scheme: Option<String>,
    domain: String,
    address: String,
    #[serde(default)]
    statement: Option<String>,
    uri: String,
    version: String,
    chain_id: String,
    #[serde(default)]
    chain_name: Option<String>,
    nonce: String,
    issued_at: Timestamp,
    #[serde(default)]
    expiration_time: Option<Timestamp>,
    #[serde(default)]
    not_before: Option<Timestamp>,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    resources: Vec<String>,
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
#[cfg_attr(feature = "serde", serde(try_from = "SiwxMessageDto"))]
pub struct SiwxMessage {
    /// Optional RFC 3986 scheme for the EIP-4361 preamble
    /// (`"{scheme}://{domain} wants you…"`).
    #[cfg_attr(feature = "serde", serde(default))]
    scheme: Option<String>,

    /// RFC 3986 `authority` requesting the signing.
    domain: String,

    /// Blockchain address performing the signing (CAIP-10 `account_address`
    /// segment — does **not** include the CAIP-2 chain id prefix).
    address: String,

    /// Human-readable assertion. When present, non-empty RFC 3986 `reserved` /
    /// `unreserved` / SP (no HT, CR, LF, other CTL, or non-ASCII).
    #[cfg_attr(feature = "serde", serde(default))]
    statement: Option<String>,

    /// RFC 3986 URI referring to the resource that is the subject of the signing.
    uri: String,

    /// Current version of the message (always [`VERSION`]).
    version: String,

    /// Chain identifier — the `reference` segment of a CAIP-2 chain id.
    ///
    /// For EIP-155 chains this is the decimal chain id (e.g. `"1"`).
    /// For Solana this is the genesis hash (e.g.
    /// `"5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"`).
    chain_id: String,

    /// Preamble chain label (`"Ethereum"`, `"Solana"`).
    ///
    /// Set by parse; [`Self::new`] leaves this `None`. Formatting still takes
    /// the verifier chain name as an argument, not this field.
    #[cfg_attr(feature = "serde", serde(default))]
    chain_name: Option<String>,

    /// Randomised token to prevent replay attacks (≥ [`MIN_NONCE_LEN`] alphanumerics).
    nonce: String,

    /// ISO 8601 / RFC 3339 issuance time (original lexical form preserved).
    issued_at: Timestamp,

    /// ISO 8601 / RFC 3339 expiration time.
    #[cfg_attr(feature = "serde", serde(default))]
    expiration_time: Option<Timestamp>,

    /// ISO 8601 / RFC 3339 earliest valid time.
    #[cfg_attr(feature = "serde", serde(default))]
    not_before: Option<Timestamp>,

    /// System-specific request identifier.
    #[cfg_attr(feature = "serde", serde(default))]
    request_id: Option<String>,

    /// List of RFC 3986 URI resources.
    #[cfg_attr(feature = "serde", serde(default))]
    resources: Vec<String>,
}

#[cfg(feature = "serde")]
impl TryFrom<SiwxMessageDto> for SiwxMessage {
    type Error = SiwxError;

    fn try_from(dto: SiwxMessageDto) -> Result<Self, Self::Error> {
        let scheme = dto.scheme.map(|s| check_scheme(&s)).transpose()?;
        let domain = check_domain(&dto.domain)?;
        if dto.address.is_empty() {
            return Err(SiwxError::InvalidAddress {
                reason: "empty".into(),
            });
        }
        if let Some(ref statement) = dto.statement {
            check_statement(statement)?;
        }
        let uri = check_uri(&dto.uri)?;
        if dto.version != VERSION {
            return Err(SiwxError::InvalidFormat {
                reason: FormatReason::VersionNotOne,
            });
        }
        if dto.chain_id.is_empty() {
            return Err(SiwxError::InvalidChainId {
                reason: ChainIdReason::Empty,
            });
        }
        let nonce = check_nonce_shape(&dto.nonce)?;
        let request_id = dto
            .request_id
            .map(|rid| check_request_id(&rid))
            .transpose()?;
        let resources = check_resources(dto.resources)?;
        Ok(Self {
            scheme,
            domain,
            address: dto.address,
            statement: dto.statement,
            uri,
            version: dto.version,
            chain_id: dto.chain_id,
            chain_name: dto.chain_name,
            nonce,
            issued_at: dto.issued_at,
            expiration_time: dto.expiration_time,
            not_before: dto.not_before,
            request_id,
            resources,
        })
    }
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
    /// assert_eq!(msg.version(), "1");
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
        let address = address.into();
        if address.is_empty() {
            return Err(SiwxError::InvalidAddress {
                reason: "empty".into(),
            });
        }
        let uri = check_uri(&uri.into())?;
        let chain_id = chain_id.into();
        if chain_id.is_empty() {
            return Err(SiwxError::InvalidChainId {
                reason: ChainIdReason::Empty,
            });
        }
        let nonce = check_nonce_shape(&nonce.into())?;

        Ok(Self {
            scheme: None,
            domain,
            address,
            uri,
            version: VERSION.to_owned(),
            chain_id,
            chain_name: None,
            nonce,
            statement: None,
            issued_at: Timestamp::from_datetime(OffsetDateTime::now_utc())?,
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: Vec::new(),
        })
    }

    /// Assemble a message from ABNF-parsed, already-checked fields.
    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors the parsed CAIP-122 field set"
    )]
    pub(crate) const fn from_parsed(
        scheme: Option<String>,
        domain: String,
        address: String,
        statement: Option<String>,
        uri: String,
        version: String,
        chain_id: String,
        chain_name: Option<String>,
        nonce: String,
        issued_at: Timestamp,
        expiration_time: Option<Timestamp>,
        not_before: Option<Timestamp>,
        request_id: Option<String>,
        resources: Vec<String>,
    ) -> Self {
        Self {
            scheme,
            domain,
            address,
            statement,
            uri,
            version,
            chain_id,
            chain_name,
            nonce,
            issued_at,
            expiration_time,
            not_before,
            request_id,
            resources,
        }
    }

    /// Set the optional preamble scheme (e.g. `"https"`).
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError::InvalidScheme`] if the scheme is empty, does not
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
    /// Returns [`SiwxError::InvalidRequestId`] if the value is not RFC 3986
    /// `pchar` or exceeds the size limit.
    pub fn with_request_id(mut self, rid: impl Into<String>) -> Result<Self, SiwxError> {
        self.request_id = Some(check_request_id(&rid.into())?);
        Ok(self)
    }

    /// Set the resources list (≤ [`MAX_RESOURCES`] RFC 3986 URIs).
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError::TooManyResources`] if there are too many entries, or
    /// [`SiwxError::InvalidUri`] if any entry is not an RFC 3986 URI.
    pub fn with_resources<I, S>(mut self, resources: I) -> Result<Self, SiwxError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.resources = check_resources(resources.into_iter().map(Into::into))?;
        Ok(self)
    }

    /// Optional RFC 3986 scheme from the EIP-4361 preamble.
    #[must_use]
    pub fn scheme(&self) -> Option<&str> {
        self.scheme.as_deref()
    }

    /// RFC 3986 authority requesting the signing.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Blockchain address performing the signing (CAIP-10 `account_address`).
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Human-readable assertion, if present.
    #[must_use]
    pub fn statement(&self) -> Option<&str> {
        self.statement.as_deref()
    }

    /// RFC 3986 URI that is the subject of the signing.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Message version (always [`VERSION`]).
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// CAIP-2 chain id `reference` segment.
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// Preamble chain label parsed from the signing string.
    ///
    /// [`Self::new`] leaves this unset. Parsing stores the label between
    /// `with your ` and ` account:`.
    #[must_use]
    pub fn chain_name(&self) -> Option<&str> {
        self.chain_name.as_deref()
    }

    /// Anti-replay nonce.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Issuance instant.
    #[must_use]
    pub const fn issued_at(&self) -> OffsetDateTime {
        self.issued_at.datetime()
    }

    /// Original RFC 3339 lexical form of `issued-at`.
    #[must_use]
    pub fn issued_at_raw(&self) -> &str {
        self.issued_at.as_str()
    }

    /// Expiration instant, if set.
    #[must_use]
    pub fn expiration_time(&self) -> Option<OffsetDateTime> {
        self.expiration_time.as_ref().map(Timestamp::datetime)
    }

    /// Original RFC 3339 lexical form of `expiration-time`, if set.
    #[must_use]
    pub fn expiration_time_raw(&self) -> Option<&str> {
        self.expiration_time.as_ref().map(Timestamp::as_str)
    }

    /// Not-before instant, if set.
    #[must_use]
    pub fn not_before(&self) -> Option<OffsetDateTime> {
        self.not_before.as_ref().map(Timestamp::datetime)
    }

    /// Original RFC 3339 lexical form of `not-before`, if set.
    #[must_use]
    pub fn not_before_raw(&self) -> Option<&str> {
        self.not_before.as_ref().map(Timestamp::as_str)
    }

    /// System-specific request identifier, if set.
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }

    /// RFC 3986 URI resources.
    #[must_use]
    pub fn resources(&self) -> &[String] {
        &self.resources
    }

    /// CAIP-10 account id `{namespace}:{chain_id}:{address}`.
    ///
    /// `namespace` must match CAIP-2 `[-a-z0-9]{3,8}`. `address` must match
    /// CAIP-10 `[-.%a-zA-Z0-9]{1,128}`.
    ///
    /// CAIP-2 / CAIP-10 specify `reference` as `[-_a-zA-Z0-9]{1,32}`. This
    /// crate stores Solana genesis hashes as `chain_id` (43 characters, e.g.
    /// `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d`), which exceed that
    /// bound, so `chain_id` is interpolated as stored and is **not** checked
    /// against `{1,32}`.
    ///
    /// # Errors
    ///
    /// Returns an error if `namespace` or `address` fail the charset checks
    /// above.
    pub fn caip10(&self, namespace: &str) -> Result<String, SiwxError> {
        if !is_caip2_namespace(namespace) {
            return Err(SiwxError::InvalidAddress {
                reason: "CAIP-10 namespace must be [-a-z0-9]{3,8}".into(),
            });
        }
        if !is_caip10_address(&self.address) {
            return Err(SiwxError::InvalidAddress {
                reason: "CAIP-10 address must be [-.%a-zA-Z0-9]{1,128}".into(),
            });
        }
        let chain_id = self.chain_id.as_str();
        let address = self.address.as_str();
        Ok(format!("{namespace}:{chain_id}:{address}"))
    }

    #[cfg(test)]
    pub(crate) fn set_chain_name(&mut self, chain_name: Option<String>) {
        self.chain_name = chain_name;
    }

    #[cfg(test)]
    pub(crate) fn set_resources_unchecked(&mut self, resources: Vec<String>) {
        self.resources = resources;
    }
}

pub(crate) fn check_scheme(scheme: &str) -> Result<String, SiwxError> {
    if scheme.is_empty() {
        return Err(SiwxError::InvalidScheme { reason: "empty" });
    }
    if !scheme
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
    {
        return Err(SiwxError::InvalidScheme {
            reason: "must start with ASCII letter",
        });
    }
    if !scheme
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
    {
        return Err(SiwxError::InvalidScheme {
            reason: "must be ASCII alphanumeric, '+', '-', or '.'",
        });
    }
    Ok(scheme.to_owned())
}

pub(crate) fn check_domain(domain: &str) -> Result<String, SiwxError> {
    if domain.is_empty() {
        return Err(SiwxError::InvalidDomain { reason: "empty" });
    }
    if domain.contains(PREAMBLE_MID) {
        return Err(SiwxError::InvalidDomain {
            reason: "preamble marker",
        });
    }
    // Empty authority is valid in iri-string (`file:///`); rejected above.
    authority::<UriSpec>(domain).map_err(|_| SiwxError::InvalidDomain {
        reason: "not RFC 3986 authority",
    })?;
    Ok(domain.to_owned())
}

pub(crate) fn check_statement(statement: &str) -> Result<(), SiwxError> {
    if statement.is_empty() {
        return Err(SiwxError::InvalidStatement { reason: "empty" });
    }
    if statement.len() > MAX_STATEMENT_BYTES {
        return Err(SiwxError::InvalidStatement {
            reason: "exceeds maximum size",
        });
    }
    if !statement.chars().all(is_statement_char) {
        return Err(SiwxError::InvalidStatement {
            reason: "must be RFC 3986 reserved / unreserved / SP",
        });
    }
    Ok(())
}

pub(crate) fn check_uri(uri: &str) -> Result<String, SiwxError> {
    if uri.len() > MAX_URI_BYTES {
        return Err(SiwxError::InvalidUri {
            reason: format!(
                "exceeds maximum size of {MAX_URI_BYTES} bytes, got {}",
                uri.len()
            ),
        });
    }
    UriString::try_from(uri).map_err(|e| SiwxError::InvalidUri {
        reason: e.to_string(),
    })?;
    Ok(uri.to_owned())
}

pub(crate) fn check_request_id(rid: &str) -> Result<String, SiwxError> {
    if rid.len() > MAX_REQUEST_ID_BYTES {
        return Err(SiwxError::InvalidRequestId {
            reason: "exceeds maximum size",
        });
    }
    if !is_pchar_string(rid) {
        return Err(SiwxError::InvalidRequestId {
            reason: "must be RFC 3986 pchar",
        });
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
        return Err(SiwxError::TooManyResources {
            count: resources.len(),
            max: MAX_RESOURCES,
        });
    }
    for uri in &resources {
        check_uri(uri)?;
    }
    Ok(resources)
}

/// Validate nonce length and charset (EIP-4361: ≥ 8 alphanumeric).
pub(crate) fn check_nonce_shape(nonce: &str) -> Result<String, SiwxError> {
    if nonce.len() < MIN_NONCE_LEN {
        return Err(SiwxError::InvalidNonce {
            reason: format!(
                "must be at least {MIN_NONCE_LEN} characters, got {}",
                nonce.len()
            ),
        });
    }
    if !nonce.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(SiwxError::InvalidNonce {
            reason: "must be ASCII alphanumeric".into(),
        });
    }
    Ok(nonce.to_owned())
}

fn is_caip2_namespace(s: &str) -> bool {
    (3..=8).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn is_caip10_address(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'%'))
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
            SiwxError::InvalidDomain { .. }
        ));
        assert!(matches!(
            SiwxMessage::new("d.com", "", "https://d.com", "1", "testnonce12345678").unwrap_err(),
            SiwxError::InvalidAddress { .. }
        ));
        assert!(matches!(
            SiwxMessage::new("d.com", "a", "https://d.com", "", "testnonce12345678").unwrap_err(),
            SiwxError::InvalidChainId {
                reason: ChainIdReason::Empty
            }
        ));
    }

    #[test]
    fn new_rejects_short_nonce() {
        assert!(matches!(
            SiwxMessage::new("d.com", "a", "https://d.com", "1", "short").unwrap_err(),
            SiwxError::InvalidNonce { .. }
        ));
    }

    #[test]
    fn new_sets_version_one() {
        let msg = SiwxMessage::new("d.com", "a", "https://d.com", "1", "testnonce12345678")
            .expect("valid");
        assert_eq!(msg.version(), VERSION);
        assert!(
            msg.chain_name().is_none(),
            "builder must leave chain_name unset"
        );
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
            SiwxError::InvalidUri { .. }
        ));
    }

    #[test]
    fn with_resources_rejects_too_many() {
        let resources = (0..=MAX_RESOURCES).map(|i| format!("https://r{i}.example"));
        let err = SiwxMessage::new("d.com", "a", "https://d.com", "1", "testnonce12345678")
            .expect("valid")
            .with_resources(resources)
            .unwrap_err();
        assert!(matches!(
            err,
            SiwxError::TooManyResources {
                count: 33,
                max: MAX_RESOURCES
            }
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
        assert_eq!(msg.statement(), Some("hi"));
        assert_eq!(msg.nonce(), "testnonce12345678");
        assert_eq!(msg.request_id(), Some("rid"));
        assert_eq!(msg.resources(), ["https://r.com"]);
    }

    #[test]
    fn with_statement_rejects_newline() {
        let err = SiwxMessage::new("d.com", "a", "https://d.com", "1", "testnonce12345678")
            .expect("valid")
            .with_statement("bad\nline")
            .unwrap_err();
        assert!(matches!(err, SiwxError::InvalidStatement { .. }));
    }

    #[test]
    fn with_statement_rejects_empty() {
        let err = SiwxMessage::new("d.com", "a", "https://d.com", "1", "testnonce12345678")
            .expect("valid")
            .with_statement("")
            .unwrap_err();
        assert!(matches!(err, SiwxError::InvalidStatement { .. }));
    }

    #[test]
    fn domain_rejects_preamble_injection() {
        let evil = format!("evil.com{PREAMBLE_MID}Ethereum account:\n0x");
        assert!(matches!(
            SiwxMessage::new(&evil, "a", "https://d.com", "1", "testnonce12345678").unwrap_err(),
            SiwxError::InvalidDomain { .. }
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
            SiwxError::InvalidDomain { .. }
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
            SiwxError::InvalidDomain { .. }
        ));
    }

    #[test]
    fn scheme_must_start_with_alpha() {
        let base = SiwxMessage::new("d.com", "a", "https://d.com", "1", "testnonce12345678")
            .expect("valid");
        let err = base.clone().with_scheme("1http").unwrap_err();
        assert!(matches!(err, SiwxError::InvalidScheme { .. }));
        let https = base.with_scheme("https").expect("alpha scheme");
        assert_eq!(https.scheme(), Some("https"));
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
        assert_eq!(reparsed.issued_at_raw(), raw_ts);
        assert_eq!(reparsed.issued_at(), datetime!(2021-09-30 16:25:24 UTC));
    }

    #[test]
    fn caip10_formats_eip155_account() {
        let msg = SiwxMessage::new(
            "d.com",
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            "https://d.com",
            "1",
            "testnonce12345678",
        )
        .expect("valid");
        assert_eq!(
            msg.caip10("eip155").expect("caip10"),
            "eip155:1:0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        );
    }

    #[test]
    fn caip10_rejects_bad_namespace() {
        let msg = SiwxMessage::new("d.com", "a", "https://d.com", "1", "testnonce12345678")
            .expect("valid");
        assert!(matches!(
            msg.caip10("EIP155").unwrap_err(),
            SiwxError::InvalidAddress { .. }
        ));
    }

    #[test]
    fn caip10_formats_solana_genesis_hash() {
        let chain_id = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
        let address = "GwAF45zjfyGzUbd3i3hXxzGeuchzEZXwpRYHZM5912F1";
        let msg = SiwxMessage::new(
            "d.com",
            address,
            "https://d.com",
            chain_id,
            "testnonce12345678",
        )
        .expect("valid");
        assert_eq!(
            msg.caip10("solana").expect("genesis hash is stored as-is"),
            format!("solana:{chain_id}:{address}")
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_preserves_field_names_and_timestamp_originals() {
        let raw_ts = "2021-09-30T16:25:24.000Z";
        let exp_ts = "2021-10-01T00:00:00.000Z";
        let msg = SiwxMessage::new("d.com", "a", "https://d.com", "1", "testnonce12345678")
            .expect("valid")
            .with_issued_at_raw(raw_ts)
            .expect("issued_at")
            .with_expiration_time_raw(exp_ts)
            .expect("expiration");
        let json = serde_json::to_value(&msg).expect("serialize");
        assert_eq!(
            json.get("issued_at").and_then(serde_json::Value::as_str),
            Some(raw_ts),
            "times must keep original strings"
        );
        assert_eq!(
            json.get("expiration_time")
                .and_then(serde_json::Value::as_str),
            Some(exp_ts),
            "expiration_time field name and original string"
        );
        assert_eq!(
            json.get("domain").and_then(serde_json::Value::as_str),
            Some("d.com"),
            "domain field name"
        );
        assert_eq!(
            json.get("chain_id").and_then(serde_json::Value::as_str),
            Some("1"),
            "chain_id field name"
        );
        let back: SiwxMessage = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back.issued_at_raw(), raw_ts);
        assert_eq!(back.expiration_time_raw(), Some(exp_ts));
        assert_eq!(back.domain(), "d.com");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_omitted_optionals_preserve_timestamp_originals() {
        let raw_ts = "2021-09-30T16:25:24.000Z";
        let exp_ts = "2021-10-01T00:00:00.000Z";
        let nbf_ts = "2021-09-29T00:00:00.382Z";
        let json = serde_json::json!({
            "domain": "d.com",
            "address": "a",
            "uri": "https://d.com",
            "version": "1",
            "chain_id": "1",
            "nonce": "testnonce12345678",
            "issued_at": raw_ts,
            "expiration_time": exp_ts,
            "not_before": nbf_ts,
        });
        let msg: SiwxMessage = serde_json::from_value(json).expect("omit optionals");
        assert_eq!(msg.scheme(), None, "omitted scheme");
        assert_eq!(msg.statement(), None, "omitted statement");
        assert_eq!(msg.request_id(), None, "omitted request_id");
        assert!(msg.resources().is_empty(), "omitted resources");
        assert_eq!(msg.chain_name(), None, "omitted chain_name");
        assert_eq!(msg.issued_at_raw(), raw_ts, "issued_at original");
        assert_eq!(
            msg.expiration_time_raw(),
            Some(exp_ts),
            "expiration original"
        );
        assert_eq!(msg.not_before_raw(), Some(nbf_ts), "not_before original");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_rejects_fields_that_fail_check_star() {
        let valid = serde_json::json!({
            "domain": "d.com",
            "address": "a",
            "uri": "https://d.com",
            "version": "1",
            "chain_id": "1",
            "nonce": "testnonce12345678",
            "issued_at": "2021-09-30T16:25:24Z",
        });

        let cases = [
            ("domain", serde_json::json!("")),
            ("nonce", serde_json::json!("short")),
            ("version", serde_json::json!("2")),
            ("uri", serde_json::json!("not a valid uri ::: bad")),
            ("resources", serde_json::json!(["not a valid uri ::: bad"])),
        ];
        for (key, bad) in cases {
            let mut obj = valid.clone();
            obj.as_object_mut()
                .expect("object")
                .insert(key.to_owned(), bad);
            serde_json::from_value::<SiwxMessage>(obj).expect_err(key);
        }
    }
}
