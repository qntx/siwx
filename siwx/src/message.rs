//! CAIP-122 abstract data model.
//!
//! Defines [`SiwxMessage`] — the chain-agnostic struct mirroring the CAIP-122
//! data model. Parsing lives in [`crate::parser`], formatting in
//! [`crate::formatter`], validation in [`crate::validate`].

use time::OffsetDateTime;

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
    /// RFC 4501 `dnsauthority` requesting the signing.
    pub domain: String,

    /// Blockchain address performing the signing (CAIP-10 `account_address`
    /// segment — does **not** include the CAIP-2 chain id prefix).
    pub address: String,

    /// Human-readable ASCII assertion. MUST NOT contain `\n`.
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

    /// ISO 8601 / RFC 3339 issuance time.
    #[cfg_attr(feature = "serde", serde(with = "time::serde::rfc3339"))]
    pub issued_at: OffsetDateTime,

    /// ISO 8601 / RFC 3339 expiration time.
    #[cfg_attr(
        feature = "serde",
        serde(default, with = "time::serde::rfc3339::option")
    )]
    pub expiration_time: Option<OffsetDateTime>,

    /// ISO 8601 / RFC 3339 earliest valid time.
    #[cfg_attr(
        feature = "serde",
        serde(default, with = "time::serde::rfc3339::option")
    )]
    pub not_before: Option<OffsetDateTime>,

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
    /// or `nonce` fails [`check_nonce_shape`].
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
        let uri = non_empty(uri.into(), "uri")?;
        let chain_id = non_empty(chain_id.into(), "chain_id")?;
        let nonce = check_nonce_shape(&nonce.into())?;

        Ok(Self {
            domain,
            address,
            uri,
            version: VERSION.to_owned(),
            chain_id,
            nonce,
            statement: None,
            issued_at: OffsetDateTime::now_utc(),
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: Vec::new(),
        })
    }

    /// Set the human-readable statement.
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError::InvalidStatement`] if the value contains `\n`.
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

    /// Set the issuance time.
    #[must_use]
    pub const fn with_issued_at(mut self, t: OffsetDateTime) -> Self {
        self.issued_at = t;
        self
    }

    /// Set the expiration time.
    #[must_use]
    pub const fn with_expiration_time(mut self, t: OffsetDateTime) -> Self {
        self.expiration_time = Some(t);
        self
    }

    /// Set the not-before time.
    #[must_use]
    pub const fn with_not_before(mut self, t: OffsetDateTime) -> Self {
        self.not_before = Some(t);
        self
    }

    /// Set the request id.
    #[must_use]
    pub fn with_request_id(mut self, rid: impl Into<String>) -> Self {
        self.request_id = Some(rid.into());
        self
    }

    /// Set the resources list.
    #[must_use]
    pub fn with_resources(
        mut self,
        resources: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.resources = resources.into_iter().map(Into::into).collect();
        self
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

pub(crate) fn check_domain(domain: &str) -> Result<String, SiwxError> {
    if domain.is_empty() {
        return Err(SiwxError::InvalidDomain("empty".into()));
    }
    if domain.contains(PREAMBLE_MID) {
        return Err(SiwxError::InvalidDomain(
            "must not contain preamble marker".into(),
        ));
    }
    if domain
        .chars()
        .any(|c| c.is_control() || c == ' ' || c == '\n' || c == '\r')
    {
        return Err(SiwxError::InvalidDomain(
            "must not contain whitespace or control characters".into(),
        ));
    }
    Ok(domain.to_owned())
}

pub(crate) fn check_statement(statement: &str) -> Result<(), SiwxError> {
    if statement.contains('\n') || statement.contains('\r') {
        return Err(SiwxError::InvalidStatement(
            "must not contain newline".into(),
        ));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
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
    fn builder_chains_all_setters() {
        let msg = SiwxMessage::new("d.com", "a", "https://d.com", "1", "testnonce12345678")
            .expect("valid")
            .with_statement("hi")
            .expect("statement")
            .with_request_id("rid")
            .with_resources(["https://r.com"]);
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
    fn domain_rejects_preamble_injection() {
        let evil = format!("evil.com{PREAMBLE_MID}Ethereum account:\n0x");
        assert!(matches!(
            SiwxMessage::new(&evil, "a", "https://d.com", "1", "testnonce12345678").unwrap_err(),
            SiwxError::InvalidDomain(_)
        ));
    }
}
