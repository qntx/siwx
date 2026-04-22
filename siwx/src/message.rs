//! CAIP-122 abstract data model.
//!
//! Defines [`SiwxMessage`] — the chain-agnostic struct mirroring the CAIP-122
//! data model. Parsing lives in [`crate::parser`], formatting in
//! [`crate::formatter`], validation in [`crate::validate`].

use time::OffsetDateTime;

use crate::SiwxError;

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

    /// Current version of the message (EIP-4361 mandates `"1"`).
    pub version: String,

    /// Chain identifier — the `reference` segment of a CAIP-2 chain id.
    ///
    /// For EIP-155 chains this is the decimal chain id (e.g. `"1"`).
    /// For Solana this is the genesis hash (e.g.
    /// `"5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"`).
    pub chain_id: String,

    /// Randomised token to prevent replay attacks.
    pub nonce: Option<String>,

    /// ISO 8601 / RFC 3339 issuance time.
    #[cfg_attr(
        feature = "serde",
        serde(default, with = "time::serde::rfc3339::option")
    )]
    pub issued_at: Option<OffsetDateTime>,

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
    /// Create a minimal valid message with only the mandatory CAIP-122 fields.
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError::InvalidFormat`] if any mandatory field is empty.
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
    ///     "1",
    /// )?;
    /// # Ok::<(), siwx::SiwxError>(())
    /// ```
    pub fn new(
        domain: impl Into<String>,
        address: impl Into<String>,
        uri: impl Into<String>,
        version: impl Into<String>,
        chain_id: impl Into<String>,
    ) -> Result<Self, SiwxError> {
        Ok(Self {
            domain: non_empty(domain.into(), "domain")?,
            address: non_empty(address.into(), "address")?,
            uri: non_empty(uri.into(), "uri")?,
            version: non_empty(version.into(), "version")?,
            chain_id: non_empty(chain_id.into(), "chain_id")?,
            statement: None,
            nonce: None,
            issued_at: None,
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: Vec::new(),
        })
    }

    /// Set the human-readable statement.
    #[must_use]
    pub fn with_statement(mut self, statement: impl Into<String>) -> Self {
        self.statement = Some(statement.into());
        self
    }

    /// Set the nonce.
    #[must_use]
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Set the issuance time.
    #[must_use]
    pub const fn with_issued_at(mut self, t: OffsetDateTime) -> Self {
        self.issued_at = Some(t);
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

fn non_empty(s: String, field: &str) -> Result<String, SiwxError> {
    if s.is_empty() {
        return Err(SiwxError::InvalidFormat(format!(
            "{field} must not be empty"
        )));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_empty_mandatory_fields() {
        assert!(matches!(
            SiwxMessage::new("", "a", "https://d.com", "1", "1").unwrap_err(),
            SiwxError::InvalidFormat(_)
        ));
        assert!(matches!(
            SiwxMessage::new("d.com", "", "https://d.com", "1", "1").unwrap_err(),
            SiwxError::InvalidFormat(_)
        ));
    }

    #[test]
    fn builder_chains_all_setters() {
        let msg = SiwxMessage::new("d.com", "a", "https://d.com", "1", "1")
            .expect("valid")
            .with_statement("hi")
            .with_nonce("n")
            .with_request_id("rid")
            .with_resources(["https://r.com"]);
        assert_eq!(msg.statement.as_deref(), Some("hi"));
        assert_eq!(msg.nonce.as_deref(), Some("n"));
        assert_eq!(msg.request_id.as_deref(), Some("rid"));
        assert_eq!(msg.resources, ["https://r.com"]);
    }
}
