//! Field- and temporal-level validation of [`SiwxMessage`].

use iri_string::types::UriString;
use time::OffsetDateTime;

use crate::SiwxError;
use crate::message::{SiwxMessage, VERSION, check_domain, check_nonce_shape, check_statement};

/// Binding and temporal options for authentication / validation.
///
/// `domain` and `nonce` are **required** so callers cannot skip replay and
/// origin binding by accident.
#[derive(Debug, Clone)]
pub struct AuthOpts {
    /// Expected domain (must match `message.domain`).
    pub domain: String,
    /// Expected nonce (must match `message.nonce`).
    pub nonce: String,
    /// Expected chain id (if set, must match `message.chain_id`).
    pub chain_id: Option<String>,
    /// The point in time to check against. Defaults to [`OffsetDateTime::now_utc`].
    pub timestamp: Option<OffsetDateTime>,
}

impl AuthOpts {
    /// Create opts that bind `domain` and `nonce`.
    #[must_use]
    pub fn new(domain: impl Into<String>, nonce: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            nonce: nonce.into(),
            chain_id: None,
            timestamp: None,
        }
    }

    /// Require `message.chain_id` to equal `chain_id`.
    #[must_use]
    pub fn with_chain_id(mut self, chain_id: impl Into<String>) -> Self {
        self.chain_id = Some(chain_id.into());
        self
    }

    /// Override the temporal evaluation point (tests / clock injection).
    #[must_use]
    pub const fn with_timestamp(mut self, t: OffsetDateTime) -> Self {
        self.timestamp = Some(t);
        self
    }
}

impl SiwxMessage {
    /// Validate field shapes, protocol rules, bindings, and temporal window.
    ///
    /// # Errors
    ///
    /// Returns the matching [`SiwxError`] for the first failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use siwx::{AuthOpts, SiwxMessage};
    ///
    /// let msg = SiwxMessage::new(
    ///     "example.com",
    ///     "addr1",
    ///     "https://example.com",
    ///     "1",
    ///     "testnonce12345678",
    /// )?;
    /// msg.validate(&AuthOpts::new("example.com", "testnonce12345678"))?;
    /// # Ok::<(), siwx::SiwxError>(())
    /// ```
    pub fn validate(&self, opts: &AuthOpts) -> Result<(), SiwxError> {
        self.check_required_shapes()?;
        self.check_uri_shapes()?;
        if let Some(ref s) = self.statement {
            check_statement(s)?;
        }
        self.check_domain_binding(&opts.domain)?;
        self.check_nonce_binding(&opts.nonce)?;
        self.check_chain_id_binding(opts.chain_id.as_deref())?;
        self.check_temporal_window(opts.timestamp)?;
        Ok(())
    }

    fn check_required_shapes(&self) -> Result<(), SiwxError> {
        check_domain(&self.domain)?;
        if self.address.is_empty() {
            return Err(SiwxError::InvalidAddress("empty".into()));
        }
        if self.version != VERSION {
            return Err(SiwxError::InvalidFormat(format!(
                "version must be {VERSION}, got {}",
                self.version
            )));
        }
        if self.chain_id.is_empty() {
            return Err(SiwxError::InvalidFormat("empty chain_id".into()));
        }
        check_nonce_shape(&self.nonce)?;
        Ok(())
    }

    fn check_uri_shapes(&self) -> Result<(), SiwxError> {
        UriString::try_from(self.uri.as_str()).map_err(|e| SiwxError::InvalidUri(e.to_string()))?;
        for r in &self.resources {
            UriString::try_from(r.as_str())
                .map_err(|e| SiwxError::InvalidUri(format!("invalid resource URI: {e}")))?;
        }
        Ok(())
    }

    fn check_domain_binding(&self, expected: &str) -> Result<(), SiwxError> {
        if expected != self.domain {
            return Err(SiwxError::InvalidDomain(format!(
                "expected {expected}, got {}",
                self.domain
            )));
        }
        Ok(())
    }

    fn check_nonce_binding(&self, expected: &str) -> Result<(), SiwxError> {
        if expected != self.nonce {
            return Err(SiwxError::InvalidNonce(format!(
                "expected {expected}, got {}",
                self.nonce
            )));
        }
        Ok(())
    }

    fn check_chain_id_binding(&self, expected: Option<&str>) -> Result<(), SiwxError> {
        if let Some(expected) = expected
            && expected != self.chain_id
        {
            return Err(SiwxError::InvalidFormat(format!(
                "chain_id: expected {expected}, got {}",
                self.chain_id
            )));
        }
        Ok(())
    }

    fn check_temporal_window(&self, at: Option<OffsetDateTime>) -> Result<(), SiwxError> {
        let now = at.unwrap_or_else(OffsetDateTime::now_utc);
        if let Some(exp) = self.expiration_time
            && now > exp
        {
            return Err(SiwxError::Expired);
        }
        if let Some(nbf) = self.not_before
            && now < nbf
        {
            return Err(SiwxError::NotYetValid);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    fn base() -> SiwxMessage {
        SiwxMessage::new("d.com", "a", "https://d.com", "1", "testnonce12345678")
            .expect("valid")
            .with_issued_at(datetime!(2024-01-01 0:00 UTC))
    }

    fn opts_for(msg: &SiwxMessage) -> AuthOpts {
        AuthOpts::new(&msg.domain, &msg.nonce)
    }

    #[test]
    fn matching_opts_accept_message() {
        let msg = base();
        msg.validate(&opts_for(&msg))
            .expect("matching opts are valid");
    }

    #[test]
    fn expired_message_is_rejected() {
        let msg = base().with_expiration_time(datetime!(2020-01-01 0:00 UTC));
        let opts = opts_for(&msg).with_timestamp(datetime!(2021-01-01 0:00 UTC));
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::Expired));
    }

    #[test]
    fn not_before_in_future_is_rejected() {
        let msg = base().with_not_before(datetime!(2099-01-01 0:00 UTC));
        let opts = opts_for(&msg).with_timestamp(datetime!(2024-06-01 0:00 UTC));
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::NotYetValid));
    }

    #[test]
    fn domain_mismatch_is_rejected() {
        let msg = base();
        let opts = AuthOpts::new("good.com", &msg.nonce);
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::InvalidDomain(_)));
    }

    #[test]
    fn nonce_mismatch_is_rejected() {
        let msg = base();
        let opts = AuthOpts::new(&msg.domain, "othernonce12345678");
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::InvalidNonce(_)));
    }

    #[test]
    fn chain_id_mismatch_is_rejected() {
        let msg = base();
        let opts = opts_for(&msg).with_chain_id("999");
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::InvalidFormat(_)));
    }

    #[test]
    fn invalid_resource_uri_is_rejected() {
        let msg = base().with_resources(["not a valid uri ::: bad"]);
        let err = msg.validate(&opts_for(&msg)).unwrap_err();
        assert!(matches!(err, SiwxError::InvalidUri(_)));
    }

    #[test]
    fn timestamp_override_changes_expiration_decision() {
        let msg = base().with_expiration_time(datetime!(2020-01-01 0:00 UTC));
        let opts = opts_for(&msg).with_timestamp(datetime!(2019-01-01 0:00 UTC));
        msg.validate(&opts).expect("valid at earlier timestamp");
    }
}
