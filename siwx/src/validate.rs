//! Field- and temporal-level validation of [`SiwxMessage`].

use iri_string::types::UriString;
use time::OffsetDateTime;

use crate::SiwxError;
use crate::message::SiwxMessage;

/// Options for domain/nonce binding and temporal validation.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ValidateOpts {
    /// The point in time to check against. Defaults to [`OffsetDateTime::now_utc`].
    pub timestamp: Option<OffsetDateTime>,
    /// Expected domain (if set, must match `message.domain`).
    pub domain: Option<String>,
    /// Expected nonce (if set, must match `message.nonce`).
    pub nonce: Option<String>,
}

impl SiwxMessage {
    /// Validate field shapes and temporal constraints.
    ///
    /// # Errors
    ///
    /// Returns the matching [`SiwxError`] variant for the first failure:
    /// missing required field, malformed URI, newline in statement, domain
    /// or nonce mismatch, [`SiwxError::Expired`], [`SiwxError::NotYetValid`].
    ///
    /// # Examples
    ///
    /// ```
    /// use siwx::{SiwxMessage, ValidateOpts};
    ///
    /// let msg = SiwxMessage::new("example.com", "addr1", "https://example.com", "1", "1")?;
    /// msg.validate(&ValidateOpts::default())?;
    /// # Ok::<(), siwx::SiwxError>(())
    /// ```
    pub fn validate(&self, opts: &ValidateOpts) -> Result<(), SiwxError> {
        self.check_required_non_empty()?;
        self.check_uri_shapes()?;
        self.check_statement_single_line()?;
        self.check_domain_binding(opts.domain.as_deref())?;
        self.check_nonce_binding(opts.nonce.as_deref())?;
        self.check_temporal_window(opts.timestamp)?;
        Ok(())
    }

    fn check_required_non_empty(&self) -> Result<(), SiwxError> {
        if self.domain.is_empty() {
            return Err(SiwxError::InvalidDomain("empty".into()));
        }
        if self.address.is_empty() {
            return Err(SiwxError::InvalidAddress("empty".into()));
        }
        if self.version.is_empty() {
            return Err(SiwxError::InvalidFormat("empty version".into()));
        }
        if self.chain_id.is_empty() {
            return Err(SiwxError::InvalidFormat("empty chain_id".into()));
        }
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

    fn check_statement_single_line(&self) -> Result<(), SiwxError> {
        if let Some(ref s) = self.statement
            && s.contains('\n')
        {
            return Err(SiwxError::InvalidStatement(
                "must not contain newline".into(),
            ));
        }
        Ok(())
    }

    fn check_domain_binding(&self, expected: Option<&str>) -> Result<(), SiwxError> {
        if let Some(expected) = expected
            && expected != self.domain
        {
            return Err(SiwxError::InvalidDomain(format!(
                "expected {expected}, got {}",
                self.domain
            )));
        }
        Ok(())
    }

    fn check_nonce_binding(&self, expected: Option<&str>) -> Result<(), SiwxError> {
        if let Some(expected) = expected {
            let actual = self.nonce.as_deref().unwrap_or("");
            if expected != actual {
                return Err(SiwxError::InvalidNonce(format!(
                    "expected {expected}, got {actual}"
                )));
            }
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
        SiwxMessage::new("d.com", "a", "https://d.com", "1", "1").expect("valid")
    }

    #[test]
    fn default_opts_accept_minimal_message() {
        base()
            .validate(&ValidateOpts::default())
            .expect("minimal message is valid");
    }

    #[test]
    fn expired_message_is_rejected() {
        let msg = base().with_expiration_time(datetime!(2020-01-01 0:00 UTC));
        let err = msg.validate(&ValidateOpts::default()).unwrap_err();
        assert!(matches!(err, SiwxError::Expired));
    }

    #[test]
    fn not_before_in_future_is_rejected() {
        let msg = base().with_not_before(datetime!(2099-01-01 0:00 UTC));
        let err = msg.validate(&ValidateOpts::default()).unwrap_err();
        assert!(matches!(err, SiwxError::NotYetValid));
    }

    #[test]
    fn domain_mismatch_is_rejected() {
        let msg = SiwxMessage::new("evil.com", "a", "https://evil.com", "1", "1").expect("valid");
        let opts = ValidateOpts {
            domain: Some("good.com".into()),
            ..Default::default()
        };
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::InvalidDomain(_)));
    }

    #[test]
    fn nonce_mismatch_is_rejected() {
        let msg = base().with_nonce("abc");
        let opts = ValidateOpts {
            nonce: Some("xyz".into()),
            ..Default::default()
        };
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::InvalidNonce(_)));
    }

    #[test]
    fn statement_with_newline_is_rejected() {
        let msg = base().with_statement("bad\nstatement");
        let err = msg.validate(&ValidateOpts::default()).unwrap_err();
        assert!(matches!(err, SiwxError::InvalidStatement(_)));
    }

    #[test]
    fn invalid_resource_uri_is_rejected() {
        let msg = base().with_resources(["not a valid uri ::: bad"]);
        let err = msg.validate(&ValidateOpts::default()).unwrap_err();
        assert!(matches!(err, SiwxError::InvalidUri(_)));
    }

    #[test]
    fn timestamp_override_changes_expiration_decision() {
        let msg = base().with_expiration_time(datetime!(2020-01-01 0:00 UTC));
        let opts = ValidateOpts {
            timestamp: Some(datetime!(2019-01-01 0:00 UTC)),
            ..Default::default()
        };
        msg.validate(&opts).expect("valid at earlier timestamp");
    }
}
