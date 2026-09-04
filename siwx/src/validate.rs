//! Field- and temporal-level validation of [`SiwxMessage`].

use time::OffsetDateTime;

use crate::error::{ChainIdReason, FormatReason, SiwxError};
use crate::message::{
    SiwxMessage, VERSION, check_domain, check_nonce_shape, check_request_id, check_resources,
    check_scheme, check_statement, check_uri,
};

/// Default leeway for `expiration_time`, `not_before`, and `max_issued_age`.
const DEFAULT_CLOCK_SKEW: time::Duration = time::Duration::seconds(60);

/// Binding and temporal options for authentication / validation.
///
/// `domain` and `nonce` are **required** so callers cannot skip replay and
/// origin binding by accident. Multi-chain deployments should also set
/// [`Self::with_chain_id`]. Set [`Self::with_uri`] / [`Self::with_scheme`]
/// to bind those claims.
#[derive(Debug, Clone)]
pub struct AuthOpts {
    domain: String,
    nonce: String,
    scheme: Option<String>,
    uri: Option<String>,
    chain_id: Option<String>,
    request_id: Option<String>,
    timestamp: Option<OffsetDateTime>,
    clock_skew: time::Duration,
    max_issued_age: Option<time::Duration>,
}

impl AuthOpts {
    /// Create opts that bind `domain` and `nonce`.
    ///
    /// Default clock skew is 60 seconds and applies to `expiration_time`,
    /// `not_before`, and `max_issued_age` even when [`Self::with_timestamp`]
    /// injects the evaluation instant. Official SIWE verify harnesses that
    /// inject JSON `time` must also call [`Self::with_clock_skew`] with
    /// `time::Duration::ZERO`. Scheme, URI, chain id, and request id are
    /// unbound until set with the corresponding `with_*` builders.
    #[must_use]
    pub fn new(domain: impl Into<String>, nonce: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            nonce: nonce.into(),
            scheme: None,
            uri: None,
            chain_id: None,
            request_id: None,
            timestamp: None,
            clock_skew: DEFAULT_CLOCK_SKEW,
            max_issued_age: None,
        }
    }

    /// Require `message.scheme` to equal `scheme`.
    #[must_use]
    pub fn with_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.scheme = Some(scheme.into());
        self
    }

    /// Require `message.uri` to equal `uri`.
    #[must_use]
    pub fn with_uri(mut self, uri: impl Into<String>) -> Self {
        self.uri = Some(uri.into());
        self
    }

    /// Require `message.chain_id` to equal `chain_id`.
    #[must_use]
    pub fn with_chain_id(mut self, chain_id: impl Into<String>) -> Self {
        self.chain_id = Some(chain_id.into());
        self
    }

    /// Require `message.request_id` to equal `id`.
    #[must_use]
    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Override the temporal evaluation point (tests / clock injection).
    ///
    /// Does not change clock skew: the default 60s leeway still applies to
    /// `expiration_time`, `not_before`, and `max_issued_age`. Official SIWE
    /// verify harnesses that inject JSON `time` must also call
    /// [`Self::with_clock_skew`] with `time::Duration::ZERO`.
    #[must_use]
    pub const fn with_timestamp(mut self, t: OffsetDateTime) -> Self {
        self.timestamp = Some(t);
        self
    }

    /// Override clock skew applied to expiration, not-before, and max issued age.
    #[must_use]
    pub const fn with_clock_skew(mut self, d: time::Duration) -> Self {
        self.clock_skew = d;
        self
    }

    /// Reject messages whose `issued_at` is older than `age` relative to the
    /// evaluation timestamp (after subtracting clock skew). Future `issued_at`
    /// is not treated as stale.
    #[must_use]
    pub const fn with_max_issued_age(mut self, age: time::Duration) -> Self {
        self.max_issued_age = Some(age);
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
        check_uri(&self.uri)?;
        if let Some(ref s) = self.statement {
            check_statement(s)?;
        }
        if let Some(ref rid) = self.request_id {
            check_request_id(rid)?;
        }
        check_resources(self.resources.iter())?;
        self.check_domain_binding(&opts.domain)?;
        self.check_nonce_binding(&opts.nonce)?;
        self.check_scheme_binding(opts.scheme.as_deref())?;
        self.check_uri_binding(opts.uri.as_deref())?;
        self.check_chain_id_binding(opts.chain_id.as_deref())?;
        self.check_request_id_binding(opts.request_id.as_deref())?;
        self.check_temporal_window(opts)?;
        Ok(())
    }

    fn check_required_shapes(&self) -> Result<(), SiwxError> {
        if let Some(ref scheme) = self.scheme {
            check_scheme(scheme)?;
        }
        check_domain(&self.domain)?;
        if self.address.is_empty() {
            return Err(SiwxError::InvalidAddress {
                reason: "empty".into(),
            });
        }
        if self.version != VERSION {
            return Err(SiwxError::InvalidFormat {
                reason: FormatReason::VersionNotOne,
            });
        }
        if self.chain_id.is_empty() {
            return Err(SiwxError::InvalidChainId {
                reason: ChainIdReason::Empty,
            });
        }
        check_nonce_shape(&self.nonce)?;
        Ok(())
    }

    fn check_domain_binding(&self, expected: &str) -> Result<(), SiwxError> {
        if expected != self.domain {
            return Err(SiwxError::DomainMismatch {
                expected: expected.to_owned(),
                actual: self.domain.clone(),
            });
        }
        Ok(())
    }

    fn check_nonce_binding(&self, expected: &str) -> Result<(), SiwxError> {
        if expected != self.nonce {
            return Err(SiwxError::NonceMismatch {
                expected: expected.to_owned(),
                actual: self.nonce.clone(),
            });
        }
        Ok(())
    }

    fn check_scheme_binding(&self, expected: Option<&str>) -> Result<(), SiwxError> {
        if let Some(expected) = expected
            && self.scheme.as_deref() != Some(expected)
        {
            return Err(SiwxError::SchemeMismatch {
                expected: Some(expected.to_owned()),
                actual: self.scheme.clone(),
            });
        }
        Ok(())
    }

    fn check_uri_binding(&self, expected: Option<&str>) -> Result<(), SiwxError> {
        if let Some(expected) = expected
            && expected != self.uri
        {
            return Err(SiwxError::UriMismatch {
                expected: expected.to_owned(),
                actual: self.uri.clone(),
            });
        }
        Ok(())
    }

    fn check_chain_id_binding(&self, expected: Option<&str>) -> Result<(), SiwxError> {
        if let Some(expected) = expected
            && expected != self.chain_id
        {
            return Err(SiwxError::ChainIdMismatch {
                expected: expected.to_owned(),
                actual: self.chain_id.clone(),
            });
        }
        Ok(())
    }

    fn check_request_id_binding(&self, expected: Option<&str>) -> Result<(), SiwxError> {
        if let Some(expected) = expected
            && self.request_id.as_deref() != Some(expected)
        {
            return Err(SiwxError::RequestIdMismatch {
                expected: Some(expected.to_owned()),
                actual: self.request_id.clone(),
            });
        }
        Ok(())
    }

    fn check_temporal_window(&self, opts: &AuthOpts) -> Result<(), SiwxError> {
        let now = opts.timestamp.unwrap_or_else(OffsetDateTime::now_utc);
        let skew = opts.clock_skew;
        if let Some(ref exp) = self.expiration_time
            && now > exp.datetime() + skew
        {
            return Err(SiwxError::Expired);
        }
        if let Some(ref nbf) = self.not_before
            && now + skew < nbf.datetime()
        {
            return Err(SiwxError::NotYetValid);
        }
        if let Some(max_age) = opts.max_issued_age {
            let issued = self.issued_at.datetime();
            if issued <= now + skew && (now - issued) - skew > max_age {
                return Err(SiwxError::StaleIssuedAt);
            }
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
            .expect("issued_at")
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
        let msg = base()
            .with_expiration_time(datetime!(2020-01-01 0:00 UTC))
            .expect("expiration");
        let opts = opts_for(&msg).with_timestamp(datetime!(2021-01-01 0:00 UTC));
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::Expired));
    }

    #[test]
    fn expiration_at_now_is_still_valid() {
        let exp = datetime!(2024-01-01 0:00 UTC);
        let msg = base().with_expiration_time(exp).expect("expiration");
        let opts = opts_for(&msg)
            .with_timestamp(exp)
            .with_clock_skew(time::Duration::ZERO);
        msg.validate(&opts).expect("now == exp is valid");
    }

    #[test]
    fn expiration_within_skew_is_valid() {
        let msg = base()
            .with_expiration_time(datetime!(2024-01-01 0:00 UTC))
            .expect("expiration");
        let opts = opts_for(&msg).with_timestamp(datetime!(2024-01-01 0:01 UTC));
        msg.validate(&opts)
            .expect("now == exp + default 60s skew is valid");
    }

    #[test]
    fn expiration_past_skew_is_expired() {
        let msg = base()
            .with_expiration_time(datetime!(2024-01-01 0:00 UTC))
            .expect("expiration");
        let opts = opts_for(&msg).with_timestamp(datetime!(2024-01-01 0:01:01 UTC));
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::Expired));
    }

    #[test]
    fn not_before_in_future_is_rejected() {
        let msg = base()
            .with_not_before(datetime!(2099-01-01 0:00 UTC))
            .expect("not_before");
        let opts = opts_for(&msg).with_timestamp(datetime!(2024-06-01 0:00 UTC));
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::NotYetValid));
    }

    #[test]
    fn not_before_within_skew_is_valid() {
        let msg = base()
            .with_not_before(datetime!(2024-01-01 0:01 UTC))
            .expect("not_before");
        let opts = opts_for(&msg).with_timestamp(datetime!(2024-01-01 0:00 UTC));
        msg.validate(&opts).expect("now + 60s skew == nbf is valid");
    }

    #[test]
    fn not_before_beyond_skew_is_not_yet_valid() {
        let msg = base()
            .with_not_before(datetime!(2024-01-01 0:01 UTC))
            .expect("not_before");
        let opts = opts_for(&msg).with_timestamp(datetime!(2023-12-31 23:59:59 UTC));
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::NotYetValid));
    }

    #[test]
    fn future_issued_at_is_not_rejected() {
        let msg = base()
            .with_issued_at(datetime!(2022-01-05 14:27:30 UTC))
            .expect("issued_at")
            .with_expiration_time(datetime!(2021-01-05 0:00 UTC))
            .expect("expiration");
        let opts = opts_for(&msg)
            .with_timestamp(datetime!(2020-01-05 0:00 UTC))
            .with_clock_skew(time::Duration::ZERO);
        msg.validate(&opts)
            .expect("future issued-at must not fail; exp is still in the future relative to now");
    }

    #[test]
    fn domain_mismatch_is_rejected() {
        let msg = base();
        let opts = AuthOpts::new("good.com", &msg.nonce);
        let err = msg.validate(&opts).unwrap_err();
        assert!(
            matches!(
                err,
                SiwxError::DomainMismatch {
                    ref expected,
                    ref actual,
                } if expected == "good.com" && actual == "d.com"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn nonce_mismatch_is_rejected() {
        let msg = base();
        let opts = AuthOpts::new(&msg.domain, "othernonce12345678");
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::NonceMismatch { .. }));
    }

    #[test]
    fn chain_id_mismatch_is_rejected() {
        let msg = base();
        let opts = opts_for(&msg).with_chain_id("999");
        let err = msg.validate(&opts).unwrap_err();
        assert!(
            matches!(
                err,
                SiwxError::ChainIdMismatch {
                    ref expected,
                    ref actual,
                } if expected == "999" && actual == "1"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn scheme_mismatch_is_rejected() {
        let msg = base();
        let opts = opts_for(&msg).with_scheme("https");
        let err = msg.validate(&opts).unwrap_err();
        assert!(
            matches!(
                err,
                SiwxError::SchemeMismatch {
                    expected: Some(ref expected),
                    actual: None,
                } if expected == "https"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn scheme_binding_accepts_match() {
        let msg = base().with_scheme("https").expect("scheme");
        let opts = opts_for(&msg).with_scheme("https");
        msg.validate(&opts).expect("matching scheme");
    }

    #[test]
    fn scheme_unbound_when_message_has_scheme() {
        let msg = base().with_scheme("https").expect("scheme");
        msg.validate(&opts_for(&msg))
            .expect("unbound scheme must not reject a preamble scheme");
    }

    #[test]
    fn scheme_mismatch_some_vs_some() {
        let msg = base().with_scheme("https").expect("scheme");
        let opts = opts_for(&msg).with_scheme("http");
        let err = msg.validate(&opts).unwrap_err();
        assert!(
            matches!(
                err,
                SiwxError::SchemeMismatch {
                    expected: Some(ref expected),
                    actual: Some(ref actual),
                } if expected == "http" && actual == "https"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn uri_mismatch_is_rejected() {
        let msg = base();
        let opts = opts_for(&msg).with_uri("https://other.com");
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::UriMismatch { .. }));
    }

    #[test]
    fn uri_binding_accepts_match() {
        let msg = base();
        let opts = opts_for(&msg).with_uri("https://d.com");
        msg.validate(&opts).expect("matching uri");
    }

    #[test]
    fn request_id_mismatch_is_rejected() {
        let msg = base();
        let opts = opts_for(&msg).with_request_id("rid-1");
        let err = msg.validate(&opts).unwrap_err();
        assert!(
            matches!(
                err,
                SiwxError::RequestIdMismatch {
                    expected: Some(ref expected),
                    actual: None,
                } if expected == "rid-1"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn request_id_binding_accepts_match() {
        let msg = base().with_request_id("rid-1").expect("request_id");
        let opts = opts_for(&msg).with_request_id("rid-1");
        msg.validate(&opts).expect("matching request_id");
    }

    #[test]
    fn request_id_unbound_when_message_has_id() {
        let msg = base().with_request_id("rid-1").expect("request_id");
        msg.validate(&opts_for(&msg))
            .expect("unbound request_id must not reject a message request id");
    }

    #[test]
    fn invalid_resource_uri_is_rejected() {
        let builder_err = base()
            .with_resources(["not a valid uri ::: bad"])
            .unwrap_err();
        assert!(matches!(builder_err, SiwxError::InvalidUri { .. }));
        let mut msg = base();
        msg.resources = vec!["not a valid uri ::: bad".into()];
        let validate_err = msg.validate(&opts_for(&msg)).unwrap_err();
        assert!(matches!(validate_err, SiwxError::InvalidUri { .. }));
    }

    #[test]
    fn timestamp_override_changes_expiration_decision() {
        let msg = base()
            .with_expiration_time(datetime!(2020-01-01 0:00 UTC))
            .expect("expiration");
        let opts = opts_for(&msg).with_timestamp(datetime!(2019-01-01 0:00 UTC));
        msg.validate(&opts).expect("valid at earlier timestamp");
    }

    #[test]
    fn max_issued_age_rejects_stale_message() {
        let msg = base()
            .with_issued_at(datetime!(2020-01-01 0:00 UTC))
            .expect("issued_at");
        let opts = opts_for(&msg)
            .with_timestamp(datetime!(2020-01-02 0:00 UTC))
            .with_max_issued_age(time::Duration::hours(1));
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::StaleIssuedAt));
    }

    #[test]
    fn max_issued_age_within_skew_is_valid() {
        let msg = base()
            .with_issued_at(datetime!(2024-01-01 0:00 UTC))
            .expect("issued_at");
        let opts = opts_for(&msg)
            .with_timestamp(datetime!(2024-01-01 1:01 UTC))
            .with_max_issued_age(time::Duration::hours(1));
        msg.validate(&opts)
            .expect("age - 60s skew == max_age is not stale");
    }

    #[test]
    fn future_issued_at_is_not_stale() {
        let msg = base()
            .with_issued_at(datetime!(2024-01-02 0:00 UTC))
            .expect("issued_at");
        let opts = opts_for(&msg)
            .with_timestamp(datetime!(2024-01-01 0:00 UTC))
            .with_max_issued_age(time::Duration::hours(1));
        msg.validate(&opts)
            .expect("future issued-at must not be treated as stale");
    }
}
