//! Server-side binding + time policy for a parsed [`Message`].

use time::OffsetDateTime;

use crate::{Error, Field, Message};

const DEFAULT_SKEW: std::time::Duration = std::time::Duration::from_secs(60);

/// `Duration` as i128 milliseconds, saturating on overflow.
fn millis(d: std::time::Duration) -> i128 {
    i128::try_from(d.as_millis()).unwrap_or(i128::MAX)
}

/// Instant in whole milliseconds since the Unix epoch, floored toward -inf.
const fn ms_floor(t: OffsetDateTime) -> i128 {
    t.unix_timestamp_nanos().div_euclid(1_000_000)
}

/// Expected bindings and clock policy checked by [`Expect::check`].
///
/// `domain` and `nonce` are always bound (server-issued values). Optional
/// bindings (`scheme`, `uri`, `chain_id`, `request_id`) are only checked when
/// set; an `actual` of `None` in [`Error::Mismatch`] means the message lacks
/// the optional field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expect {
    domain: String,
    nonce: String,
    scheme: Option<String>,
    uri: Option<String>,
    chain_id: Option<String>,
    request_id: Option<String>,
    time: Option<OffsetDateTime>,
    skew: std::time::Duration,
    max_age: Option<std::time::Duration>,
}

impl Expect {
    /// Bind the server-expected `domain` and `nonce`.
    #[must_use]
    pub fn new(domain: impl Into<String>, nonce: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            nonce: nonce.into(),
            scheme: None,
            uri: None,
            chain_id: None,
            request_id: None,
            time: None,
            skew: DEFAULT_SKEW,
            max_age: None,
        }
    }

    /// Bind the optional `scheme` field.
    #[must_use]
    pub fn with_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.scheme = Some(scheme.into());
        self
    }

    /// Bind the `uri` field.
    #[must_use]
    pub fn with_uri(mut self, uri: impl Into<String>) -> Self {
        self.uri = Some(uri.into());
        self
    }

    /// Bind the `chain-id` field.
    #[must_use]
    pub fn with_chain_id(mut self, chain_id: impl Into<String>) -> Self {
        self.chain_id = Some(chain_id.into());
        self
    }

    /// Bind the `request-id` field.
    #[must_use]
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// Override the reference instant (defaults to now, for tests).
    #[must_use]
    pub const fn with_time(mut self, time: OffsetDateTime) -> Self {
        self.time = Some(time);
        self
    }

    /// Clock-skew tolerance (default 60 s).
    #[must_use]
    pub const fn with_skew(mut self, skew: std::time::Duration) -> Self {
        self.skew = skew;
        self
    }

    /// Maximum age of `issued-at` (beyond skew).
    #[must_use]
    pub const fn with_max_age(mut self, max_age: std::time::Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    /// Check `message` against the bindings and time policy.
    ///
    /// Order: domain, nonce, scheme, uri, chain-id, request-id
    /// ([`Error::Mismatch`]), then [`Error::Expired`],
    /// [`Error::NotYetValid`], [`Error::IssuedAtTooOld`]. A future
    /// `issued-at` is not an error.
    ///
    /// # Errors
    ///
    /// Returns the first failing check's error.
    pub fn check(&self, message: &Message) -> Result<(), Error> {
        let mismatch = |field: Field, expected: &str, actual: Option<&str>| Error::Mismatch {
            field,
            expected: expected.to_owned(),
            actual: actual.map(str::to_owned),
        };
        if message.domain() != self.domain {
            return Err(mismatch(
                Field::Domain,
                &self.domain,
                Some(message.domain()),
            ));
        }
        if message.nonce() != self.nonce {
            return Err(mismatch(Field::Nonce, &self.nonce, Some(message.nonce())));
        }
        if let Some(expected) = &self.scheme
            && message.scheme() != Some(expected.as_str())
        {
            return Err(mismatch(Field::Scheme, expected, message.scheme()));
        }
        if let Some(expected) = &self.uri
            && message.uri() != expected
        {
            return Err(mismatch(Field::Uri, expected, Some(message.uri())));
        }
        if let Some(expected) = &self.chain_id
            && message.chain_id() != expected
        {
            return Err(mismatch(Field::ChainId, expected, Some(message.chain_id())));
        }
        if let Some(expected) = &self.request_id
            && message.request_id() != Some(expected.as_str())
        {
            return Err(mismatch(Field::RequestId, expected, message.request_id()));
        }

        // All comparisons at millisecond precision (toISOString floor),
        // truncated toward -inf like JS Date.
        let now = ms_floor(self.time.unwrap_or_else(OffsetDateTime::now_utc));
        let skew_ms = millis(self.skew);
        if let Some(exp) = message.expiration_time()
            && now > ms_floor(exp.instant()) + skew_ms
        {
            return Err(Error::Expired);
        }
        if let Some(nbf) = message.not_before()
            && now + skew_ms < ms_floor(nbf.instant())
        {
            return Err(Error::NotYetValid);
        }
        if let Some(max_age) = self.max_age {
            let issued = ms_floor(message.issued_at().instant());
            if issued <= now + skew_ms && now - issued - skew_ms > millis(max_age) {
                return Err(Error::IssuedAtTooOld);
            }
        }
        Ok(())
    }
}
