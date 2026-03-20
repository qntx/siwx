use std::fmt;

/// Errors produced by siwx operations.
#[derive(Debug, thiserror::Error)]
pub enum SiwxError {
    /// The `domain` field is missing or malformed.
    #[error("invalid domain: {0}")]
    InvalidDomain(String),

    /// The `address` field does not conform to the expected format.
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// The `uri` field is not a valid RFC 3986 URI.
    #[error("invalid uri: {0}")]
    InvalidUri(String),

    /// A timestamp field is not valid RFC 3339.
    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(String),

    /// The `nonce` field is missing or malformed.
    #[error("invalid nonce: {0}")]
    InvalidNonce(String),

    /// The `statement` field contains a forbidden `\n` character.
    #[error("invalid statement: {0}")]
    InvalidStatement(String),

    /// The message has expired (`expiration_time` is in the past).
    #[error("message expired")]
    Expired,

    /// The message is not yet valid (`not_before` is in the future).
    #[error("message not yet valid")]
    NotYetValid,

    /// A required field is missing or the overall format is wrong.
    #[error("invalid message format: {0}")]
    InvalidFormat(String),

    /// Signature bytes are malformed or the wrong length.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// The cryptographic verification did not succeed.
    #[error("verification failed: {0}")]
    VerificationFailed(String),
}

impl SiwxError {
    /// Convenience helper: creates [`SiwxError::InvalidFormat`] from any
    /// [`Display`](fmt::Display) value.
    pub(crate) fn invalid_format(msg: impl fmt::Display) -> Self {
        Self::InvalidFormat(msg.to_string())
    }
}
