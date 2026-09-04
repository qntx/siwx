use std::fmt;

/// Errors produced by siwx operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SiwxError {
    /// The `domain` field is missing or malformed.
    #[error("invalid domain: {reason}")]
    InvalidDomain {
        /// Why the domain is invalid.
        reason: &'static str,
    },
    /// Bound domain does not equal the message domain.
    #[error("domain mismatch: expected {expected}, got {actual}")]
    DomainMismatch {
        /// Domain required by [`crate::AuthOpts`].
        expected: String,
        /// Domain from the message.
        actual: String,
    },

    /// The optional preamble `scheme` is malformed.
    #[error("invalid scheme: {reason}")]
    InvalidScheme {
        /// Why the scheme is invalid.
        reason: &'static str,
    },
    /// Bound scheme does not equal the message scheme.
    #[error("scheme mismatch: expected {expected:?}, got {actual:?}")]
    SchemeMismatch {
        /// Scheme required by [`crate::AuthOpts`].
        expected: Option<String>,
        /// Scheme from the message.
        actual: Option<String>,
    },

    /// The `address` field does not conform to the expected format.
    #[error("invalid address: {reason}")]
    InvalidAddress {
        /// Why the address is invalid.
        reason: String,
    },

    /// The `uri` field is not a valid RFC 3986 URI.
    #[error("invalid uri: {reason}")]
    InvalidUri {
        /// Why the URI is invalid.
        reason: String,
    },
    /// Bound URI does not equal the message URI.
    #[error("uri mismatch: expected {expected}, got {actual}")]
    UriMismatch {
        /// URI required by [`crate::AuthOpts`].
        expected: String,
        /// URI from the message.
        actual: String,
    },

    /// A timestamp field is not valid RFC 3339.
    #[error("invalid timestamp: {reason}")]
    InvalidTimestamp {
        /// Why the timestamp is invalid.
        reason: String,
    },

    /// The `nonce` field is missing or malformed.
    #[error("invalid nonce: {reason}")]
    InvalidNonce {
        /// Why the nonce is invalid.
        reason: String,
    },
    /// Bound nonce does not equal the message nonce.
    #[error("nonce mismatch: expected {expected}, got {actual}")]
    NonceMismatch {
        /// Nonce required by [`crate::AuthOpts`].
        expected: String,
        /// Nonce from the message.
        actual: String,
    },

    /// The `statement` field is empty or not RFC 3986 reserved / unreserved / SP.
    #[error("invalid statement: {reason}")]
    InvalidStatement {
        /// Why the statement is invalid.
        reason: &'static str,
    },

    /// The optional `request-id` is not RFC 3986 `pchar` or exceeds the size limit.
    #[error("invalid request id: {reason}")]
    InvalidRequestId {
        /// Why the request id is invalid.
        reason: &'static str,
    },
    /// Bound request id does not equal the message request id.
    #[error("request id mismatch: expected {expected:?}, got {actual:?}")]
    RequestIdMismatch {
        /// Request id required by [`crate::AuthOpts`].
        expected: Option<String>,
        /// Request id from the message.
        actual: Option<String>,
    },

    /// The `chain-id` field is missing or fails the namespace profile.
    #[error("invalid chain id: {reason}")]
    InvalidChainId {
        /// Why the chain id is invalid.
        reason: ChainIdReason,
    },
    /// Bound chain id does not equal the message chain id.
    #[error("chain id mismatch: expected {expected}, got {actual}")]
    ChainIdMismatch {
        /// Chain id required by [`crate::AuthOpts`].
        expected: String,
        /// Chain id from the message.
        actual: String,
    },
    /// Preamble chain name does not match the verifier.
    #[error("chain name mismatch: expected {expected}, got {actual:?}")]
    ChainNameMismatch {
        /// Chain name required by the verifier.
        expected: String,
        /// Preamble chain name from the parsed message.
        actual: Option<String>,
    },

    /// The message has expired (`expiration_time` is in the past, beyond clock skew).
    #[error("message expired")]
    Expired,
    /// The message is not yet valid (`not_before` is in the future, beyond clock skew).
    #[error("message not yet valid")]
    NotYetValid,
    /// `issued-at` is older than [`crate::AuthOpts`] `max_issued_age` (beyond clock skew).
    #[error("issued-at exceeds max age")]
    StaleIssuedAt,

    /// A required field is missing or the overall format is wrong.
    #[error("invalid message format: {reason}")]
    InvalidFormat {
        /// ABNF / layout reason.
        reason: FormatReason,
    },

    /// The signing string exceeds [`crate::MAX_MESSAGE_BYTES`].
    #[error("message exceeds maximum size of {max} bytes, got {len}")]
    MessageTooLarge {
        /// Observed size in bytes.
        len: usize,
        /// Configured maximum.
        max: usize,
    },
    /// The resources list exceeds [`crate::MAX_RESOURCES`].
    #[error("too many resources: {count} > {max}")]
    TooManyResources {
        /// Observed count.
        count: usize,
        /// Configured maximum.
        max: usize,
    },

    /// Signature bytes are malformed or the wrong length.
    #[error("invalid signature: {reason}")]
    InvalidSignature {
        /// Why the signature encoding is invalid.
        reason: String,
    },
    /// The cryptographic verification did not succeed.
    #[error("verification failed: {reason}")]
    VerificationFailed {
        /// Verifier-specific failure detail (must not include RPC URLs).
        reason: String,
    },
}

/// Why a SIWX message failed ABNF / layout parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatReason {
    /// Input contained CR (`\r`).
    CrLf,
    /// Preamble missing ` wants you to sign in with your `.
    MissingPreamble,
    /// Preamble missing ` account:` suffix.
    MissingAccountSuffix,
    /// Input ended before a required line.
    UnexpectedEof,
    /// ABNF required a blank line.
    ExpectedBlankLine,
    /// Extra content after the last field.
    UnexpectedTrailing,
    /// A required tagged field was missing or out of order.
    MissingField(&'static str),
    /// `Version` was not `"1"`.
    VersionNotOne,
    /// `Chain ID:` tag present with empty value.
    EmptyChainId,
    /// Resource line did not start with `- `.
    ResourceSyntax,
    /// Other layout error.
    Other,
}

/// Why a `chain-id` field failed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainIdReason {
    /// Empty string.
    Empty,
    /// EVM: not `[0-9]+`.
    NotDecimal,
    /// EVM: leading zero (`"01"`); `"0"` is allowed.
    LeadingZero,
    /// Cannot fit in `u64`.
    Overflow,
    /// SVM: not `[-_a-zA-Z0-9]` of length 1..=44.
    ///
    /// CAIP-2 references are `{1,32}`. This product uses Solana genesis hashes
    /// (base58 of 32 bytes, typically 43 characters, max 44), so siwx-svm does
    /// not cap at 32.
    BadCharset,
}

impl fmt::Display for FormatReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CrLf => f.write_str("CR not allowed"),
            Self::MissingPreamble => f.write_str("missing preamble marker"),
            Self::MissingAccountSuffix => f.write_str("missing account suffix"),
            Self::UnexpectedEof => f.write_str("unexpected end of input"),
            Self::ExpectedBlankLine => f.write_str("expected blank line"),
            Self::UnexpectedTrailing => f.write_str("unexpected trailing content"),
            Self::MissingField(field) => write!(f, "missing {field}"),
            Self::VersionNotOne => f.write_str("version must be 1"),
            Self::EmptyChainId => f.write_str("empty chain id"),
            Self::ResourceSyntax => f.write_str("resource line must start with '- '"),
            Self::Other => f.write_str("invalid format"),
        }
    }
}

impl fmt::Display for ChainIdReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty"),
            Self::NotDecimal => f.write_str("not decimal"),
            Self::LeadingZero => f.write_str("leading zero"),
            Self::Overflow => f.write_str("overflow"),
            Self::BadCharset => f.write_str("bad charset"),
        }
    }
}

impl SiwxError {
    /// Convenience helper: creates [`SiwxError::InvalidFormat`].
    pub(crate) const fn invalid_format(reason: FormatReason) -> Self {
        Self::InvalidFormat { reason }
    }
}
