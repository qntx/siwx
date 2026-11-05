use std::fmt;

/// CAIP-122 message field or preamble component, camelCase-named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Field {
    /// Preamble chain label (`"your Ethereum account"`).
    Label,
    /// Optional RFC 3986 scheme prefixing the domain.
    Scheme,
    /// RFC 3986 authority requesting the signing.
    Domain,
    /// Blockchain address performing the signing.
    Address,
    /// Human-readable assertion.
    Statement,
    /// `URI:` field.
    Uri,
    /// `Version:` field.
    Version,
    /// `Chain ID:` field.
    ChainId,
    /// `Nonce:` field.
    Nonce,
    /// `Issued At:` field.
    IssuedAt,
    /// `Expiration Time:` field.
    ExpirationTime,
    /// `Not Before:` field.
    NotBefore,
    /// `Request ID:` field.
    RequestId,
    /// `Resources:` field.
    Resources,
}

impl Field {
    /// camelCase field name as used by JSON objects.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Label => "label",
            Self::Scheme => "scheme",
            Self::Domain => "domain",
            Self::Address => "address",
            Self::Statement => "statement",
            Self::Uri => "uri",
            Self::Version => "version",
            Self::ChainId => "chainId",
            Self::Nonce => "nonce",
            Self::IssuedAt => "issuedAt",
            Self::ExpirationTime => "expirationTime",
            Self::NotBefore => "notBefore",
            Self::RequestId => "requestId",
            Self::Resources => "resources",
        }
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Layout-level (ABNF) syntax failure of a signing text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[expect(
    clippy::enum_variant_names,
    reason = "variant names are the cross-language contract"
)]
pub enum Syntax {
    /// Input was not valid UTF-8.
    InvalidUtf8,
    /// Input contained CR (`\r`).
    CarriageReturn,
    /// Preamble missing ` wants you to sign in with your `.
    MissingPreamble,
    /// Preamble missing ` account:` suffix.
    MissingAccountSuffix,
    /// Input ended before a required line.
    UnexpectedEof,
    /// ABNF required a blank line.
    ExpectedBlankLine,
    /// A required tagged field was missing or out of order.
    MissingField(Field),
    /// Extra content after the last field (including a trailing LF).
    UnexpectedTrailing,
    /// A `Resources:` item did not start with `- `.
    ResourceSyntax,
    /// A Solana off-chain message envelope was malformed.
    InvalidEnvelope,
}

impl Syntax {
    /// Variant name as used by [`Error::code`].
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidUtf8 => "InvalidUtf8",
            Self::CarriageReturn => "CarriageReturn",
            Self::MissingPreamble => "MissingPreamble",
            Self::MissingAccountSuffix => "MissingAccountSuffix",
            Self::UnexpectedEof => "UnexpectedEof",
            Self::ExpectedBlankLine => "ExpectedBlankLine",
            Self::MissingField(_) => "MissingField",
            Self::UnexpectedTrailing => "UnexpectedTrailing",
            Self::ResourceSyntax => "ResourceSyntax",
            Self::InvalidEnvelope => "InvalidEnvelope",
        }
    }
}

impl fmt::Display for Syntax {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 => f.write_str("invalid UTF-8"),
            Self::CarriageReturn => f.write_str("CR not allowed"),
            Self::MissingPreamble => f.write_str("missing preamble marker"),
            Self::MissingAccountSuffix => f.write_str("missing account suffix"),
            Self::UnexpectedEof => f.write_str("unexpected end of input"),
            Self::ExpectedBlankLine => f.write_str("expected blank line"),
            Self::MissingField(field) => write!(f, "missing {field}"),
            Self::UnexpectedTrailing => f.write_str("unexpected trailing content"),
            Self::ResourceSyntax => f.write_str("resource line must start with '- '"),
            Self::InvalidEnvelope => f.write_str("invalid off-chain message envelope"),
        }
    }
}

/// Errors produced by siwx operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[expect(clippy::error_impl_error, reason = "type name is the public contract")]
pub enum Error {
    /// The signing text exceeds [`crate::MAX_MESSAGE_BYTES`].
    #[error("message exceeds maximum size of {max} bytes, got {len}")]
    MessageTooLarge {
        /// Observed size in bytes.
        len: usize,
        /// Configured maximum.
        max: usize,
    },
    /// ABNF / layout syntax failure.
    #[error("invalid message syntax: {0}")]
    Syntax(Syntax),
    /// A field value is malformed.
    #[error("invalid {field}: {reason}")]
    InvalidField {
        /// The malformed field.
        field: Field,
        /// Why the value is invalid.
        reason: &'static str,
    },
    /// A bound expectation does not equal the message value.
    #[error("{field} mismatch: expected {expected}, got {actual:?}")]
    Mismatch {
        /// The mismatched field.
        field: Field,
        /// Required value.
        expected: String,
        /// Message value (`None` when the optional field is absent).
        actual: Option<String>,
    },
    /// The request origin is not a serialized web origin.
    #[error("invalid origin: not a serialized web origin")]
    InvalidOrigin,
    /// The message has expired (`expiration_time` is in the past, beyond skew).
    #[error("message expired")]
    Expired,
    /// The message is not yet valid (`not_before` is in the future, beyond skew).
    #[error("message not yet valid")]
    NotYetValid,
    /// `issued_at` is older than the [`crate::Expect`] `max_age` (beyond skew).
    #[error("issued-at exceeds max age")]
    IssuedAtTooOld,
    /// Signature bytes are malformed or the wrong length.
    #[error("invalid signature: {reason}")]
    InvalidSignature {
        /// Why the signature encoding is invalid.
        reason: &'static str,
    },
    /// The cryptographic verification did not succeed.
    #[error("verification failed")]
    VerificationFailed,
    /// The operation needs a feature or configuration that is not enabled.
    #[error("unsupported: {reason}")]
    Unsupported {
        /// What is missing.
        reason: &'static str,
    },
    /// RPC / transport failed (timeout, connect, empty `eth_call`).
    #[error("backend error: {reason}")]
    Backend {
        /// Transport detail (must not include RPC URLs).
        reason: String,
    },
}

impl Error {
    /// Stable variant name for cross-language contract tests.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MessageTooLarge { .. } => "MessageTooLarge",
            Self::Syntax(_) => "Syntax",
            Self::InvalidField { .. } => "InvalidField",
            Self::Mismatch { .. } => "Mismatch",
            Self::InvalidOrigin => "InvalidOrigin",
            Self::Expired => "Expired",
            Self::NotYetValid => "NotYetValid",
            Self::IssuedAtTooOld => "IssuedAtTooOld",
            Self::InvalidSignature { .. } => "InvalidSignature",
            Self::VerificationFailed => "VerificationFailed",
            Self::Unsupported { .. } => "Unsupported",
            Self::Backend { .. } => "Backend",
        }
    }

    /// Convenience constructor for [`Error::InvalidField`].
    pub(crate) const fn field(field: Field, reason: &'static str) -> Self {
        Self::InvalidField { field, reason }
    }
}

#[cfg(test)]
mod tests {
    use proptest as _;
    use serde_json as _;
    use tokio as _;

    use super::*;

    #[test]
    fn field_names_are_camel_case() {
        assert_eq!(Field::ChainId.as_str(), "chainId");
        assert_eq!(Field::IssuedAt.as_str(), "issuedAt");
        assert_eq!(Field::NotBefore.as_str(), "notBefore");
        assert_eq!(Field::RequestId.as_str(), "requestId");
    }

    #[test]
    fn codes_are_variant_names() {
        assert_eq!(Error::Expired.code(), "Expired");
        assert_eq!(Syntax::CarriageReturn.code(), "CarriageReturn");
        assert_eq!(
            Error::field(Field::Domain, "userinfo not allowed").to_string(),
            "invalid domain: userinfo not allowed"
        );
        assert_eq!(
            Error::Syntax(Syntax::MissingField(Field::Uri)).to_string(),
            "invalid message syntax: missing uri"
        );
    }
}
