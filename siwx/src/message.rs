use std::fmt;
use std::str::FromStr;

use iri_string::types::UriString;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::SiwxError;

const PREAMBLE_MID: &str = " wants you to sign in with your ";
const PREAMBLE_TAIL: &str = " account:";
const URI_TAG: &str = "URI: ";
const VERSION_TAG: &str = "Version: ";
const CHAIN_TAG: &str = "Chain ID: ";
const NONCE_TAG: &str = "Nonce: ";
const IAT_TAG: &str = "Issued At: ";
const EXP_TAG: &str = "Expiration Time: ";
const NBF_TAG: &str = "Not Before: ";
const RID_TAG: &str = "Request ID: ";
const RES_TAG: &str = "Resources:";

/// CAIP-122 Sign-In with X message.
///
/// This struct models the **abstract data model** defined in [CAIP-122].
/// It is chain-agnostic; chain-specific formatting and verification live in
/// companion crates.
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

    /// RFC 3986 URI referring to the resource that is the subject of the
    /// signing.
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
        serde(serialize_with = "ser_opt_ts", deserialize_with = "de_opt_ts", default)
    )]
    pub issued_at: Option<OffsetDateTime>,

    /// ISO 8601 / RFC 3339 expiration time.
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "ser_opt_ts", deserialize_with = "de_opt_ts", default)
    )]
    pub expiration_time: Option<OffsetDateTime>,

    /// ISO 8601 / RFC 3339 earliest valid time.
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "ser_opt_ts", deserialize_with = "de_opt_ts", default)
    )]
    pub not_before: Option<OffsetDateTime>,

    /// System-specific request identifier.
    pub request_id: Option<String>,

    /// List of RFC 3986 URI resources.
    #[cfg_attr(feature = "serde", serde(default))]
    pub resources: Vec<String>,
}

/// Options for temporal validation.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ValidateOpts {
    /// The point in time to check against. Defaults to `OffsetDateTime::now_utc()`.
    pub timestamp: Option<OffsetDateTime>,
    /// Expected domain (if set, must match `message.domain`).
    pub domain: Option<String>,
    /// Expected nonce (if set, must match `message.nonce`).
    pub nonce: Option<String>,
}

impl SiwxMessage {
    /// Create a minimal valid message with only the mandatory CAIP-122 fields.
    ///
    /// # Errors
    ///
    /// Returns [`SiwxError`] if any mandatory field is empty.
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
        let msg = Self {
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
        };
        Ok(msg)
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

    /// Render the human-readable signing string.
    ///
    /// `chain_name` is the human-readable ecosystem label shown in the
    /// preamble (e.g. `"Ethereum"`, `"Solana"`).  Each chain crate provides a
    /// constant for this.
    ///
    /// # Examples
    ///
    /// ```
    /// use siwx::SiwxMessage;
    ///
    /// let msg = SiwxMessage::new("example.com", "addr1", "https://example.com", "1", "1")?;
    /// let text = msg.to_sign_string("Ethereum");
    /// assert!(text.starts_with("example.com wants you to sign in with your Ethereum account:"));
    /// # Ok::<(), siwx::SiwxError>(())
    /// ```
    #[must_use]
    pub fn to_sign_string(&self, chain_name: &str) -> String {
        let mut out = String::with_capacity(512);

        // Preamble
        out.push_str(&self.domain);
        out.push_str(PREAMBLE_MID);
        out.push_str(chain_name);
        out.push_str(PREAMBLE_TAIL);
        out.push('\n');
        out.push_str(&self.address);
        out.push('\n');

        // Statement (optional, surrounded by blank lines)
        out.push('\n');
        if let Some(ref stmt) = self.statement {
            out.push_str(stmt);
            out.push('\n');
            out.push('\n');
        }

        // Required tagged fields
        push_tag(&mut out, URI_TAG, &self.uri);
        push_tag(&mut out, VERSION_TAG, &self.version);
        push_tag(&mut out, CHAIN_TAG, &self.chain_id);

        // Optional tagged fields
        if let Some(ref n) = self.nonce {
            push_tag(&mut out, NONCE_TAG, n);
        }
        if let Some(t) = self.issued_at {
            push_tag(&mut out, IAT_TAG, &fmt_ts(t));
        }
        if let Some(t) = self.expiration_time {
            push_tag(&mut out, EXP_TAG, &fmt_ts(t));
        }
        if let Some(t) = self.not_before {
            push_tag(&mut out, NBF_TAG, &fmt_ts(t));
        }
        if let Some(ref rid) = self.request_id {
            push_tag(&mut out, RID_TAG, rid);
        }

        // Resources
        if !self.resources.is_empty() {
            out.push_str(RES_TAG);
            out.push('\n');
            for r in &self.resources {
                out.push_str("- ");
                out.push_str(r);
                out.push('\n');
            }
        }

        let trimmed_len = out.trim_end_matches('\n').len();
        out.truncate(trimmed_len);
        out
    }

    /// Validate the message fields and temporal constraints.
    ///
    /// # Errors
    ///
    /// Returns an appropriate [`SiwxError`] variant on any validation failure.
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
        // Required fields must be non-empty
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

        // URI must parse
        UriString::try_from(self.uri.as_str()).map_err(|e| SiwxError::InvalidUri(e.to_string()))?;

        // Statement must not contain newlines
        if let Some(ref s) = self.statement
            && s.contains('\n')
        {
            return Err(SiwxError::InvalidStatement(
                "must not contain newline".into(),
            ));
        }

        // Resources must be valid RFC 3986 URIs
        for r in &self.resources {
            UriString::try_from(r.as_str())
                .map_err(|e| SiwxError::InvalidUri(format!("invalid resource URI: {e}")))?;
        }

        // Domain binding
        if let Some(ref expected) = opts.domain
            && *expected != self.domain
        {
            return Err(SiwxError::InvalidDomain(format!(
                "expected {expected}, got {}",
                self.domain
            )));
        }

        // Nonce binding
        if let Some(ref expected) = opts.nonce {
            let actual = self.nonce.as_deref().unwrap_or("");
            if *expected != actual {
                return Err(SiwxError::InvalidNonce(format!(
                    "expected {expected}, got {actual}"
                )));
            }
        }

        // Temporal checks
        let now = opts.timestamp.unwrap_or_else(OffsetDateTime::now_utc);

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

impl FromStr for SiwxMessage {
    type Err = SiwxError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut lines = input.split('\n').peekable();

        // Preamble: "{domain} wants you to sign in with your {chain} account:"
        let header = next(&mut lines, "preamble")?;
        let mid_pos = header
            .find(PREAMBLE_MID)
            .ok_or_else(|| SiwxError::invalid_format("missing preamble marker"))?;
        let domain = header[..mid_pos].to_owned();
        let after_mid = &header[mid_pos + PREAMBLE_MID.len()..];
        let _chain_name = after_mid
            .strip_suffix(PREAMBLE_TAIL)
            .ok_or_else(|| SiwxError::invalid_format("missing 'account:' suffix"))?;

        // Address
        let address = next(&mut lines, "address")?.to_owned();

        // Blank line
        let blank = next(&mut lines, "blank line after address")?;
        if !blank.is_empty() {
            return Err(SiwxError::invalid_format(
                "expected blank line after address",
            ));
        }

        // Optional statement (any line not starting with a known tag)
        let statement = match lines.peek() {
            Some(&line) if !line.is_empty() && !is_tag(line) => {
                let stmt = line.to_owned();
                lines.next();
                // consume trailing blank line
                if let Some(&bl) = lines.peek()
                    && bl.is_empty()
                {
                    lines.next();
                }
                Some(stmt)
            }
            _ => None,
        };

        // Tagged fields
        let uri = take_required_tag(&mut lines, URI_TAG)?;
        let version = take_required_tag(&mut lines, VERSION_TAG)?;
        let chain_id = take_required_tag(&mut lines, CHAIN_TAG)?;

        let nonce = take_optional_tag(&mut lines, NONCE_TAG);
        let issued_at = take_optional_tag(&mut lines, IAT_TAG)
            .map(|s| parse_ts(&s))
            .transpose()?;
        let expiration_time = take_optional_tag(&mut lines, EXP_TAG)
            .map(|s| parse_ts(&s))
            .transpose()?;
        let not_before = take_optional_tag(&mut lines, NBF_TAG)
            .map(|s| parse_ts(&s))
            .transpose()?;
        let request_id = take_optional_tag(&mut lines, RID_TAG);

        // Resources
        let resources = if lines.peek().is_some_and(|l| *l == RES_TAG) {
            lines.next();
            parse_resource_lines(&mut lines)?
        } else {
            Vec::new()
        };

        Ok(Self {
            domain,
            address,
            statement,
            uri,
            version,
            chain_id,
            nonce,
            issued_at,
            expiration_time,
            not_before,
            request_id,
            resources,
        })
    }
}

impl fmt::Display for SiwxMessage {
    /// Renders with a generic `"X"` chain name. For a proper signing string
    /// use [`SiwxMessage::to_sign_string`] with the correct chain label.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_sign_string("X"))
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

fn push_tag(out: &mut String, tag: &str, value: &str) {
    out.push_str(tag);
    out.push_str(value);
    out.push('\n');
}

fn fmt_ts(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_else(|_| t.to_string())
}

fn parse_resource_lines(
    lines: &mut std::iter::Peekable<std::str::Split<'_, char>>,
) -> Result<Vec<String>, SiwxError> {
    let mut res = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let item = line
            .strip_prefix("- ")
            .ok_or_else(|| SiwxError::invalid_format("resource line must start with '- '"))?;
        res.push(item.to_owned());
    }
    Ok(res)
}

fn parse_ts(s: &str) -> Result<OffsetDateTime, SiwxError> {
    OffsetDateTime::parse(s, &Rfc3339).map_err(|e| SiwxError::InvalidTimestamp(e.to_string()))
}

fn next<'a>(lines: &mut impl Iterator<Item = &'a str>, ctx: &str) -> Result<&'a str, SiwxError> {
    lines
        .next()
        .ok_or_else(|| SiwxError::invalid_format(format!("unexpected end of input ({ctx})")))
}

fn take_required_tag(
    lines: &mut std::iter::Peekable<std::str::Split<'_, char>>,
    tag: &str,
) -> Result<String, SiwxError> {
    let line = lines
        .peek()
        .ok_or_else(|| SiwxError::invalid_format(format!("missing {tag}")))?;
    let val = line
        .strip_prefix(tag)
        .ok_or_else(|| SiwxError::invalid_format(format!("expected {tag}")))?
        .to_owned();
    lines.next();
    Ok(val)
}

fn take_optional_tag(
    lines: &mut std::iter::Peekable<std::str::Split<'_, char>>,
    tag: &str,
) -> Option<String> {
    let val = lines.peek().and_then(|l| l.strip_prefix(tag))?.to_owned();
    lines.next();
    Some(val)
}

const TAGS: &[&str] = &[
    URI_TAG,
    VERSION_TAG,
    CHAIN_TAG,
    NONCE_TAG,
    IAT_TAG,
    EXP_TAG,
    NBF_TAG,
    RID_TAG,
];

fn is_tag(line: &str) -> bool {
    TAGS.iter().any(|tag| line.starts_with(tag)) || line == RES_TAG
}

#[cfg(feature = "serde")]
#[expect(
    clippy::ref_option,
    reason = "serde serialize_with requires &Option<T> signature"
)]
fn ser_opt_ts<S: serde::Serializer>(
    ts: &Option<OffsetDateTime>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match ts {
        Some(t) => {
            let s = t.format(&Rfc3339).map_err(serde::ser::Error::custom)?;
            serializer.serialize_some(&s)
        }
        None => serializer.serialize_none(),
    }
}

#[cfg(feature = "serde")]
fn de_opt_ts<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<OffsetDateTime>, D::Error> {
    let opt: Option<String> = serde::Deserialize::deserialize(deserializer)?;
    opt.map(|s| OffsetDateTime::parse(&s, &Rfc3339).map_err(serde::de::Error::custom))
        .transpose()
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    fn sample_message() -> SiwxMessage {
        SiwxMessage::new(
            "service.org",
            "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
            "https://service.org/login",
            "1",
            "1",
        )
        .expect("valid")
        .with_statement("I accept the ServiceOrg Terms of Service: https://service.org/tos")
        .with_nonce("32891756")
        .with_issued_at(datetime!(2021-09-30 16:25:24 UTC))
        .with_resources([
            "ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/",
            "https://example.com/my-web2-claim.json",
        ])
    }

    #[test]
    fn format_ethereum_message() {
        let msg = sample_message();
        let text = msg.to_sign_string("Ethereum");
        let expected = "\
service.org wants you to sign in with your Ethereum account:
0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2

I accept the ServiceOrg Terms of Service: https://service.org/tos

URI: https://service.org/login
Version: 1
Chain ID: 1
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z
Resources:
- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/
- https://example.com/my-web2-claim.json";
        assert_eq!(text, expected);
    }

    #[test]
    fn roundtrip_parse() {
        let msg = sample_message();
        let text = msg.to_sign_string("Ethereum");
        let parsed: SiwxMessage = text.parse().expect("parse");
        assert_eq!(parsed, msg);
    }

    #[test]
    fn format_solana_message() {
        let msg = SiwxMessage::new(
            "service.org",
            "GwAF45zjfyGzUbd3i3hXxzGeuchzEZXwpRYHZM5912F1",
            "https://service.org/login",
            "1",
            "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
        )
        .expect("valid");
        let text = msg.to_sign_string("Solana");
        assert!(text.starts_with("service.org wants you to sign in with your Solana account:"));
        assert!(text.contains("Chain ID: 5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"));
    }

    #[test]
    fn minimal_message_no_optionals() {
        let msg =
            SiwxMessage::new("example.com", "addr1", "https://example.com", "1", "1").unwrap();
        let text = msg.to_sign_string("Ethereum");
        let parsed: SiwxMessage = text.parse().unwrap();
        assert_eq!(parsed.domain, "example.com");
        assert!(parsed.statement.is_none());
        assert!(parsed.nonce.is_none());
        assert!(parsed.issued_at.is_none());
    }

    #[test]
    fn validate_expired() {
        let msg = SiwxMessage::new("d.com", "a", "https://d.com", "1", "1")
            .unwrap()
            .with_expiration_time(datetime!(2020-01-01 0:00 UTC));
        let err = msg.validate(&ValidateOpts::default()).unwrap_err();
        assert!(matches!(err, SiwxError::Expired));
    }

    #[test]
    fn validate_not_yet_valid() {
        let msg = SiwxMessage::new("d.com", "a", "https://d.com", "1", "1")
            .unwrap()
            .with_not_before(datetime!(2099-01-01 0:00 UTC));
        let err = msg.validate(&ValidateOpts::default()).unwrap_err();
        assert!(matches!(err, SiwxError::NotYetValid));
    }

    #[test]
    fn validate_domain_mismatch() {
        let msg = SiwxMessage::new("evil.com", "a", "https://evil.com", "1", "1").unwrap();
        let opts = ValidateOpts {
            domain: Some("good.com".into()),
            ..Default::default()
        };
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::InvalidDomain(_)));
    }

    #[test]
    fn validate_nonce_mismatch() {
        let msg = SiwxMessage::new("d.com", "a", "https://d.com", "1", "1")
            .unwrap()
            .with_nonce("abc");
        let opts = ValidateOpts {
            nonce: Some("xyz".into()),
            ..Default::default()
        };
        let err = msg.validate(&opts).unwrap_err();
        assert!(matches!(err, SiwxError::InvalidNonce(_)));
    }

    #[test]
    fn statement_newline_rejected() {
        let msg = SiwxMessage::new("d.com", "a", "https://d.com", "1", "1")
            .unwrap()
            .with_statement("bad\nstatement");
        let err = msg.validate(&ValidateOpts::default()).unwrap_err();
        assert!(matches!(err, SiwxError::InvalidStatement(_)));
    }

    #[test]
    fn empty_domain_rejected() {
        let err = SiwxMessage::new("", "a", "https://d.com", "1", "1").unwrap_err();
        assert!(matches!(err, SiwxError::InvalidFormat(_)));
    }

    #[test]
    fn parse_tolerates_trailing_newline() {
        let msg = sample_message();
        let mut text = msg.to_sign_string("Ethereum");
        text.push('\n');
        let parsed: SiwxMessage = text.parse().expect("should parse with trailing newline");
        assert_eq!(parsed, msg);
    }

    #[test]
    fn invalid_resource_uri_rejected() {
        let msg = SiwxMessage::new("d.com", "a", "https://d.com", "1", "1")
            .unwrap()
            .with_resources(["not a valid uri ::: bad"]);
        let err = msg.validate(&ValidateOpts::default()).unwrap_err();
        assert!(matches!(err, SiwxError::InvalidUri(_)));
    }
}
