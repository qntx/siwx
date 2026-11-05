//! Wallet-side request-origin verification (ERC-4361 "Verifying the Request
//! Origin"), mirroring TypeScript `checkOrigin`.

use iri_string::spec::UriSpec;
use iri_string::validate::{host, port, scheme};

use crate::{Error, Message};

/// Wallet-side request-origin policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginPolicy {
    allowed_schemes: Vec<String>,
    default_scheme: String,
    developer_mode: bool,
}

impl Default for OriginPolicy {
    /// https only, default scheme `https`, developer mode off.
    fn default() -> Self {
        Self {
            allowed_schemes: vec!["https".to_owned()],
            default_scheme: "https".to_owned(),
            developer_mode: false,
        }
    }
}

impl OriginPolicy {
    /// Schemes the wallet accepts (compared case-insensitively).
    #[must_use]
    pub fn with_allowed_schemes<I, S>(mut self, schemes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_schemes = schemes.into_iter().map(Into::into).collect();
        self
    }

    /// Scheme assumed when the message has none.
    #[must_use]
    pub fn with_default_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.default_scheme = scheme.into();
        self
    }

    /// Scheme and host mismatches become warnings instead of rejections.
    #[must_use]
    pub const fn with_developer_mode(mut self, developer_mode: bool) -> Self {
        self.developer_mode = developer_mode;
        self
    }
}

/// What a finding is about; names are the cross-language contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OriginFindingCode {
    /// The message scheme is not in the allowed set.
    SchemeNotAllowed,
    /// The message scheme differs from the origin scheme.
    SchemeMismatch,
    /// The message host differs from the origin host.
    HostMismatch,
    /// The effective ports differ.
    PortMismatch,
}

impl OriginFindingCode {
    /// Variant name shared with the TypeScript implementation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SchemeNotAllowed => "SchemeNotAllowed",
            Self::SchemeMismatch => "SchemeMismatch",
            Self::HostMismatch => "HostMismatch",
            Self::PortMismatch => "PortMismatch",
        }
    }
}

/// How a wallet should treat a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Refuse the request.
    Reject,
    /// Warn the user.
    Warn,
}

/// One origin-verification finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginFinding {
    /// What was found.
    pub code: OriginFindingCode,
    /// How to treat it.
    pub severity: Severity,
}

struct Endpoint<'a> {
    host: &'a str,
    port: Option<&'a str>,
    has_port: bool,
}

/// Splits `host [":" port]`; an IPv6 literal keeps its brackets.
fn split_host_port(host_port: &str) -> Option<Endpoint<'_>> {
    if host_port.starts_with('[') {
        let end = host_port.find(']')?;
        let (host, after) = host_port.split_at(end.checked_add(1)?);
        return match after.strip_prefix(':') {
            _ if after.is_empty() => Some(Endpoint {
                host,
                port: None,
                has_port: false,
            }),
            Some(port) => Some(Endpoint {
                host,
                port: Some(port),
                has_port: true,
            }),
            None => None,
        };
    }
    Some(match host_port.rsplit_once(':') {
        Some((host, port)) => Endpoint {
            host,
            port: Some(port),
            has_port: true,
        },
        None => Endpoint {
            host: host_port,
            port: None,
            has_port: false,
        },
    })
}

fn default_port(scheme: &str) -> Option<&'static str> {
    match scheme {
        "https" => Some("443"),
        "http" => Some("80"),
        _ => None,
    }
}

/// Explicit port, else the scheme default; leading zeros are insignificant.
fn effective_port<'a>(port: Option<&'a str>, scheme: &str) -> Option<&'a str> {
    port.map_or_else(
        || default_port(scheme),
        |p| {
            Some(if p.bytes().all(|b| b == b'0') {
                "0"
            } else {
                p.trim_start_matches('0')
            })
        },
    )
}

/// Verify the request `origin` against the message `scheme` and `domain`.
///
/// Findings are returned in order: `SchemeNotAllowed`, `SchemeMismatch`,
/// `HostMismatch`, `PortMismatch`; an empty vector means the origin
/// verifies. `PortMismatch` is always a warning.
///
/// # Errors
///
/// [`Error::InvalidOrigin`] when `origin` is not a serialized web origin:
/// `scheme "://" host [ ":" port ]`.
pub fn check_origin(
    message: &Message,
    origin: &str,
    policy: &OriginPolicy,
) -> Result<Vec<OriginFinding>, Error> {
    let (origin_scheme, rest) = origin.split_once("://").ok_or(Error::InvalidOrigin)?;
    let target = split_host_port(rest).ok_or(Error::InvalidOrigin)?;
    let valid = scheme(origin_scheme).is_ok()
        && !target.host.is_empty()
        && host::<UriSpec>(target.host).is_ok()
        && (!target.has_port
            || target
                .port
                .is_some_and(|p| !p.is_empty() && port(p).is_ok()));
    if !valid {
        return Err(Error::InvalidOrigin);
    }
    let origin_scheme = origin_scheme.to_ascii_lowercase();

    let mismatch = if policy.developer_mode {
        Severity::Warn
    } else {
        Severity::Reject
    };
    let mut findings = Vec::new();
    let mut push = |code, severity| findings.push(OriginFinding { code, severity });

    let message_scheme = message
        .scheme()
        .unwrap_or(&policy.default_scheme)
        .to_ascii_lowercase();
    if !policy
        .allowed_schemes
        .iter()
        .any(|s| s.eq_ignore_ascii_case(&message_scheme))
    {
        push(OriginFindingCode::SchemeNotAllowed, Severity::Reject);
    }
    if message_scheme != origin_scheme {
        push(OriginFindingCode::SchemeMismatch, mismatch);
    }

    let own = split_host_port(message.domain());
    if !own
        .as_ref()
        .map_or("", |e| e.host)
        .eq_ignore_ascii_case(target.host)
    {
        push(OriginFindingCode::HostMismatch, mismatch);
    }

    let own_port = own.as_ref().and_then(|e| e.port).filter(|p| !p.is_empty());
    if effective_port(own_port, &message_scheme) != effective_port(target.port, &origin_scheme) {
        push(OriginFindingCode::PortMismatch, Severity::Warn);
    }
    Ok(findings)
}
