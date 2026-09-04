//! Property tests: `format` → `parse` preserves original field strings.

#![allow(
    unused_crate_dependencies,
    reason = "integration test crate links lib deps it does not use"
)]

use proptest::prelude::*;
use siwx::{SiwxMessage, Timestamp};

/// Parsed-field prefixes that would steal the statement line.
const TAGGED_PREFIXES: &[&str] = &[
    "URI: ",
    "Version: ",
    "Chain ID: ",
    "Nonce: ",
    "Issued At: ",
    "Expiration Time: ",
    "Not Before: ",
    "Request ID: ",
];

#[derive(Debug, Clone)]
struct ArbFields {
    scheme: Option<String>,
    domain: String,
    address: String,
    statement: Option<String>,
    uri: String,
    chain_id: String,
    nonce: String,
    issued_at: String,
    expiration_time: Option<String>,
    not_before: Option<String>,
    request_id: Option<String>,
    resources: Vec<String>,
}

fn is_tagged_line(line: &str) -> bool {
    TAGGED_PREFIXES.iter().any(|tag| line.starts_with(tag)) || line == "Resources:"
}

fn arb_label() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9]{0,11}"
}

fn arb_reg_name() -> impl Strategy<Value = String> {
    proptest::collection::vec(arb_label(), 1..4).prop_map(|labels| labels.join("."))
}

fn arb_ipv4() -> impl Strategy<Value = String> {
    (0u8..=255, 0u8..=255, 0u8..=255, 0u8..=255).prop_map(|(a, b, c, d)| format!("{a}.{b}.{c}.{d}"))
}

fn arb_ipv6_literal() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("[::1]".to_owned()),
        Just("[::cafe]".to_owned()),
        Just("[2001:db8::1]".to_owned()),
    ]
}

fn arb_host() -> impl Strategy<Value = String> {
    prop_oneof![arb_reg_name(), arb_ipv4(), arb_ipv6_literal()]
}

fn arb_domain() -> impl Strategy<Value = String> {
    (
        proptest::option::of("[A-Za-z0-9._~-]{1,12}"),
        arb_host(),
        proptest::option::of(1u16..=65535),
    )
        .prop_map(|(user, host, port)| {
            let mut out = String::new();
            if let Some(user) = user {
                out.push_str(&user);
                out.push('@');
            }
            out.push_str(&host);
            if let Some(port) = port {
                out.push(':');
                out.push_str(&port.to_string());
            }
            out
        })
}

fn arb_address() -> impl Strategy<Value = String> {
    "[0-9a-fA-F]{40}".prop_map(|hex| format!("0x{hex}"))
}

fn arb_scheme() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("https".to_owned()),
        Just("http".to_owned()),
        "[a-z][a-z0-9+.-]{0,6}",
    ]
}

fn arb_http_uri() -> impl Strategy<Value = String> {
    (
        prop_oneof![Just("https"), Just("http")],
        arb_host(),
        proptest::option::of(1u16..=65535),
        proptest::option::of("[A-Za-z0-9._~-]{1,24}"),
    )
        .prop_map(|(scheme, host, port, path)| {
            let mut uri = format!("{scheme}://{host}");
            if let Some(port) = port {
                uri.push(':');
                uri.push_str(&port.to_string());
            }
            if let Some(path) = path {
                uri.push('/');
                uri.push_str(&path);
            }
            uri
        })
}

fn arb_uri() -> impl Strategy<Value = String> {
    prop_oneof![
        arb_http_uri(),
        "[a-z0-9]{16,32}".prop_map(|cid| format!("ipfs://{cid}")),
    ]
}

fn arb_statement() -> impl Strategy<Value = String> {
    r"[A-Za-z0-9 ._~:/?#\[\]@!$&'()*+,;=-]{1,64}"
        .prop_filter("not a tagged field line", |s| !is_tagged_line(s))
}

fn arb_nonce() -> impl Strategy<Value = String> {
    "[0-9A-Za-z]{8,24}"
}

fn arb_chain_id() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("1".to_owned()),
        Just("0".to_owned()),
        "[1-9][0-9]{0,7}",
        "[A-Za-z0-9_-]{1,16}",
    ]
}

fn arb_request_id() -> impl Strategy<Value = String> {
    r"[A-Za-z0-9._~!$&'()*+,;=:@-]{1,32}"
}

fn arb_frac() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        Just(".000".to_owned()),
        Just(".382".to_owned()),
        "[0-9]{1,9}".prop_map(|digits| format!(".{digits}")),
    ]
}

fn arb_offset() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("Z".to_owned()),
        (0u8..=23, 0u8..=59, any::<bool>()).prop_map(|(hours, minutes, positive)| {
            format!(
                "{}{hours:02}:{minutes:02}",
                if positive { '+' } else { '-' }
            )
        }),
    ]
}

fn arb_rfc3339() -> impl Strategy<Value = String> {
    (
        1970u16..=2100,
        1u8..=12,
        1u8..=28,
        0u8..=23,
        0u8..=59,
        0u8..=59,
        arb_frac(),
        arb_offset(),
    )
        .prop_map(|(year, month, day, hour, minute, second, frac, offset)| {
            format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{frac}{offset}")
        })
        .prop_filter("RFC 3339 accepted by Timestamp::parse", |s| {
            Timestamp::parse(s).is_ok()
        })
}

fn arb_head() -> impl Strategy<
    Value = (
        Option<String>,
        String,
        String,
        Option<String>,
        String,
        String,
        String,
    ),
> {
    (
        proptest::option::of(arb_scheme()),
        arb_domain(),
        arb_address(),
        proptest::option::of(arb_statement()),
        arb_uri(),
        arb_chain_id(),
        arb_nonce(),
    )
}

fn arb_tail() -> impl Strategy<
    Value = (
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Vec<String>,
    ),
> {
    (
        arb_rfc3339(),
        proptest::option::of(arb_rfc3339()),
        proptest::option::of(arb_rfc3339()),
        proptest::option::of(arb_request_id()),
        proptest::collection::vec(arb_uri(), 0..4),
    )
}

fn arb_fields() -> impl Strategy<Value = ArbFields> {
    (arb_head(), arb_tail()).prop_map(
        |(
            (scheme, domain, address, statement, uri, chain_id, nonce),
            (issued_at, expiration_time, not_before, request_id, resources),
        )| ArbFields {
            scheme,
            domain,
            address,
            statement,
            uri,
            chain_id,
            nonce,
            issued_at,
            expiration_time,
            not_before,
            request_id,
            resources,
        },
    )
}

fn message_from_fields(fields: &ArbFields) -> Result<SiwxMessage, siwx::SiwxError> {
    let mut msg = SiwxMessage::new(
        &fields.domain,
        fields.address.clone(),
        &fields.uri,
        fields.chain_id.clone(),
        &fields.nonce,
    )?;
    if let Some(ref scheme) = fields.scheme {
        msg = msg.with_scheme(scheme)?;
    }
    if let Some(ref statement) = fields.statement {
        msg = msg.with_statement(statement.clone())?;
    }
    msg = msg.with_issued_at_raw(&fields.issued_at)?;
    if let Some(ref expiration) = fields.expiration_time {
        msg = msg.with_expiration_time_raw(expiration)?;
    }
    if let Some(ref not_before) = fields.not_before {
        msg = msg.with_not_before_raw(not_before)?;
    }
    if let Some(ref request_id) = fields.request_id {
        msg = msg.with_request_id(request_id)?;
    }
    if !fields.resources.is_empty() {
        msg = msg.with_resources(fields.resources.clone())?;
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 128,
            ..ProptestConfig::default()
        })]

        #[test]
        fn format_parse_preserves_originals(fields in arb_fields()) {
            let msg = message_from_fields(&fields)
                .map_err(|err| TestCaseError::fail(format!("valid fields rejected: {err}")))?;
            let raw = msg.to_sign_string("Ethereum");
            let parsed: SiwxMessage = raw
                .parse()
                .map_err(|err| TestCaseError::fail(format!("parse failed: {err}; raw={raw:?}")))?;

            prop_assert_eq!(
                parsed.to_sign_string("Ethereum"),
                raw,
                "format(parse(raw)) == raw"
            );
            prop_assert_eq!(parsed.issued_at.as_str(), fields.issued_at.as_str(), "issued_at_raw");
            prop_assert_eq!(
                parsed.expiration_time.as_ref().map(Timestamp::as_str),
                fields.expiration_time.as_deref(),
                "expiration raw"
            );
            prop_assert_eq!(
                parsed.not_before.as_ref().map(Timestamp::as_str),
                fields.not_before.as_deref(),
                "not_before raw"
            );
            prop_assert_eq!(parsed.statement, fields.statement, "statement");
            prop_assert_eq!(parsed.uri, fields.uri, "uri");
            prop_assert_eq!(parsed.domain, fields.domain, "domain");
            prop_assert_eq!(parsed.address, fields.address, "address");
            prop_assert_eq!(parsed.nonce, fields.nonce, "nonce");
            prop_assert_eq!(parsed.scheme, fields.scheme, "scheme");
            prop_assert_eq!(parsed.chain_id, fields.chain_id, "chain_id");
            prop_assert_eq!(parsed.request_id, fields.request_id, "request_id");
            prop_assert_eq!(parsed.resources, fields.resources, "resources");
        }
    }
}
