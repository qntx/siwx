//! Round-trip property: every accepted text formats back byte-for-byte,
//! and every valid message parses back to identical fields.

#![allow(
    unused_crate_dependencies,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::excessive_nesting,
    clippy::map_unwrap_or,
    clippy::match_same_arms,
    reason = "integration test crate links lib deps it does not use; test helpers may panic/index"
)]

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use siwx::{Message, MessageFields, eip4361};

    fn arb_string(chars: &str, max: usize) -> impl Strategy<Value = String> {
        let chars: Vec<char> = chars.chars().collect();
        proptest::collection::vec(proptest::sample::select(chars), 0..=max)
            .prop_map(|v| v.into_iter().collect())
    }

    const STMT_CHARS: &str =
        ":/?#[]@!$&'()*+,;= abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
    const PCHAR: &str =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=:@";

    fn arb_fields() -> impl Strategy<Value = MessageFields> {
        (
            proptest::option::of("[a-z][a-z0-9+.-]{0,6}"),
            "[a-z0-9][a-z0-9.-]{0,20}",
            arb_string("abcdef0123456789ABCDEF-.%", 8),
            proptest::option::of(arb_string(STMT_CHARS, 32)),
            proptest::option::of(arb_string(PCHAR, 16)),
            proptest::option::of(proptest::collection::vec("uri:[a-z0-9/-]{0,16}", 0..=4)),
        )
            .prop_map(|(scheme, dom, addr, stmt, rid, resources)| MessageFields {
                scheme,
                domain: dom,
                address: if addr.is_empty() { "a".into() } else { addr },
                statement: stmt,
                uri: "https://example.com".into(),
                version: "1".into(),
                chain_id: "1".into(),
                nonce: "12341234".into(),
                issued_at: "2021-09-30T16:25:24.000Z".into(),
                expiration_time: None,
                not_before: None,
                request_id: rid,
                resources,
            })
    }

    proptest! {
        #[test]
        fn format_parse_roundtrip(fields in arb_fields()) {
            let msg = Message::new(fields.clone()).expect("valid fields");
            let text = eip4361::format("TestChain", &msg);
            let parsed = eip4361::parse(&text).expect("parse");
            prop_assert_eq!(parsed.label, "TestChain");
            prop_assert_eq!(parsed.message.into_fields(), fields);
        }

        #[test]
        fn parse_format_is_identity(text in "([ -~]{0,400})") {
            if let Ok(parsed) = eip4361::parse(&text) {
                prop_assert_eq!(eip4361::format(&parsed.label, &parsed.message), text);
            }
        }
    }
}
