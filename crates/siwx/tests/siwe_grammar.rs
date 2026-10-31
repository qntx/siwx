//! Canonical SIWE grammar vectors (vectors/siwe/grammar/*.json).
//!
//! Rule-level char cases are mapped into a message position AND checked
//! against the raw rule charset (URI delimiters like `?`/`#` remain valid
//! URIs when embedded, so the embed alone cannot express the rule). The
//! expected `answer` must hold for both. uri/resources files are
//! complete messages that must parse or fail.
//!
//! `vectors/siwe-overrides.json` registers canonical cases siwx answers
//! differently (e.g. RFC 3986 dec-octet rejects leading-zero IPv4 octets
//! that the canonical uri-js harness accepts).

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
    use serde_json::{Map, Value};

    use siwx::{Message, MessageFields};

    fn cases(file: &str) -> Map<String, Value> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/siwe/grammar/");
        let text = std::fs::read_to_string(format!("{path}{file}")).expect("read vector");
        serde_json::from_str(&text).expect("vector json")
    }

    fn overrides() -> Map<String, Value> {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/siwe-overrides.json"
        ))
        .expect("read overrides");
        serde_json::from_str(&text).expect("overrides json")
    }

    fn base_fields() -> MessageFields {
        MessageFields {
            scheme: None,
            domain: "service.org".into(),
            address: "0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946".into(),
            statement: None,
            uri: "uri:".into(),
            version: "1".into(),
            chain_id: "1".into(),
            nonce: "12341234".into(),
            issued_at: "2021-09-30T16:25:24.000Z".into(),
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: None,
        }
    }

    const fn unreserved(b: u8) -> bool {
        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
    }

    const fn sub_delims(b: u8) -> bool {
        matches!(
            b,
            b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
        )
    }

    const fn pchar(b: u8) -> bool {
        unreserved(b) || sub_delims(b) || b == b':' || b == b'@'
    }

    fn charset(input: &str, allow_pct: bool, allowed: impl Fn(u8) -> bool) -> bool {
        let mut it = input.bytes();
        while let Some(b) = it.next() {
            if b == b'%' && allow_pct {
                match (it.next(), it.next()) {
                    (Some(h1), Some(h2)) if h1.is_ascii_hexdigit() && h2.is_ascii_hexdigit() => {
                        continue;
                    }
                    _ => return false,
                }
            }
            if !allowed(b) {
                return false;
            }
        }
        true
    }

    fn is_statement_char(c: char) -> bool {
        matches!(
            c,
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' | '~'
                | ':' | '/' | '?' | '#' | '[' | ']' | '@'
                | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '=' | ' '
        )
    }

    /// Raw-rule verdict for the grammar `rule` on `input`.
    fn rule_ok(rule: &str, input: &str) -> bool {
        match rule {
            "scheme" => {
                input
                    .bytes()
                    .next()
                    .is_some_and(|b| b.is_ascii_alphabetic())
                    && input
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
            }
            "statement" => input.chars().all(is_statement_char),
            "pct-encoded" => {
                input.len() == 3
                    && input.starts_with('%')
                    && input.as_bytes()[1].is_ascii_hexdigit()
                    && input.as_bytes()[2].is_ascii_hexdigit()
            }
            "userinfo" => charset(input, true, |b| unreserved(b) || sub_delims(b) || b == b':'),
            "IPvFuture" => {
                let Some(rest) = input.strip_prefix('v').or_else(|| input.strip_prefix('V')) else {
                    return false;
                };
                let Some((hex, tail)) = rest.split_once('.') else {
                    return false;
                };
                !hex.is_empty()
                    && hex.bytes().all(|b| b.is_ascii_hexdigit())
                    && !tail.is_empty()
                    && tail
                        .bytes()
                        .all(|b| unreserved(b) || sub_delims(b) || b == b':')
            }
            "reg-name" => charset(input, true, |b| unreserved(b) || sub_delims(b)),
            "IPv6address" | "IPv4address" => true, // structure covered by the URI embed
            "segment-nz" | "segment" | "pchar" => !input.is_empty() && charset(input, true, pchar),
            "fragment" | "query" => charset(input, true, |b| pchar(b) || b == b'/' || b == b'?'),
            _ => panic!("unmapped grammar rule {rule}"),
        }
    }

    /// Embed `input` for `rule` into a message position; `None` when the rule
    /// has no field position (charset check only).
    fn embed(rule: &str, input: &str) -> Option<MessageFields> {
        let mut f = base_fields();
        match rule {
            "scheme" => f.scheme = Some(input.into()),
            "statement" => f.statement = Some(input.into()),
            "userinfo" => f.uri = format!("uri://{input}@h"),
            "IPvFuture" | "IPv6address" => f.uri = format!("uri://[{input}]"),
            "reg-name" | "IPv4address" => f.uri = format!("uri://{input}"),
            "pct-encoded" | "segment-nz" | "segment" | "pchar" => f.uri = format!("uri:{input}"),
            "fragment" => f.uri = format!("uri:#{input}"),
            "query" => f.uri = format!("uri:?{input}"),
            _ => return None,
        }
        Some(f)
    }

    fn accepts(rule: &str, input: &str) -> bool {
        rule_ok(rule, input)
            && embed(rule, input)
                .map(|f| Message::new(f).is_ok())
                .unwrap_or(true)
    }

    fn run_chars(file: &str) {
        for (name, case) in cases(file) {
            let rule = case["rule"].as_str().unwrap();
            let input = case["input"].as_str().unwrap();
            let answer = case["answer"].as_bool().unwrap();
            assert_eq!(
                accepts(rule, input),
                answer,
                "{file}#{name} rule {rule} input {input:?}"
            );
        }
    }

    fn run_messages(file: &str, expect_ok: bool) {
        let ov = overrides();
        for (name, case) in cases(file) {
            let msg = case
                .get("msg")
                .and_then(Value::as_str)
                .or_else(|| case.as_str())
                .unwrap_or_else(|| panic!("{file}#{name}: no message"));
            let result = siwx::eip4361::parse(msg);
            let key = format!("{file}#{name}");
            if let Some(o) = ov.get(&key) {
                let err = result.expect_err(&format!("{key} must fail per overrides"));
                assert_eq!(
                    err.code(),
                    o["error"]["code"].as_str().unwrap(),
                    "{key}: {err}"
                );
                continue;
            }
            assert_eq!(result.is_ok(), expect_ok, "{key}: {result:?}");
            if let Ok(parsed) = result {
                assert_eq!(
                    siwx::eip4361::format(&parsed.label, &parsed.message),
                    msg,
                    "{key} round-trip"
                );
            }
        }
    }

    #[test]
    fn valid_chars() {
        run_chars("valid_chars.json");
    }

    #[test]
    fn invalid_chars() {
        run_chars("invalid_chars.json");
    }

    #[test]
    fn valid_uris() {
        run_messages("valid_uris.json", true);
    }

    #[test]
    fn invalid_uris() {
        run_messages("invalid_uris.json", false);
    }

    #[test]
    fn valid_resources() {
        run_messages("valid_resources.json", true);
    }

    #[test]
    fn invalid_resources() {
        run_messages("invalid_resources.json", false);
    }

    #[test]
    fn valid_specification() {
        run_messages("valid_specification.json", true);
    }
}
