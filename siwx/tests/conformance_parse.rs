//! Official SIWE parse-vector conformance (`FromStr` only).

#![allow(
    unused_crate_dependencies,
    reason = "integration test crate links lib deps it does not use"
)]

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::str::FromStr;

    use serde_json::Value;
    use siwx::SiwxMessage;

    const PARSING_POSITIVE: &str = include_str!("vectors/siwe/parsing_positive.json");
    const PARSING_NEGATIVE: &str = include_str!("vectors/siwe/parsing_negative.json");

    /// EIP-55 checksum is an EVM-profile rule, not core ABNF.
    const SKIP_EIP55: &str = "address not EIP-55";

    fn load_object(json: &str) -> BTreeMap<String, Value> {
        serde_json::from_str(json).expect("official SIWE vector JSON")
    }

    fn chain_id_line(raw: &str) -> Option<&str> {
        raw.lines().find_map(|line| line.strip_prefix("Chain ID: "))
    }

    fn is_decimal_chain_id(chain_id: &str) -> bool {
        !chain_id.is_empty() && chain_id.bytes().all(|b| b.is_ascii_digit())
    }

    /// Core is chain-agnostic: skip EVM-only negatives (EIP-55, non-decimal chain id).
    fn skip_evm_only_negative(name: &str, raw: &str) -> bool {
        name == SKIP_EIP55
            || chain_id_line(raw).is_some_and(|chain_id| !is_decimal_chain_id(chain_id))
    }

    #[test]
    fn parsing_positive_from_str_round_trips() {
        let cases = load_object(PARSING_POSITIVE);
        assert!(!cases.is_empty(), "parsing_positive.json must not be empty");
        for (name, case) in cases {
            let raw = case.get("message").and_then(Value::as_str);
            assert!(raw.is_some(), "{name}: missing `message` string");
            let raw = raw.expect("message present");
            let parsed = SiwxMessage::from_str(raw);
            assert!(parsed.is_ok(), "{name}: FromStr failed: {parsed:?}");
            let parsed = parsed.expect("FromStr succeeded");
            assert_eq!(
                parsed.to_sign_string("Ethereum"),
                raw,
                "{name}: to_sign_string(\"Ethereum\") must equal official message"
            );
        }
    }

    #[test]
    fn parsing_negative_from_str_fails() {
        let cases: BTreeMap<String, String> =
            serde_json::from_str(PARSING_NEGATIVE).expect("parsing_negative.json");
        assert!(!cases.is_empty(), "parsing_negative.json must not be empty");
        for (name, raw) in cases {
            let parsed = SiwxMessage::from_str(&raw);
            if skip_evm_only_negative(&name, &raw) {
                assert!(
                    parsed.is_ok(),
                    "{name}: EVM-only negative must still parse in core: {parsed:?}"
                );
                continue;
            }
            assert!(parsed.is_err(), "{name}: FromStr must fail, got {parsed:?}");
        }
    }
}
