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

    const POSITIVE_COUNT: usize = 19;
    const NEGATIVE_COUNT: usize = 29;

    /// EIP-55 checksum is an EVM-profile rule, not core ABNF.
    const SKIP_EIP55: &str = "address not EIP-55";
    /// Decimal chain id is an EVM-profile rule, not core ABNF.
    const SKIP_CHAIN_ID: &str = "not a valid chainId";

    fn load_object(json: &str) -> BTreeMap<String, Value> {
        serde_json::from_str(json).expect("official SIWE vector JSON")
    }

    fn skip_evm_only_negative(name: &str) -> bool {
        name == SKIP_EIP55 || name == SKIP_CHAIN_ID
    }

    fn optional_str<'a>(fields: &'a Value, key: &str) -> Option<&'a str> {
        fields.get(key).and_then(Value::as_str)
    }

    fn required_str<'a>(name: &str, fields: &'a Value, key: &str) -> &'a str {
        let value = optional_str(fields, key);
        assert!(value.is_some(), "{name}: fields.{key} missing string");
        value.expect("string field present")
    }

    fn expected_chain_id(name: &str, fields: &Value) -> String {
        let value = fields.get("chainId");
        assert!(value.is_some(), "{name}: fields.chainId missing");
        let value = value.expect("chainId present");
        let decimal = value
            .as_u64()
            .map(|n| n.to_string())
            .or_else(|| value.as_str().map(str::to_owned));
        assert!(
            decimal.is_some(),
            "{name}: fields.chainId must be a decimal number or string, got {value}"
        );
        decimal.expect("chainId decimal")
    }

    fn expected_resources(fields: &Value) -> Vec<String> {
        match fields.get("resources") {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            _ => Vec::new(),
        }
    }

    fn assert_matches_fields(name: &str, parsed: &SiwxMessage, fields: &Value) {
        assert_eq!(
            parsed.scheme(),
            optional_str(fields, "scheme"),
            "{name}: scheme"
        );
        assert_eq!(
            parsed.domain(),
            required_str(name, fields, "domain"),
            "{name}: domain"
        );
        assert_eq!(
            parsed.address(),
            required_str(name, fields, "address"),
            "{name}: address"
        );
        assert_eq!(parsed.uri(), required_str(name, fields, "uri"), "{name}: uri");
        assert_eq!(
            parsed.nonce(),
            required_str(name, fields, "nonce"),
            "{name}: nonce"
        );
        assert_eq!(
            parsed.issued_at_raw(),
            required_str(name, fields, "issuedAt"),
            "{name}: issuedAt"
        );
        assert_eq!(
            parsed.chain_id(),
            expected_chain_id(name, fields),
            "{name}: chainId"
        );
        assert_eq!(
            parsed.statement(),
            optional_str(fields, "statement"),
            "{name}: statement"
        );
        assert_eq!(
            parsed.resources(),
            expected_resources(fields),
            "{name}: resources"
        );
    }

    #[test]
    fn parsing_positive_from_str_round_trips() {
        let cases = load_object(PARSING_POSITIVE);
        assert_eq!(
            cases.len(),
            POSITIVE_COUNT,
            "parsing_positive.json case count"
        );
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
            let fields = case.get("fields");
            assert!(fields.is_some(), "{name}: missing `fields` object");
            assert_matches_fields(&name, &parsed, fields.expect("fields present"));
        }
    }

    #[test]
    fn parsing_negative_from_str_fails() {
        let cases: BTreeMap<String, String> =
            serde_json::from_str(PARSING_NEGATIVE).expect("parsing_negative.json");
        assert_eq!(
            cases.len(),
            NEGATIVE_COUNT,
            "parsing_negative.json case count"
        );
        assert!(
            cases.contains_key(SKIP_EIP55) && cases.contains_key(SKIP_CHAIN_ID),
            "parsing_negative.json must contain `{SKIP_EIP55}` and `{SKIP_CHAIN_ID}`"
        );
        for (name, raw) in cases {
            let parsed = SiwxMessage::from_str(&raw);
            if skip_evm_only_negative(&name) {
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
