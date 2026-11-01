//! Project-owned EIP-4361 contract vectors (vectors/eip4361/contract.json).
//!
//! `accept` cases must parse, match `label`/`fields`, and round-trip
//! byte-for-byte. `reject` cases must fail with the pinned error code
//! (and `syntax`/`field` when given).

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
    use serde_json::Value;
    use siwx::{Error, MessageFields, Syntax, eip4361};

    /// Build `MessageFields` from a JSON object; `chainId` may be a
    /// JSON number or string. `None` on missing/wrong required keys.
    fn fields_from_json(v: &Value) -> Option<MessageFields> {
        let get = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
        let chain_id = match v.get("chainId") {
            Some(Value::Number(n)) => n.to_string(),
            Some(Value::String(s)) => s.clone(),
            _ => return None,
        };
        Some(MessageFields {
            scheme: v.get("scheme").and_then(Value::as_str).map(str::to_owned),
            domain: get("domain")?,
            address: get("address")?,
            statement: v
                .get("statement")
                .and_then(Value::as_str)
                .map(str::to_owned),
            uri: get("uri")?,
            version: get("version")?,
            chain_id,
            nonce: get("nonce")?,
            issued_at: get("issuedAt")?,
            expiration_time: v
                .get("expirationTime")
                .and_then(Value::as_str)
                .map(str::to_owned),
            not_before: v
                .get("notBefore")
                .and_then(Value::as_str)
                .map(str::to_owned),
            request_id: v
                .get("requestId")
                .and_then(Value::as_str)
                .map(str::to_owned),
            resources: v.get("resources").and_then(Value::as_array).map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            }),
        })
    }
    fn vector() -> Value {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/eip4361/contract.json"
        ))
        .expect("read vector");
        serde_json::from_str(&text).expect("vector json")
    }

    fn check_error(err: &Error, expected: &Value, name: &str) {
        assert_eq!(
            err.code(),
            expected["code"].as_str().unwrap(),
            "{name}: {err}"
        );
        if let Some(f) = expected.get("field").and_then(Value::as_str) {
            let got = match err {
                Error::InvalidField { field, .. } => field.as_str(),
                Error::Mismatch { field, .. } => field.as_str(),
                Error::Syntax(Syntax::MissingField(fld)) => fld.as_str(),
                _ => panic!("{name}: {err} carries no field"),
            };
            assert_eq!(got, f, "{name}: {err}");
        }
        if let Some(s) = expected.get("syntax").and_then(Value::as_str) {
            match err {
                Error::Syntax(k) => assert_eq!(k.code(), s, "{name}: {err}"),
                _ => panic!("{name}: {err} is not a syntax error"),
            }
        }
    }

    #[test]
    fn accept_cases() {
        let v = vector();
        for case in v["accept"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let text = case["text"].as_str().unwrap();
            let parsed = eip4361::parse(text).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(parsed.label, case["label"].as_str().unwrap(), "{name}");
            let fields = fields_from_json(&case["fields"]).expect("fields");
            assert_eq!(*parsed.message.domain(), *fields.domain, "{name}");
            assert_eq!(parsed.message.clone().into_fields(), fields, "{name}");
            assert_eq!(
                eip4361::format(&parsed.label, &parsed.message),
                text,
                "{name} round-trip"
            );
        }
    }

    #[test]
    fn reject_cases() {
        let v = vector();
        for case in v["reject"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let expected = &case["error"];
            if case.get("note").is_some() {
                // The InvalidUtf8 contract: bytes-level rejection.
                let err = eip4361::parse_bytes(&[0xff]).expect_err("utf8");
                check_error(&err, expected, name);
                continue;
            }
            let text = case["text"].as_str().unwrap();
            let err = eip4361::parse(text).expect_err(&format!("{name} must fail"));
            check_error(&err, expected, name);
        }
    }
}
