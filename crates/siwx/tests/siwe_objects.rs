//! Canonical SIWE object vectors (vectors/siwe/objects/*.json).
//!
//! `msg` objects are converted to [`siwx::MessageFields`] — the
//! `chainId` number is stringified — then `Message::new` + `Evm::format`
//! must succeed for `"error": "none"` and fail otherwise.
//! `parsing_negative_objects.json` objects (missing keys) must fail to
//! build or validate.

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

    use siwx::{Message, MessageFields, Namespace, evm::Evm};

    fn cases(file: &str) -> Value {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/siwe/objects/");
        let text = std::fs::read_to_string(format!("{path}{file}")).expect("read vector");
        serde_json::from_str(&text).expect("vector json")
    }

    /// Build `MessageFields` from a JSON object; `None` on missing/wrong keys.
    fn fields_from_json(v: &Value) -> Option<MessageFields> {
        let get = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
        let get_opt = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
        let chain_id = match v.get("chainId") {
            Some(Value::Number(n)) => n.to_string(),
            Some(Value::String(s)) => s.clone(),
            _ => return None,
        };
        Some(MessageFields {
            scheme: get_opt("scheme"),
            domain: get("domain")?,
            address: get("address")?,
            statement: get_opt("statement"),
            uri: get("uri")?,
            version: get("version")?,
            chain_id,
            nonce: get("nonce")?,
            issued_at: get("issuedAt")?,
            expiration_time: get_opt("expirationTime"),
            not_before: get_opt("notBefore"),
            request_id: get_opt("requestId"),
            resources: v.get("resources").and_then(Value::as_array).map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            }),
        })
    }

    #[test]
    fn message_objects() {
        for (name, case) in cases("message_objects.json").as_object().unwrap() {
            let fields =
                fields_from_json(&case["msg"]).unwrap_or_else(|| panic!("{name}: bad fields"));
            let expect_ok = case["error"].as_str() == Some("none");
            let result = Message::new(fields).and_then(|m| Evm::new().format(&m).map(|_| m));
            assert_eq!(
                result.is_ok(),
                expect_ok,
                "{name}: {result:?} want error={:?}",
                case["error"]
            );
        }
    }

    #[test]
    fn parsing_negative_objects() {
        if let Value::Object(cases) = cases("parsing_negative_objects.json") {
            let evm = Evm::new();
            for (name, obj) in cases {
                let ok = fields_from_json(&obj)
                    .and_then(|f| Message::new(f).ok())
                    .and_then(|m| evm.account(&m).ok())
                    .is_some();
                assert!(!ok, "{name} must fail");
            }
        }
    }
}
