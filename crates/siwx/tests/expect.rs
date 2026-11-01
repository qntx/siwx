//! Expect binding + time policy vectors (vectors/eip4361/expect.json).

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
    use siwx::{Error, Expect, Message, MessageFields, Timestamp};

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
            "/../../vectors/eip4361/expect.json"
        ))
        .expect("read vector");
        serde_json::from_str(&text).expect("vector json")
    }

    #[test]
    fn expect_cases() {
        let v = vector();
        for case in v["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let fields: MessageFields = fields_from_json(&case["fields"]).expect("fields");
            let msg = Message::new(fields).unwrap_or_else(|e| panic!("{name}: fields {e}"));

            let e = &case["expect"];
            let mut expect =
                Expect::new(e["domain"].as_str().unwrap(), e["nonce"].as_str().unwrap());
            if let Some(s) = e.get("scheme").and_then(Value::as_str) {
                expect = expect.with_scheme(s);
            }
            if let Some(s) = e.get("uri").and_then(Value::as_str) {
                expect = expect.with_uri(s);
            }
            if let Some(s) = e.get("chainId").and_then(Value::as_str) {
                expect = expect.with_chain_id(s);
            }
            if let Some(s) = e.get("requestId").and_then(Value::as_str) {
                expect = expect.with_request_id(s);
            }
            if let Some(t) = e.get("time").and_then(Value::as_str) {
                expect = expect.with_time(Timestamp::parse(t).expect("time").instant());
            }
            if let Some(s) = e.get("skewSeconds").and_then(Value::as_i64) {
                expect = expect.with_skew(std::time::Duration::from_secs(
                    u64::try_from(s).unwrap_or(u64::MAX),
                ));
            }
            if let Some(s) = e.get("maxAgeSeconds").and_then(Value::as_i64) {
                expect = expect.with_max_age(std::time::Duration::from_secs(
                    u64::try_from(s).unwrap_or(u64::MAX),
                ));
            }

            let res = expect.check(&msg);
            match &case["error"] {
                Value::Null => assert!(res.is_ok(), "{name}: {res:?}"),
                want => {
                    let err = res.expect_err(&format!("{name} must fail"));
                    assert_eq!(err.code(), want["code"].as_str().unwrap(), "{name}: {err}");
                    if let Some(f) = want.get("field").and_then(Value::as_str) {
                        match err {
                            Error::Mismatch { field, .. } => {
                                assert_eq!(field.as_str(), f, "{name}");
                            }
                            _ => panic!("{name}: {err} carries no field"),
                        }
                    }
                }
            }
        }
    }
}
