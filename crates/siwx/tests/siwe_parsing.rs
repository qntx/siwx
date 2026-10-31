//! Canonical SIWE parsing vectors (vectors/siwe/parsing/*.json).
//!
//! Positive and warning cases must `Evm::parse` + `Evm::account`
//! successfully; negative cases must fail — except the deliberate
//! divergences registered in `vectors/siwe-overrides.json`.

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
    use siwx::evm::Evm;
    use siwx::{MessageFields, Namespace};

    fn cases(file: &str) -> serde_json::Map<String, Value> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/siwe/parsing/");
        let text = std::fs::read_to_string(format!("{path}{file}")).expect("read vector");
        serde_json::from_str(&text).expect("vector json")
    }

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

    fn overrides() -> serde_json::Map<String, Value> {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/siwe-overrides.json"
        ))
        .expect("read overrides");
        serde_json::from_str(&text).expect("overrides json")
    }

    fn assert_fields(message: &siwx::Message, fields: &Value) {
        let mf = fields_from_json(fields).expect("fields -> MessageFields");
        assert_eq!(message.domain(), mf.domain);
        assert_eq!(message.address(), mf.address);
        assert_eq!(message.statement(), mf.statement.as_deref());
        assert_eq!(message.uri(), mf.uri);
        assert_eq!(message.version(), mf.version);
        assert_eq!(message.chain_id(), mf.chain_id);
        assert_eq!(message.nonce(), mf.nonce);
        assert_eq!(message.issued_at().as_str(), mf.issued_at);
        assert_eq!(
            message.expiration_time().map(siwx::Timestamp::as_str),
            mf.expiration_time.as_deref()
        );
        assert_eq!(
            message.not_before().map(siwx::Timestamp::as_str),
            mf.not_before.as_deref()
        );
        assert_eq!(message.request_id(), mf.request_id.as_deref());
        assert_eq!(message.resources(), mf.resources.as_deref());
    }

    fn check_error(err: &siwx::Error, expected: &Value) {
        assert_eq!(err.code(), expected["code"].as_str().unwrap(), "{err}");
        if let Some(want) = expected.get("field").and_then(Value::as_str) {
            match err {
                siwx::Error::InvalidField { field, .. } => {
                    assert_eq!(field.as_str(), want, "{err}");
                }
                siwx::Error::Mismatch { field, .. } => assert_eq!(field.as_str(), want, "{err}"),
                siwx::Error::Syntax(siwx::Syntax::MissingField(f)) => {
                    assert_eq!(f.as_str(), want, "{err}");
                }
                _ => panic!("{err} carries no field"),
            }
        }
        if let Some(syn) = expected.get("syntax") {
            match err {
                siwx::Error::Syntax(s) => assert_eq!(s.code(), syn.as_str().unwrap(), "{err}"),
                _ => panic!("{err} is not a syntax error"),
            }
        }
    }

    fn run_parse(text: &str) -> Result<siwx::Message, siwx::Error> {
        let msg = Evm::new().parse(text.as_bytes())?;
        Evm::new().account(&msg)?;
        Ok(msg)
    }

    #[test]
    fn parsing_positive() {
        let ov = overrides();
        for (name, case) in cases("parsing_positive.json") {
            let key = format!("parsing_positive.json#{name}");
            let text = case["message"].as_str().unwrap();
            if let Some(o) = ov.get(&key) {
                let err = run_parse(text).expect_err(&format!("{key} must fail: {o}"));
                check_error(&err, &o["error"]);
                continue;
            }
            let msg = run_parse(text).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_fields(&msg, &case["fields"]);
            // Round-trip invariant.
            let text2 = Evm::new().format(&msg).expect("format");
            assert_eq!(text2, text, "{name}: round-trip");
        }
    }

    #[test]
    fn parsing_warnings() {
        for (name, case) in cases("parsing_warnings.json") {
            let text = case["message"].as_str().unwrap();
            let msg = run_parse(text).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_fields(&msg, &case["fields"]);
            assert_eq!(Evm::new().format(&msg).expect("format"), text, "{name}");
        }
    }

    #[test]
    fn parsing_negative() {
        for (name, text) in cases("parsing_negative.json") {
            let text = text.as_str().unwrap();
            assert!(run_parse(text).is_err(), "{name} must fail");
        }
    }
}
