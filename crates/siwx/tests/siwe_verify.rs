//! Canonical SIWE verification vectors (vectors/siwe/verification/).
//!
//! Fields are formatted with `Evm::format`, then `authenticate` runs with
//! an `Expect` (domain binding where given, nonce, vector `time`,
//! skew 0). `verification/eip1271.json` requires RPC and is registered
//! in `parity.json` as planned — it is not run here.

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
    use siwx::{Expect, MessageFields, Namespace, Timestamp, authenticate, evm::Evm};

    fn cases(file: &str) -> serde_json::Map<String, Value> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/siwe/verification/"
        );
        let text = std::fs::read_to_string(format!("{path}{file}")).expect("read vector");
        serde_json::from_str(&text).expect("vector json")
    }

    fn decode_hex(s: &str) -> Vec<u8> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(s.get(i..i + 2).unwrap_or("00"), 16).unwrap_or(0))
            .collect()
    }

    fn fields_of(case: &Value) -> MessageFields {
        let get = |k: &str| case.get(k).and_then(Value::as_str).map(str::to_owned);
        MessageFields {
            scheme: None,
            domain: get("domain").expect("domain"),
            address: get("address").expect("address"),
            statement: get("statement"),
            uri: get("uri").expect("uri"),
            version: "1".into(),
            chain_id: case["chainId"].to_string().trim_matches('"').to_owned(),
            nonce: get("nonce").expect("nonce"),
            issued_at: get("issuedAt").expect("issuedAt"),
            expiration_time: get("expirationTime"),
            not_before: get("notBefore"),
            request_id: get("requestId"),
            resources: case.get("resources").map(|r| {
                r.as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default()
            }),
        }
    }

    async fn run(file: &str, expect_ok: bool) {
        for (name, case) in cases(file) {
            let evm = Evm::new();
            let text = match siwx::Message::new(fields_of(&case)).and_then(|m| evm.format(&m)) {
                Ok(text) => text,
                Err(e) => {
                    assert!(!expect_ok, "{file}#{name}: unexpected field error {e}");
                    continue;
                }
            };

            let domain = case
                .get("domainBinding")
                .and_then(Value::as_str)
                .or_else(|| case.get("domain").and_then(Value::as_str))
                .unwrap();
            let nonce = case
                .get("matchNonce")
                .and_then(Value::as_str)
                .or_else(|| case.get("nonce").and_then(Value::as_str))
                .unwrap();
            let mut expect = Expect::new(domain, nonce).with_skew(std::time::Duration::ZERO);
            if let Some(t) = case.get("time").and_then(Value::as_str) {
                let ts = Timestamp::parse(t).unwrap_or_else(|| panic!("{name}: bad time"));
                expect = expect.with_time(ts.instant());
            }
            let sig = decode_hex(case["signature"].as_str().unwrap());
            let res = authenticate(&evm, text.as_bytes(), &sig, &expect).await;
            assert_eq!(res.is_ok(), expect_ok, "{file}#{name}: {res:?}");
        }
    }

    #[tokio::test]
    async fn verification_positive() {
        run("verification_positive.json", true).await;
    }

    #[tokio::test]
    async fn verification_negative() {
        run("verification_negative.json", false).await;
    }
}
