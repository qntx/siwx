//! EVM vector runners (vectors/evm/eip191.json, vectors/evm/account.json).
#![cfg(feature = "evm")]
#![allow(
    unused_crate_dependencies,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::excessive_nesting,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    reason = "integration test crate links lib deps it does not use; test helpers may panic/index"
)]

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use siwx::evm::Evm;
    use siwx::{MessageFields, Namespace};

    fn cases(file: &str) -> Vec<Value> {
        let v: Value = serde_json::from_str(
            &std::fs::read_to_string(format!(
                "{}/../../vectors/evm/{file}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .expect("read"),
        )
        .expect("json");
        v["cases"].as_array().unwrap().clone()
    }

    #[test]
    fn account_cases() {
        for case in cases("account.json") {
            let name = case["name"].as_str().unwrap();
            let fields = MessageFields {
                domain: "service.org".into(),
                address: case["address"].as_str().unwrap().into(),
                uri: "https://x".into(),
                version: "1".into(),
                chain_id: case["chainId"].as_str().unwrap().into(),
                nonce: "12341234".into(),
                issued_at: "2022-03-17T12:45:13.610Z".into(),
                ..Default::default()
            };
            let result =
                siwx::Message::new(fields).and_then(|msg| Evm::new().account(&msg).map(|_| msg));
            match result.map(|msg| Evm::new().account(&msg)) {
                Ok(Ok(id)) => assert_eq!(
                    Some(id.to_string().as_str()),
                    case["accountId"].as_str(),
                    "{name}"
                ),
                Ok(Err(e)) | Err(e) => {
                    let want = &case["error"];
                    assert_eq!(e.code(), want["code"].as_str().unwrap(), "{name}: {e}");
                    if let Some(f) = want["field"].as_str() {
                        if let siwx::Error::InvalidField { field, .. } = e {
                            assert_eq!(field.as_str(), f, "{name}");
                        } else {
                            panic!("{name}: expected InvalidField, got {e}");
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn eip191_cases() {
        for case in cases("eip191.json") {
            let name = case["name"].as_str().unwrap();
            let text = case["text"].as_str().unwrap();
            let sig = hex_decode(case["signatureHex"].as_str().unwrap());
            let msg = Evm::new().parse(text.as_bytes());
            match (msg, case["error"].is_null()) {
                (Ok(m), true) => Evm::new()
                    .verify(&m, text.as_bytes(), &sig)
                    .await
                    .unwrap_or_else(|e| panic!("{name}: {e}")),
                (Ok(m), false) => {
                    let e = Evm::new()
                        .verify(&m, text.as_bytes(), &sig)
                        .await
                        .unwrap_err();
                    assert_eq!(
                        e.code(),
                        case["error"]["code"].as_str().unwrap(),
                        "{name}: {e}"
                    );
                }
                (Err(e), false) => {
                    assert_eq!(
                        e.code(),
                        case["error"]["code"].as_str().unwrap(),
                        "{name}: {e}"
                    );
                }
                (Err(e), true) => panic!("{name}: parse failed: {e}"),
            }
        }
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        let h = s.strip_prefix("0x").unwrap_or(s);
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
            .collect()
    }
}
