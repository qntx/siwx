//! SVM vector runners (vectors/siws, vectors/svm).
#![allow(
    unused_crate_dependencies,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::excessive_nesting,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::expect_used,
    clippy::tests_outside_test_module,
    reason = "integration test crate links lib deps it does not use; test helpers may panic/index"
)]
#![cfg(all(feature = "svm", feature = "evm"))]

use serde_json::Value;
use siwx::{Message, MessageFields, Namespace, svm::Svm};

fn vector(file: &str) -> Value {
    let root = format!("{}/../../vectors", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(format!("{root}/{file}")).expect("read"))
        .expect("json")
}

fn hex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

fn fields(v: &Value) -> MessageFields {
    MessageFields {
        scheme: v["scheme"].as_str().map(String::from),
        domain: v["domain"].as_str().unwrap_or_default().into(),
        address: v["address"].as_str().unwrap_or_default().into(),
        statement: v["statement"].as_str().map(String::from),
        uri: v["uri"].as_str().unwrap_or_default().into(),
        version: v["version"].as_str().unwrap_or_default().into(),
        chain_id: v["chainId"].as_str().unwrap_or_default().into(),
        nonce: v["nonce"].as_str().unwrap_or_default().into(),
        issued_at: v["issuedAt"].as_str().unwrap_or_default().into(),
        expiration_time: v["expirationTime"].as_str().map(String::from),
        not_before: v["notBefore"].as_str().map(String::from),
        request_id: v["requestId"].as_str().map(String::from),
        resources: v["resources"].as_array().map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        }),
    }
}

fn check_err(e: &siwx::Error, want: &Value, name: &str) {
    assert_eq!(e.code(), want["code"].as_str().unwrap(), "{name}: {e}");
    if let Some(s) = want["syntax"].as_str() {
        if let siwx::Error::Syntax(k) = e {
            assert_eq!(k.code(), s, "{name}");
            if let Some(f) = want["field"].as_str()
                && let siwx::Syntax::MissingField(field) = k
            {
                assert_eq!(field.as_str(), f, "{name}");
            }
        } else {
            panic!("{name}: expected Syntax error, got {e}");
        }
        return;
    }
    if let (
        siwx::Error::InvalidField { field, .. } | siwx::Error::Mismatch { field, .. },
        Some(w),
    ) = (e, want["field"].as_str())
    {
        assert_eq!(field.as_str(), w, "{name}");
    }
}

#[test]
fn siws_contract() {
    let v = vector("siws/contract.json");
    let ns = Svm::new();
    for case in v["accept"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let text = case["text"].as_str().unwrap();
        let parsed = ns
            .parse(text.as_bytes())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let want = Message::new(fields(&case["fields"])).unwrap();
        assert_eq!(parsed, want, "{name}");
        assert_eq!(ns.format(&parsed).unwrap(), text, "{name} round-trip");
    }
    for case in v["reject"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let text = case["text"].as_str().unwrap();
        let err = ns.parse(text.as_bytes()).expect_err(name);
        check_err(&err, &case["error"], name);
    }
}

#[test]
fn siws_offchain() {
    let v = vector("siws/offchain.json");
    let ns = Svm::new();
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let signed = hex(case["signedHex"].as_str().unwrap());
        match (ns.parse(&signed), &case["error"]) {
            (Ok(m), _) if case["fields"].is_object() => {
                assert_eq!(m, Message::new(fields(&case["fields"])).unwrap(), "{name}");
            }
            (Err(e), want) if !want.is_null() => check_err(&e, want, name),
            (Err(e), _) => panic!("{name}: unexpected error {e}"),
            (Ok(_), _) => panic!("{name}: parsed but expected error or fields"),
        }
    }
}

#[test]
fn svm_account() {
    let v = vector("svm/account.json");
    let ns = Svm::new();
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let mut f = fields(&json_fields());
        f.address = case["address"].as_str().unwrap().into();
        f.chain_id = case["chainId"].as_str().unwrap().into();
        let r = Message::new(f).and_then(|m| ns.account(&m));
        match (r, case["accountId"].as_str(), &case["error"]) {
            (Ok(id), Some(want), _) => assert_eq!(id.to_string(), want, "{name}"),
            (Err(e), None, e2) if !e2.is_null() => check_err(&e, e2, name),
            (Ok(id), _, _) => panic!("{name}: got {id}, expected error"),
            (Err(e), _, _) => panic!("{name}: unexpected error {e}"),
        }
    }
}

fn json_fields() -> Value {
    json!({
        "domain":"service.org","address":"x","uri":"https://service.org/login",
        "version":"1","chainId":"mainnet","nonce":"12341234",
        "issuedAt":"2022-03-17T12:45:13.610Z"
    })
}
use serde_json::json;

#[test]
fn svm_ed25519() {
    let v = vector("svm/ed25519.json");
    let ns = Svm::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let signed = case["text"].as_str().map_or_else(
            || hex(case["signedHex"].as_str().unwrap()),
            |t| t.as_bytes().to_vec(),
        );
        let msg = ns
            .parse(&signed)
            .unwrap_or_else(|e| panic!("{name}: parse {e}"));
        let sig = hex(case["signatureHex"].as_str().unwrap());
        match (rt.block_on(ns.verify(&msg, &signed, &sig)), &case["error"]) {
            (Ok(()), e) if e.is_null() => {}
            (Err(e), want) if !want.is_null() => check_err(&e, want, name),
            (Ok(()), _) => panic!("{name}: verified but expected error"),
            (Err(e), _) => panic!("{name}: verify failed {e}"),
        }
    }
}

/// ed25519-speccheck vectors through our strict verify path.
#[test]
fn svm_speccheck() {
    let cases = vector("svm/speccheck/cases.json");
    let expected = vector("svm/speccheck-expected.json");
    let ns = Svm::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    for (i, c) in cases.as_array().unwrap().iter().enumerate() {
        let msg_bytes = hex(c["message"].as_str().unwrap());
        let pk_hex = c["pub_key"].as_str().unwrap();
        let sig = hex(c["signature"].as_str().unwrap());
        // pub_key hex -> base58 address for our verify path.
        let address = bs58::encode(hex(pk_hex)).into_string();
        let mut f = fields(&json_fields());
        f.address = address;
        let want = expected["cases"].as_array().unwrap()[i]["accept"]
            .as_bool()
            .unwrap();
        let verdict = Message::new(f).and_then(|m| {
            rt.block_on(async { ns.verify(&m, &msg_bytes, &sig).await })
                .map(|()| m)
        });
        assert_eq!(verdict.is_ok(), want, "case {i}");
    }
}

/// Round-trip property: every accepted text must re-format identically.
#[test]
fn siws_roundtrip_prop() {
    use proptest::prelude::*;
    proptest!(|(stmt in proptest::option::of("[A-Za-z0-9 .,!?]{1,40}"),
                res in proptest::option::of(proptest::collection::vec("[a-z]{3,10}://[a-z.]{3,12}/[a-z]{1,8}", 0..2)))| {
        let mut f = fields(&json_fields());
        f.address = "9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj".into();
        f.statement.clone_from(&stmt);
        f.resources = res;
        let msg = Message::new(f).unwrap();
        let ns = Svm::new();
        let text = ns.format(&msg).unwrap();
        let back = ns.parse(text.as_bytes()).unwrap();
        prop_assert_eq!(&back, &msg);
        prop_assert_eq!(ns.format(&back).unwrap(), text);
    });
}
