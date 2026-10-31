//! On-chain smart-account tests with a mocked JSON-RPC transport.
#![allow(
    unused_crate_dependencies,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::tests_outside_test_module,
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    reason = "integration test crate links lib deps it does not use; test helpers may panic/index"
)]
#![cfg(feature = "rpc")]

use std::sync::atomic::{AtomicUsize, Ordering};

use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::transports::mock::Asserter;
use serde_json::Value;
use siwx::{Error, Field, Message, MessageFields, Namespace, evm::Evm};

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

fn fields(chain_id: &str) -> MessageFields {
    MessageFields {
        domain: "service.org".into(),
        address: "0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946".into(),
        uri: "https://service.org/login".into(),
        version: "1".into(),
        chain_id: chain_id.into(),
        nonce: "12341234".into(),
        issued_at: "2022-03-17T12:45:13.610Z".into(),
        ..Default::default()
    }
}

fn provider(asserter: &Asserter) -> DynProvider {
    Provider::erased(ProviderBuilder::new().connect_mocked_client(asserter.clone()))
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn offline_success_makes_zero_rpc_calls() {
    // The Anvil #0 key signature over the eip4361 text — a valid EIP-191 sig
    // must short-circuit before any RPC is even attempted.
    let v = vector("evm/eip191.json");
    let case = v["cases"].as_array().unwrap()[0].clone();
    let text = case["text"].as_str().unwrap().as_bytes().to_vec();
    let sig = hex(case["signatureHex"].as_str().unwrap());
    let ns = Evm::new();
    let msg = ns.parse(&text).unwrap();

    let asserter = Asserter::new();
    let evm = Evm::new().with_provider(1, provider(&asserter));
    rt().block_on(async { evm.verify(&msg, &text, &sig).await })
        .unwrap();
    // Any request would have panicked the asserter; also nothing popped.
    assert_eq!(asserter.read_q().len(), 0);
}

#[test]
fn magic_suffix_without_provider_is_unsupported() {
    let mut sig = [0u8; 65].to_vec();
    sig.extend_from_slice(&[0x64, 0x92].repeat(16));
    let msg = Message::new(fields("1")).unwrap();
    let err = rt()
        .block_on(async { Evm::new().verify(&msg, b"x", &sig).await })
        .expect_err("unsupported");
    assert!(matches!(err, Error::Unsupported { .. }), "{err:?}");
}

#[test]
fn eip191_failure_without_provider_returns_191_error() {
    let msg = Message::new(fields("1")).unwrap();
    let err = rt()
        .block_on(async { Evm::new().verify(&msg, b"x", &[0u8; 65]).await })
        .expect_err("eip191 error");
    assert!(matches!(err, Error::InvalidSignature { .. }), "{err:?}");
}

#[test]
fn chain_id_mismatch_is_mismatch_and_no_eth_call() {
    let asserter = Asserter::new();
    asserter.push_success(&serde_json::json!("0x7a69")); // eth_chainId → 31337
    let evm = Evm::new().with_provider(1, provider(&asserter));
    let msg = Message::new(fields("1")).unwrap();
    let mut sig = [0u8; 65].to_vec();
    sig.extend_from_slice(&[0x64, 0x92].repeat(16));
    let err = rt()
        .block_on(async { evm.verify(&msg, b"x", &sig).await })
        .expect_err("mismatch");
    match err {
        Error::Mismatch {
            field,
            expected,
            actual,
        } => {
            assert_eq!(field, Field::ChainId);
            assert_eq!(expected, "1");
            assert_eq!(actual.as_deref(), Some("31337"));
        }
        e => panic!("expected Mismatch, got {e:?}"),
    }
    assert_eq!(asserter.read_q().len(), 0, "no further call after mismatch");
}

#[test]
fn chain_id_is_cached_across_verifies() {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    let asserter = Asserter::new();
    // One eth_chainId (0x1) + two eth_call results for two verifies.
    asserter.push_success(&serde_json::json!("0x1"));
    asserter.push_success(&serde_json::json!("0x01"));
    asserter.push_success(&serde_json::json!("0x01"));
    let evm = Evm::new().with_provider(1, provider(&asserter));
    let msg = Message::new(fields("1")).unwrap();
    let mut sig = [0u8; 65].to_vec();
    sig.extend_from_slice(&[0x64, 0x92].repeat(16));
    let rt = rt();
    rt.block_on(async { evm.verify(&msg, b"x", &sig).await })
        .unwrap();
    rt.block_on(async { evm.verify(&msg, b"x", &sig).await })
        .unwrap();
    let _ = CALLS.fetch_add(1, Ordering::SeqCst);
    assert_eq!(asserter.read_q().len(), 0);
}

#[test]
fn code3_revert_is_verification_failed() {
    let asserter = Asserter::new();
    asserter.push_success(&serde_json::json!("0x1"));
    let payload: alloy::rpc::json_rpc::ErrorPayload =
        serde_json::from_str(r#"{"code":3,"message":"execution reverted"}"#).unwrap();
    asserter.push_failure(payload);
    let evm = Evm::new().with_provider(1, provider(&asserter));
    let msg = Message::new(fields("1")).unwrap();
    let mut sig = [0u8; 65].to_vec();
    sig.extend_from_slice(&[0x64, 0x92].repeat(16));
    let err = rt()
        .block_on(async { evm.verify(&msg, b"x", &sig).await })
        .expect_err("revert");
    assert!(matches!(err, Error::VerificationFailed), "{err:?}");
}

#[test]
fn other_rpc_code_is_backend() {
    let asserter = Asserter::new();
    asserter.push_success(&serde_json::json!("0x1"));
    let payload: alloy::rpc::json_rpc::ErrorPayload =
        serde_json::from_str(r#"{"code":-32000,"message":"node error"}"#).unwrap();
    asserter.push_failure(payload);
    let evm = Evm::new().with_provider(1, provider(&asserter));
    let msg = Message::new(fields("1")).unwrap();
    let mut sig = [0u8; 65].to_vec();
    sig.extend_from_slice(&[0x64, 0x92].repeat(16));
    let err = rt()
        .block_on(async { evm.verify(&msg, b"x", &sig).await })
        .expect_err("backend");
    assert!(matches!(err, Error::Backend { .. }), "{err:?}");
}

#[test]
fn malformed_result_is_backend() {
    let asserter = Asserter::new();
    asserter.push_success(&serde_json::json!("0x1"));
    asserter.push_success(&serde_json::json!("0x02")); // not a bool shape
    let evm = Evm::new().with_provider(1, provider(&asserter));
    let msg = Message::new(fields("1")).unwrap();
    let mut sig = [0u8; 65].to_vec();
    sig.extend_from_slice(&[0x64, 0x92].repeat(16));
    let err = rt()
        .block_on(async { evm.verify(&msg, b"x", &sig).await })
        .expect_err("backend");
    assert!(matches!(err, Error::Backend { .. }), "{err:?}");
}

/// Canonical Argent/Loopring EIP-1271 mainnet vectors — opt-in via
/// `SIWX_MAINNET_RPC=<url>` (hits a real mainnet node).
#[test]
fn eip1271_mainnet_vectors() {
    let Ok(url) = std::env::var("SIWX_MAINNET_RPC") else {
        eprintln!("SIWX_MAINNET_RPC unset — skipping mainnet 1271 vectors");
        return;
    };
    let v = vector("siwe/verification/eip1271.json");
    let provider: DynProvider =
        Provider::erased(ProviderBuilder::new().connect_http(url.parse().unwrap()));
    let evm = Evm::new().with_provider(1, provider);
    let rt = rt();
    for (name, case) in v.as_object().unwrap() {
        let text = case["message"].as_str().unwrap().as_bytes().to_vec();
        let sig = hex(case["signature"].as_str().unwrap());
        let msg = evm.parse(&text).unwrap();
        rt.block_on(async { evm.verify(&msg, &text, &sig).await })
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}
