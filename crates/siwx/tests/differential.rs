//! Differential replay of the TypeScript-generated parity stream
//! (`bun run test:parity` → `scripts/parity/differential.ts`). Run with:
//!
//! ```sh
//! SIWX_DIFFERENTIAL=target/parity/differential.json cargo test -p siwx \
//!     --test differential --all-features -- --ignored
//! ```
#![allow(
    unused_crate_dependencies,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::tests_outside_test_module,
    reason = "test harness"
)]

use serde_json::Value;
use siwx::{Error, Message, MessageFields, Namespace, Syntax};

fn err_json(e: &Error) -> Value {
    let mut v = serde_json::json!({ "code": e.code() });
    match e {
        Error::Syntax(s) => {
            v["syntax"] = s.code().into();
            if let Syntax::MissingField(f) = s {
                v["field"] = f.as_str().into();
            }
        }
        Error::InvalidField { field, .. } | Error::Mismatch { field, .. } => {
            v["field"] = field.as_str().into();
        }
        _ => {}
    }
    v
}

fn outcome(run: impl FnOnce() -> Result<String, Error>) -> Value {
    match run() {
        Ok(s) => serde_json::json!({ "ok": s }),
        Err(e) => serde_json::json!({ "error": err_json(&e) }),
    }
}

fn fields(case: &Value) -> MessageFields {
    serde_json::from_value(case["fields"].clone()).expect("fields json")
}

fn namespace(op: &str) -> Box<dyn Namespace> {
    if op.ends_with("eip4361") || op.ends_with("evm") {
        Box::new(siwx::evm::Evm::new())
    } else {
        Box::new(siwx::svm::Svm::new())
    }
}

fn check(record: &Value) {
    let op = record["op"].as_str().unwrap();
    let got = match op {
        "create" => outcome(|| Message::new(fields(record)).map(|_| "ok".to_owned())),
        "format_eip4361" | "format_siws" => {
            outcome(|| Message::new(fields(record)).and_then(|m| namespace(op).format(&m)))
        }
        "parse_eip4361" | "parse_siws" => outcome(|| {
            namespace(op)
                .parse(record["text"].as_str().unwrap().as_bytes())
                .and_then(|m| namespace(op).format(&m))
        }),
        "account_evm" | "account_svm" => outcome(|| {
            Message::new(fields(record))
                .and_then(|m| namespace(op).account(&m).map(|a| a.to_string()))
        }),
        other => panic!("unknown op {other}"),
    };
    assert_eq!(
        got,
        record["outcome"],
        "seq {} op {op}: {}",
        record["seq"],
        record["fields"]
    );
}

#[test]
#[ignore = "requires generated differential stream (bun run test:parity)"]
fn replay_differential_stream() {
    let path = std::env::var("SIWX_DIFFERENTIAL").unwrap_or_else(|_| {
        format!(
            "{}/../../target/parity/differential.json",
            env!("CARGO_MANIFEST_DIR")
        )
    });
    let stream: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("stream file")).unwrap();
    let records = stream["records"].as_array().unwrap();
    for record in records {
        check(record);
    }
    eprintln!("{} records replayed", records.len());
}
