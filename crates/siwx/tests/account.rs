//! AccountId contract vectors (vectors/account/caip10.json).
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
    use siwx::AccountId;

    fn vector() -> Value {
        serde_json::from_str(
            &std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../vectors/account/caip10.json"
            ))
            .expect("read"),
        )
        .expect("json")
    }

    fn check_err(e: &siwx::Error, want: &Value, name: &str) {
        assert_eq!(e.code(), want["code"].as_str().unwrap(), "{name}: {e}");
        if let (siwx::Error::InvalidField { field, .. }, Some(w)) = (e, want["field"].as_str()) {
            assert_eq!(field.as_str(), w, "{name}");
        }
    }

    #[test]
    fn create_cases() {
        for case in vector()["create"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            match AccountId::new(
                case["namespace"].as_str().unwrap(),
                case["reference"].as_str().unwrap(),
                case["address"].as_str().unwrap(),
            ) {
                Ok(id) => assert_eq!(
                    Some(id.to_string().as_str()),
                    case["id"].as_str(),
                    "{name} created but vector expected error"
                ),
                Err(e) => check_err(&e, &case["error"], name),
            }
        }
    }

    #[test]
    fn parse_cases() {
        for case in vector()["parse"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            match case["id"].as_str().unwrap().parse::<AccountId>() {
                Ok(id) => {
                    assert_eq!(id.to_string(), case["id"].as_str().unwrap(), "{name}");
                }
                Err(e) => check_err(&e, &case["error"], name),
            }
        }
    }
}
