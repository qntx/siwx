//! Timestamp contract vectors (vectors/timestamp/from-instant.json).
//!
//! Each `input` is an RFC 3339 instant; `from_instant` must produce the
//! JavaScript `Date.prototype.toISOString()` string in `out`.

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
    use siwx::Timestamp;

    #[test]
    fn from_instant_matches_js_to_iso_string() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/timestamp/from-instant.json"
        ))
        .expect("read vector");
        let v: Value = serde_json::from_str(&text).expect("vector json");
        for case in v["cases"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            let want = case["out"].as_str().unwrap();
            let ts = Timestamp::parse(input).unwrap_or_else(|| panic!("{input}"));
            let got = Timestamp::from_instant(ts.instant()).expect("in range");
            assert_eq!(got.as_str(), want, "{input}");
        }
    }

    #[test]
    fn parse_vectors() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/timestamp/parse.json"
        ))
        .expect("read vector");
        let v: Value = serde_json::from_str(&text).expect("vector json");
        for case in v["cases"].as_array().unwrap() {
            let lexeme = case["lexeme"].as_str().unwrap();
            match Timestamp::parse(lexeme) {
                Some(ts) => {
                    assert!(case["valid"].as_bool().unwrap(), "{lexeme} rejected");
                    let got = ts.instant().unix_timestamp_nanos().div_euclid(1_000_000);
                    let want: i128 = case["epochMs"].as_i64().unwrap().into();
                    assert_eq!(got, want, "{lexeme}");
                }
                None => assert!(!case["valid"].as_bool().unwrap(), "{lexeme} rejected"),
            }
        }
    }
}
