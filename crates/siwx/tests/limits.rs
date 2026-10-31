//! Shared-vector contract: core limits must equal `vectors/limits/defaults.json`.

#![allow(
    unused_crate_dependencies,
    reason = "integration test crate links lib deps it does not use"
)]

#[cfg(test)]
mod tests {
    use serde_json::Value;

    const DEFAULTS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/limits/defaults.json"
    ));

    #[test]
    fn core_limits_match_shared_vector() {
        let parsed: Value = serde_json::from_str(DEFAULTS).expect("valid limits JSON");
        let limits = parsed
            .as_object()
            .expect("limits defaults must be an object");
        let get = |key: &str| -> usize {
            limits
                .get(key)
                .and_then(Value::as_u64)
                .and_then(|v| usize::try_from(v).ok())
                .expect("limit must be a non-negative integer")
        };

        assert_eq!(siwx::MAX_MESSAGE_BYTES, get("maxMessageBytes"));
        assert_eq!(siwx::MAX_RESOURCES, get("maxResources"));
        assert_eq!(siwx::MAX_STATEMENT_BYTES, get("maxStatementBytes"));
        assert_eq!(siwx::MAX_REQUEST_ID_BYTES, get("maxRequestIdBytes"));
        assert_eq!(siwx::MAX_URI_BYTES, get("maxUriBytes"));
        assert_eq!(siwx::MIN_NONCE_LEN, get("minNonceLength"));
    }
}
