//! Request-origin verification vectors (vectors/origin/check.json).

#![allow(
    unused_crate_dependencies,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::excessive_nesting,
    reason = "integration test crate links lib deps it does not use; test helpers may panic/index"
)]

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use siwx::{Message, MessageFields, OriginPolicy, Severity, check_origin};

    fn message(case: &Value) -> Result<Message, siwx::Error> {
        Message::new(MessageFields {
            scheme: case["scheme"].as_str().map(str::to_owned),
            domain: case["domain"].as_str().unwrap().to_owned(),
            address: "0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946".to_owned(),
            statement: None,
            uri: "https://service.org/login".to_owned(),
            version: "1".to_owned(),
            chain_id: "1".to_owned(),
            nonce: "12341234".to_owned(),
            issued_at: "2022-03-17T12:45:13.610Z".to_owned(),
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: None,
        })
    }

    fn policy(case: &Value) -> OriginPolicy {
        let p = &case["policy"];
        let mut out = OriginPolicy::default();
        if let Some(list) = p.get("allowedSchemes").and_then(Value::as_array) {
            out = out.with_allowed_schemes(list.iter().filter_map(Value::as_str));
        }
        if let Some(s) = p.get("defaultScheme").and_then(Value::as_str) {
            out = out.with_default_scheme(s);
        }
        if let Some(on) = p.get("developerMode").and_then(Value::as_bool) {
            out = out.with_developer_mode(on);
        }
        out
    }

    #[test]
    fn origin_cases() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/origin/check.json"
        ))
        .expect("read vector");
        let v: Value = serde_json::from_str(&text).expect("vector json");
        let cases = v["cases"].as_array().unwrap();
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let msg = message(case);
            let msg = msg.unwrap_or_else(|e| panic!("{name}: {e}"));
            let res = check_origin(&msg, case["origin"].as_str().unwrap(), &policy(case));
            if let Some(code) = case["error"].as_str() {
                assert_eq!(res.expect_err(name).code(), code, "{name}");
                continue;
            }
            let got: Vec<(&str, &str)> = res
                .unwrap_or_else(|e| panic!("{name}: {e}"))
                .iter()
                .map(|f| {
                    (
                        f.code.as_str(),
                        match f.severity {
                            Severity::Reject => "reject",
                            Severity::Warn => "warn",
                        },
                    )
                })
                .collect();
            let want: Vec<(&str, &str)> = case["findings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| (f["code"].as_str().unwrap(), f["severity"].as_str().unwrap()))
                .collect();
            assert_eq!(got, want, "{name}");
        }
    }
}
