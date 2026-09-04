//! Extra ABNF charset / pchar cases not covered by official SIWE JSON vectors.

#![allow(
    unused_crate_dependencies,
    reason = "integration test crate links lib deps it does not use"
)]

use siwx::{SiwxError, SiwxMessage};

fn with_statement(statement: &str) -> String {
    format!(
        "example.com wants you to sign in with your Ethereum account:\n\
         addr1\n\
         \n\
         {statement}\n\
         \n\
         URI: https://example.com\n\
         Version: 1\n\
         Chain ID: 1\n\
         Nonce: testnonce12345678\n\
         Issued At: 2021-09-30T16:25:24Z"
    )
}

fn with_request_id(request_id: &str) -> String {
    format!(
        "example.com wants you to sign in with your Ethereum account:\n\
         addr1\n\
         \n\
         \n\
         URI: https://example.com\n\
         Version: 1\n\
         Chain ID: 1\n\
         Nonce: testnonce12345678\n\
         Issued At: 2021-09-30T16:25:24Z\n\
         Request ID: {request_id}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tab_in_statement_is_rejected() {
        let err: SiwxError = with_statement("hello\tworld")
            .parse::<SiwxMessage>()
            .expect_err("HT is not reserved/unreserved/SP");
        assert!(
            matches!(err, SiwxError::InvalidStatement { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn illegal_pchar_in_request_id_is_rejected() {
        let err: SiwxError = with_request_id("req/id")
            .parse::<SiwxMessage>()
            .expect_err("`/` is not pchar");
        assert!(
            matches!(err, SiwxError::InvalidRequestId { .. }),
            "got {err:?}"
        );
    }
}
