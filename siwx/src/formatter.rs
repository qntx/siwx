//! CAIP-122 signing-string rendering ([`SiwxMessage::to_sign_string`] + [`Display`]).

use std::fmt;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::message::SiwxMessage;
use crate::parser::{
    CHAIN_TAG, EXP_TAG, IAT_TAG, NBF_TAG, NONCE_TAG, PREAMBLE_MID, PREAMBLE_TAIL, RES_TAG, RID_TAG,
    URI_TAG, VERSION_TAG,
};

impl SiwxMessage {
    /// Render the human-readable CAIP-122 signing string.
    ///
    /// `chain_name` is the ecosystem label shown in the preamble (e.g.
    /// `"Ethereum"`, `"Solana"`). Each chain crate exposes the canonical
    /// value via the [`Verifier::CHAIN_NAME`](crate::Verifier::CHAIN_NAME)
    /// associated constant.
    ///
    /// # Examples
    ///
    /// ```
    /// use siwx::SiwxMessage;
    ///
    /// let msg = SiwxMessage::new("example.com", "addr1", "https://example.com", "1", "1")?;
    /// let text = msg.to_sign_string("Ethereum");
    /// assert!(text.starts_with("example.com wants you to sign in with your Ethereum account:"));
    /// # Ok::<(), siwx::SiwxError>(())
    /// ```
    #[must_use]
    pub fn to_sign_string(&self, chain_name: &str) -> String {
        let mut out = String::with_capacity(512);

        out.push_str(&self.domain);
        out.push_str(PREAMBLE_MID);
        out.push_str(chain_name);
        out.push_str(PREAMBLE_TAIL);
        out.push('\n');
        out.push_str(&self.address);
        out.push('\n');

        out.push('\n');
        if let Some(ref stmt) = self.statement {
            out.push_str(stmt);
            out.push('\n');
            out.push('\n');
        }

        push_tag(&mut out, URI_TAG, &self.uri);
        push_tag(&mut out, VERSION_TAG, &self.version);
        push_tag(&mut out, CHAIN_TAG, &self.chain_id);

        if let Some(ref n) = self.nonce {
            push_tag(&mut out, NONCE_TAG, n);
        }
        if let Some(t) = self.issued_at {
            push_tag(&mut out, IAT_TAG, &fmt_ts(t));
        }
        if let Some(t) = self.expiration_time {
            push_tag(&mut out, EXP_TAG, &fmt_ts(t));
        }
        if let Some(t) = self.not_before {
            push_tag(&mut out, NBF_TAG, &fmt_ts(t));
        }
        if let Some(ref rid) = self.request_id {
            push_tag(&mut out, RID_TAG, rid);
        }

        if !self.resources.is_empty() {
            out.push_str(RES_TAG);
            out.push('\n');
            for r in &self.resources {
                out.push_str("- ");
                out.push_str(r);
                out.push('\n');
            }
        }

        let trimmed_len = out.trim_end_matches('\n').len();
        out.truncate(trimmed_len);
        out
    }
}

/// Renders with a generic `"X"` chain name — for a proper signing string use
/// [`SiwxMessage::to_sign_string`] with the chain-specific label.
impl fmt::Display for SiwxMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_sign_string("X"))
    }
}

pub(crate) fn fmt_ts(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_else(|_| t.to_string())
}

fn push_tag(out: &mut String, tag: &str, value: &str) {
    out.push_str(tag);
    out.push_str(value);
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    #[test]
    fn ethereum_format_matches_siwe_reference() {
        let msg = SiwxMessage::new(
            "service.org",
            "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
            "https://service.org/login",
            "1",
            "1",
        )
        .expect("valid")
        .with_statement("I accept the ServiceOrg Terms of Service: https://service.org/tos")
        .with_nonce("32891756")
        .with_issued_at(datetime!(2021-09-30 16:25:24 UTC))
        .with_resources([
            "ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/",
            "https://example.com/my-web2-claim.json",
        ]);

        let expected = "\
service.org wants you to sign in with your Ethereum account:
0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2

I accept the ServiceOrg Terms of Service: https://service.org/tos

URI: https://service.org/login
Version: 1
Chain ID: 1
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z
Resources:
- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/
- https://example.com/my-web2-claim.json";

        assert_eq!(msg.to_sign_string("Ethereum"), expected);
    }

    #[test]
    fn solana_preamble() {
        let msg = SiwxMessage::new(
            "service.org",
            "GwAF45zjfyGzUbd3i3hXxzGeuchzEZXwpRYHZM5912F1",
            "https://service.org/login",
            "1",
            "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
        )
        .expect("valid");
        let text = msg.to_sign_string("Solana");
        assert!(text.starts_with("service.org wants you to sign in with your Solana account:"));
        assert!(text.contains("Chain ID: 5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"));
    }

    #[test]
    fn display_uses_generic_x_label() {
        let msg = SiwxMessage::new("d.com", "a", "https://d.com", "1", "1").expect("valid");
        assert!(msg.to_string().contains("sign in with your X account:"));
    }
}
