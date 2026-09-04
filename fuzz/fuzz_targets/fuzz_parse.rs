//! Fuzz [`siwx::SiwxMessage`] [`std::str::FromStr`]. Must not panic.
//!
//! Nightly + cargo-fuzz only. Not part of `cargo test` or stable CI:
//!
//! ```sh
//! cargo +nightly fuzz run fuzz_parse
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use siwx::SiwxMessage;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = text.parse::<SiwxMessage>();
    }
});
