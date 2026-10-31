//! Fuzz [`siwx::eip4361::parse_bytes`]. Must not panic.
//!
//! Nightly + cargo-fuzz only. Not part of `cargo test` or stable CI:
//!
//! ```sh
//! cargo +nightly fuzz run fuzz_parse
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = siwx::eip4361::parse_bytes(data);
});
