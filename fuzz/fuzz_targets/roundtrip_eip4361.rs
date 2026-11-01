//! Fuzz the EIP-4361 round-trip invariant: for every text `t` the parser
//! accepts, `format(label, parse(t)) == t` byte-for-byte.
//!
//! Nightly + cargo-fuzz only:
//!
//! ```sh
//! cargo +nightly fuzz run roundtrip_eip4361
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = siwx::eip4361::parse_bytes(data) {
        let text = siwx::eip4361::format(&parsed.label, &parsed.message);
        assert_eq!(text.as_bytes(), data, "round-trip invariant violated");
    }
});
