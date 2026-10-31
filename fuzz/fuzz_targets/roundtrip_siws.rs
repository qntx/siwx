#![no_main]

use libfuzzer_sys::fuzz_target;
use siwx::svm::{Svm, siws};

fuzz_target!(|data: &[u8]| {
    let ns = Svm::new();
    if let Ok(m) = ns.parse(data) {
        // Accepted input must re-format to the identical text (unless the
        // bytes came wrapped in an off-chain envelope, where round-trip is
        // content-level).
        if let Ok(text) = ns.format(&m)
            && siws::parse_bytes(text.as_bytes()).is_ok()
        {
            assert_eq!(siws::format(&siws::parse_bytes(text.as_bytes()).unwrap()).unwrap(), text);
        }
    }
});
