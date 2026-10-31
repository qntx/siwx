#![no_main]

use libfuzzer_sys::fuzz_target;
use siwx::svm::Svm;

fuzz_target!(|data: &[u8]| {
    let _ = Svm::new().parse(data);
});
