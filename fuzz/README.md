# Parser fuzz

Nightly-only `cargo-fuzz` target. Not wired into `cargo test` or GitHub Actions stable CI.

```sh
cargo +nightly install cargo-fuzz
cargo +nightly fuzz run fuzz_parse
```
