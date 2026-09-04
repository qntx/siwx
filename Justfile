# Justfile for Rust project using Cargo

all: fmt clippy-fix

# Build the project with all features enabled in release mode
build:
    cargo build --workspace --release --all-features

# Check the project for compilation errors without producing binaries
check:
    cargo check --workspace --all-features

# Update dependencies to their latest compatible versions
update:
    cargo update

# Run the project with all features enabled in release mode
run:
    cargo run --release --all-features

# Run all tests with all features enabled, then EIP-6492 cfg-off paths
# (`not_enabled` is compiled out under --all-features).
test:
    cargo test --workspace --all-features
    cargo test -p siwx-evm --lib eip6492
    cargo test -p siwx-evm --lib eip6492 --features eip1271

# Run benchmarks with all features enabled
bench:
    cargo bench --all-features

# Run Clippy linter with nightly toolchain (check only, for CI)
# Uses workspace lints from Cargo.toml
clippy:
    cargo +nightly clippy --workspace \
        --all-targets \
        --all-features \
        -- -D warnings

# Run Clippy linter with auto-fix (for development)
clippy-fix:
    cargo +nightly clippy --workspace \
        --fix \
        --all-targets \
        --all-features \
        --allow-dirty \
        --allow-staged \
        -- -D warnings

# Format the code using rustfmt with nightly toolchain
fmt:
    cargo +nightly fmt

# Generate documentation for all crates and open it in the browser
doc:
    cargo +nightly doc --all-features --no-deps --open
