# AGENTS.md

- Do not preserve backward compatibility. Remove obsolete paths instead of adding compatibility layers, fallbacks, or migrations.
- Choose the simplest implementation that fully meets the current requirements. Avoid speculative abstractions, configuration, and indirection.
- Grow the system in layers. Start from the smallest version that works end to end, and add each new capability on top of a product that already works. Never trade a working product for unfinished complexity.
- Keep components modular and concerns clearly separated.
- Prefer established, well-maintained libraries when they reduce overall complexity or improve reliability. Do not reimplement common functionality without a clear reason.
- Lean on the dependencies already in the project before writing your own implementation or adding packages. Do not assume a library lacks a capability without checking its documentation and types.
- Make architectural decisions for the long term. Do not accept a stopgap that only works for now and is meant to be replaced later.

## Architecture invariants

- `packages/siwx/src` is platform-neutral and Hermes V1-safe (no Node/browser-only globals, no `node:*` imports, no ES2023+ array methods).
- All I/O is injected; `packages/*/src/` holds no ambient singletons. RPC providers are injected per chain id (`Evm::with_provider` / `evm({ rpc })`); the library builds no transports and applies no timeouts.
- `crates/siwx` is the library crate; `crates/siwx-cli` is the only workspace member allowed to depend on it (enforced by `scripts/check-layers.ts`). Chain verifiers are feature-gated modules: `siwx::evm` (`evm`, plus `rpc` for on-chain smart-account verification via the ERC-6492 universal validator) and `siwx::svm` (`svm`). Two layouts: eip4361 (EVM) and SIWS (Solana, incl. off-chain message v1 envelopes); `format(parse(t)) == t` for every accepted text.
- No panics and no `unwrap`/`expect` in library code.
- npm package and crates are versioned lockstep (`@qntx/siwx` and `siwx`/`siwx-cli` share one version; `bump.config.ts` bumps `packages/siwx/package.json` + `Cargo.toml` together, `scripts/check-version.ts` guards drift).
- Shared test vectors live in `vectors/` and every capability is tracked in `parity.json`; both languages run the same files. `scripts/parity/differential.ts` generates a seeded TS outcome stream replayed by `crates/siwx/tests/differential.rs`.
- Anvil e2e is opt-in (`SIWX_E2E_ANVIL=1`); mainnet 1271 vectors are opt-in (`SIWX_MAINNET_RPC`).
- TOML is formatted by taplo (`.taplo.toml`, aligned `=`); run `taplo fmt` and keep `taplo fmt --check` green in `bun run lint`.

## Commands

Local gate before a pull request:

```bash
bun run lint && bun run typecheck && bun run test   # lint includes taplo,
                                                    # version, layer and
                                                    # parity checks
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets --no-default-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
cargo deny check
bun run test:parity                             # seeded differential replay (seed 42)
bun run test:parity:random                      # random seed, printed
SIWX_E2E_ANVIL=1 bun run test:e2e               # anvil e2e (needs foundry)
bun run --cwd packages/siwx smoke:hermes        # needs HERMES=<binary>
SIWX_MAINNET_RPC=<url> cargo test -p siwx --test evm_rpc eip1271  # opt-in mainnet vectors
```

Fuzz one target locally (needs a nightly toolchain and cargo-fuzz):

```bash
cargo +nightly fuzz run fuzz_parse   # run from fuzz/
```
