# Contributing

## Prerequisites

- **Bun 1.4** — package scripts, tests, and tooling.
- **Rust 1.99** — via `rust-toolchain.toml` (kept in sync with
  `[workspace.package].rust-version`).
- **cargo-deny** for the supply-chain check (`cargo install cargo-deny`).
- **Optional**, for fuzzing: a nightly toolchain and cargo-fuzz
  (`cargo install cargo-fuzz`), then `cd fuzz && cargo +nightly fuzz run fuzz_parse`.

## Repository layout

```text
packages/siwx/    @qntx/siwx — TypeScript SIWX library; builds with vp pack
crates/siwx/      siwx — Rust CAIP-122 core (evm and svm verifiers behind features)
crates/siwx-cli/  siwx-cli — `siwx` CLI (message build/parse/verify)
fuzz/             libFuzzer targets for siwx (separate workspace, nightly)
vectors/          shared golden data consumed by both languages (see vectors/README.md)
parity.json       capability ledger: every shared capability and the vectors/tests behind it
scripts/          repository checks (version lockstep, crate layers, parity)
```

## Local gate

Run before opening a pull request:

```bash
bun run lint && bun run typecheck && bun run test   # lint includes taplo, version,
                                                    # layer and parity checks
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets --no-default-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
cargo deny check
bun run test:parity                # TS→Rust differential replay
SIWX_E2E_ANVIL=1 bun run test:e2e  # anvil e2e (needs foundry)
bun run --cwd packages/siwx smoke:hermes   # needs HERMES=<binary>
SIWX_E2E_ANVIL=1 bun run test:e2e               # anvil e2e (needs foundry)
SIWX_MAINNET_RPC=<url> cargo test -p siwx --test evm_rpc eip1271  # opt-in mainnet vectors
```

## Versioning and release

`@qntx/siwx`, `siwx`, and `siwx-cli` share one lockstep version. `bun run release`
runs `bumpp` (`bump.config.ts`), which bumps `packages/siwx/package.json` and the
Cargo workspace version together, refreshes `Cargo.lock`, and opens a
`release/v<version>` pull request. `scripts/check-version.ts` (part of `bun run
lint`) guards against drift: every published package version must equal
`[workspace.package].version`, internal path dependencies must pin `=<version>`,
and the version string may appear nowhere else in `Cargo.toml`.

After the release PR merges, tag the merge commit `v*.*.*` and push it by hand;
one tag publishes npm (`@qntx/siwx`), crates.io (`siwx`, `siwx-cli`), and the
GitHub Release (`siwx` binaries).

## Commits

English Conventional Commits: `type(scope): subject` (`feat`, `fix`, `docs`,
`style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build`, `revert`), subject
in imperative mood, no period, ≤ 50 chars; `BREAKING CHANGE:` footer for
breaking changes.

## Documentation policy

`docs/` is public documentation mirrored to docs.qntx.org. `docs/internal/` is
local-only design material and must never be committed.

## License

Contributions are dual-licensed under MIT OR Apache-2.0.
