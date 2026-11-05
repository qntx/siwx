# Changelog

## 0.8.0

### Added

- **`checkOrigin` / `check_origin`**: wallet-side request-origin verification
  (ERC-4361 "Verifying the Request Origin"). Compares the message `scheme`
  and `domain` with a serialized web origin under an `OriginPolicy`
  (`allowedSchemes`, `defaultScheme`, `developerMode`) and returns ordered
  findings (`SchemeNotAllowed`, `SchemeMismatch`, `HostMismatch`,
  `PortMismatch`) with `reject` / `warn` severity. A malformed
  origin fails with the new error code `InvalidOrigin`.
- Shared vectors `vectors/origin/check.json` and the `core.origin` parity
  entry.

## 0.7.1

### Changed

- Minimal READMEs for the repository, npm package and both crates;
  crates.io pages now render a README.

## 0.7.0

### Breaking

- **Dual TypeScript + Rust monorepo**: `@qntx/siwx` (npm) and `siwx` /
  `siwx-cli` (crates) share one contract — shared golden vectors in
  `vectors/`, capability tracking in `parity.json`, and a seeded
  differential replay harness (`bun run test:parity`).
- **Single crate**: `siwx-evm` and `siwx-svm` are merged into `siwx` as the
  `evm` / `svm` / `rpc` features (`siwx::evm::Evm`, `siwx::svm::Svm`).
- **Spec baseline**: canonical `signinwithethereum/test-vectors`. Parsing
  accepts empty statements, empty `Request ID:` and bare `Resources:`;
  `userinfo@` and empty hosts in `domain` are rejected (ERC-4361 erratum).
  EVM addresses accept uniform case and require EIP-55 for mixed case;
  CAIP-10 accounts use the checksum form.
- **Solana uses SIWS**: the `svm` profile parses and formats the Sign In With
  Solana layout produced by wallet-standard wallets (not the EIP-4361
  layout), chain ids are `mainnet|testnet|devnet|localnet` (optionally
  `solana:`-prefixed) mapped to CAIP-2 genesis references. A `statement`
  starting with `URI: ` is rejected at format (`InvalidField` `statement`)
  because it would round-trip as the `URI:` field.
- **New core API** replacing `SiwxMessage`/`SiwxError`/`Verifier`:
  `Message`/`MessageFields`, `Timestamp`, `Expect` (domain/nonce bindings +
  skew/max-age), `AccountId` (CAIP-10), `Namespace` trait, `Error` +
  `Syntax` + `Field` with stable `code()` names.
- **Smart-account verification is one path**: the `eip1271` and `eip6492`
  cargo features, the standalone `isValidSignature` call, `with_rpc_map` /
  `with_rpc_for_chain` / `with_rpc_timeout`, and the `--rpc-chain-id` CLI
  flag are gone. The new `rpc` feature injects providers
  (`Evm::with_provider(chain_id, DynProvider)`; TS `evm({ rpc })` keyed by
  decimal chain ids) and every on-chain check runs through the ERC-6492
  universal validator deployless `eth_call` with `eth_chainId` binding.
- **Error model**: `Expired`/`NotYetValid`/`IssuedAtTooOld`,
  `Unsupported`, `Backend` replace ad-hoc strings; JSON-RPC code 3 is
  `VerificationFailed`, all other RPC failures are `Backend` with fixed,
  URL-free reason strings.
- **CLI**: `siwx evm|svm message|verify|parse` + `siwx nonce`, JSON-first
  output (`{valid, chain, account, fields}` / `{error:{code,message,…}}`);
  `parse` moved under the namespaces; `--message-hex` for exact signed
  bytes (SIWS off-chain envelopes); repeatable `--rpc CHAIN_ID=URL` under
  feature `rpc`.
- **Ed25519 rule**: `A` and `R` must be canonical prime-order-subgroup
  (torsion-free, non-identity) encodings; identity `R` is rejected in both
  languages.
- **`Expect` takes `std::time::Duration`** for `with_skew` / `with_max_age`
  (negative skews are unrepresentable); TS throws `RangeError` for
  non-finite or negative `skewSeconds` / `maxAgeSeconds` and for an invalid
  `time` — policy values can no longer silently disable every check.
- **Leap seconds rejected** (`:60` seconds) in both languages; TS/Rust
  `Timestamp` parse identically, with millisecond truncation and no
  `Date.UTC` year-0–99 mapping.

### Added

- **SVM namespace**: real SIWS layout (Phantom ABNF), off-chain message v1
  envelope (`offchain_message`), strict Ed25519
  (`verify_strict` / `zip215:false` + prechecks), base58 address
  validation.
- **Canonical vector sets** for eip4361, SIWS, accounts, Ed25519
  (incl. ed25519-speccheck), and universal-validator calldata/results;
  mainnet Argent/Loopring vectors opt-in via `SIWX_MAINNET_RPC`.
- **Anvil e2e suites** (`SIWX_E2E_ANVIL=1`, `bun run test:e2e`) covering
  EOA, deployed 1271, counterfactual 6492, and chain-id mismatch.
- **Hermes smoke bundle** (`smoke:hermes`) and daily differential CI
  (`parity.yml`).

### Removed

- `siwx-evm` and `siwx-svm` crates, `SiwxMessage`, `AuthOpts`, `Verifier`,
  `EvmVerifier`, `Ed25519Verifier`, `nonce::generate(len)`.
- `eip1271` / `eip6492` features and URL-based RPC configuration.
- Top-level `siwx parse` and `siwx nonce --len`.

## 0.6.1

### Breaking

- **SVM addresses**: `validate_address` / verify reject
  [`ed25519_dalek::VerifyingKey::is_weak`] keys (small-order torsion,
  including the 32-zero identity). Signature verification still uses RFC 8032
  `verify`, not `verify_strict`.

### Added

- **`SiwxError::Backend`**: RPC timeout, connect failure, and empty
  `eth_call`. Crypto failure stays `VerificationFailed`.
  `"EIP-6492 requires RPC"` / `"EIP-6492 not enabled"` stay
  `InvalidSignature`. Reasons must not include RPC URLs.

## 0.6.0

Breaking release. EIP-4361 ABNF-strict parse, original-byte verify, production
EOA and SVM profiles, optional EIP-1271 / EIP-6492. No 0.5 compatibility layer.

### Breaking

- **Timestamp originals**: `issued_at` / `expiration_time` / `not_before` keep
  the RFC 3339 input string. Formatter emits that original; `.000Z` and `Z` are
  not `Eq` even when they denote the same instant.
- **No canonical check**: `authenticate` does not require
  `format_message() == raw_message`. Signature verification hashes the original
  bytes. Parse is ABNF-strict: reject CR, reject trailing LF, reject out-of-order
  or unknown fields.
- **Structured errors**: mismatch variants carry `{ expected, actual }`;
  `InvalidFormat { reason: FormatReason }`; `InvalidChainId { reason: ChainIdReason }`.
  There is **no** `FutureIssuedAt`. Over-age `issued_at` is `StaleIssuedAt`, not
  `Expired`.
- **Private fields**: `SiwxMessage`, `AuthOpts`, and `Authenticated` fields are
  private. Use getters and builders.
- **Builder `Result`**: `with_issued_at` / `with_expiration_time` /
  `with_not_before` are no longer `const fn -> Self`; they return `Result`.
  `with_request_id` / `with_resources` now return `Result`.
- **No-statement blank lines**: formatter and parser use `address\n\n\nURI:`
  (two blanks). 0.5 `address\n\nURI:` fails with `ExpectedBlankLine`.
- **`AuthOpts`**: `domain` and `nonce` required. Default `clock_skew` is 60s
  (applies only to `expiration_time` / `not_before` / `max_issued_age`). Optional
  `scheme` / `uri` / `chain_id` / `request_id`. Future `issued_at` is accepted.
- **EIP-55**: EVM `validate_address` uses `Address::parse_checksummed`.
  All-lowercase is rejected unless that string is the checksum form.
- **EVM `chain_id`**: `validate_chain_id` rejects non-decimal and leading zeros
  (`"01"`); `"0"` is allowed.
- **`Verifier::NAMESPACE`**: required associated const (`"eip155"` / `"solana"`).
  No default.
- **Deleted `EvmVerifier::with_rpc`**: use `with_rpc_for_chain` / `with_rpc_map`
  / `with_rpc_timeout`. RPC `eth_chainId` must equal the message chain.
- **Deleted CLI `--trust-message-bindings`**: `evm verify` / `svm verify` require
  `--domain` and `--nonce`. Optional `--uri` / `--scheme` / `--chain-id`.
  EIP-1271 uses paired `--rpc-chain-id` / `--rpc` (repeatable, same order).
- **SVM**: `validate_address` requires `VerifyingKey::from_bytes` (off-curve and
  the all-zero identity fail). `chain_id` charset is `[-_a-zA-Z0-9]`, length
  `1..=44` (Solana genesis hashes). This is **not** CAIP-2 `{1,32}`.
- **EIP-191**: reject high-s (EIP-2). Workspace version **0.6.0**.

### Added

- Feature **`eip6492 = ["eip1271"]`** (default off): ERC-6492 counterfactual
  signatures via vendored wevm/ox `universalSignatureValidatorBytecode`. Magic
  suffix is checked before EIP-191. No RPC for the message chain returns
  `EIP-6492 requires RPC`. Without the feature, magic signatures return
  `EIP-6492 not enabled`.
- `siwx-cli` feature **`eip6492`** (implies `eip1271`) so
  `evm verify --rpc-chain-id` / `--rpc` can validate wrapped signatures.
- SpruceID SIWE parse vectors in core CI; verify vectors in `siwx-evm`.
- `SiwxMessage::caip10`.
- CLI `--uri` / `--scheme` bindings on verify.

### Removed

- Canonical bit-identical check in `authenticate`
- `EvmVerifier::with_rpc(url)`
- CLI `--trust-message-bindings`
- Public mutation of message / auth / opts fields

## 0.5.0

Hardening toward production-integrable verification.

### Breaking

- **`Verifier::validate_address`** — chain crates must implement shape checks;
  `authenticate` calls it before verify.
- **CLI `verify`** requires `--domain` and `--nonce` unless
  `--trust-message-bindings` is set (debug self-binding).
- **`SiwxMessage.scheme`** field added (optional EIP-4361 preamble scheme).
- Workspace version **0.5.0**.

### Added

- `MAX_MESSAGE_BYTES` / `MAX_RESOURCES` DoS bounds on parse and authenticate
- `AuthOpts::with_max_issued_age` for issued-at freshness
- Optional `scheme://` preamble (`with_scheme` / parser / formatter)
- CLI feature `eip1271` and `evm verify --rpc` (when enabled)
- `EvmVerifier::with_rpc_map` for chain_id → RPC selection (`eip1271`)
- `SECURITY.md` threat-boundary notes
- EIP-1271 magic / construction unit tests
- EOA end-to-end `authenticate` fixture tests (shipped path)
- Offline EIP-1271 failure paths (`with_rpc_map` missing chain_id after 191 fail)
- `deny.toml` license allow list

### Library vs product residuals

Session/JWT, nonce store, and live-RPC 1271 e2e remain **out of library
scope** (see SECURITY.md). 0.5 claims a production-integrable **verification
library**, not a full hosted auth stack.

## 0.4.0

Breaking release focused on a single correct authentication path.

### Breaking

- **`authenticate` is the recommended login entry point** — parse, validate,
  require canonical form, and verify over the original message bytes.
- **`Verifier::verify` now takes `raw_message: &str`** and must hash/verify those
  exact bytes (not a re-serialized form).
- **`ValidateOpts` removed** — replaced by **`AuthOpts`** with required
  `domain` and `nonce` (optional `chain_id`, `timestamp`).
- **`SiwxMessage`**:
  - `nonce: String` and `issued_at: OffsetDateTime` are required.
  - `SiwxMessage::new(domain, address, uri, chain_id, nonce)` — version is
    fixed to `"1"` (no version parameter).
  - `with_statement` / `with_nonce` return `Result`.
- **`Display` for `SiwxMessage` removed** — use `Verifier::format_message` or
  `to_sign_string(chain_name)`.
- **`siwx-evm`**: only **`EvmVerifier`** is public. `Eip191Verifier` /
  `Eip1271Verifier` are no longer exported. EIP-1271 requires feature
  **`eip1271`** and `EvmVerifier::with_rpc`.
- **`siwx-svm`**: `Ed25519Verifier` derives the public key only from
  `message.address` (no external pubkey injection).
- **`nonce::generate(len)`** returns `Result` and requires `len >= 8`.
- **CLI `verify`**: failure exits non-zero; no longer emits `valid: false` with
  exit 0. Optional `--domain` / `--nonce` / `--chain-id` bindings.

### Added

- `siwx::authenticate` / `Authenticated`
- Parser rejects trailing non-empty garbage; nonce and issued-at required
- Domain / statement control-character checks
- Feature `eip1271` on `siwx-evm`

### Removed

- Duplicate `Makefile` (use `Justfile`)
