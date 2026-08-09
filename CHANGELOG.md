# Changelog

## 0.4.0

Breaking release focused on a single correct authentication path.

### Breaking

- **`authenticate` is the recommended login entry point** — parse, validate,
  require canonical form, then verify over the original message bytes.
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
