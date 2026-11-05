# Test vectors

Shared golden vectors consumed by both the TypeScript and Rust
implementations. Files under this directory are **frozen data**: change
them only via a deliberate upstream sync or a reviewed contract change —
never to make a failing test pass.

## Layout

| Path | Provenance |
| ---- | ---------- |
| `limits/defaults.json` | Project-owned: shared default limits (`MAX_*`/`MIN_*`). |
| `siwe/` | Vendored byte-for-byte from [signinwithethereum/test-vectors] at commit `7f480da491b651164d7a31e43f45cc26557518e7` (licensed MIT OR Apache-2.0). |
| `siwe-overrides.json` | Project-owned: canonical cases siwx intentionally answers differently (keyed `"<file>#<case name>"`). |
| `eip4361/contract.json` | Project-owned: EIP-4361 layout accept/reject contract. |
| `eip4361/expect.json` | Project-owned: `Expect` binding + time policy contract. |
| `origin/check.json` | Project-owned: wallet-side request-origin verification contract. |
| `timestamp/from-instant.json` | Project-owned: instant → JS `toISOString` contract. |
| `timestamp/parse.json` | Project-owned: RFC 3339 parse accept/reject + epoch-ms contract. |

## `siwe/` contents

- `parsing/` — `parsing_positive`, `parsing_negative`, `parsing_warnings`.
- `verification/` — `verification_positive`, `verification_negative`,
  `eip1271.json` — canonical Argent/Loopring mainnet vectors; runs only
  when `SIWX_MAINNET_RPC=<url>` is set (both languages; see `parity.json`).
- `grammar/` — `valid_chars`, `invalid_chars`, `valid_uris`,
  `invalid_uris`, `valid_resources`, `invalid_resources`,
  `valid_specification`.
- `objects/` — `message_objects`, `parsing_negative_objects`.

## Deliberate divergence

`domain` rejects `userinfo@` (ERC-4361 erratum
[signinwithethereum/ERCs#1]). The two canonical cases that expect
acceptance live in `siwe-overrides.json`; runners must assert the pinned
error rather than skip.

[signinwithethereum/test-vectors]: https://github.com/signinwithethereum/test-vectors
[signinwithethereum/ERCs#1]: https://github.com/signinwithethereum/ERCs/issues/1
