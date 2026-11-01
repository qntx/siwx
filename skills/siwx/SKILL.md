---
name: siwx
description: >-
  CAIP-122 Sign-In with X CLI for generating signing messages and verifying
  signatures on Ethereum and Solana. Use for sign-in challenges, wallet
  signature verification, nonces, or CAIP-122 message parsing. --json output
  is designed for agent consumption.
---

# siwx CLI — CAIP-122 Sign-In with X

Single binary for the [CAIP-122](https://chainagnostic.org/CAIPs/caip-122)
Sign-In with X flow: `siwx evm|svm message|verify|parse` + `siwx nonce`.
EVM verifies EIP-191 (plus smart accounts via the ERC-6492 universal
validator when `rpc` providers are given); Solana verifies strict Ed25519
over SIWS text or off-chain message v1 envelopes.

## Install

```sh
curl -fsSL https://sh.qntx.org/siwx | sh   # macOS/Linux
siwx --version
```

## Commands

```sh
siwx [--json] evm message --domain D --address A --uri U --chain-id C \
    [--statement S] [--scheme https] [--nonce N] [--issued-at RFC3339] \
    [--expiration SECS|RFC3339] [--not-before SECS|RFC3339] \
    [--request-id ID] [--resource R ...]
siwx [--json] svm message ...             # same minus --scheme (SIWS rejects it)

siwx [--json] evm verify (--message TEXT | --message-file PATH | --message-hex HEX) \
    --signature SIG --domain D --nonce N \
    [--uri U] [--scheme S] [--chain-id C] [--request-id ID] \
    [--skew SECS] [--max-age SECS] [--rpc CHAIN_ID=URL ...]
siwx [--json] svm verify --message-hex HEX --signature B58 --domain D --nonce N

siwx [--json] evm|svm parse (--message|--message-file|--message-hex)
siwx [--json] nonce
```

- Message input: exactly one of `--message` / `--message-file` /
  `--message-hex` (hex carries exact signed bytes — required for SIWS
  off-chain envelopes).
- Signatures: evm = hex (`0x` optional); svm = base58 (or hex with `0x`).
- `--rpc CHAIN_ID=URL` is repeatable, evm only, needs feature `rpc`; used
  when the signature is a smart-account (1271/6492) signature.
- Nonce auto-generates for `message`; `--issued-at` defaults to now.

## JSON schemas

Success outputs:

```jsonc
// evm|svm message
{ "chain": "ethereum", "message": "<text>", "fields": {…}, "account": "eip155:1:0x…" }
// evm|svm verify (exit 0)
{ "valid": true, "chain": "ethereum", "account": "eip155:1:0x…", "fields": {…} }
// evm|svm parse
{ "chain": "ethereum", "fields": { "domain": "…", "address": "…", "uri": "…",
    "version": "1", "chainId": "1", "nonce": "…", "issuedAt": "…", "scheme?": "…",
    "statement?": "…", "expirationTime?": "…", "notBefore?": "…", "requestId?": "…",
    "resources?": ["…"] } }
// nonce
{ "nonce": "…" }
```

Any failure exits 1 with:

```jsonc
{
  "error": {
    "code": "VerificationFailed",
    "message": "…",
    "field?": "chainId",
    "syntax?": "MissingField",
  },
}
```

`code` values: `MessageTooLarge`, `Syntax`, `InvalidField`, `Mismatch`,
`Expired`, `NotYetValid`, `IssuedAtTooOld`, `InvalidSignature`,
`VerificationFailed`, `Unsupported`, `Backend`.

## Agent tips

- Always pass `--json` for parsing output.
- `verify` binds domain+nonce via `Expect` — always supply the
  server-issued values, never trust the message's own fields.
- Use `--message-hex` when verifying wallet-produced bytes (SIWS envelopes
  are not valid UTF-8).
- `--max-age` bounds issued-at freshness; `--skew` defaults to 60 s.
