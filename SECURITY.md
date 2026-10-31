# Security model

`siwx` verifies wallet-claimed identities for CAIP-122 Sign-In with X. This
document describes what the library does and does not promise.

## Scope

- Message syntax (eip4361 / SIWS), field validation, `Expect` binding +
  time policy, signature verification for `eip155` and `solana` namespaces.
- The library is byte-in/byte-out: it never performs I/O, builds transports,
  or applies timeouts.

## Recommended flow

1. Server: `createMessage`/`Message::new` with a fresh `nonce`, `issuedAt`,
   short `expirationTime`; store domain+nonce (+ chainId/requestId) per
   challenge.
2. Wallet signs the formatted text (or SIWS envelope).
3. Server: `authenticate(ns, signed, signature, expect)` — `Expect` binds
   domain and nonce (required) plus any of scheme/uri/chainId/requestId;
   then expiry/not-before/max-age, then the signature. Treat a valid-but-
   unbound signature as hostile.

## Trust boundaries

- **RPC providers are injected** (`with_provider` / `rpc` map). Provider
  trust, URL selection and transport timeouts belong to the caller — never
  accept provider URLs from untrusted input (SSRF).
- On-chain verification (`rpc` feature) binds `eth_chainId` to the message
  chain before any `eth_call` and caches it per chain-id key; smart-account
  verdicts are only as strong as the account contract's `isValidSignature`.
- Error `reason` strings are fixed and never contain URLs, hosts or provider
  error text.

## Erratum divergences (pinned, not bugs)

- Reliance-party profile requires `uri`, `version`, `chainId`, `nonce`,
  `issuedAt` — the spec grammar marks them optional.
- Only lowercase/uppercase-hex or valid EIP-55 EVM addresses; mixed-case
  checksum failures are `InvalidField { address }`.
- Ed25519: A and R must be canonical encodings of prime-order-subgroup
  (torsion-free, non-identity) points, `S < L`, strict verification.
- SIWS `version` must be `1`; off-chain envelopes are version 1 with exactly
  one signer.

## Residual risks

| Risk                                    | Owner                                            |
| --------------------------------------- | ------------------------------------------------ |
| Nonce reuse / missing domain binding    | Caller (`Expect` is required)                    |
| Smart-account logic changes post-deploy | Inherent to on-chain state                       |
| Wallet signing UI clarity               | Wallet/app; statement text is opaque bytes to us |
| RPC provider compromise                 | Caller transport policy                          |
