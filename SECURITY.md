# Security

## Scope

`siwx` verifies CAIP-122 / EIP-4361-style wallet sign-in **messages and signatures**.
It does **not** implement:

- Nonce storage or single-use consumption
- Session cookies / JWT issuance
- Rate limiting or abuse prevention
- Origin/Host HTTP binding beyond string equality on `domain`

Those belong in the application that calls [`authenticate`](https://docs.rs/siwx).

## Recommended production flow

1. Server generates a cryptographic nonce (`siwx::nonce::generate_default`) and stores it with TTL.
2. Server builds `SiwxMessage` and renders with `Verifier::format_message`.
3. Client signs the **exact** rendered string.
4. Server calls `authenticate` with `AuthOpts::new(configured_domain, stored_nonce)` and, for multi-chain apps, `.with_chain_id(...)`.
5. On success, **atomically invalidate** the nonce and create an application session.
6. Prefer a short `expiration_time` (minutes) and optional `AuthOpts::with_max_issued_age`.

## Trust boundaries

| Input | Rule |
|-------|------|
| `raw_message` | Must match this library’s canonical formatter bit-for-bit |
| `AuthOpts.domain` / `nonce` | Must come from **server** configuration / store, not the client alone |
| RPC URL (`eip1271`) | **Server-configured only** — never take untrusted user URLs (SSRF) |
| Signature | Untrusted; cryptographic verification only |

## Message size

Parsing and authentication reject messages larger than `MAX_MESSAGE_BYTES` (16 KiB)
and resource lists larger than `MAX_RESOURCES` (32).

## Out of library scope (explicit residuals)

These are **not** provided by this crate and must not be assumed present when
calling the stack “production ready” as a full auth product:

| Residual | Owner |
|----------|--------|
| Nonce single-use store / atomic consume | Application |
| Session / JWT / cookie issuance and revocation | Application |
| HTTP Origin/Host multi-environment policy beyond `AuthOpts.domain` | Application |
| Rate limiting, CAPTCHA, device risk | Application / edge |
| **EIP-6492** predeploy smart-account signatures | Not implemented (future feature) |
| Live mainnet/anvil EIP-1271 success e2e in CI | App/ops; library tests cover offline selection and magic checks |
| Third-party security audit reports | Process outside the repo |

**Library production-ready** means: correct EOA (and optional 1271-with-trusted-RPC)
verification via `authenticate`, with binding and DoS bounds—not a hosted IdP.

## Reporting

Report vulnerabilities privately to the maintainers via the repository security advisory
channel or project contact listed on the GitHub org.
