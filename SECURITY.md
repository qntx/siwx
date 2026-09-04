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
4. Server calls `authenticate` with `AuthOpts::new(configured_domain, stored_nonce)` and, for multi-chain apps, `.with_chain_id(...)`. Bind `uri` / `scheme` / `request_id` when those claims must match server configuration.
5. On success, **atomically invalidate** the nonce and create an application session.
6. Prefer a short `expiration_time` (minutes), single-use nonce consumption, and optional `AuthOpts::with_max_issued_age`.

## Trust boundaries

| Input | Rule |
|-------|------|
| `raw_message` | ABNF-parsed; preamble `chain_name` must equal `Verifier::CHAIN_NAME`; signature is verified over these original bytes |
| `AuthOpts.domain` / `nonce` | Must come from **server** configuration / store, not the client alone |
| RPC URL (`eip1271` / `eip6492`) | **Server-configured only** — never take untrusted user URLs (SSRF) |
| Signature | Untrusted; cryptographic verification only |

## Message size

Parsing and authentication reject messages larger than `MAX_MESSAGE_BYTES` (16 KiB)
and resource lists larger than `MAX_RESOURCES` (32).

## Trailing LF

ABNF uses `LF` and does not allow a trailing newline after the last field. Parse
rejects a trailing LF (`InvalidFormat` / `UnexpectedTrailing`). If a client
`join("\n")`s lines and leaves a leftover LF, the relying party may call
`raw.trim_end_matches('\n')` before `authenticate`. The library does not trim.

## Time window and clock skew

`AuthOpts` default `clock_skew` is 60 seconds. Skew applies only to
`expiration_time`, `not_before`, and `max_issued_age`:

- expired when `now > expiration_time + skew` (`now == expiration_time` is still valid)
- not yet valid when `now + skew < not_before`
- stale when `issued_at <= now + skew` and `(now - issued_at) - skew > max_issued_age`

The library does **not** reject a future `issued_at`. There is no `FutureIssuedAt`
error. Freshness is a short `expiration_time`, single-use nonce consumption, and
optional `max_issued_age`. Official SIWE verify vector `"expired message"` has
`issuedAt` after the injected `time` and must succeed.

## Out of library scope (explicit residuals)

These are **not** provided by this crate and must not be assumed present when
calling the stack “production ready” as a full auth product:

| Residual | Owner |
|----------|--------|
| Nonce single-use store / atomic consume | Application |
| Session / JWT / cookie issuance and revocation | Application |
| HTTP Origin/Host multi-environment policy beyond `AuthOpts.domain` | Application |
| Rate limiting, CAPTCHA, device risk | Application / edge |
| Live mainnet/anvil EIP-1271 / EIP-6492 success e2e in CI | App/ops; library tests cover offline selection, magic, and `eth_call_bool` |
| Third-party security audit reports | Process outside the repo |

**Library production-ready** means: correct EOA (and optional 1271/6492-with-trusted-RPC)
verification via `authenticate`, with binding and DoS bounds—not a hosted IdP.

## EIP-6492 (feature `eip6492`)

Counterfactual / predeploy smart-account signatures. The 32-byte magic suffix
`0x6492` repeated 16 times is checked **before** EIP-191. Without the feature,
those signatures return `InvalidSignature` (`EIP-6492 not enabled`) and do not
fall through to EIP-191.

With the feature, verification is a deployless `eth_call` (`to` omitted) of
vendored wevm/ox `universalSignatureValidatorBytecode` concatenated with
`abi.encode(signer, hash, signature)`. The pin is
`siwx-evm/src/bytecode/SOURCE.txt`. Success is `eth_call_bool`: last byte
`0x01` and the rest zero (nodes pad `return(31,1)` to 32 bytes). Last byte
`0x00` is `VerificationFailed` (`EIP-6492 invalid`). Revert or RPC failure is
`VerificationFailed` **without** the RPC URL in the string.

No RPC for the message chain (including `EvmVerifier::new()`) returns
`InvalidSignature` (`EIP-6492 requires RPC`) and does not `eth_call`. The
call is `eth_call` only (simulation); the library never sends a deployment
transaction.

## Reporting

Report vulnerabilities privately to the maintainers via the repository security advisory
channel or project contact listed on the GitHub org.
