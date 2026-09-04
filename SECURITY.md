# Security

## Scope

`siwx` verifies CAIP-122 / EIP-4361-style wallet sign-in **messages and signatures**.
It does **not** implement:

- Nonce storage or single-use consumption
- Session cookies / JWT issuance
- Rate limiting or abuse prevention
- Origin/Host HTTP binding beyond string equality on `domain`
- ENS resolution

Those belong in the application that calls [`authenticate`](https://docs.rs/siwx).

## Recommended production flow

1. Server generates a cryptographic nonce (`siwx::nonce::generate_default`) and stores it with TTL.
2. Server builds `SiwxMessage` and renders with `Verifier::format_message`.
3. Client signs the **exact** rendered string.
4. Server calls `authenticate` with `AuthOpts::new(configured_domain, stored_nonce)` and, for multi-chain apps, `.with_chain_id(...)`. Bind `uri` / `scheme` / `request_id` when those claims must match server configuration. Prefer `.with_uri(...)` to block confused-deputy (honest domain, attacker URI). The library does **not** require URI host == domain.
5. On success, **atomically invalidate** the nonce and create an application session.
6. Prefer a short `expiration_time` (minutes), single-use nonce consumption, and optional `AuthOpts::with_max_issued_age`.

## Trust boundaries

| Input | Rule |
|-------|------|
| `raw_message` | ABNF-parsed; preamble `chain_name` must equal `Verifier::CHAIN_NAME`; signature is verified over these original bytes |
| `AuthOpts.domain` / `nonce` | Must come from **server** configuration / store, not the client alone. Exact byte equality. |
| RPC URL (`eip1271` / `eip6492`) | **Server-configured only** — never take untrusted user URLs (SSRF) |
| Signature | Untrusted; cryptographic verification only |

CLI `--trust-message-bindings` is **deleted**. `evm verify` / `svm verify` always require `--domain` and `--nonce`. Debug self-sign by passing the same values the message already contains; there is no “trust the message” switch.

## Message size

Parsing and authentication reject messages larger than `MAX_MESSAGE_BYTES` (16 KiB)
and resource lists larger than `MAX_RESOURCES` (32).

## Trailing LF and parser differential

ABNF uses `LF` only. Parse rejects:

- CR (`InvalidFormat` / `CrLf`)
- a trailing LF after the last field (`UnexpectedTrailing`)
- out-of-order or unknown fields

If a client `join("\n")`s lines and leaves a leftover LF, the relying party may
call `raw.trim_end_matches('\n')` before `authenticate` (ASCII LF only, not
spaces). The library does not trim.

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

## EVM address and signatures

- Addresses must be EIP-55 checksummed (`Address::parse_checksummed`). All-lowercase
  is accepted only when that string is the checksum form.
- EIP-191 signatures must be 65 bytes and **low-s** (EIP-2). Without RPC, high-s
  is returned as `InvalidSignature`. With RPC, any 191 error falls through to
  EIP-1271.
- EIP-1271 / EIP-6492 call `eth_chainId` first; mismatch is `ChainIdMismatch`
  and does not invoke `isValidSignature` on the wrong chain.
- Deleted `EvmVerifier::with_rpc(url)` — a single unscoped URL would hit the
  wrong chain. Use `with_rpc_for_chain` / `with_rpc_map`.

EIP-1271 is not a pure function. If contract validation logic changes, the
application must invalidate sessions (short TTL / webhook). Out of library.

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

## EIP-6492 (feature `eip6492`, default off)

Counterfactual / predeploy smart-account signatures. The 32-byte magic suffix
`0x6492` repeated 16 times is checked **before** EIP-191. Without the feature,
those signatures return `InvalidSignature` (`EIP-6492 not enabled`) and do not
fall through to EIP-191.

With the feature, verification is a deployless `eth_call` (`to` omitted) of
vendored wevm/ox `universalSignatureValidatorBytecode` concatenated with
`abi.encode(signer, hash, signature)`. The pin is
`siwx-evm/src/bytecode/SOURCE.txt` (ox commit SHA + source path). Success is
`eth_call_bool`: last byte `0x01` and the rest zero (nodes pad `return(31,1)`
to 32 bytes). Last byte `0x00` is `VerificationFailed` (`EIP-6492 invalid`).
Revert or RPC failure is `VerificationFailed` **without** the RPC URL in the
string.

No RPC for the message chain (including `EvmVerifier::new()`) returns
`InvalidSignature` (`EIP-6492 requires RPC`) and does not `eth_call`. The
call is `eth_call` only (simulation); the library never sends a deployment
transaction.

## Logging

Do not log signature bytes or the full `raw_message`. Error strings must not
include RPC URLs (SSRF / internal network leak).

## Reporting

Report vulnerabilities privately to the maintainers via the repository security advisory
channel or project contact listed on the GitHub org.
