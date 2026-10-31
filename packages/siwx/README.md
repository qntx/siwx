# @qntx/siwx

CAIP-122 Sign-In with X for TypeScript — platform-neutral and Hermes-safe.
Mirrors the Rust `siwx` crate one-to-one through shared vectors.

```ts
import { createMessage, authenticate, generateNonce } from "@qntx/siwx";
import { evm } from "@qntx/siwx/evm";
import { svm } from "@qntx/siwx/svm";

const ns = evm();
const message = createMessage({
  domain: "service.org",
  address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  uri: "https://service.org/login",
  version: "1",
  chainId: "1",
  nonce: generateNonce(),
  issuedAt: "2026-01-01T00:00:00.000Z",
});
const text = ns.format(message); // wallet signs these bytes

const auth = await authenticate(ns, {
  message: text,
  signature, // Uint8Array
  expect: { domain: "service.org", nonce: message.nonce, skewSeconds: 60 },
});
```

- `evm()` — EIP-4361 layout + EIP-191 offline verification; pass
  `{ rpc: { "1": provider } }` (`Eip1193Provider`) to enable the ERC-6492
  universal-validator path for smart accounts.
- `svm()` — SIWS layout + strict Ed25519 (canonical prime-order-subgroup
  keys, `S < L`); `offchainMessage(text, signer)` builds the v1 envelope.
- Errors: `SiwxError` with `info.code` (`Syntax`, `InvalidField`, `Mismatch`,
  `VerificationFailed`, `Unsupported`, `Backend`, …) — see `errors.mdx` in
  the repo docs.

License: Apache-2.0 OR MIT.
