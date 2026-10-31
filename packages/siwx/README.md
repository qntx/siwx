# @qntx/siwx

Sign-In with X (CAIP-122) for TypeScript: SIWE, SIWS, message parsing,
validation, and signature verification. Mirrors the `siwx` Rust crate
and shares the same test vectors in `vectors/`.

```ts
import { authenticate, createMessage, generateNonce } from "@qntx/siwx";
import { evm } from "@qntx/siwx/evm";

const message = createMessage({
  domain: "service.org",
  address: "0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946",
  uri: "https://service.org/login",
  version: "1",
  chainId: "1",
  nonce: generateNonce(),
  issuedAt: new Date().toISOString(),
});

// Signer side: exact text the wallet signs.
const text = evm().format(message);

// Server side: parse → check bindings → verify (EIP-191).
const { account } = await authenticate(evm(), {
  message: text,
  signature: signatureBytes,
  expect: { domain: "service.org", nonce: message.nonce },
});
// account.id === "eip155:1:0xe5A12547fe4E872D192E3eCecb76F2Ce1aeA4946"
```

## License

MIT OR Apache-2.0
