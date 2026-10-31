# Shared test vectors

Frozen golden data consumed by both implementations: the TypeScript tests in
`packages/siwx/tests/` and the Rust tests in `crates/siwx/tests/` read exactly
these files. Do not reformat, re-wrap, or normalize them; any change is a
deliberate contract change and must land in both languages in the same
commit. Provenance lives in this README rather than in per-directory
`SOURCE.txt` files.

## Layout

| Path                                   | Contents                                              |
| -------------------------------------- | ----------------------------------------------------- |
| `spruceid/parsing_positive.json`       | Official SIWE messages that must parse                |
| `spruceid/parsing_negative.json`       | Official SIWE messages that must fail to parse        |
| `spruceid/verification_positive.json`  | Official SIWE field objects + signatures that verify  |
| `spruceid/verification_negative.json`  | Official SIWE field objects + signatures that fail    |
| `limits/defaults.json`                 | Core message limits shared by both implementations    |

## Provenance

- `spruceid/` — official test vectors from
  [spruceid/siwe](https://github.com/spruceid/siwe) `test/` at commit
  `911f6f2c73ef24deac73fec2f6b84930721d2fb4` (MIT OR Apache-2.0), vendored as
  git blobs:

  | File                          | Blob SHA                                   |
  | ----------------------------- | ------------------------------------------ |
  | `parsing_positive.json`       | `95ca7540c557455eeaa5442f4cc56ba3c428d25e` |
  | `parsing_negative.json`       | `8fd22cfc3a362ef50b58b357977b8afac54ad168` |
  | `verification_positive.json`  | `c4d38ba7e20bef5daa3193e7784ff1d382cf8eb5` |
  | `verification_negative.json`  | `3dd9206e54fcbc7f46f246af0ab131110819ad8b` |

  Only goldens are vendored, no source. The `eip1271.json` upstream file is
  intentionally not vendored: contract-signature cases need RPC.

- `limits/` — contract vector authored for this repository's `@qntx/siwx` +
  `siwx` (crate) interop suite. Names are camelCase JSON keys mirroring the
  TypeScript constant names.
