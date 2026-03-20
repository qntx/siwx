---
name: siwx
description: >-
  CAIP-122 Sign-In with X CLI tool for generating signing messages and verifying
  signatures across Ethereum and Solana. Use when the user asks to create sign-in
  challenges, verify wallet signatures, generate nonces, or parse CAIP-122
  messages. Supports JSON output via --json flag for agent consumption.
---

# siwx CLI — CAIP-122 Sign-In with X Tool

`siwx` is a single binary CLI for generating and verifying blockchain sign-in messages following the [CAIP-122](https://chainagnostic.org/CAIPs/caip-122) standard. Supports **Ethereum (EIP-191)** and **Solana (Ed25519)**.

## Installation

**Shell** (macOS / Linux):

```sh
curl -fsSL https://sh.qntx.fun/siwx | sh
```

**PowerShell** (Windows):

```powershell
irm https://sh.qntx.fun/siwx/ps | iex
```

Or via Cargo:

```bash
cargo install siwx-cli
```

### Verify installation

```sh
siwx --version
```

## CLI Structure

```sh
siwx [--json] <chain> <subcommand> [options]
```

The `--json` flag is **global** and must appear **before** the chain subcommand. When set, all output (including errors) is a single JSON object on stdout.

### Commands

| Command       | Description                                    |
|---------------|------------------------------------------------|
| `evm message` | Generate an Ethereum CAIP-122 signing message  |
| `evm verify`  | Verify an EIP-191 signature                    |
| `svm message` | Generate a Solana CAIP-122 signing message     |
| `svm verify`  | Verify an Ed25519 signature                    |
| `nonce`       | Generate a cryptographic nonce                 |
| `parse`       | Parse a CAIP-122 message string into fields    |

### Chain aliases

| Chain      | Primary | Aliases |
|------------|---------|---------|
| Ethereum   | `evm`   | `eth`   |
| Solana     | `svm`   | `sol`   |

## Message Generation Flags

| Flag            | Required | Description                                             |
|-----------------|----------|---------------------------------------------------------|
| `--domain`      | ✓        | RFC 4501 domain requesting the signing                  |
| `--address`     | ✓        | Blockchain address (0x-hex for EVM, base58 for SVM)     |
| `--uri`         | ✓        | RFC 3986 URI subject of the signing                     |
| `--chain-id`    | ✓        | CAIP-2 chain identifier (e.g. "1" for Ethereum mainnet) |
| `--statement`   |          | Human-readable statement                                |
| `--nonce`       |          | Nonce (auto-generated if omitted)                       |
| `--expiration`  |          | Expiration (RFC 3339 timestamp or seconds from now)     |
| `--not-before`  |          | Not-before time (RFC 3339 or seconds from now)          |
| `--request-id`  |          | System-specific request ID                              |
| `--resource`    |          | Resource URI (repeatable)                               |
| `--msg-version` |          | Message version (default: "1")                          |

## Verify Flags

| Flag          | Required | Description                                |
|---------------|----------|--------------------------------------------|
| `--message`   | ✓        | The raw CAIP-122 signing message text      |
| `--signature` | ✓        | Hex-encoded signature (0x prefix optional) |

## Usage Examples

### Generate Ethereum signing message (JSON)

```bash
siwx --json evm message \
  --domain example.com \
  --address 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 \
  --uri https://example.com/login \
  --chain-id 1 \
  --statement "I accept the Terms of Service"
```

### Generate Solana signing message (JSON)

```bash
siwx --json svm message \
  --domain example.com \
  --address GwAF45zjfyGzUbd3i3hXxzGeuchzEZXwpRYHZM5912F1 \
  --uri https://example.com/login \
  --chain-id 5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d
```

### Verify an EIP-191 signature (JSON)

```bash
siwx --json evm verify \
  --message "example.com wants you to sign in with your Ethereum account:..." \
  --signature 0x1234abcd...
```

### Verify a Solana Ed25519 signature (JSON)

```bash
siwx --json svm verify \
  --message "example.com wants you to sign in with your Solana account:..." \
  --signature abcd1234...
```

### Generate a nonce

```bash
siwx --json nonce
siwx nonce --len 32
```

### Parse a message

```bash
siwx --json parse --message "example.com wants you to sign in with your Ethereum account:..."
```

## JSON Output Schemas

### Message Generation

```json
{
  "chain": "ethereum",
  "message": "example.com wants you to sign in with your Ethereum account:\n0xd8dA...\n\n...",
  "domain": "example.com",
  "address": "0xd8dA...",
  "uri": "https://example.com/login",
  "version": "1",
  "chain_id": "1",
  "nonce": "abc123def456",
  "issued_at": "2026-03-20T12:00:00Z"
}
```

### Verify

```json
{
  "valid": true,
  "chain": "ethereum",
  "domain": "example.com",
  "address": "0xd8dA..."
}
```

### Nonce

```json
{
  "nonce": "M07wdVLtaJVndQAx5",
  "len": 17
}
```

### Parse

```json
{
  "domain": "example.com",
  "address": "0xd8dA...",
  "uri": "https://example.com/login",
  "version": "1",
  "chain_id": "1",
  "nonce": "abc123",
  "issued_at": "2026-03-20T12:00:00Z"
}
```

### Error

All errors in JSON mode return exit code 1 with:

```json
{
  "error": "invalid message format: missing preamble marker"
}
```

## Agent Best Practices

1. **Always use `--json`** for programmatic consumption to avoid ANSI escape codes.
2. **`--json` placement**: Must appear before the chain subcommand: `siwx --json evm message`, not `siwx evm --json message`.
3. **Nonce auto-generation**: If `--nonce` is omitted in `message`, a 17-character cryptographic nonce is auto-generated.
4. **Issued-at auto-set**: `issued_at` is always set to the current UTC time.
5. **Expiration shorthand**: Pass seconds for relative expiration: `--expiration 3600` = 1 hour from now.
6. **Verify reads address from message**: For SVM verify, the public key is derived from the address in the parsed message.
7. **Errors** in JSON mode return `{"error": "..."}` with exit code 1.
8. **Signature format**: Always hex-encoded, `0x` prefix is optional.
