# Example: random-token

Generate cryptographically-random tokens, IDs, and keys.

## Run

```sh
cd examples/random-token
node --import tsx main.ts
```

## API quick reference

| Function         | Output                    | Use case                          |
| ---------------- | ------------------------- | --------------------------------- |
| `randomBytes(n)` | `Buffer` of `n` raw bytes | AEAD keys, HMAC keys, salts       |
| `randomToken(n)` | base64url-no-pad string   | API keys, magic-link tokens, CSRF |
| `randomHex(n)`   | lowercase hex string      | IDs, filenames, log correlation   |

## Sizing guide

| Use case             | Recommended bytes    | Result string         |
| -------------------- | -------------------- | --------------------- |
| Short-lived (≤24h)   | 16                   | 22 chars base64url    |
| API keys             | 24–32                | 32–43 chars base64url |
| AEAD encryption keys | 32 (`AEAD_KEY_SIZE`) | use raw `randomBytes` |
| HMAC keys            | 32                   | use raw `randomBytes` |
| Log correlation IDs  | 8                    | 16 hex chars          |

## Why URL-safe base64

`randomToken` uses `randomBytes(n).toString("base64url")` — `-` and `_` instead of `+/`, no `=` padding. URL-safe and HTTP-header-safe with no escaping.

## Why not `Math.random()`

Never. `Math.random()` is not cryptographically secure — predictable from internal state. `randomBytes` reads from the OS-level CSPRNG via `node:crypto.randomBytes`.
