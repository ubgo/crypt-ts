# Example: hkdf-derive-key

HKDF-SHA256 key derivation. Derive sub-keys from a single application root key.

## When to use this pattern

- Per-tenant isolation: one root key, independent derived keys per tenant.
- Per-purpose split: derive separate keys for AEAD encryption vs HMAC signing from one master.
- Per-environment binding: salt with `env:prod` / `env:dev`.

## When NOT to use

- Hashing user passwords. HKDF assumes high-entropy input. For passwords use the Go counterpart's `HashPassword` (argon2id), or pull `argon2` directly in Node.

## Run

```sh
cd examples/hkdf-derive-key
node --import tsx main.ts
```

## What it does

1. From one root key, derives a unique 32-byte AEAD key per tenant ("acme", "globex", "initech").
2. Each tenant encrypts with their own derived key.
3. Demonstrates per-purpose split.
4. Demonstrates salt binding.

## Cross-language

`deriveKey` produces byte-identical output to the Go counterpart's `crypt.DeriveKey` for the same `(masterKey, salt, info, length)`. The TS example outputs `tenant acme key prefix: 67429899cfd14887...` — paste the same root + tenant info into the Go example and you get the same bytes.

## Adapting to your code

```ts
import { AEAD_KEY_SIZE, deriveKey, Sealer } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

class TenantKeys {
  constructor(private readonly root: Buffer) {}

  sealer(tenantID: string): Sealer {
    const k = deriveKey(this.root, undefined, Buffer.from(`tenant:${tenantID}`), AEAD_KEY_SIZE)
    return new Sealer(k)
  }
}

// Per-request:
const sealer = tenantKeys.sealer(req.tenantID)
const ct = sealer.seal(payload)
```

For high-throughput services, cache derived `Sealer`s with an LRU keyed on tenantID.
