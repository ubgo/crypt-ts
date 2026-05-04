# Example: tenant-keys

Per-tenant encryption keys derived from a single root key using HKDF.

This example calls `node:crypto.hkdfSync` directly. For new code, prefer the [`hkdf-derive-key`](../hkdf-derive-key) example which uses `deriveKey` from the package (one line, same result).

## When to use this pattern

- Multi-tenant SaaS where each tenant's data is encrypted under an independent key.
- Compromise of one tenant's data should not expose other tenants — even though all derived keys come from the same root.
- Per-tenant key rotation: rotate one tenant's derived key by changing the `info` parameter; other tenants are unaffected.

## Run

```sh
cd examples/tenant-keys
node --import tsx main.ts
```

## What it does

1. From one root key, derives a unique 32-byte AEAD key per tenant.
2. Each tenant encrypts with their own derived key.
3. Demonstrates that one tenant's key cannot decrypt another tenant's data.

## Production-ready version

```ts
import { AEAD_KEY_SIZE, deriveKey, Sealer } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

function tenantSealer(rootKey: Buffer, tenantID: string): Sealer {
  const k = deriveKey(rootKey, undefined, Buffer.from(`tenant:${tenantID}`), AEAD_KEY_SIZE)
  return new Sealer(k)
}
```

For high-throughput services, cache the derived `Sealer` per tenantID with an LRU.

## Cross-language

Output is byte-identical to the Go counterpart's `crypt.DeriveKey` for the same `(root, salt, info, length)`.
