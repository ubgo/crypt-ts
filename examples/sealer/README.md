# Example: sealer

Application-wide bound-key `Sealer` injected as a service dependency.

## When to use this pattern

Always, in production code:

- One key validation at boot, not per-call.
- Long-lived `cipher.AEAD` reused across operations.
- Testable services that take a `Sealer` as a constructor argument.

## Run

```sh
cd examples/sealer
node --import tsx main.ts
```

## What it does

1. Boot: load 32-byte key, validate via `new Sealer(key)`.
2. Inject the `Sealer` into a `Service` class.
3. Use everywhere — concurrent across promises is safe (Node's `cipher.AEAD` is concurrent-safe).

## DI integration sketch

```ts
import { Sealer } from "@ubgo/crypt"

interface Plugin {
  sealer: Sealer
  db: Database
}

async function bootPlugin(cfg: Config): Promise<Plugin> {
  const sealer = new Sealer(cfg.encryptionKey)
  const db = await openDatabase(cfg)
  return { sealer, db }
}
```

## Test injection

```ts
import { describe, it, expect } from "vitest"
import { Sealer } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

describe("MyService", () => {
  const testKey = Buffer.alloc(32, 0x01)
  const sealer = new Sealer(testKey)
  const svc = new MyService(sealer)

  it("encrypts and decrypts", () => {
    const ct = svc.encrypt("hello")
    expect(svc.decrypt(ct)).toBe("hello")
  })
})
```

No globals to monkey-patch, no env vars to set, no mocks needed.
