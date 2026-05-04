# Example: audit-log-chain

HMAC-chained audit log with tamper detection. Each entry is signed over (previous-MAC || payload).

## When to use this pattern

- Regulated audit trails (SOC2, HIPAA, PCI).
- Security event logging.
- Append-only ledgers where order matters.

## Run

```sh
cd examples/audit-log-chain
node --import tsx main.ts
```

## What it does

1. Builds an `AuditLog` with three entries.
2. Each MAC is computed over `prevMAC || payload`, binding to the chain.
3. `verify()` walks forward; returns `-1` if all entries verify or the index of the first broken one.
4. Demonstrates that modifying an entry breaks the chain at that point.

## Adapting to your code

```ts
import { sign, verify } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

class AuditLog {
  private entries: { payload: Buffer; mac: Buffer }[] = []
  constructor(private readonly secret: Buffer) {}

  append(actor: string, action: string, resource: string): void {
    const prev = this.entries.at(-1)?.mac ?? Buffer.alloc(0)
    const payload = Buffer.from(`${new Date().toISOString()}|${actor}|${action}|${resource}`)
    const mac = sign(this.secret, Buffer.concat([prev, payload]))
    this.entries.push({ payload, mac })
  }

  verify(): number {
    let prev = Buffer.alloc(0)
    for (let i = 0; i < this.entries.length; i++) {
      const e = this.entries[i]!
      if (!verify(this.secret, Buffer.concat([prev, e.payload]), e.mac)) return i
      prev = e.mac
    }
    return -1
  }
}
```
