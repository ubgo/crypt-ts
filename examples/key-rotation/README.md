# Example: key-rotation

Hand-rolled multi-key reader pattern. For new code, prefer the [`keyring-rotation`](../keyring-rotation) example using the built-in `KeyRing` class.

## When to use this pattern

- Reading v1-format ciphertext (no kid embedded) where you need fallback across multiple keys.
- Understanding the underlying try-each pattern.

## When to use `KeyRing` instead

New code. The built-in tags ciphertext with the kid, so reads dispatch O(1) instead of trying each key.

## Run

```sh
cd examples/key-rotation
node --import tsx main.ts
```

## What it does

1. Defines a `MultiKeyReader` class that holds an ordered list of keys.
2. Tries each key on `open` until one succeeds.
3. Demonstrates reading old + new ciphertexts with the same reader.

## Adapting to your code

For new code:

```ts
import { KeyRing } from "@ubgo/crypt"

const ring = new KeyRing("v1", oldKey)
ring.add("v2", newKey)
ring.setActive("v2")

const ct = ring.seal(payload)
const pt = ring.open(oldCiphertext) // dispatches by kid
```

For reading legacy v1-format (no kid) where you just need fallback:

```ts
import { open } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

class MultiKeyReader {
  constructor(private readonly keys: Buffer[]) {}
  open(ct: string, aad?: Buffer): Buffer {
    let last: Error | null = null
    for (const k of this.keys) {
      try {
        return open(k, ct, aad)
      } catch (e) {
        last = e as Error
      }
    }
    throw last ?? new Error("no keys")
  }
}
```

## See also

- [`keyring-rotation`](../keyring-rotation) — built-in `KeyRing` (recommended).
