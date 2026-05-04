/**
 * Key rotation pattern using a multi-key reader.
 *
 * One active key signs new ciphertexts; recent retired keys remain
 * readable. As old data turns over, retire keys entirely.
 */

import { open, seal } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

class MultiKeyReader {
  constructor(private readonly keys: Buffer[]) {}

  static fromActive(active: Buffer, ...retired: Buffer[]): MultiKeyReader {
    return new MultiKeyReader([active, ...retired])
  }

  open(ciphertext: string, aad?: Buffer): Buffer {
    let lastErr: Error | null = null
    for (const k of this.keys) {
      try {
        return open(k, ciphertext, aad)
      } catch (e) {
        lastErr = e as Error
      }
    }
    throw lastErr ?? new Error("no keys configured")
  }
}

const keyV1 = Buffer.alloc(32, 0x01)
const keyV2 = Buffer.alloc(32, 0x02)

const oldCT = seal(keyV1, "encrypted with old key")
const newCT = seal(keyV2, "encrypted with new key")

const reader = MultiKeyReader.fromActive(keyV2, keyV1)

for (const [label, ct] of [
  ["old data", oldCT],
  ["new data", newCT],
] as const) {
  console.log(`${label}: ${reader.open(ct).toString("utf8")}`)
}

const fresh = seal(keyV2, "just written")
console.log(`fresh write: ${reader.open(fresh).toString("utf8")}`)
