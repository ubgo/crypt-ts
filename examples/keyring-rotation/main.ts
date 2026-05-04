/**
 * Built-in KeyRing for graceful key rotation.
 *
 * Reads dispatch by the kid (key id) embedded in each ciphertext.
 * Active key for new writes; retired keys remain readable until
 * data naturally rotates through.
 */

import { KeyRing } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

const keyV1 = Buffer.alloc(32, 0x01)
const keyV2 = Buffer.alloc(32, 0x02)

// Boot in 2025 with one key.
const ring = new KeyRing("2025", keyV1)

const old = ring.seal("encrypted in 2025")
console.log(`2025 active=${ring.activeKid()}: ${old.slice(0, 32)}...`)

// 2026: rotate.
ring.add("2026", keyV2)
ring.setActive("2026")

const fresh = ring.seal("encrypted in 2026")
console.log(`2026 active=${ring.activeKid()}: ${fresh.slice(0, 32)}...`)

console.log(`\nopened old: ${ring.open(old).toString("utf8")}`)
console.log(`opened new: ${ring.open(fresh).toString("utf8")}`)

// After all 2025 data rotates through, drop the old key.
ring.remove("2025")
console.log(`\nremoved 2025 — now ring has only ${ring.activeKid()}`)

try {
  ring.open(old)
} catch (e) {
  console.log(`opening orphaned 2025 ct: ${(e as Error).message}`)
}
