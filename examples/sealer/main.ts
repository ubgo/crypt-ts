/**
 * Application-wide bound-key Sealer injected via dependency.
 *
 * Pattern: at boot, validate the application key once and construct
 * a single Sealer. Inject it into services that need encryption.
 */

import { Sealer } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

class Service {
  constructor(private readonly sealer: Sealer) {}

  encrypt(plaintext: string): string {
    return this.sealer.seal(plaintext)
  }

  decrypt(ciphertext: string): string {
    return this.sealer.open(ciphertext).toString("utf8")
  }
}

// Boot.
const appKey = Buffer.from("01234567890123456789012345678901")
const sealer = new Sealer(appKey)

// Inject.
const svc = new Service(sealer)

// Use.
const a = svc.encrypt("first")
console.log(`encrypted first:  ${a}`)
console.log(`decrypted:        ${svc.decrypt(a)}`)

const b = svc.encrypt("second")
console.log(`encrypted second: ${b}`)
console.log(`decrypted:        ${svc.decrypt(b)}`)

// Concurrent use is safe.
await Promise.all(
  Array.from({ length: 3 }, async (_, i) => {
    const ct = svc.encrypt(`from task ${i}`)
    const pt = svc.decrypt(ct)
    console.log(`task ${i} -> ${pt}`)
  }),
)
