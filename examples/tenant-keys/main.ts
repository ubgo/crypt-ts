/**
 * Per-tenant encryption keys derived from a single root key using
 * HKDF-SHA256.
 *
 * Compromise of one tenant's data does not expose other tenants —
 * even though the root key is shared, each derived key is independent.
 *
 * Uses node:crypto.hkdfSync directly. v1.1 of @ubgo/crypt will
 * expose a built-in deriveKey helper.
 */

import { AEAD_KEY_SIZE, open, seal } from "@ubgo/crypt"
import { Buffer } from "node:buffer"
import { hkdfSync } from "node:crypto"

function deriveTenantKey(rootKey: Buffer, tenantID: string): Buffer {
  const out = hkdfSync(
    "sha256",
    rootKey,
    Buffer.alloc(0), // salt
    Buffer.from(`tenant:${tenantID}`),
    AEAD_KEY_SIZE,
  )
  return Buffer.from(out)
}

const rootKey = Buffer.from("root-application-key-32-bytes!!!")
const tenants = ["acme", "globex", "initech"]

const keys = new Map<string, Buffer>()
for (const t of tenants) {
  const k = deriveTenantKey(rootKey, t)
  keys.set(t, k)
  console.log(
    `derived key for tenant "${t}" (first 8 bytes): ${k.subarray(0, 8).toString("hex")}...`,
  )
}

const plaintext = "tenant-private-data"
const enc = new Map<string, string>()
for (const t of tenants) {
  enc.set(t, seal(keys.get(t)!, plaintext))
}

for (const t of tenants) {
  const pt = open(keys.get(t)!, enc.get(t)!).toString("utf8")
  console.log(`tenant "${t}" decrypted: ${pt}`)
}

try {
  open(keys.get("acme")!, enc.get("globex")!)
} catch (e) {
  console.log(`\ncross-tenant decrypt blocked: ${(e as Error).message}`)
}
