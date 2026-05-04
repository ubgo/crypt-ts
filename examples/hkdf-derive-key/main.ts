/**
 * HKDF key derivation: derive sub-keys from a single master.
 *
 * One application root key. Derive per-tenant or per-purpose
 * sub-keys at runtime using HKDF-SHA256. Compromise of one tenant's
 * data does not expose other tenants — even with a shared root key,
 * derived keys are cryptographically independent.
 */

import { AEAD_KEY_SIZE, deriveKey, open, seal } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

const root = Buffer.from("root-application-key-32-bytes!!!")

for (const tenant of ["acme", "globex", "initech"]) {
  const k = deriveKey(root, undefined, Buffer.from(`tenant:${tenant}`), AEAD_KEY_SIZE)
  console.log(`tenant ${tenant.padEnd(7)} key prefix: ${k.subarray(0, 8).toString("hex")}...`)

  const ct = seal(k, "tenant data")
  const pt = open(k, ct).toString("utf8")
  console.log(`  round-trip: ${pt}`)
}

const aeadKey = deriveKey(root, undefined, Buffer.from("aead-v1"), AEAD_KEY_SIZE)
const macKey = deriveKey(root, undefined, Buffer.from("mac-v1"), AEAD_KEY_SIZE)
console.log(`\nAEAD-purpose key prefix: ${aeadKey.subarray(0, 8).toString("hex")}...`)
console.log(`MAC-purpose key prefix:  ${macKey.subarray(0, 8).toString("hex")}...`)

const prodKey = deriveKey(root, Buffer.from("env:prod"), Buffer.from("aead-v1"), AEAD_KEY_SIZE)
const devKey = deriveKey(root, Buffer.from("env:dev"), Buffer.from("aead-v1"), AEAD_KEY_SIZE)
console.log(`\nprod aead key prefix: ${prodKey.subarray(0, 8).toString("hex")}...`)
console.log(
  `dev  aead key prefix: ${devKey.subarray(0, 8).toString("hex")}... (independent of prod)`,
)
