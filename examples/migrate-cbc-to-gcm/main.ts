/**
 * One-shot migration from legacy AES-CBC ciphertext to AES-GCM AEAD.
 *
 * Pattern: iterate every row in a table that holds CBC-encrypted
 * data. For each row, decrypt with openAuto (handles both formats),
 * re-encrypt with seal, write back.
 *
 * In a real migration: backup first, run in batches, log per row,
 * use a cursor for very large tables.
 */

import { open, seal } from "@ubgo/crypt"
import { encryptCbc, openAuto } from "@ubgo/crypt/legacy"
import { Buffer } from "node:buffer"

const key = Buffer.from("01234567890123456789012345678901")

// --- Setup: simulate CBC-encrypted rows from the past, plus one
// already-AEAD row to demonstrate idempotence.
const db = new Map<string, string>()
for (const [id, plain] of [
  ["row_0", "sk_live_aaaa1111"],
  ["row_1", "sk_live_bbbb2222"],
  ["row_2", "sk_live_cccc3333"],
] as const) {
  db.set(id, encryptCbc(key, plain))
}
db.set("row_3", seal(key, "sk_live_dddd4444"))

console.log("--- before migration ---")
for (const [id, ct] of db) {
  console.log(`  ${id} = ${ct.slice(0, 32)}...`)
}

// --- Migration ---
let migrated = 0
let errored = 0
for (const [id, oldCt] of db) {
  try {
    const plain = openAuto(key, oldCt)
    const newCt = seal(key, plain)
    db.set(id, newCt)
    migrated++
  } catch (e) {
    console.log(`  ${id}: error: ${(e as Error).message}`)
    errored++
  }
}

console.log(`\n--- migration result ---`)
console.log(`migrated: ${migrated}`)
console.log(`errored:  ${errored}\n`)

console.log("--- after migration ---")
for (const [id, ct] of db) {
  console.log(`  ${id} = ${ct.slice(0, 32)}...`)
}

console.log("\n--- sanity check (all rows decrypt with open) ---")
for (const [id, ct] of db) {
  const pt = open(key, ct).toString("utf8")
  console.log(`  ${id} = ${pt}`)
}
