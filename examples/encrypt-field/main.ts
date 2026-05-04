/**
 * Encrypt-at-rest of a database column.
 *
 * Pattern: an application key is loaded once at boot. A long-lived
 * Sealer is constructed from that key. Every write encrypts; every
 * read decrypts.
 */

import { Sealer } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

interface FakeRow {
  id: string
  clientSecret: string // ciphertext stored in DB
}

async function main() {
  // In production, load from env / KMS. Never hard-code.
  const appKey = Buffer.from("01234567890123456789012345678901") // 32 bytes

  const sealer = new Sealer(appKey)

  // --- Save path ---
  const plaintext = "sk_live_4242deadbeef"
  const encrypted = sealer.seal(plaintext)
  const row: FakeRow = { id: "prtn_001", clientSecret: encrypted }
  console.log(`stored row:`)
  console.log(`  id=${row.id}`)
  console.log(`  client_secret=${row.clientSecret}\n`)

  // --- Load path ---
  const decrypted = sealer.open(row.clientSecret).toString("utf8")
  console.log(`loaded plaintext: ${decrypted}`)

  // --- Tamper detection ---
  const tampered = row.clientSecret.slice(0, -1) + "X"
  try {
    sealer.open(tampered)
  } catch (e) {
    console.log(`\ntamper detected: ${(e as Error).message}`)
  }
}

void main()
