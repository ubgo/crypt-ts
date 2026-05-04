/**
 * Cross-language interop demo, TS side.
 *
 * Decrypts ciphertext produced by the Go cross_lang_go example.
 *
 * Usage:
 *   node --import tsx examples/cross-lang-ts/decrypt.ts <ciphertext-from-go>
 */

import { open } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

const SHARED_KEY_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

const ct = process.argv[2]
if (!ct) {
  console.error("usage: decrypt.ts <ciphertext>")
  process.exit(2)
}

const key = Buffer.from(SHARED_KEY_HEX, "hex")
const aad = Buffer.from("crypt-demo-v1")

try {
  const pt = open(key, ct, aad)
  console.log(`plaintext: ${pt.toString("utf8")}`)
} catch (e) {
  console.error(`decrypt failed: ${(e as Error).message}`)
  process.exit(1)
}
